import crypto from 'crypto';
import R from 'ramda';
import { createQuery, compile, queryClass, PreAggregations, QueryFactory } from '@cubejs-backend/schema-compiler';
import { v4 as uuidv4 } from 'uuid';
import { NativeInstance } from '@cubejs-backend/native';

export class CompilerApi {
  /**
   * Class constructor.
   * @param {SchemaFileRepository} repository
   * @param {DbTypeAsyncFn} dbType
   * @param {*} options
   */
  constructor(repository, dbType, options) {
    this.repository = repository;
    this.dbType = dbType;
    this.dialectClass = options.dialectClass;
    this.options = options || {};
    this.allowNodeRequire = options.allowNodeRequire == null ? true : options.allowNodeRequire;
    this.logger = this.options.logger;
    this.preAggregationsSchema = this.options.preAggregationsSchema;
    this.allowUngroupedWithoutPrimaryKey = this.options.allowUngroupedWithoutPrimaryKey;
    this.convertTzForRawTimeDimension = this.options.convertTzForRawTimeDimension;
    this.schemaVersion = this.options.schemaVersion;
    this.compileContext = options.compileContext;
    this.allowJsDuplicatePropsInSchema = options.allowJsDuplicatePropsInSchema;
    this.sqlCache = options.sqlCache;
    this.standalone = options.standalone;
    this.nativeInstance = this.createNativeInstance();
  }

  setGraphQLSchema(schema) {
    this.graphqlSchema = schema;
  }

  getGraphQLSchema() {
    return this.graphqlSchema;
  }

  createNativeInstance() {
    return new NativeInstance();
  }

  async getCompilers({ requestId } = {}) {
    let compilerVersion = (
      this.schemaVersion && await this.schemaVersion() ||
      'default_schema_version'
    );

    if (typeof compilerVersion === 'object') {
      compilerVersion = JSON.stringify(compilerVersion);
    }

    if (this.options.devServer) {
      const files = await this.repository.dataSchemaFiles();
      compilerVersion += `_${crypto.createHash('md5').update(JSON.stringify(files)).digest('hex')}`;
    }

    if (!this.compilers || this.compilerVersion !== compilerVersion) {
      this.compilers = this.compileSchema(compilerVersion, requestId).catch(e => {
        this.compilers = undefined;
        throw e;
      });
      this.compilerVersion = compilerVersion;
    }

    return this.compilers;
  }

  async compileSchema(compilerVersion, requestId) {
    const startCompilingTime = new Date().getTime();
    try {
      this.logger(this.compilers ? 'Recompiling schema' : 'Compiling schema', {
        version: compilerVersion,
        requestId
      });

      const compilers = await compile(this.repository, {
        allowNodeRequire: this.allowNodeRequire,
        compileContext: this.compileContext,
        allowJsDuplicatePropsInSchema: this.allowJsDuplicatePropsInSchema,
        standalone: this.standalone,
        nativeInstance: this.nativeInstance,
      });
      this.queryFactory = await this.createQueryFactory(compilers);

      this.logger('Compiling schema completed', {
        version: compilerVersion,
        requestId,
        duration: ((new Date()).getTime() - startCompilingTime),
      });

      return compilers;
    } catch (e) {
      this.logger('Compiling schema error', {
        version: compilerVersion,
        requestId,
        duration: ((new Date()).getTime() - startCompilingTime),
        error: (e.stack || e).toString()
      });
      throw e;
    }
  }

  async createQueryFactory(compilers) {
    const { cubeEvaluator } = compilers;

    const cubeToQueryClass = R.fromPairs(
      await Promise.all(
        cubeEvaluator.cubeNames().map(async cube => {
          const dataSource = cubeEvaluator.cubeFromPath(cube).dataSource ?? 'default';
          const dbType = await this.getDbType(dataSource);
          const dialectClass = this.getDialectClass(dataSource, dbType);
          return [cube, queryClass(dbType, dialectClass)];
        })
      )
    );
    return new QueryFactory(cubeToQueryClass);
  }

  async getDbType(dataSource = 'default') {
    return this.dbType({ dataSource, });
  }

  getDialectClass(dataSource = 'default', dbType) {
    return this.dialectClass && this.dialectClass({ dataSource, dbType });
  }

  async getSqlGenerator(query, dataSource) {
    const dbType = await this.getDbType(dataSource);
    const compilers = await this.getCompilers({ requestId: query.requestId });
    let sqlGenerator = await this.createQueryByDataSource(compilers, query, dataSource, dbType);

    if (!sqlGenerator) {
      throw new Error(`Unknown dbType: ${dbType}`);
    }

    dataSource = compilers.compiler.withQuery(sqlGenerator, () => sqlGenerator.dataSource);
    const _dbType = await this.getDbType(dataSource);
    if (dataSource !== 'default' && dbType !== _dbType) {
      // TODO consider more efficient way than instantiating query
      sqlGenerator = await this.createQueryByDataSource(
        compilers,
        query,
        dataSource,
        _dbType
      );

      if (!sqlGenerator) {
        throw new Error(`Can't find dialect for '${dataSource}' data source: ${_dbType}`);
      }
    }

    return { sqlGenerator, compilers };
  }

  async getSql(query, options = {}) {
    const { includeDebugInfo, exportAnnotatedSql } = options;
    const { sqlGenerator, compilers } = await this.getSqlGenerator(query);

    const getSqlFn = () => compilers.compiler.withQuery(sqlGenerator, () => ({
      external: sqlGenerator.externalPreAggregationQuery(),
      sql: sqlGenerator.buildSqlAndParams(exportAnnotatedSql),
      lambdaQueries: sqlGenerator.buildLambdaQuery(),
      timeDimensionAlias: sqlGenerator.timeDimensions[0] && sqlGenerator.timeDimensions[0].unescapedAliasName(),
      timeDimensionField: sqlGenerator.timeDimensions[0] && sqlGenerator.timeDimensions[0].dimension,
      order: sqlGenerator.order,
      cacheKeyQueries: sqlGenerator.cacheKeyQueries(),
      preAggregations: sqlGenerator.preAggregations.preAggregationsDescription(),
      dataSource: sqlGenerator.dataSource,
      aliasNameToMember: sqlGenerator.aliasNameToMember,
      rollupMatchResults: includeDebugInfo ?
        sqlGenerator.preAggregations.rollupMatchResultDescriptions() : undefined,
      canUseTransformedQuery: sqlGenerator.preAggregations.canUseTransformedQuery(),
      memberNames: sqlGenerator.collectAllMemberNames(),
    }));

    if (this.sqlCache) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { requestId, ...keyOptions } = query;
      const key = { query: keyOptions, options };
      return compilers.compilerCache.getQueryCache(key).cache(['sql'], getSqlFn);
    } else {
      return getSqlFn();
    }
  }

  getRolesFromContext(context) {
    const securityContext = (context && context.securityContext) || {};
    return new Set((securityContext.cloud && securityContext.cloud.roles) || []);
  }

  userHasRole(userRoles, role) {
    return userRoles.has(role);
  }

  roleMeetsConditions(evaluatedConditions) {
    if (evaluatedConditions && evaluatedConditions.length) {
      return evaluatedConditions.reduce((a, b) => {
        if (typeof b !== 'boolean') {
          throw new Error(`Access policy condition must return boolean, got ${JSON.stringify(b)}`);
        }
        return a || b;
      });
    }
    return true;
  }

  async getCubesFromQuery(query) {
    const sql = await this.getSql(query, { requestId: query.requestId });
    return new Set(sql.memberNames.map(memberName => memberName.split('.')[0]));
  }

  getApplicablePolicies(cube, context, cubeEvaluator) {
    const userRoles = this.getRolesFromContext(context);
    return cube.accessPolicy.filter(policy => {
      const evaluatedConditions = (policy.conditions || []).map(
        condition => cubeEvaluator.evaluateContextFunction(cube, condition.if, context)
      );
      const res = this.userHasRole(userRoles, policy.role) && this.roleMeetsConditions(evaluatedConditions);
      return res;
    });
  }

  rlsEnabledForCube(cube) {
    return cube.accessPolicy && cube.accessPolicy.length && cube.accessPolicy.length > 0;
  }

  isRlsEnabled(cubeEvaluator) {
    return cubeEvaluator.cubeNames().some(cubeName => this.rlsEnabledForCube(cubeEvaluator.cubeFromPath(cubeName)));
  }

  async applyRowLevelSecurity(query, context) {
    const { cubeEvaluator } = await this.getCompilers({ requestId: query.requestId });
    if (!this.isRlsEnabled(cubeEvaluator)) {
      return query;
    }
    console.log('Applying RLS');
    const queryCubes = await this.getCubesFromQuery(query);
    // TODO(maxim): how do we determine when "new style" RLS is on?
    // when at least one accessPolicy is defined?
    const filtersPerRole = {};
    cubeEvaluator.cubeNames().forEach(cubeName => {
      const cube = cubeEvaluator.cubeFromPath(cubeName);
      if (queryCubes.has(cube.name) && this.rlsEnabledForCube(cube)) {
        let hasRoleWithAccess = false;
        for (const policy of this.getApplicablePolicies(cube, context, cubeEvaluator)) {
          console.log('Processing policy for cube: ', cube.name, policy);
          hasRoleWithAccess = true;
          (policy?.rowLevel?.filters || []).forEach(filter => {
            filtersPerRole[policy.role] = filtersPerRole[policy.role] || [];
            const evaluatedValues = cubeEvaluator.evaluateContextFunction(
              cube,
              filter.values,
              context
            );
            console.log('pushing a filter for role', filter, policy.role);
            filtersPerRole[policy.role].push({
              member: filter.memberReference,
              operator: filter.operator,
              values: evaluatedValues
            });
          });
        }
        if (!hasRoleWithAccess) {
          query.segments.push({
            expression: () => '1 = 0',
            cubeName: cube.name,
            name: 'RLS Access Denied',
          });
        }
      }
    });
    const rlsFilter = {
      or: Object.keys(filtersPerRole).map(role => ({
        and: filtersPerRole[role]
      }))
    };
    console.log('rlsFilter', rlsFilter);
    query.filters.push(rlsFilter);
    return query;
  }

  async compilerCacheFn(requestId, key, path) {
    const compilers = await this.getCompilers({ requestId });
    if (this.sqlCache) {
      return (subKey, cacheFn) => compilers.compilerCache.getQueryCache(key).cache(path.concat(subKey), cacheFn);
    } else {
      return (subKey, cacheFn) => cacheFn();
    }
  }

  async preAggregations(filter) {
    const { cubeEvaluator } = await this.getCompilers();
    return cubeEvaluator.preAggregations(filter);
  }

  async scheduledPreAggregations() {
    const { cubeEvaluator } = await this.getCompilers();
    return cubeEvaluator.scheduledPreAggregations();
  }

  async createQueryByDataSource(compilers, query, dataSource, dbType) {
    if (!dbType) {
      dbType = await this.getDbType(dataSource);
    }

    return this.createQuery(compilers, dbType, this.getDialectClass(dataSource, dbType), query);
  }

  createQuery(compilers, dbType, dialectClass, query) {
    return createQuery(
      compilers,
      dbType,
      {
        ...query,
        dialectClass,
        externalDialectClass: this.options.externalDialectClass,
        externalDbType: this.options.externalDbType,
        preAggregationsSchema: this.preAggregationsSchema,
        allowUngroupedWithoutPrimaryKey: this.allowUngroupedWithoutPrimaryKey,
        convertTzForRawTimeDimension: this.convertTzForRawTimeDimension,
        queryFactory: this.queryFactory,
      }
    );
  }

  filterVisibilityByAccessPolicy(cubeEvaluator, context, cubes) {
    const isMemberVisibleInContext = {};

    if (!this.isRlsEnabled(cubeEvaluator)) {
      return cubes;
    }

    for (const cube of cubes.filter(c => this.rlsEnabledForCube(c.config))) {
      console.log('filterVisibilityByAccessPolicy', cube.config.name);
      const evaluatedCube = cubeEvaluator.cubeFromPath(cube.config.name);

      const calculateContextVisibility = (item) => {
        let isIncluded = false;
        let isExplicitlyExcluded = false;
        for (const policy of this.getApplicablePolicies(evaluatedCube, context, cubeEvaluator)) {
          if (policy.memberLevel) {
            isIncluded = policy.memberLevel.includesMembers.includes(item.name) || isIncluded;
            isExplicitlyExcluded = policy.memberLevel.excludesMembers.includes(item.name) || isExplicitlyExcluded;
          } else {
            // TODO(maxim): validate this, it looks sus
            // a policy without explicit memberLevel definition implicitly allow all members
            isIncluded = true;
          }
        }
        return isIncluded && !isExplicitlyExcluded;
      };

      for (const dimension of cube.config.dimensions) {
        isMemberVisibleInContext[dimension.name] = calculateContextVisibility(dimension);
      }

      for (const measure of cube.config.measures) {
        isMemberVisibleInContext[measure.name] = calculateContextVisibility(measure);
      }

      // TODO(maxim): should we filter segments as well?
      // for (const segment of cube.config.segments) {
      //   isMemberVisibleInContext[segment.name] = calculateContextVisibility(segment);
      // }
    }

    console.log('isMemberVisibleInContext', isMemberVisibleInContext);

    const visibilityFilterForCube = (cube) => {
      if (!this.rlsEnabledForCube(cube.config)) {
        return (item) => item.isVisible;
      }
      return (item) => (item.isVisible && isMemberVisibleInContext[item.name] || false);
    };

    return cubes
      .map((cube) => ({
        config: {
          ...cube.config,
          measures: cube.config.measures?.filter(visibilityFilterForCube(cube)),
          dimensions: cube.config.dimensions?.filter(visibilityFilterForCube(cube)),
          // segments: cube.config.segments?.filter(visibilityFilterForCube(cube)),
        },
      })).filter(
        cube => cube.config.measures?.length ||
          cube.config.dimensions?.length ||
          cube.config.segments?.length
      );
  }

  async metaConfig(requestContext, options = {}) {
    const { includeCompilerId, ...restOptions } = options;
    const compilers = await this.getCompilers(restOptions);
    const { cubes } = compilers.metaTransformer;
    const filteredCubes = this.filterVisibilityByAccessPolicy(compilers.cubeEvaluator, requestContext, cubes);
    if (includeCompilerId) {
      return {
        cubes: filteredCubes,
        compilerId: compilers.compilerId,
      };
    }
    return filteredCubes;
  }

  async metaConfigExtended(requestContext, options) {
    const { metaTransformer, cubeEvaluator } = await this.getCompilers(options);
    const filteredCubes = this.filterVisibilityByAccessPolicy(
      cubeEvaluator,
      requestContext,
      metaTransformer?.cubes
    );
    return {
      metaConfig: filteredCubes,
      cubeDefinitions: metaTransformer?.cubeEvaluator?.cubeDefinitions,
    };
  }

  async compilerId(options = {}) {
    return (await this.getCompilers(options)).compilerId;
  }

  async cubeNameToDataSource(query) {
    const { cubeEvaluator } = await this.getCompilers({ requestId: query.requestId });
    return cubeEvaluator
      .cubeNames()
      .map(
        (cube) => ({ [cube]: cubeEvaluator.cubeFromPath(cube).dataSource || 'default' })
      ).reduce((a, b) => ({ ...a, ...b }), {});
  }

  async dataSources(orchestratorApi, query) {
    const cubeNameToDataSource = await this.cubeNameToDataSource(query || { requestId: `datasources-${uuidv4()}` });

    let dataSources = Object.keys(cubeNameToDataSource).map(c => cubeNameToDataSource[c]);

    dataSources = [...new Set(dataSources)];

    dataSources = await Promise.all(
      dataSources.map(async (dataSource) => {
        try {
          await orchestratorApi.driverFactory(dataSource);
          const dbType = await this.getDbType(dataSource);
          return { dataSource, dbType };
        } catch (err) {
          return null;
        }
      })
    );

    return {
      dataSources: dataSources.filter((source) => source),
    };
  }

  canUsePreAggregationForTransformedQuery(transformedQuery, refs) {
    return PreAggregations.canUsePreAggregationForTransformedQueryFn(transformedQuery, refs);
  }
}
