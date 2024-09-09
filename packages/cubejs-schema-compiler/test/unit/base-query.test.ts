import moment from 'moment-timezone';
import { BaseQuery, PostgresQuery, MssqlQuery, UserError } from '../../src';
import { prepareCompiler, prepareYamlCompiler } from './PrepareCompiler';
import {
  createCubeSchema,
  createCubeSchemaWithCustomGranularities,
  createCubeSchemaYaml,
  createJoinedCubesSchema,
  createSchemaYaml
} from './utils';
import { BigqueryQuery } from '../../src/adapter/BigqueryQuery';

describe('SQL Generation', () => {
  describe('Common - Yaml - syntax sugar', () => {
    const compilers = /** @type Compilers */ prepareYamlCompiler(
      createCubeSchemaYaml({ name: 'cards', sqlTable: 'card_tbl' })
    );

    it('Simple query', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.count'
        ],
        timeDimensions: [],
        filters: [],
      });
      const queryAndParams = query.buildSqlAndParams();
      expect(queryAndParams[0]).toContain('card_tbl');
    });
  });

  describe('Common - JS - syntax sugar', () => {
    const compilers = /** @type Compilers */ prepareCompiler(
      createCubeSchema({
        name: 'cards',
        sqlTable: 'card_tbl'
      })
    );

    it('Simple query', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.count'
        ],
        timeDimensions: [],
        filters: [],
      });
      const queryAndParams = query.buildSqlAndParams();
      expect(queryAndParams[0]).toContain('card_tbl');
    });
  });

  describe('Custom granularities', () => {
    const compilers = /** @type Compilers */ prepareCompiler(
      createCubeSchemaWithCustomGranularities('orders')
    );

    const granularityQueries = [
      {
        measures: [
          'orders.count'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.count'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year_by_1st_april',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.count'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year_by_1st_march',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.count'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year_by_1st_june',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.rollingCountByUnbounded'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.status'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.rollingCountByUnbounded'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year_by_1st_april',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.status'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.rollingCountByTrailing2Day'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.status'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.rollingCountByTrailing2Day'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year_by_1st_april',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.status'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.rollingCountByLeading2Day'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.status'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.rollingCountByLeading2Day'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year_by_1st_april',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.status'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      }
    ];

    const proxiedGranularitiesQueries = [
      {
        measures: [
          'orders.count'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.createdAtHalfYear'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.count'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.createdAtHalfYearBy1stJune'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.count'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            granularity: 'half_year_by_1st_june',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.createdAtHalfYearBy1stMarch'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.count'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.createdAtPredefinedYear'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
      {
        measures: [
          'orders.count'
        ],
        timeDimensions: [
          {
            dimension: 'orders.createdAt',
            dateRange: [
              '2020-01-01',
              '2021-12-31'
            ]
          }
        ],
        dimensions: [
          'orders.createdAtPredefinedQuarter'
        ],
        filters: [],
        timezone: 'Europe/Kyiv'
      },
    ];

    it('Test time series with different granularities', async () => {
      await compilers.compiler.compile();

      const query = new BaseQuery(compilers, granularityQueries[0]);

      {
        const timeDimension = query.newTimeDimension({
          dimension: 'orders.createdAt',
          granularity: 'half_year',
          dateRange: ['2021-01-01', '2021-12-31']
        });
        expect(timeDimension.timeSeries()).toEqual([
          ['2021-01-01T00:00:00.000', '2021-06-30T23:59:59.999'],
          ['2021-07-01T00:00:00.000', '2021-12-31T23:59:59.999']
        ]);
      }

      {
        const timeDimension = query.newTimeDimension({
          dimension: 'orders.createdAt',
          granularity: 'half_year_by_1st_april',
          dateRange: ['2021-01-01', '2021-12-31']
        });
        expect(timeDimension.timeSeries()).toEqual([
          ['2020-10-01T00:00:00.000', '2021-03-31T23:59:59.999'],
          ['2021-04-01T00:00:00.000', '2021-09-30T23:59:59.999'],
          ['2021-10-01T00:00:00.000', '2022-03-31T23:59:59.999']
        ]);
      }
    });

    describe('via PostgresQuery', () => {
      beforeAll(async () => {
        await compilers.compiler.compile();
      });

      granularityQueries.forEach(q => {
        it(`measure "${q.measures[0]}" + granularity "${q.timeDimensions[0].granularity}"`, () => {
          const query = new PostgresQuery(compilers, q);
          const queryAndParams = query.buildSqlAndParams();
          const queryString = queryAndParams[0];
          console.log('Generated query: ', queryString);

          if (q.measures[0].includes('count')) {
            expect(queryString.includes('INTERVAL \'6 months\'')).toBeTruthy();
          } else if (q.measures[0].includes('rollingCountByTrailing2Day')) {
            expect(queryString.includes('- interval \'2 day\'')).toBeTruthy();
          } else if (q.measures[0].includes('rollingCountByLeading2Day')) {
            expect(queryString.includes('+ interval \'3 day\'')).toBeTruthy();
          }
        });
      });

      proxiedGranularitiesQueries.forEach(q => {
        it(`proxy granularity reference "${q.dimensions[0]}"`, () => {
          const query = new PostgresQuery(compilers, q);
          const queryAndParams = query.buildSqlAndParams();
          const queryString = queryAndParams[0];
          console.log('Generated query: ', queryString);

          if (q.dimensions[0].includes('PredefinedYear')) {
            expect(queryString.includes('date_trunc(\'year\'')).toBeTruthy();
          } else if (q.dimensions[0].includes('PredefinedQuarter')) {
            expect(queryString.includes('date_trunc(\'quarter\'')).toBeTruthy();
          } else {
            expect(queryString.includes('INTERVAL \'6 months\'')).toBeTruthy();
            expect(queryString.includes('count("orders".id')).toBeTruthy();
          }
        });
      });
    });
  });

  describe('Common - JS', () => {
    const compilers = /** @type Compilers */ prepareCompiler(
      createCubeSchema({
        name: 'cards',
        refreshKey: `
          refreshKey: {
            every: '10 minute',
          },
        `,
      })
    );

    it('Test time series with 6 digits timestamp precision - bigquery', async () => {
      await compilers.compiler.compile();

      const query = new BigqueryQuery(compilers, {
        measures: [
          'cards.count'
        ],
        timeDimensions: [],
        filters: [],
      });

      {
        const timeDimension = query.newTimeDimension({
          dimension: 'cards.createdAt',
          granularity: 'day',
          dateRange: ['2021-01-01', '2021-01-02']
        });
        expect(timeDimension.timeSeries()).toEqual([
          ['2021-01-01T00:00:00.000000', '2021-01-01T23:59:59.999999'],
          ['2021-01-02T00:00:00.000000', '2021-01-02T23:59:59.999999']
        ]);
      }

      const timeDimension = query.newTimeDimension({
        dimension: 'cards.createdAt',
        granularity: 'day',
        dateRange: ['2021-01-01', '2021-01-02']
      });

      expect(timeDimension.formatFromDate('2021-01-01T00:00:00.000')).toEqual(
        '2021-01-01T00:00:00.000000'
      );
      expect(timeDimension.formatFromDate('2021-01-01T00:00:00.000000')).toEqual(
        '2021-01-01T00:00:00.000000'
      );

      expect(timeDimension.formatToDate('2021-01-01T23:59:59.998')).toEqual(
        '2021-01-01T23:59:59.998000'
      );
      expect(timeDimension.formatToDate('2021-01-01T23:59:59.999')).toEqual(
        '2021-01-01T23:59:59.999999'
      );
      expect(timeDimension.formatToDate('2021-01-01T23:59:59.999999')).toEqual(
        '2021-01-01T23:59:59.999999'
      );
    });

    it('Test time series with different granularity - postgres', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.count'
        ],
        timeDimensions: [],
        filters: [],
      });

      {
        const timeDimension = query.newTimeDimension({
          dimension: 'cards.createdAt',
          granularity: 'day',
          dateRange: ['2021-01-01', '2021-01-02']
        });
        expect(timeDimension.timeSeries()).toEqual([
          ['2021-01-01T00:00:00.000', '2021-01-01T23:59:59.999'],
          ['2021-01-02T00:00:00.000', '2021-01-02T23:59:59.999']
        ]);
      }

      {
        const timeDimension = query.newTimeDimension({
          dimension: 'cards.createdAt',
          granularity: 'day',
          dateRange: ['2021-01-01', '2021-01-02']
        });
        expect(timeDimension.timeSeries()).toEqual([
          ['2021-01-01T00:00:00.000', '2021-01-01T23:59:59.999'],
          ['2021-01-02T00:00:00.000', '2021-01-02T23:59:59.999']
        ]);
      }

      {
        const timeDimension = query.newTimeDimension({
          dimension: 'cards.createdAt',
          granularity: 'hour',
          dateRange: ['2021-01-01', '2021-01-01']
        });
        expect(timeDimension.timeSeries()).toEqual(
          new Array(24).fill(null).map((v, index) => [
            `2021-01-01T${index.toString().padStart(2, '0')}:00:00.000`,
            `2021-01-01T${index.toString().padStart(2, '0')}:59:59.999`
          ])
        );
      }

      {
        const timeDimension = query.newTimeDimension({
          dimension: 'cards.createdAt',
          granularity: 'minute',
          // for 1 hour only
          dateRange: ['2021-01-01T00:00:00.000', '2021-01-01T00:59:59.999']
        });
        expect(timeDimension.timeSeries()).toEqual(
          new Array(60).fill(null).map((v, index) => [
            `2021-01-01T00:${index.toString().padStart(2, '0')}:00.000`,
            `2021-01-01T00:${index.toString().padStart(2, '0')}:59.999`
          ])
        );
      }

      {
        const timeDimension = query.newTimeDimension({
          dimension: 'cards.createdAt',
          granularity: 'second',
          // for 1 minute only
          dateRange: ['2021-01-01T00:00:00.000', '2021-01-01T00:00:59.000']
        });
        expect(timeDimension.timeSeries()).toEqual(
          new Array(60).fill(null).map((v, index) => [
            `2021-01-01T00:00:${index.toString().padStart(2, '0')}.000`,
            `2021-01-01T00:00:${index.toString().padStart(2, '0')}.999`
          ])
        );
      }
    });

    it('Test same dimension with different granularities - postgres', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.count'
        ],
        timeDimensions: [
          {
            dimension: 'cards.createdAt',
            granularity: 'quarter',
          },
          {
            dimension: 'cards.createdAt',
            granularity: 'month',
          }
        ],
        filters: [],
      });

      const queryAndParams = query.buildSqlAndParams();
      const queryString = queryAndParams[0];
      expect(queryString.includes('date_trunc(\'quarter\'')).toBeTruthy();
      expect(queryString.includes('cards__created_at_quarter')).toBeTruthy();
      expect(queryString.includes('date_trunc(\'month\'')).toBeTruthy();
      expect(queryString.includes('cards__created_at_month')).toBeTruthy();
    });

    it('Test for everyRefreshKeySql', async () => {
      await compilers.compiler.compile();

      const timezone = 'America/Los_Angeles';
      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.count'
        ],
        timeDimensions: [],
        filters: [],
        timezone,
      });
      //
      const utcOffset = moment.tz('America/Los_Angeles').utcOffset() * 60;
      expect(query.everyRefreshKeySql({
        every: '1 hour'
      })).toEqual(['FLOOR((EXTRACT(EPOCH FROM NOW())) / 3600)', false, expect.any(BaseQuery)]);

      // Standard syntax (minutes hours day month dow)
      expect(query.everyRefreshKeySql({ every: '0 * * * *', timezone }))
        .toEqual([`FLOOR((${utcOffset} + EXTRACT(EPOCH FROM NOW()) - 0) / 3600)`, false, expect.any(BaseQuery)]);

      expect(query.everyRefreshKeySql({ every: '0 10 * * *', timezone }))
        .toEqual([`FLOOR((${utcOffset} + EXTRACT(EPOCH FROM NOW()) - 36000) / 86400)`, false, expect.any(BaseQuery)]);

      // Additional syntax with seconds (seconds minutes hours day month dow)
      expect(query.everyRefreshKeySql({ every: '0 * * * * *', timezone, }))
        .toEqual([`FLOOR((${utcOffset} + EXTRACT(EPOCH FROM NOW()) - 0) / 60)`, false, expect.any(BaseQuery)]);

      expect(query.everyRefreshKeySql({ every: '0 * * * *', timezone }))
        .toEqual([`FLOOR((${utcOffset} + EXTRACT(EPOCH FROM NOW()) - 0) / 3600)`, false, expect.any(BaseQuery)]);

      expect(query.everyRefreshKeySql({ every: '30 * * * *', timezone }))
        .toEqual([`FLOOR((${utcOffset} + EXTRACT(EPOCH FROM NOW()) - 1800) / 3600)`, false, expect.any(BaseQuery)]);

      expect(query.everyRefreshKeySql({ every: '30 5 * * 5', timezone }))
        .toEqual([`FLOOR((${utcOffset} + EXTRACT(EPOCH FROM NOW()) - 365400) / 604800)`, false, expect.any(BaseQuery)]);

      for (let i = 1; i < 59; i++) {
        expect(query.everyRefreshKeySql({ every: `${i} * * * *`, timezone }))
          .toEqual([`FLOOR((${utcOffset} + EXTRACT(EPOCH FROM NOW()) - ${i * 60}) / ${1 * 60 * 60})`, false, expect.any(BaseQuery)]);
      }

      try {
        query.everyRefreshKeySql({
          every: '*/9 */7 * * *',
          timezone: 'America/Los_Angeles'
        });

        throw new Error();
      } catch (error) {
        expect(error).toBeInstanceOf(UserError);
      }
    });
  });

  describe('refreshKey from schema', () => {
    const compilers = /** @type Compilers */ prepareCompiler(
      createCubeSchema({
        name: 'cards',
        refreshKey: `
        refreshKey: {
          every: '10 minute',
        },
      `,
        preAggregations: `
        countCreatedAt: {
            type: 'rollup',
            external: true,
            measureReferences: [count],
            timeDimensionReference: createdAt,
            granularity: \`day\`,
            partitionGranularity: \`month\`,
            refreshKey: {
              every: '1 hour',
            },
            scheduledRefresh: true,
        },
        maxCreatedAt: {
            type: 'rollup',
            external: true,
            measureReferences: [max],
            timeDimensionReference: createdAt,
            granularity: \`day\`,
            partitionGranularity: \`month\`,
            refreshKey: {
              sql: 'SELECT MAX(created_at) FROM cards',
            },
            scheduledRefresh: true,
        },
        minCreatedAt: {
            type: 'rollup',
            external: false,
            measureReferences: [min],
            timeDimensionReference: createdAt,
            granularity: \`day\`,
            partitionGranularity: \`month\`,
            refreshKey: {
              every: '1 hour',
              incremental: true,
            },
            scheduledRefresh: true,
        },
      `
      })
    );

    it('cacheKeyQueries for cube with refreshKey.every (source)', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.sum'
        ],
        timeDimensions: [],
        filters: [],
        timezone: 'America/Los_Angeles',
      });

      // Query should not match any pre-aggregation!
      expect(query.cacheKeyQueries()).toEqual([
        [
          // Postgres dialect
          'SELECT FLOOR((EXTRACT(EPOCH FROM NOW())) / 600) as refresh_key',
          [],
          {
            // false, because there is no externalQueryClass
            external: false,
            renewalThreshold: 60,
          }
        ]
      ]);
    });

    it('cacheKeyQueries for cube with refreshKey.every (external)', async () => {
      await compilers.compiler.compile();

      // Query should not match any pre-aggregation!
      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.sum'
        ],
        timeDimensions: [],
        filters: [],
        timezone: 'America/Los_Angeles',
        externalQueryClass: MssqlQuery
      });

      // Query should not match any pre-aggregation!
      expect(query.cacheKeyQueries()).toEqual([
        [
          // MSSQL dialect, because externalQueryClass
          'SELECT FLOOR((DATEDIFF(SECOND,\'1970-01-01\', GETUTCDATE())) / 600) as refresh_key',
          [],
          {
            // true, because externalQueryClass
            external: true,
            renewalThreshold: 60,
          }
        ]
      ]);
    });

    /**
     * Testing: pre-aggregation which use refreshKey.every & external database defined, should be executed in
     * external database
     */
    it('preAggregationsDescription for query - refreshKey every (external)', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.count'
        ],
        timeDimensions: [],
        filters: [],
        timezone: 'America/Los_Angeles',
        externalQueryClass: MssqlQuery
      });

      const preAggregations: any = query.newPreAggregations().preAggregationsDescription();
      expect(preAggregations.length).toEqual(1);
      expect(preAggregations[0].invalidateKeyQueries).toEqual([
        [
          // MSSQL dialect
          'SELECT FLOOR((DATEDIFF(SECOND,\'1970-01-01\', GETUTCDATE())) / 3600) as refresh_key',
          [],
          {
            external: true,
            renewalThreshold: 300,
          }
        ]
      ]);
    });

    /**
     * Testing: preAggregation which has refresh.sql, should be executed in source db
     */
    it('preAggregationsDescription for query - refreshKey manually (external)', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.max'
        ],
        timeDimensions: [],
        filters: [],
        timezone: 'America/Los_Angeles',
        externalQueryClass: MssqlQuery
      });

      const preAggregations: any = query.newPreAggregations().preAggregationsDescription();
      expect(preAggregations.length).toEqual(1);
      expect(preAggregations[0].invalidateKeyQueries).toEqual([
        [
          'SELECT MAX(created_at) FROM cards',
          [],
          {
            external: false,
            renewalThreshold: 10,
          }
        ]
      ]);
    });

    it('preAggregationsDescription for query - refreshKey incremental (timeDimensions range)', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.min'
        ],
        timeDimensions: [{
          dimension: 'cards.createdAt',
          granularity: 'day',
          dateRange: ['2016-12-30', '2017-01-05']
        }],
        filters: [],
        timezone: 'America/Los_Angeles',
        externalQueryClass: MssqlQuery
      });

      const preAggregations: any = query.newPreAggregations().preAggregationsDescription();
      expect(preAggregations.length).toEqual(1);
      expect(preAggregations[0].invalidateKeyQueries).toEqual([
        [
          'SELECT CASE\n    WHEN CURRENT_TIMESTAMP < CAST(@_1 AS DATETIME2) THEN FLOOR((DATEDIFF(SECOND,\'1970-01-01\', GETUTCDATE())) / 3600) END as refresh_key',
          [
            '__TO_PARTITION_RANGE',
          ],
          {
            external: true,
            incremental: true,
            renewalThreshold: 300,
            renewalThresholdOutsideUpdateWindow: 86400,
            updateWindowSeconds: undefined
          }
        ]
      ]);
    });
  });

  describe('refreshKey only cube (immutable)', () => {
    /** @type Compilers */ prepareCompiler(
      createCubeSchema({
        name: 'cards',
        refreshKey: `
        refreshKey: {
          immutable: true,
        },
      `,
        preAggregations: `
          countCreatedAt: {
              type: 'rollup',
              external: true,
              measureReferences: [count],
              timeDimensionReference: createdAt,
              granularity: \`day\`,
              partitionGranularity: \`month\`,
              scheduledRefresh: true,
          },
        `
      })
    );
  });

  describe('refreshKey only cube (every)', () => {
    const compilers = /** @type Compilers */ prepareCompiler(
      createCubeSchema({
        name: 'cards',
        refreshKey: `
          refreshKey: {
            every: '10 minute',
          },
        `,
        preAggregations: `
          countCreatedAt: {
              type: 'rollup',
              external: true,
              measureReferences: [count],
              timeDimensionReference: createdAt,
              granularity: \`day\`,
              partitionGranularity: \`month\`,
              scheduledRefresh: true,
          },
        `
      })
    );

    it('refreshKey from cube (source)', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.count'
        ],
        timeDimensions: [{
          dimension: 'cards.createdAt',
          granularity: 'day',
          dateRange: ['2016-12-30', '2017-01-05']
        }],
        filters: [],
        timezone: 'America/Los_Angeles',
      });

      const preAggregations: any = query.newPreAggregations().preAggregationsDescription();
      expect(preAggregations.length).toEqual(1);
      expect(preAggregations[0].invalidateKeyQueries).toEqual([
        [
          'SELECT FLOOR((EXTRACT(EPOCH FROM NOW())) / 600) as refresh_key',
          [],
          {
            external: false,
            renewalThreshold: 60,
          }
        ]
      ]);
    });

    it('refreshKey from cube (external)', async () => {
      await compilers.compiler.compile();

      const query = new PostgresQuery(compilers, {
        measures: [
          'cards.count'
        ],
        timeDimensions: [{
          dimension: 'cards.createdAt',
          granularity: 'day',
          dateRange: ['2016-12-30', '2017-01-05']
        }],
        filters: [],
        timezone: 'America/Los_Angeles',
        externalQueryClass: MssqlQuery
      });

      const preAggregations: any = query.newPreAggregations().preAggregationsDescription();
      expect(preAggregations.length).toEqual(1);
      expect(preAggregations[0].invalidateKeyQueries).toEqual([
        [
          'SELECT FLOOR((DATEDIFF(SECOND,\'1970-01-01\', GETUTCDATE())) / 600) as refresh_key',
          [],
          {
            external: true,
            renewalThreshold: 60,
          }
        ]
      ]);
    });
  });

  it('refreshKey (sql + every) in cube', async () => {
    const compilers = /** @type Compilers */ prepareCompiler(
      createCubeSchema({
        name: 'cards',
        refreshKey: `
          refreshKey: {
            sql: 'SELECT MAX(created) FROM cards',
            every: '2 hours'
          },
        `,
        preAggregations: `
          countCreatedAt: {
              type: 'rollup',
              external: true,
              measureReferences: [count],
              timeDimensionReference: createdAt,
              granularity: \`day\`,
              partitionGranularity: \`month\`,
              scheduledRefresh: true,
          },
        `
      })
    );
    await compilers.compiler.compile();

    const query = new PostgresQuery(compilers, {
      measures: [
        'cards.count'
      ],
      timeDimensions: [],
      filters: [],
      timezone: 'America/Los_Angeles',
      externalQueryClass: MssqlQuery
    });

    const preAggregations: any = query.newPreAggregations().preAggregationsDescription();
    expect(preAggregations.length).toEqual(1);
    expect(preAggregations[0].invalidateKeyQueries).toEqual([
      [
        'SELECT MAX(created) FROM cards',
        [],
        {
          external: false,
          renewalThreshold: 7200,
        }
      ]
    ]);
  });

  it('refreshKey (sql + every) in preAggregation', async () => {
    const compilers = /** @type Compilers */ prepareCompiler(
      createCubeSchema({
        name: 'cards',
        refreshKey: '',
        preAggregations: `
          countCreatedAt: {
              type: 'rollup',
              external: true,
              measureReferences: [count],
              timeDimensionReference: createdAt,
              granularity: \`day\`,
              partitionGranularity: \`month\`,
              scheduledRefresh: true,
              refreshKey: {
                sql: 'SELECT MAX(created) FROM cards',
                every: '2 hour'
              },
          },
        `
      })
    );
    await compilers.compiler.compile();

    const query = new PostgresQuery(compilers, {
      measures: [
        'cards.count'
      ],
      timeDimensions: [],
      filters: [],
      timezone: 'America/Los_Angeles',
      externalQueryClass: MssqlQuery
    });

    const preAggregations: any = query.newPreAggregations().preAggregationsDescription();
    expect(preAggregations.length).toEqual(1);
    expect(preAggregations[0].invalidateKeyQueries).toEqual([
      [
        'SELECT MAX(created) FROM cards',
        [],
        {
          external: false,
          // 60 * 60 *2
          renewalThreshold: 7200,
        }
      ]
    ]);
  });

  describe('FILTER_PARAMS', () => {
    /** @type {Compilers} */
    const compilers = prepareYamlCompiler(
      createSchemaYaml({
        cubes: [{
          name: 'Order',
          sql: 'select * from order where {FILTER_PARAMS.Order.type.filter(\'type\')}',
          measures: [{
            name: 'count',
            type: 'count',
          }],
          dimensions: [{
            name: 'type',
            sql: 'type',
            type: 'string'
          }]
        }],
        views: [{
          name: 'orders_view',
          cubes: [{
            join_path: 'Order',
            prefix: true,
            includes: [
              'type',
              'count',
            ]
          }]
        }]
      })
    );

    it('inserts filter params into query', async () => {
      await compilers.compiler.compile();
      const query = new BaseQuery(compilers, {
        measures: ['Order.count'],
        filters: [
          {
            member: 'Order.type',
            operator: 'equals',
            values: ['online'],
          },
        ],
      });
      const cubeSQL = query.cubeSql('Order');
      expect(cubeSQL).toContain('where ((type = $0$))');
    });

    it('inserts "or" filter', async () => {
      await compilers.compiler.compile();
      const query = new BaseQuery(compilers, {
        measures: ['Order.count'],
        filters: [
          {
            or: [
              {
                member: 'Order.type',
                operator: 'equals',
                values: ['online'],
              },
              {
                member: 'Order.type',
                operator: 'equals',
                values: ['in-store'],
              },
            ]
          }
        ]
      });
      const cubeSQL = query.cubeSql('Order');
      expect(cubeSQL).toContain('where (((type = $0$) OR (type = $1$)))');
    });

    it('inserts "and" filter', async () => {
      await compilers.compiler.compile();
      const query = new BaseQuery(compilers, {
        measures: ['Order.count'],
        filters: [
          {
            and: [
              {
                member: 'Order.type',
                operator: 'equals',
                values: ['online'],
              },
              {
                member: 'Order.type',
                operator: 'equals',
                values: ['in-store'],
              },
            ]
          }
        ]
      });
      const cubeSQL = query.cubeSql('Order');
      expect(cubeSQL).toContain('where (((type = $0$) AND (type = $1$)))');
    });

    it('inserts "or + and" filter', async () => {
      await compilers.compiler.compile();
      const query = new BaseQuery(compilers, {
        measures: ['Order.count'],
        filters: [
          {
            or: [
              {
                and: [
                  {
                    member: 'Order.type',
                    operator: 'equals',
                    values: ['value1'],
                  },
                  {
                    member: 'Order.type',
                    operator: 'equals',
                    values: ['value2'],
                  }
                ]
              },
              {
                and: [
                  {
                    member: 'Order.type',
                    operator: 'equals',
                    values: ['value3'],
                  },
                  {
                    member: 'Order.type',
                    operator: 'equals',
                    values: ['value4'],
                  }
                ]
              }
            ]
          }
        ]
      });
      const cubeSQL = query.cubeSql('Order');
      expect(cubeSQL).toContain('where ((((type = $0$) AND (type = $1$)) OR ((type = $2$) AND (type = $3$))))');
    });

    it('inserts "and + or" filter', async () => {
      await compilers.compiler.compile();
      const query = new BaseQuery(compilers, {
        measures: ['Order.count'],
        filters: [
          {
            and: [
              {
                or: [
                  {
                    member: 'Order.type',
                    operator: 'equals',
                    values: ['value1'],
                  },
                  {
                    member: 'Order.type',
                    operator: 'equals',
                    values: ['value2'],
                  }
                ]
              },
              {
                or: [
                  {
                    member: 'Order.type',
                    operator: 'equals',
                    values: ['value3'],
                  },
                  {
                    member: 'Order.type',
                    operator: 'equals',
                    values: ['value4'],
                  }
                ]
              }
            ]
          }
        ]
      });
      const cubeSQL = query.cubeSql('Order');
      expect(cubeSQL).toMatch(/\(\s*\(.*type\s*=\s*\$\d\$.*OR.*type\s*=\s*\$\d\$.*\)\s*AND\s*\(.*type\s*=\s*\$\d\$.*OR.*type\s*=\s*\$\d\$.*\)\s*\)/);
    });

    it('propagate filter params from view into cube\'s query', async () => {
      await compilers.compiler.compile();
      const query = new BaseQuery(compilers, {
        measures: ['orders_view.Order_count'],
        filters: [
          {
            member: 'orders_view.Order_type',
            operator: 'equals',
            values: ['online'],
          },
        ],
      });
      const cubeSQL = query.cubeSql('Order');
      console.log('TEST: ', cubeSQL);
      expect(cubeSQL).toContain('select * from order where ((type = $0$))');
    });
  });

  describe('FILTER_GROUP', () => {
    /** @type {Compilers} */
    const compilers = prepareYamlCompiler(
      createSchemaYaml({
        cubes: [
          {
            name: 'Order',
            sql: `select * from order where {FILTER_GROUP(
              FILTER_PARAMS.Order.dim0.filter('dim0'),
              FILTER_PARAMS.Order.dim1.filter('dim1')
            )}`,
            measures: [{
              name: 'count',
              type: 'count',
            }],
            dimensions: [
              {
                name: 'dim0',
                sql: 'dim0',
                type: 'string'
              },
              {
                name: 'dim1',
                sql: 'dim1',
                type: 'string'
              }
            ]
          },
        ]
      })
    );

    it('inserts "or" filter', async () => {
      await compilers.compiler.compile();
      const query = new BaseQuery(compilers, {
        measures: ['Order.count'],
        filters: [
          {
            or: [
              {
                member: 'Order.dim0',
                operator: 'equals',
                values: ['val0'],
              },
              {
                member: 'Order.dim1',
                operator: 'equals',
                values: ['val1'],
              },
            ]
          }
        ],
      });
      const cubeSQL = query.cubeSql('Order');
      expect(cubeSQL).toContain('where (((dim0 = $0$) OR (dim1 = $1$)))');
    });

    it('inserts "and" filter', async () => {
      await compilers.compiler.compile();
      const query = new BaseQuery(compilers, {
        measures: ['Order.count'],
        filters: [
          {
            and: [
              {
                member: 'Order.dim0',
                operator: 'equals',
                values: ['val0'],
              },
              {
                member: 'Order.dim1',
                operator: 'equals',
                values: ['val1'],
              },
            ]
          }
        ],
      });
      const cubeSQL = query.cubeSql('Order');
      expect(cubeSQL).toContain('where (((dim0 = $0$) AND (dim1 = $1$)))');
    });

    it('inserts "or + and" filter', async () => {
      await compilers.compiler.compile();
      const query = new BaseQuery(compilers, {
        measures: ['Order.count'],
        filters: [
          {
            or: [
              {
                and: [
                  {
                    member: 'Order.dim0',
                    operator: 'equals',
                    values: ['val0'],
                  },
                  {
                    member: 'Order.dim1',
                    operator: 'equals',
                    values: ['val1'],
                  }
                ]
              },
              {
                and: [
                  {
                    member: 'Order.dim0',
                    operator: 'equals',
                    values: ['another_val0'],
                  },
                  {
                    member: 'Order.dim1',
                    operator: 'equals',
                    values: ['another_val1'],
                  }
                ]
              }
            ]
          }
        ]
      });
      const cubeSQL = query.cubeSql('Order');
      expect(cubeSQL).toContain('where ((((dim0 = $0$) AND (dim1 = $1$)) OR ((dim0 = $2$) AND (dim1 = $3$))))');
    });
  });
});

describe('Class unit tests', () => {
  it('Test BaseQuery with unaliased cube', async () => {
    const set = /** @type Compilers */ prepareCompiler(`
      cube('CamelCaseCube', {
        sql: 'SELECT * FROM TABLE_NAME',
        measures: {
          grant_total: {
            format: 'currency',
            sql: 'grant_field',
            type: 'sum'
          },
        },
        dimensions: {
          id: {
            format: 'id',
            primaryKey: true,
            shown: true,
            sql: 'id',
            type: 'number'
          },
          description: {
            sql: 'description_field',
            type: 'string'
          },
        }
      })
    `);
    await set.compiler.compile();
    const baseQuery = new BaseQuery(set, {});
    // aliasName
    expect(baseQuery.aliasName('CamelCaseCube', false)).toEqual('camel_case_cube');
    expect(baseQuery.aliasName('CamelCaseCube.id', false)).toEqual('camel_case_cube__id');
    expect(baseQuery.aliasName('CamelCaseCube.description', false)).toEqual('camel_case_cube__description');
    expect(baseQuery.aliasName('CamelCaseCube.grant_total', false)).toEqual('camel_case_cube__grant_total');

    // aliasName for pre-agg
    expect(baseQuery.aliasName('CamelCaseCube', true)).toEqual('camel_case_cube');
    expect(baseQuery.aliasName('CamelCaseCube.id', true)).toEqual('camel_case_cube_id');
    expect(baseQuery.aliasName('CamelCaseCube.description', true)).toEqual('camel_case_cube_description');
    expect(baseQuery.aliasName('CamelCaseCube.grant_total', true)).toEqual('camel_case_cube_grant_total');

    // cubeAlias
    expect(baseQuery.cubeAlias('CamelCaseCube')).toEqual('"camel_case_cube"');
    expect(baseQuery.cubeAlias('CamelCaseCube.id')).toEqual('"camel_case_cube__id"');
    expect(baseQuery.cubeAlias('CamelCaseCube.description')).toEqual('"camel_case_cube__description"');
    expect(baseQuery.cubeAlias('CamelCaseCube.grant_total')).toEqual('"camel_case_cube__grant_total"');
  });

  it('Test BaseQuery with aliased cube', async () => {
    const set = /** @type Compilers */ prepareCompiler(`
      cube('CamelCaseCube', {
        sql: 'SELECT * FROM TABLE_NAME',
        sqlAlias: 'T1',
        measures: {
          grant_total: {
            format: 'currency',
            sql: 'grant_field',
            type: 'sum'
          },
        },
        dimensions: {
          id: {
            format: 'id',
            primaryKey: true,
            shown: true,
            sql: 'id',
            type: 'number'
          },
          description: {
            sql: 'description_field',
            type: 'string'
          },
        }
      })
    `);
    await set.compiler.compile();
    const baseQuery = new BaseQuery(set, {});

    // aliasName
    expect(baseQuery.aliasName('CamelCaseCube', false)).toEqual('t1');
    expect(baseQuery.aliasName('CamelCaseCube.id', false)).toEqual('t1__id');
    expect(baseQuery.aliasName('CamelCaseCube.description', false)).toEqual('t1__description');
    expect(baseQuery.aliasName('CamelCaseCube.grant_total', false)).toEqual('t1__grant_total');

    // aliasName for pre-agg
    expect(baseQuery.aliasName('CamelCaseCube', true)).toEqual('t1');
    expect(baseQuery.aliasName('CamelCaseCube.id', true)).toEqual('t1_id');
    expect(baseQuery.aliasName('CamelCaseCube.description', true)).toEqual('t1_description');
    expect(baseQuery.aliasName('CamelCaseCube.grant_total', true)).toEqual('t1_grant_total');

    // cubeAlias
    expect(baseQuery.cubeAlias('CamelCaseCube')).toEqual('"t1"');
    expect(baseQuery.cubeAlias('CamelCaseCube.id')).toEqual('"t1__id"');
    expect(baseQuery.cubeAlias('CamelCaseCube.description')).toEqual('"t1__description"');
    expect(baseQuery.cubeAlias('CamelCaseCube.grant_total')).toEqual('"t1__grant_total"');
  });

  it('Test BaseQuery columns order for the query with the sub-query', async () => {
    const joinedSchemaCompilers = prepareCompiler(createJoinedCubesSchema());
    await joinedSchemaCompilers.compiler.compile();
    await joinedSchemaCompilers.compiler.compile();
    const query = new BaseQuery({
      joinGraph: joinedSchemaCompilers.joinGraph,
      cubeEvaluator: joinedSchemaCompilers.cubeEvaluator,
      compiler: joinedSchemaCompilers.compiler,
    },
    {
      measures: ['B.bval_sum', 'B.count'],
      dimensions: ['B.aid'],
      filters: [{
        member: 'C.did',
        operator: 'lt',
        values: ['10']
      }],
      order: [['B.bval_sum', 'desc']]
    });
    const sql = query.buildSqlAndParams();
    const re = new RegExp('(b__aid).*(b__bval_sum).*(b__count).*');
    expect(re.test(sql[0])).toBeTruthy();
  });
});
