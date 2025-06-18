# Dynamic Report Generator for PostgreSQL

**Version**: 10.0 (June 17, 2025)  
**License**: MIT  
**Repository**: [https://github.com/your-repo/dynamic-report](https://github.com/your-repo/dynamic-report)  
**Issues**: Report bugs or request features at [GitHub Issues](https://github.com/your-repo/dynamic-report/issues)

## Overview

The `generate_dynamic_report` stored procedure is a robust PostgreSQL tool for generating dynamic data aggregation and pivoting reports. It groups data by a specified dimension column, aggregates a metric column using standard or custom functions (`SUM`, `AVG`, `COUNT`, `MAX`, `MIN`), and optionally pivots results based on a pivot column and user-defined values. The output is written to a new table, supporting both permanent and temporary tables.

Designed for production environments, the procedure includes exhaustive input validation, schema and permission checks, transaction management, performance optimizations, and detailed logging. It is compatible with PostgreSQL 9.4+ and handles edge cases such as quoted identifiers, custom data types, high cardinality, and extension conflicts.

## Features

- **Dynamic Aggregation**: Supports `SUM`, `AVG`, `COUNT`, `MAX`, `MIN` with validation for numeric types and custom aggregates.
- **Pivoting**: Transforms rows into columns based on a pivot column and up to 100 unique values (case-sensitive, max 1024 bytes each).
- **Schema Support**: Handles schema-qualified table names, quoted identifiers, and temporary tables.
- **Input Validation**: Checks for:
  - `NULL` or invalid inputs.
  - Table/column existence, type, and collation.
  - Data type compatibility (rejects arrays, ranges, composites for `SUM`/`AVG` unless custom aggregates exist).
  - Identifier length against `max_identifier_length`.
  - Permissions (`SELECT`, `USAGE`, `CREATE`).
  - Cardinality limits (up to 1,000,000 groups, skippable).
- **Transaction Safety**: Uses `BEGIN`/`COMMIT`/`ROLLBACK` with configurable timeouts and lock retries.
- **Performance Optimizations**:
  - Approximate row counts via `pg_class.reltuples`.
  - Skippable cardinality checks for large tables.
  - Index recommendations (`btree` on dimension/pivot columns).
  - Warnings for high cardinality, `work_mem`, table bloat, freeze status, TOASTed columns, foreign tables, parallel queries, JIT compilation, skewed data, plan cache reuse, and memory pressure.
- **Error Handling**: Logs errors, failing SQL, and inputs; catches all exceptions.
- **Logging**: Detailed notices for execution time, row counts, SQL statements, and maintenance recommendations.
- **Maintainability**: Includes version, GitHub link, and notes on `ANALYZE`, `VACUUM`, `pgstattuple`, `amcheck`, `temp_buffers`, RLS, roles, and extensions.
- **Edge Case Handling**: Supports Unicode, custom collations, storage managers, access methods, query rewrite, RLS, and extension conflicts (e.g., TimescaleDB, Citus).

## Requirements

- **PostgreSQL Version**: 9.4 or higher (tested up to 17; compatible with 18 expected in 2026).
- **Permissions**:
  - `SELECT` and `USAGE` on the source table’s schema.
  - `CREATE` and `USAGE` on the output table’s schema (if not temporary).
  - `USAGE` on `pg_catalog` and `information_schema` (granted by default).
- **Extensions**: None required, but compatible with `pgstattuple` and `amcheck` for maintenance.
- **Configuration**:
  - Ensure `client_min_messages` is set to `NOTICE` or lower to see warnings.
  - Recommended: `work_mem` ≥ 16MB for high-cardinality datasets, sufficient `temp_buffers` for temporary tables.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/dynamic-report.git
   cd dynamic-report
   ```

2. **Deploy the Stored Procedure**:
   Run the SQL script using `psql` or a database client:
   ```bash
   psql -U your_user -d your_database -f dynamic_report_final_v10.sql
   ```
   This creates the `generate_dynamic_report` procedure and a sample `public.sales_data` table for testing.

3. **Verify Installation**:
   Check the procedure exists:
   ```sql
   \df generate_dynamic_report
   ```

## Usage

### Basic Example
Generate a report grouping sales by department, summing sales, and pivoting by year:
```sql
CALL generate_dynamic_report(
    p_table_name := 'public.sales_data',
    p_dimension_column := 'department',
    p_metric_column := 'sales',
    p_aggregation_type := 'SUM',
    p_pivot_column := 'year',
    p_pivot_values := ARRAY['2023', '2024'],
    p_output_table := 'public.sales_report',
    p_statement_timeout := '30s',
    p_temporary_table := FALSE,
    p_lock_retry_delay_ms := 100,
    p_max_groups := 1000000,
    p_skip_cardinality_check := FALSE
);
```

### Parameters
| Parameter                  | Type         | Description                                                                 | Default       |
|----------------------------|--------------|-----------------------------------------------------------------------------|---------------|
| `p_table_name`             | `VARCHAR`    | Source table (schema-qualified, e.g., `public.sales_data`).                 | Required      |
| `p_dimension_column`       | `VARCHAR`    | Column to group by (e.g., `department`).                                    | Required      |
| `p_metric_column`          | `VARCHAR`    | Column to aggregate (e.g., `sales`).                                        | Required      |
| `p_aggregation_type`       | `VARCHAR`    | Aggregation type (`SUM`, `AVG`, `COUNT`, `MAX`, `MIN`).                     | Required      |
| `p_pivot_column`           | `VARCHAR`    | Column to pivot on (e.g., `year`).                                          | `NULL`        |
| `p_pivot_values`           | `VARCHAR[]`  | Array of pivot values (e.g., `ARRAY['2023', '2024']`).                      | `NULL`        |
| `p_output_table`           | `VARCHAR`    | Output table (schema-qualified, e.g., `public.sales_report`).               | Required      |
| `p_statement_timeout`      | `VARCHAR`    | Query timeout (e.g., `30s`, `1min`).                                        | `'30s'`       |
| `p_temporary_table`        | `BOOLEAN`    | Create output as a temporary table.                                         | `FALSE`       |
| `p_lock_retry_delay_ms`    | `INTEGER`    | Delay (ms) between `DROP TABLE` retries (0–1000).                           | `100`         |
| `p_max_groups`             | `INTEGER`    | Maximum unique groups in `p_dimension_column`.                              | `1000000`     |
| `p_skip_cardinality_check` | `BOOLEAN`    | Skip cardinality check for large tables.                                    | `FALSE`       |

### Sample Output
For the above example, the `public.sales_report` table might look like:
| department   | sales_2023 | sales_2024 |
|--------------|------------|------------|
| Electronics  | 10000      | 15000      |
| Clothing     | 8000       | 12000      |
| Furniture    | 20000      | 25000      |

### Non-Pivoted Example
Generate a simple report without pivoting:
```sql
CALL generate_dynamic_report(
    p_table_name := 'public.sales_data',
    p_dimension_column := 'department',
    p_metric_column := 'sales',
    p_aggregation_type := 'AVG',
    p_pivot_column := NULL,
    p_pivot_values := NULL,
    p_output_table := 'public.avg_sales',
    p_temporary_table := TRUE
);
```

## Performance Considerations

- **Indexes**: Create `btree` indexes on `p_dimension_column` and `p_pivot_column` for optimal `GROUP BY` and pivoting performance. Non-`btree` indexes (e.g., GIN, GiST) may not help.
- **Cardinality**: High cardinality (>100,000 unique values) in `p_dimension_column` may slow execution. Use `p_skip_cardinality_check := TRUE` for large tables, but ensure cardinality is below `p_max_groups`.
- **Work Memory**: Set `work_mem` ≥ 16MB for large datasets to avoid disk spills during `GROUP BY`.
- **Temporary Tables**: Increase `temp_buffers` for temporary table outputs.
- **Maintenance**:
  - Run `ANALYZE` on `p_table_name` for accurate query plans.
  - Use `VACUUM` to prevent bloat (check with `pgstattuple`).
  - Monitor freeze status and transaction ID wraparound (`pg_stat_activity`).
  - Verify index health with `amcheck` or `REINDEX`.
- **Parallel Queries**: Enabled if `max_parallel_workers_per_gather > 0`, but `COUNT(DISTINCT)` may not parallelize.
- **JIT Compilation**: Enabled if `enable_jit = on`, may add latency for small datasets.
- **Skewed Data**: Highly skewed `p_dimension_column` values may degrade `GROUP BY` performance.
- **Plan Cache**: Frequent calls with identical parameters may reuse suboptimal plans.
- **Foreign Tables**: Cardinality checks may incur network latency; use `p_skip_cardinality_check`.
- **TOASTed Columns**: TOASTed `p_dimension_column` slows cardinality checks.
- **Memory Pressure**: Extreme memory constraints may cause failures; monitor system resources.
- **Query Rewrite**: Views or rules on `p_table_name` may impact performance.
- **Extensions**: Test with TimescaleDB, Citus, or custom storage/access methods for compatibility.

## Troubleshooting

- **Error: "Invalid table name format"**:
  - Ensure `p_table_name` and `p_output_table` are valid, schema-qualified names (e.g., `public.sales_data`).
  - Avoid system schemas (`pg_catalog`, `information_schema`, `pg_toast`).
- **Error: "Too many unique values"**:
  - Reduce unique values in `p_dimension_column` or increase `p_max_groups`.
  - Use `p_skip_cardinality_check := TRUE` for large tables.
- **Error: "User lacks privilege"**:
  - Grant `SELECT` and `USAGE` on the source schema, `CREATE` and `USAGE` on the output schema.
  - Verify `current_user` permissions.
- **Slow Performance**:
  - Create `btree` indexes on `p_dimension_column` and `p_pivot_column`.
  - Increase `work_mem` or `temp_buffers`.
  - Skip cardinality checks for large/foreign tables.
  - Check for skewed data, parallel query, or JIT compilation impact.
- **Missing Warnings**:
  - Set `client_min_messages` to `NOTICE` or lower:
    ```sql
    SET client_min_messages = 'NOTICE';
    ```
- **Extension Conflicts**:
  - Test with specific extensions (e.g., TimescaleDB hypertables, Citus distributed tables).
  - Report issues with custom storage or access methods.

## Testing

The script includes a sample `public.sales_data` table and data for testing. To verify functionality, run:
```sql
-- Create and populate sample table
CREATE TABLE IF NOT EXISTS public.sales_data (
    department TEXT NOT NULL,
    sales NUMERIC,
    year INTEGER NOT NULL
);
INSERT INTO public.sales_data (department, sales, year) VALUES
    ('Electronics', 10000, 2023),
    ('Electronics', 15000, 2024),
    ('Clothing', 8000, 2023),
    ('Clothing', 12000, 2024),
    ('Furniture', 20000, 2023),
    ('Furniture', 25000, 2024);

-- Run the procedure
CALL generate_dynamic_report(
    p_table_name := 'public.sales_data',
    p_dimension_column := 'department',
    p_metric_column := 'sales',
    p_aggregation_type := 'SUM',
    p_pivot_column := 'year',
    p_pivot_values := ARRAY['2023', '2024'],
    p_output_table := 'public.sales_report'
);

-- Verify output
SELECT * FROM public.sales_report;
```

### Recommended Test Scenarios
1. **Frequent Calls**: Loop 1000 times with identical parameters to check plan cache reuse.
2. **Skewed Data**: Insert 1M rows with 99% identical `p_dimension_column` values.
3. **Custom Access Method**: Test with a hypothetical table access method extension.
4. **Memory Pressure**: Run with `vm.overcommit_memory = 2` and low RAM.
5. **Parallel Queries**: Set `max_parallel_workers_per_gather = 4` with a large table.
6. **JIT Compilation**: Set `enable_jit = on` with small/large datasets.
7. **RLS**: Enable row-level security on `p_table_name`.
8. **Extensions**: Test with TimescaleDB or Citus.
9. **TOASTed Columns**: Use a `TEXT` column with 1MB+ values for `p_dimension_column`.
10. **High Cardinality**: Test with `p_dimension_column` having 500,000 unique values.

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request with a clear description and test cases.

### Guidelines
- Ensure compatibility with PostgreSQL 9.4+.
- Include tests for new features or edge cases.
- Update version number and documentation.
- Follow PostgreSQL coding standards (e.g., use `format()` for SQL injection safety).
- Test with extensions and edge cases (e.g., Unicode, custom types, high concurrency).

## Known Limitations

- Maximum 100 pivot values and 1,000,000 groups (configurable via `p_max_groups`).
- `COUNT(DISTINCT)` cardinality checks may be slow for foreign or TOASTed tables.
- Non-`btree` indexes (GIN, GiST) are not optimized for `GROUP BY` or pivoting.
- Extensions like TimescaleDB or Citus may require additional testing.
- No built-in skewness detection for `p_dimension_column`.
- Plan cache reuse may affect performance in frequent calls.

## Future Enhancements

- Add skewness detection for `p_dimension_column`.
- Integrate `amcheck` for automatic index health checks.
- Support additional aggregations (e.g., `MEDIAN`, `MODE`).
- Optimize for specific extensions (e.g., TimescaleDB hypertables).
- Add logging to a table for audit trails.
- Provide a wrapper function for simpler calls.

## Acknowledgments

- Built with PostgreSQL best practices and community feedback.
- Inspired by real-world reporting needs in data analytics.

For questions, contact the maintainers via [GitHub Issues](https://github.com/your-repo/dynamic-report/issues) or email [your-email@example.com](mailto:your-email@example.com).