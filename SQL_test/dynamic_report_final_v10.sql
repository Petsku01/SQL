-- Creating a stored procedure for dynamic data aggregation and pivoting
-- Purpose: Generate flexible reports with robust validation, transaction safety, and schema support
-- Version: 10.0 (2025-06-17)
-- GitHub: Report issues to me


-- Required Permissions: 
--   - SELECT and USAGE on p_table_name schema
--   - CREATE, USAGE on p_output_table schema (if not temporary)
--   - USAGE on pg_catalog and information_schema
-- Notes:
--   - Table/column names must be valid PostgreSQL identifiers (quoted or unquoted)
--   - Recommended indexes: btree on p_dimension_column, p_pivot_column
--   - Run ANALYZE on p_table_name for accurate row counts and query plans
--   - Check work_mem for large GROUP BY operations
--   - Run VACUUM on system catalogs for heavy usage to prevent bloat
--   - Check table bloat (e.g., via pgstattuple) and vacuum freeze status
--   - Monitor transaction ID wraparound risk in long-running systems
--   - Check index health (e.g., via amcheck or REINDEX) to avoid corruption
--   - Check temp_buffers for temporary table usage
--   - Row-level security (RLS) policies may filter p_table_name rows
--   - Permissions are checked against current_user, not session_user
--   - Parallel queries or JIT compilation may affect performance
--   - Views/rules on p_table_name may trigger query rewrite, impacting performance
--   - Custom storage managers or access methods (e.g., via extensions) may affect behavior
--   - Skewed data in p_dimension_column may degrade GROUP BY performance
--   - Frequent calls may trigger plan cache reuse; monitor performance
--   - Extreme memory pressure may cause failures; monitor system resources
--   - May conflict with extensions (e.g., TimescaleDB, Citus); test thoroughly
--   - Assumes SECURITY INVOKER; avoid SECURITY DEFINER unless tested
--   - Set client_min_messages to NOTICE or lower to see all warnings
CREATE OR REPLACE PROCEDURE generate_dynamic_report(
    p_table_name VARCHAR,        -- Source table (schema-qualified, e.g., public.sales_data or "my schema".sales_data)
    p_dimension_column VARCHAR,  -- Column to group by (e.g., department)
    p_metric_column VARCHAR,     -- Column to aggregate (e.g., sales)
    p_aggregation_type VARCHAR,  -- Aggregation type (SUM, AVG, COUNT, MAX, MIN)
    p_pivot_column VARCHAR,      -- Column to pivot on (e.g., year)
    p_pivot_values VARCHAR[],    -- Array of pivot values (e.g., {2023, 2024})
    p_output_table VARCHAR,      -- Output table (schema-qualified, e.g., public.sales_report)
    p_statement_timeout VARCHAR DEFAULT '30s', -- Query timeout (e.g., '30s', '1min')
    p_temporary_table BOOLEAN DEFAULT FALSE, -- Create output as TEMPORARY table
    p_lock_retry_delay_ms INTEGER DEFAULT 100, -- Delay (ms) between DROP TABLE retries
    p_max_groups INTEGER DEFAULT 1000000, -- Maximum number of GROUP BY groups
    p_skip_cardinality_check BOOLEAN DEFAULT FALSE -- Skip cardinality check for large tables
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_sql TEXT := '';           -- Dynamic SQL statement
    v_pivot_clause TEXT;        -- Pivot column definitions
    v_value TEXT;               -- Individual pivot value
    v_valid_aggregation BOOLEAN; -- Flag to validate aggregation type
    v_metric_data_type TEXT;    -- Data type of the metric column
    v_table_exists BOOLEAN;     -- Flag to check if table exists
    v_column_exists BOOLEAN;    -- Flag to check if column exists
    v_schema_name TEXT;         -- Schema name for source table
    v_table_name TEXT;          -- Table name without schema
    v_output_schema TEXT;       -- Schema name for output table
    v_output_table_name TEXT;   -- Output table name without schema
    v_row_count BIGINT;         -- Row count of source table
    v_unique_pivot_values VARCHAR[]; -- Unique, non-NULL, non-empty pivot values
    v_start_time TIMESTAMP;      -- Execution start time
    v_has_privilege BOOLEAN;    -- Permission check flag
    v_collation TEXT;           -- Collation of dimension/pivot column
    v_db_collation TEXT;        -- Database default collation
    v_timeout_ms BIGINT;        -- Timeout in milliseconds
    v_max_identifier_length INTEGER; -- Database NAMEDATALEN
    v_group_count BIGINT;       -- Estimated number of groups
    v_work_mem TEXT;            -- Current work_mem setting
    v_fallback_collation TEXT;  -- Collation for pivot values
    v_is_foreign_table BOOLEAN; -- Flag for foreign tables
    v_temp_buffers TEXT;        -- Current temp_buffers setting
    v_is_toasted BOOLEAN;       -- Flag for TOASTed dimension column
    v_parallel_workers TEXT;    -- Current max_parallel_workers_per_gather
    v_jit_enabled TEXT;         -- Current enable_jit setting
BEGIN
    -- Record start time for logging
    v_start_time := clock_timestamp();

    -- Start transaction
    BEGIN
        -- Check if running on a standby replica
        IF pg_is_in_recovery() THEN
            RAISE EXCEPTION 'Cannot run on a standby replica due to write operations';
        END IF;

        -- Validate statement_timeout format
        SELECT extract(epoch from interval p_statement_timeout) * 1000 INTO v_timeout_ms;
        IF v_timeout_ms IS NULL OR v_timeout_ms <= 0 THEN
            RAISE EXCEPTION 'Invalid statement_timeout format: %', p_statement_timeout;
        END IF;
        EXECUTE format('SET LOCAL statement_timeout = %L', p_statement_timeout);

        -- Validate lock retry delay
        IF p_lock_retry_delay_ms < 0 OR p_lock_retry_delay_ms > 1000 THEN
            RAISE EXCEPTION 'Invalid lock_retry_delay_ms: %; must be between 0 and 1000', p_lock_retry_delay_ms;
        END IF;

        -- Validate max groups
        IF p_max_groups < 1 THEN
            RAISE EXCEPTION 'Invalid max_groups: %; must be positive', p_max_groups;
        END IF;

        -- Validate input parameters
        IF p_table_name IS NULL OR p_dimension_column IS NULL OR p_metric_column IS NULL OR p_output_table IS NULL THEN
            RAISE EXCEPTION 'Table name, dimension column, metric column, and output table cannot be null';
        END IF;

        -- Validate aggregation type
        v_valid_aggregation := p_aggregation_type IN ('SUM', 'AVG', 'COUNT', 'MAX', 'MIN');
        IF NOT v_valid_aggregation THEN
            RAISE EXCEPTION 'Invalid aggregation type: %. Supported types: SUM, AVG, COUNT, MAX, MIN', p_aggregation_type;
        END IF;

        -- Get database NAMEDATALEN
        SELECT current_setting('max_identifier_length')::INTEGER INTO v_max_identifier_length;
        IF v_max_identifier_length IS NULL THEN
            v_max_identifier_length := 63; -- Default PostgreSQL value
        END IF;

        -- Get work_mem, temp_buffers, parallel workers, and JIT settings
        SELECT current_setting('work_mem') INTO v_work_mem;
        SELECT current_setting('temp_buffers') INTO v_temp_buffers;
        SELECT current_setting('max_parallel_workers_per_gather') INTO v_parallel_workers;
        SELECT current_setting('enable_jit') INTO v_jit_enabled;

        -- Parse schema and table name for source table
        BEGIN
            EXECUTE format('SELECT nspname, relname, relkind = ''f'' AS is_foreign FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid WHERE c.oid = %L::regclass', p_table_name)
            INTO v_schema_name, v_table_name, v_is_foreign_table;
        EXCEPTION
            WHEN OTHERS THEN
                RAISE EXCEPTION 'Invalid table name format: %', p_table_name;
        END;

        -- Reject system schemas
        IF v_schema_name IN ('pg_catalog', 'information_schema', 'pg_toast') THEN
            RAISE EXCEPTION 'Source table %.% cannot be in system schema %', v_schema_name, v_table_name, v_schema_name;
        END IF;

        -- Parse schema and table name for output table
        BEGIN
            IF p_temporary_table AND p_output_table ~ '\.' THEN
                RAISE EXCEPTION 'Schema-qualified output table (%s) not allowed with p_temporary_table = TRUE', p_output_table;
            END IF;
            EXECUTE format('SELECT nspname, relname FROM pg_namespace n WHERE n.oid = (SELECT CASE WHEN %L ~ ''^"[^"]+"$'' THEN (SELECT oid FROM pg_namespace WHERE nspname = %L) ELSE %L::regclass::regnamespace END)', 
                           p_output_table, regexp_replace(p_output_table, '^"(.*)"$', '\1'), p_output_table)
            INTO v_output_schema, v_output_table_name;
            IF v_output_table_name IS NULL THEN
                v_output_table_name := v_output_schema;
                v_output_schema := CASE WHEN p_temporary_table THEN 'pg_temp' ELSE 'public' END;
            END IF;
        EXCEPTION
            WHEN OTHERS THEN
                RAISE EXCEPTION 'Invalid output table name format: %', p_output_table;
        END;

        -- Validate output schema existence (skip for temporary tables)
        IF NOT p_temporary_table THEN
            SELECT EXISTS (
                SELECT FROM information_schema.schemata WHERE schema_name = v_output_schema
            ) INTO v_table_exists;
            IF NOT v_table_exists THEN
                RAISE EXCEPTION 'Output schema % does not exist', v_output_schema;
            END IF;
        END IF;

        -- Validate permissions
        SELECT has_schema_privilege(current_user, v_schema_name, 'USAGE') INTO v_has_privilege;
        IF NOT v_has_privilege THEN
            RAISE EXCEPTION 'User % lacks USAGE privilege on schema %', current_user, v_schema_name;
        END IF;
        SELECT has_table_privilege(current_user, format('%I.%I', v_schema_name, v_table_name), 'SELECT') INTO v_has_privilege;
        IF NOT v_has_privilege THEN
            RAISE EXCEPTION 'User % lacks SELECT privilege on table %.%', current_user, v_schema_name, v_table_name;
        END IF;
        IF NOT p_temporary_table THEN
            SELECT has_schema_privilege(current_user, v_output_schema, 'CREATE') AND 
                   has_schema_privilege(current_user, v_output_schema, 'USAGE') INTO v_has_privilege;
            IF NOT v_has_privilege THEN
                RAISE EXCEPTION 'User % lacks CREATE/USAGE privileges on schema %', current_user, v_output_schema;
            END IF;
        END IF;

        -- Validate table existence
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_schema = v_schema_name AND table_name = v_table_name
            AND table_type IN ('BASE TABLE', 'MATERIALIZED VIEW', 'FOREIGN TABLE')
        ) INTO v_table_exists;
        IF NOT v_table_exists THEN
            RAISE EXCEPTION 'Table %.% does not exist or is not a base table, materialized view, or foreign table', v_schema_name, v_table_name;
        END IF;

        -- Check source table row count (approximate)
        EXECUTE format('SELECT reltuples::BIGINT FROM pg_class WHERE relname = %L AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = %L)', 
                       v_table_name, v_schema_name) INTO v_row_count;
        IF v_row_count = 0 THEN
            RAISE NOTICE 'Source table %.% is empty; output will be empty. Run ANALYZE for accurate counts.', v_schema_name, v_table_name;
        END IF;

        -- Warn about foreign table latency
        IF v_is_foreign_table AND NOT p_skip_cardinality_check THEN
            RAISE NOTICE 'Source table %.% is a foreign table; cardinality checks may incur network latency. Consider p_skip_cardinality_check := TRUE.', v_schema_name, v_table_name;
        END IF;

        -- Get database default collation
        SELECT datcollate INTO v_db_collation FROM pg_database WHERE datname = current_database();
        -- Determine fallback collation
        v_fallback_collation := CASE WHEN EXISTS (SELECT FROM pg_collation WHERE collname = 'C') THEN 'C' ELSE v_db_collation END;

        -- Validate dimension column and check collation
        SELECT collation_name, a.attoptions IS NOT NULL AS is_toasted
        INTO v_collation, v_is_toasted
        FROM information_schema.columns c
        JOIN pg_attribute a ON a.attname = c.column_name
        JOIN pg_class r ON a.attrelid = r.oid
        JOIN pg_namespace n ON r.relnamespace = n.oid
        WHERE n.nspname = v_schema_name AND r.relname = v_table_name AND c.column_name = p_dimension_column;
        IF v_collation IS NULL THEN
            RAISE EXCEPTION 'Dimension column % does not exist in table %.%', p_dimension_column, v_schema_name, v_table_name;
        END IF;
        IF v_collation IS NOT NULL AND v_collation != v_db_collation THEN
            RAISE NOTICE 'Collation (%) on dimension column % differs from database default (%), which may affect grouping', v_collation, p_dimension_column, v_db_collation;
        END IF;
        IF v_is_toasted AND NOT p_skip_cardinality_check THEN
            RAISE NOTICE 'Dimension column % is TOASTed; cardinality checks may be slow due to decompression. Consider p_skip_cardinality_check := TRUE.', p_dimension_column;
        END IF;

        -- Validate metric column and get its data type
        SELECT c.data_type, t.typcategory IN ('R', 'C') AS is_range_or_composite, t.typarray != 0 AS is_array
        INTO v_metric_data_type, v_table_exists, v_column_exists
        FROM information_schema.columns c
        JOIN pg_type t ON c.data_type = t.typname
        WHERE c.table_schema = v_schema_name AND c.table_name = v_table_name AND c.column_name = p_metric_column;
        IF v_metric_data_type IS NULL THEN
            RAISE EXCEPTION 'Metric column % does not exist in table %.%', p_metric_column, v_schema_name, v_table_name;
        END IF;
        IF v_table_exists AND p_aggregation_type IN ('SUM', 'AVG') THEN
            RAISE EXCEPTION 'Metric column % is a range or composite type, which is not compatible with %', p_metric_column, p_aggregation_type;
        END IF;
        IF v_column_exists AND p_aggregation_type IN ('SUM', 'AVG') THEN
            RAISE EXCEPTION 'Metric column % is an array type, which is not compatible with %', p_metric_column, p_aggregation_type;
        END IF;

        -- Validate aggregation compatibility
        IF p_aggregation_type IN ('SUM', 'AVG') AND v_metric_data_type NOT IN ('integer', 'bigint', 'numeric', 'real', 'double precision') THEN
            -- Check for custom aggregate function
            SELECT EXISTS (
                SELECT FROM pg_aggregate a JOIN pg_proc p ON a.aggfnoid = p.oid
                WHERE p.proname = lower(p_aggregation_type) AND p.proargtypes[0] = (SELECT oid FROM pg_type WHERE typname = v_metric_data_type)
            ) INTO v_table_exists;
            IF NOT v_table_exists THEN
                RAISE EXCEPTION 'Metric column % (type %) is not compatible with %; no custom aggregate found', p_metric_column, v_metric_data_type, p_aggregation_type;
            END IF;
        END IF;
        IF p_aggregation_type IN ('MAX', 'MIN') THEN
            SELECT EXISTS (
                SELECT FROM pg_type t JOIN pg_opclass o ON t.typname = o.opcname 
                WHERE t.typname = v_metric_data_type AND o.opcmethod = (SELECT oid FROM pg_am WHERE amname = 'btree')
            ) INTO v_table_exists;
            IF NOT v_table_exists THEN
                -- Check for custom aggregate function
                SELECT EXISTS (
                    SELECT FROM pg_aggregate a JOIN pg_proc p ON a.aggfnoid = p.oid
                    WHERE p.proname = lower(p_aggregation_type) AND p.proargtypes[0] = (SELECT oid FROM pg_type WHERE typname = v_metric_data_type)
                ) INTO v_table_exists;
                IF NOT v_table_exists THEN
                    RAISE EXCEPTION 'Metric column % (type %) does not support %; no btree operator class or custom aggregate found', p_metric_column, v_metric_data_type, p_aggregation_type;
                END IF;
            END IF;
        END IF;

        -- Set output data type
        v_metric_data_type := CASE 
            WHEN p_aggregation_type = 'COUNT' THEN 'BIGINT'
            WHEN p_aggregation_type IN ('SUM', 'AVG') AND v_metric_data_type IN ('real', 'double precision') THEN v_metric_data_type
            ELSE 'NUMERIC'
        END;

        -- Validate pivot column and values
        IF p_pivot_column IS NOT NULL THEN
            SELECT collation_name INTO v_collation
            FROM information_schema.columns 
            WHERE table_schema = v_schema_name AND table_name = v_table_name AND column_name = p_pivot_column;
            IF v_collation IS NULL THEN
                RAISE EXCEPTION 'Pivot column % does not exist in table %.%', p_pivot_column, v_schema_name, v_table_name;
            END IF;
            IF v_collation IS NOT NULL AND v_collation != v_db_collation THEN
                RAISE NOTICE 'Collation (%) on pivot column % differs from database default (%), which may affect pivoting', v_collation, p_pivot_column, v_db_collation;
            END IF;

            -- Filter out NULLs and empty strings, validate uniqueness (case-sensitive)
            IF array_length(p_pivot_values, 1) > 0 THEN
                WITH values AS (
                    SELECT val, row_number() OVER (ORDER BY val COLLATE v_fallback_collation) AS rn
                    FROM unnest(p_pivot_values) val
                    WHERE val IS NOT NULL AND val != ''
                )
                SELECT ARRAY_AGG(val ORDER BY rn) INTO v_unique_pivot_values
                FROM values
                GROUP BY val
                HAVING COUNT(*) = 1;
                IF array_length(v_unique_pivot_values, 1) IS NULL THEN
                    RAISE EXCEPTION 'Pivot values cannot all be NULL or empty: %', p_pivot_values;
                END IF;
                IF array_length(v_unique_pivot_values, 1) < array_length(p_pivot_values, 1) THEN
                    RAISE EXCEPTION 'Duplicate values found in p_pivot_values (case-sensitive): %', p_pivot_values;
                END IF;
                IF array_length(v_unique_pivot_values, 1) > 100 THEN
                    RAISE EXCEPTION 'Too many pivot values (%); maximum is 100', array_length(v_unique_pivot_values, 1);
                END IF;

                -- Validate pivot column names for length
                FOREACH v_value IN ARRAY v_unique_pivot_values
                LOOP
                    IF length(v_value) > 1024 THEN
                        RAISE EXCEPTION 'Pivot value % exceeds 1024 bytes', v_value;
                    END IF;
                    IF length(p_metric_column || '_' || v_value) > v_max_identifier_length THEN
                        RAISE EXCEPTION 'Generated column name %_% exceeds % bytes', p_metric_column, v_value, v_max_identifier_length;
                    END IF;
                END LOOP;
            END IF;
        END IF;

        -- Estimate group count for cardinality check (if not skipped)
        IF NOT p_skip_cardinality_check THEN
            EXECUTE format('SELECT COUNT(DISTINCT %I) FROM %I.%I', p_dimension_column, v_schema_name, v_table_name) INTO v_group_count;
            IF v_group_count > p_max_groups THEN
                RAISE EXCEPTION 'Too many unique values (%) in dimension column %; maximum is %', v_group_count, p_dimension_column, p_max_groups;
            END IF;
            IF v_group_count > 100000 THEN
                RAISE NOTICE 'High cardinality (% rows) in dimension column % may impact performance. Current work_mem: %; consider increasing to at least 16MB.', v_group_count, p_dimension_column, v_work_mem;
            END IF;
        ELSE
            RAISE NOTICE 'Cardinality check skipped; ensure % has fewer than % unique values for optimal performance', p_dimension_column, p_max_groups;
        END IF;

        -- Check for recommended indexes
        SELECT NOT EXISTS (
            SELECT FROM pg_index i JOIN pg_class c ON i.indrelid = c.oid 
            WHERE c.relname = v_table_name AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = v_schema_name)
            AND i.indkey::text ~ ('\m' || (SELECT attnum::text FROM pg_attribute WHERE attrelid = c.oid AND attname = p_dimension_column) || '\M')
        ) INTO v_table_exists;
        IF v_table_exists THEN
            RAISE NOTICE 'No btree index found on %.%. Consider creating a btree index (including partial or expression indexes) for better performance. Non-btree indexes (e.g., GIN, GiST) are not checked and may not optimize GROUP BY. Run ANALYZE for optimal query plans.', p_dimension_column, p_table_name;
        END IF;
        IF p_pivot_column IS NOT NULL THEN
            SELECT NOT EXISTS (
                SELECT FROM pg_index i JOIN pg_class c ON i.indrelid = c.oid 
                WHERE c.relname = v_table_name AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = v_schema_name)
                AND i.indkey::text ~ ('\m' || (SELECT attnum::text FROM pg_attribute WHERE attrelid = c.oid AND attname = p_pivot_column) || '\M')
            ) INTO v_table_exists;
            IF v_table_exists THEN
                RAISE NOTICE 'No btree index found on %.%. Consider creating a btree index (including partial or expression indexes) for better performance. Non-btree indexes (e.g., GIN, GiST) are not checked and may not optimize pivoting. Run ANALYZE for optimal query plans.', p_pivot_column, p_table_name;
            END IF;
        END IF;

        -- Log performance and maintenance notices
        RAISE NOTICE 'Ensure %.% is vacuumed to avoid bloat (check via pgstattuple) and monitor freeze status to prevent performance issues. Verify index health (e.g., via amcheck or REINDEX).', v_schema_name, v_table_name;
        RAISE NOTICE 'Row-level security (RLS) policies or views/rules on %.% may filter rows or rewrite queries, affecting output or performance.', v_schema_name, v_table_name;
        RAISE NOTICE 'Permissions are checked against current_user (%); verify role settings.', current_user;
        RAISE NOTICE 'Monitor transaction ID wraparound risk in % (check pg_stat_activity).', current_database();
        RAISE NOTICE 'Parallel queries may be used for %.% (max_parallel_workers_per_gather: %); COUNT(DISTINCT) may not parallelize, slowing execution.', v_schema_name, v_table_name, v_parallel_workers;
        RAISE NOTICE 'JIT compilation may be used for %.% (enable_jit: %); may add latency for small datasets.', v_schema_name, v_table_name, v_jit_enabled;
        RAISE NOTICE 'Custom storage managers or access methods for %.% (e.g., via extensions) may affect behavior; test thoroughly.', v_schema_name, v_table_name;
        RAISE NOTICE 'Skewed data in %.% may degrade GROUP BY performance; check data distribution.', p_dimension_column, p_table_name;
        RAISE NOTICE 'Frequent calls to this procedure may trigger plan cache reuse for %.%; monitor performance.', v_schema_name, v_table_name;
        RAISE NOTICE 'Extreme memory pressure on % may cause failures; monitor system resources.', current_database();
        RAISE NOTICE 'Set client_min_messages to NOTICE or lower to see all warnings.';

        -- Log temp_buffers for temporary tables
        IF p_temporary_table THEN
            RAISE NOTICE 'Using temporary table %.%. Current temp_buffers: %; consider increasing for large outputs.', v_output_schema, v_output_table_name, v_temp_buffers;
        END IF;

        -- Drop existing output table with retry logic
        FOR i IN 1..3 LOOP
            BEGIN
                EXECUTE format('DROP TABLE IF EXISTS %I.%I NOWAIT', v_output_schema, v_output_table_name);
                EXIT;
            EXCEPTION
                WHEN lock_not_available THEN
                    IF i = 3 THEN
                        RAISE EXCEPTION 'Unable to drop table %.% after 3 attempts due to lock', v_output_schema, v_output_table_name;
                    END IF;
                    PERFORM pg_sleep(p_lock_retry_delay_ms / 1000.0);
            END;
        END LOOP;

        -- Initialize dynamic SQL for creating the output table
        v_sql := format('CREATE %s TABLE %I.%I (%I TEXT', 
                        CASE WHEN p_temporary_table THEN 'TEMPORARY' ELSE '' END, 
                        v_output_schema, v_output_table_name, p_dimension_column);

        -- Build pivot clause if pivoting is requested
        IF p_pivot_column IS NOT NULL AND array_length(v_unique_pivot_values, 1) > 0 THEN
            v_pivot_clause := '';
            FOREACH v_value IN ARRAY v_unique_pivot_values
            LOOP
                -- Add pivot column with aggregation
                v_sql := v_sql || format(', %I_%s %s', p_metric_column, v_value, v_metric_data_type);
                v_pivot_clause := v_pivot_clause || format(
                    ', %s((CASE WHEN %I = %L THEN %I END)) AS %I_%s',
                    p_aggregation_type, p_pivot_column, v_value, p_metric_column, p_metric_column, v_value
                );
            END LOOP;
        ELSE
            -- Non-pivoted case: just add the aggregated metric
            v_sql := v_sql || format(', %I %s', p_metric_column, v_metric_data_type);
            v_pivot_clause := format(', %s(%I) AS %I', p_aggregation_type, p_metric_column, p_metric_column);
        END IF;

        -- Complete the create table statement
        v_sql := v_sql || ')';
        EXECUTE v_sql;

        -- Log the generated SQL for debugging
        RAISE NOTICE 'Generated SQL for table creation: %', v_sql;

        -- Build and execute the dynamic insert statement
        v_sql := format(
            'INSERT INTO %I.%I SELECT %I %s FROM %I.%I GROUP BY %I',
            v_output_schema, v_output_table_name, p_dimension_column, v_pivot_clause, v_schema_name, v_table_name, p_dimension_column
        );
        EXECUTE v_sql;

        -- Log the generated SQL for debugging
        RAISE NOTICE 'Generated SQL for insert: %', v_sql;

        -- Log execution time and row count
        EXECUTE format('SELECT COUNT(*) FROM %I.%I', v_output_schema, v_output_table_name) INTO v_row_count;
        RAISE NOTICE 'Report generated successfully in table %.% with % rows in %. Run VACUUM on system catalogs if used frequently.',
            v_output_schema, v_output_table_name, v_row_count, clock_timestamp() - v_start_time;

        -- Commit transaction
        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            -- Rollback transaction on error
            ROLLBACK;
            RAISE EXCEPTION 'Error generating report: %. SQL: %, Inputs: table=%, dimension=%, metric=%, aggregation=%, pivot=%, output=%, temporary=%, max_groups=%, skip_cardinality=%',
                SQLERRM, v_sql, p_table_name, p_dimension_column, p_metric_column, p_aggregation_type, p_pivot_column, p_output_table, p_temporary_table, p_max_groups, p_skip_cardinality_check;
    END;
END;
$$;

-- Example usage of the stored procedure
-- Purpose: Demonstrate how to call the procedure for a sales report
DO $$
BEGIN
    -- Call the procedure to generate a report pivoting sales by year
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
END;
$$;

-- Create a sample table for testing
-- Purpose: Provide a structure to test the stored procedure
CREATE TABLE IF NOT EXISTS public.sales_data (
    department TEXT NOT NULL,
    sales NUMERIC,
    year INTEGER NOT NULL
);

-- Insert sample data for testing
-- Purpose: Populate the table with realistic data
INSERT INTO public.sales_data (department, sales, year) VALUES
    ('Electronics', 10000, 2023),
    ('Electronics', 15000, 2024),
    ('Clothing', 8000, 2023),
    ('Clothing', 12000, 2024),
    ('Furniture', 20000, 2023),
    ('Furniture', 25000, 2024);
