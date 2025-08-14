-- PostgreSQL: Comprehensive sales analytics with window functions
-- Calculates running totals, moving averages, rankings, and growth metrics by region

WITH sales_with_lag AS (
    SELECT 
        s.region,
        s.sale_date,
        s.amount,
        -- Running calculations
        SUM(s.amount) OVER (
            PARTITION BY s.region 
            ORDER BY s.sale_date 
            ROWS UNBOUNDED PRECEDING
        ) AS running_total,
        
        -- Moving averages with different windows
        AVG(s.amount) OVER (
            PARTITION BY s.region 
            ORDER BY s.sale_date 
            ROWS BETWEEN 6 PRECEDING AND CURRENT ROW
        ) AS moving_avg_7day,
        
        AVG(s.amount) OVER (
            PARTITION BY s.region 
            ORDER BY s.sale_date 
            ROWS BETWEEN 29 PRECEDING AND CURRENT ROW
        ) AS moving_avg_30day,
        
        -- Previous period comparison
        LAG(s.amount, 1) OVER (
            PARTITION BY s.region 
            ORDER BY s.sale_date
        ) AS prev_day_amount,
        
        LAG(s.amount, 7) OVER (
            PARTITION BY s.region 
            ORDER BY s.sale_date
        ) AS same_day_prev_week,
        
        -- Rankings and percentiles
        ROW_NUMBER() OVER (
            PARTITION BY s.region 
            ORDER BY s.amount DESC
        ) AS amount_rank,
        
        PERCENT_RANK() OVER (
            PARTITION BY s.region 
            ORDER BY s.amount
        ) AS amount_percentile,
        
        -- Regional context
        SUM(s.amount) OVER (ORDER BY s.sale_date) AS company_running_total,
        
        s.amount / NULLIF(
            SUM(s.amount) OVER (
                PARTITION BY s.sale_date
            ), 0
        ) * 100 AS daily_region_share_pct
        
    FROM sales s
    WHERE s.sale_date >= '2024-01-01' 
      AND s.sale_date < '2025-01-01'
      AND s.amount IS NOT NULL
      AND s.region IS NOT NULL
)

SELECT 
    region,
    sale_date,
    amount,
    running_total,
    
    -- Formatted moving averages
    ROUND(moving_avg_7day, 2) AS moving_avg_7day,
    ROUND(moving_avg_30day, 2) AS moving_avg_30day,
    
    -- Growth calculations
    CASE 
        WHEN prev_day_amount IS NOT NULL AND prev_day_amount != 0 
        THEN ROUND(((amount - prev_day_amount) / prev_day_amount * 100), 2)
        ELSE NULL 
    END AS day_over_day_growth_pct,
    
    CASE 
        WHEN same_day_prev_week IS NOT NULL AND same_day_prev_week != 0 
        THEN ROUND(((amount - same_day_prev_week) / same_day_prev_week * 100), 2)
        ELSE NULL 
    END AS week_over_week_growth_pct,
    
    -- Performance indicators
    amount_rank,
    ROUND(amount_percentile * 100, 1) AS amount_percentile,
    ROUND(daily_region_share_pct, 2) AS daily_region_share_pct,
    
    -- Trend indicators
    CASE 
        WHEN amount > moving_avg_7day THEN 'Above Trend'
        WHEN amount < moving_avg_7day THEN 'Below Trend'
        ELSE 'On Trend'
    END AS trend_status,
    
    -- Regional performance vs company
    ROUND(
        (running_total / NULLIF(company_running_total, 0)) * 100, 2
    ) AS region_contribution_pct

FROM sales_with_lag
ORDER BY 
    region, 
    sale_date DESC;

-- Optional: Create indexes for better performance
-- CREATE INDEX IF NOT EXISTS idx_sales_region_date ON sales (region, sale_date);
-- CREATE INDEX IF NOT EXISTS idx_sales_date_region ON sales (sale_date, region);

-- Example usage for specific analysis:
/*
-- Top performing days by region
SELECT DISTINCT
    region,
    sale_date,
    amount,
    amount_rank
FROM sales_analytics 
WHERE amount_rank <= 5
ORDER BY region, amount_rank;

-- Weekly trend analysis
SELECT 
    region,
    DATE_TRUNC('week', sale_date) AS week_start,
    SUM(amount) AS weekly_total,
    AVG(day_over_day_growth_pct) AS avg_daily_growth,
    COUNT(*) AS sales_days
FROM sales_analytics
WHERE day_over_day_growth_pct IS NOT NULL
GROUP BY region, DATE_TRUNC('week', sale_date)
ORDER BY region, week_start;
*/
