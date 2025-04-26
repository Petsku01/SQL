-- PostgreSQL: Calculate running sales totals by region with window functions
SELECT 
    s.Region,
    s.SaleDate,
    s.Amount,
    SUM(s.Amount) OVER (PARTITION BY s.Region ORDER BY s.SaleDate) AS RunningTotal,
    AVG(s.Amount) OVER (
        PARTITION BY s.Region 
        ORDER BY s.SaleDate 
        ROWS BETWEEN 3 PRECEDING AND CURRENT ROW
    ) AS MovingAvg
FROM Sales s
WHERE s.SaleDate BETWEEN '2010-01-01' AND '2010-12-31'
ORDER BY s.Region, s.SaleDate;
