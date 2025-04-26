WITH RECURSIVE EmployeeHierarchy AS (
    SELECT EmployeeID, ManagerID, EmployeeName, 1 AS Level
    FROM Employees
    WHERE ManagerID IS NULL
    UNION ALL
    SELECT e.EmployeeID, e.ManagerID, e.EmployeeName, eh.Level + 1
    FROM Employees e
    INNER JOIN EmployeeHierarchy eh ON e.ManagerID = eh.EmployeeID
)
SELECT EmployeeName, Level, (
    SELECT COUNT(*) 
    FROM EmployeeHierarchy sub 
    WHERE sub.ManagerID = eh.EmployeeID
) AS DirectReports
FROM EmployeeHierarchy eh
ORDER BY Level, EmployeeName;
