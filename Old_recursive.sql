WITH RECURSIVE EmployeeHierarchy AS (
    SELECT EmployeeID, ManagerID, EmployeeName, 1 AS Level
    FROM Employees
    WHERE ManagerID IS NULL
    UNION ALL
    SELECT e.EmployeeID, e.ManagerID, e.EmployeeName, eh.Level + 1
    FROM Employees e
    INNER JOIN EmployeeHierarchy eh ON e.ManagerID = eh.EmployeeID
)
SELECT eh.EmployeeName, eh.Level, (
    SELECT COUNT(*) 
    FROM Employees e2
    WHERE e2.ManagerID = eh.EmployeeID
) AS DirectReports
FROM EmployeeHierarchy eh
ORDER BY eh.Level, eh.EmployeeName;
