<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once 'config.php';
require_once 'logs.php';
require_once 'admin_functions.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}

// Function to get suspicious login attempts by role
function getSuspiciousLoginsByRole($conn) {
    $suspicious_logins = [];
    $sql = "SELECT 
                u.role,
                COUNT(*) as attempt_count,
                MAX(l.created_at) as last_attempt,
                GROUP_CONCAT(DISTINCT l.ip_address) as ip_addresses,
                COUNT(DISTINCT l.user_id) as affected_users
            FROM security_logs l
            LEFT JOIN users u ON l.user_id = u.id
            WHERE l.action = 'LOGIN_FAILED'
            AND l.created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY u.role
            HAVING COUNT(*) >= 3";
    
    $result = mysqli_query($conn, $sql);
    while ($row = mysqli_fetch_assoc($result)) {
        $suspicious_logins[] = $row;
    }
    return $suspicious_logins;
}

// Get suspicious logins by role
$suspicious_logins = getSuspiciousLoginsByRole($conn);

// Get role-based activity
$role_activity = getRoleActivitySummary(7);

// Example: Fetch system health and logs
$system_health = [
    'database' => 'Connected',
    'uptime' => '99.99%',
    'failed_logins' => count($suspicious_logins)
];
$logs = getRecentSecurityEvents(20);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>System Monitoring</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/admin.css">
    <style>
        .admin-section-container {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            padding: 2rem;
            max-width: 900px;
            margin: 2rem auto;
        }
        .admin-section-header {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 1.5rem;
            color: #2c3e50;
        }
        .back-btn {
            display: inline-block;
            margin-bottom: 1.5rem;
            background: #3498db;
            color: #fff;
            padding: 0.5rem 1.2rem;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            transition: background 0.2s;
        }
        .back-btn:hover {
            background: #217dbb;
        }
        .table-responsive {
            margin-bottom: 2rem;
        }
        .suspicious {
            background-color: #fff3f3;
            color: #c0392b;
        }
        .suspicious td {
            font-weight: bold;
        }
        .warning-icon {
            color: #e74c3c;
            margin-right: 5px;
        }
        .role-admin { color: #e74c3c; }
        .role-user { color: #3498db; }
        .role-guest { color: #95a5a6; }
    </style>
</head>
<body>
    <div class="admin-section-container">
        <div class="admin-section-header">System Monitoring</div>
        <a class="back-btn" href="admin_dashboard.php">&larr; Back to Dashboard</a>
        
        <h3>System Health</h3>
        <ul>
            <li>Database: <?= $system_health['database'] ?></li>
            <li>Uptime: <?= $system_health['uptime'] ?></li>
            <li>Failed Logins (1h): <?= $system_health['failed_logins'] ?></li>
        </ul>

        <h3>Suspicious Login Attempts by Role (Last Hour)</h3>
        <div class="table-responsive">
        <table class="dashboard-table">
            <tr>
                <th>Role</th>
                <th>Failed Attempts</th>
                <th>Affected Users</th>
                <th>Last Attempt</th>
                <th>IP Addresses</th>
                <th>Status</th>
            </tr>
            <?php if (count($suspicious_logins) > 0): ?>
                <?php foreach ($suspicious_logins as $login): ?>
                <tr class="suspicious">
                    <td class="role-<?= strtolower($login['role']) ?>"><?= htmlspecialchars($login['role']) ?></td>
                    <td><?= htmlspecialchars($login['attempt_count']) ?></td>
                    <td><?= htmlspecialchars($login['affected_users']) ?></td>
                    <td><?= htmlspecialchars($login['last_attempt']) ?></td>
                    <td><?= htmlspecialchars($login['ip_addresses']) ?></td>
                    <td><span class="warning-icon">⚠️</span> Suspicious</td>
                </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="6" style="text-align: center;">No suspicious login attempts found</td>
                </tr>
            <?php endif; ?>
        </table>
        </div>

        <h3>Recent Security Events</h3>
        <div class="table-responsive">
        <table class="dashboard-table">
            <tr><th>Time</th><th>Role</th><th>Action</th><th>Status</th></tr>
            <?php foreach ($logs as $event): ?>
            <tr>
                <td><?= htmlspecialchars($event['timestamp']) ?></td>
                <td class="role-<?= strtolower($event['role'] ?? 'guest') ?>"><?= htmlspecialchars($event['role'] ?? 'Guest') ?></td>
                <td><?= htmlspecialchars($event['action']) ?></td>
                <td><?= htmlspecialchars($event['status']) ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
        </div>

        <h3>Role-based Activity (Last 7 Days)</h3>
        <div class="table-responsive">
        <table class="dashboard-table">
            <tr>
                <th>Date</th>
                <th>Role</th>
                <th>Active Users</th>
                <th>Total Actions</th>
            </tr>
            <?php foreach ($role_activity as $activity): ?>
            <tr>
                <td><?= htmlspecialchars($activity['date']) ?></td>
                <td class="role-<?= strtolower($activity['role']) ?>"><?= htmlspecialchars($activity['role']) ?></td>
                <td><?= htmlspecialchars($activity['active_users']) ?></td>
                <td><?= htmlspecialchars($activity['total_actions']) ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
        </div>
    </div>
</body>
</html> 