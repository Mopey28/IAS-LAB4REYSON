<?php
session_start();
require_once 'config.php';
require_once 'rbac.php';
require_once 'logs.php';
require_once 'admin_functions.php';

// Check if user is logged in, MFA is verified, and is an admin
if (!isset($_SESSION['user_id']) || !isset($_SESSION['mfa_verified']) || 
    $_SESSION['mfa_verified'] !== true || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}

// Get various statistics and data
$user_stats = getUserStatistics();
$security_events = getRecentSecurityEvents(10);
$system_health = getSystemHealth();
$user_activity = getUserActivitySummary(7);
$mfa_stats = getMFAStatistics();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - Admin Dashboard</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/admin.css">
</head>
<body>
    <div class="farm-bg"></div>
    <div class="dashboard-container" style="max-width:1200px;">
        <div class="logo">G<span>R</span>OW <span>A GARDEN</span></div>
        <div class="login-title">Admin Dashboard</div>
        
        <!-- Profile Bar -->
        <div class="profile-bar">
            <img class="profile-avatar" src="https://i.pravatar.cc/40?img=3" alt="Avatar">
            <div class="profile-info">
                <div class="profile-name"><?php echo htmlspecialchars($_SESSION['username']); ?></div>
                <div class="profile-role"><?php echo htmlspecialchars(ucfirst($_SESSION['role'])); ?></div>
            </div>
            <a class="profile-logout-btn" href="logout.php">Logout</a>
        </div>

        <!-- Quick Stats -->
        <div class="dashboard-section">
            <div class="dashboard-header">Quick Stats</div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value"><?php echo $user_stats['total_users']; ?></div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value"><?php echo $user_stats['active_users']; ?></div>
                    <div class="stat-label">Active Users (30d)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value"><?php echo $user_stats['mfa_enabled']; ?></div>
                    <div class="stat-label">MFA Enabled</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value"><?php echo $system_health['failed_logins']; ?></div>
                    <div class="stat-label">Failed Logins (1h)</div>
                </div>
            </div>
        </div>  

        <!-- Admin Actions -->
        <div class="dashboard-section">
            <div class="dashboard-header">Admin Actions</div>
            <div class="admin-actions-cards">
                <a class="admin-card card-blue admin-card-link" href="security_report.php">
                    <span class="admin-card-icon">🔒</span>
                    <span class="admin-card-title">Security Views</span>
                </a>
                <a class="admin-card card-lightblue admin-card-link" href="manage_users.php">
                    <span class="admin-card-icon">👥</span>
                    <span class="admin-card-title">User Management</span>
                </a>
                <a class="admin-card card-yellow admin-card-link" href="logs.php">
                    <span class="admin-card-icon">📋</span>
                    <span class="admin-card-title">View Logs</span>
                </a>
                <a class="admin-card card-red admin-card-link" href="setup.php">
                    <span class="admin-card-icon">🔑</span>
                    <span class="admin-card-title">Manage MFA</span>
                </a>
            </div>
        </div>

        <!-- System Health -->
        <div class="dashboard-section">
            <div class="dashboard-header">System Health</div>
            <div class="health-grid">
                <div class="health-card">
                    <div class="health-label">Database Status</div>
                    <div class="health-value <?php echo $system_health['database'] === 'Connected' ? 'status-ok' : 'status-error'; ?>">
                        <?php echo $system_health['database']; ?>
                    </div>
                </div>
                <div class="health-card">
                    <div class="health-label">MFA Success Rate</div>
                    <div class="health-value"><?php echo $mfa_stats['mfa_success_rate']; ?>%</div>
                </div>
                <div class="health-card">
                    <div class="health-label">System Uptime</div>
                    <div class="health-value"><?php echo $system_health['uptime']; ?></div>
                </div>
            </div>
        </div>

        <!-- Recent Security Events -->
        <div class="dashboard-section">
            <div class="dashboard-header">Recent Security Events</div>
            <div class="table-responsive">
                <table class="dashboard-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($security_events as $event): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($event['timestamp']); ?></td>
                            <td><?php echo isset($event['username']) ? htmlspecialchars($event['username']) : 'N/A'; ?></td>
                            <td><?php echo htmlspecialchars($event['action']); ?></td>
                            <td class="<?php echo $event['status'] === 'success' ? 'status-ok' : 'status-error'; ?>">
                                <?php echo htmlspecialchars($event['status']); ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- User Activity Chart -->
        <div class="dashboard-section">
            <div class="dashboard-header">User Activity (Last 7 Days)</div>
            <div class="chart-container">
                <canvas id="activityChart"></canvas>
            </div>
        </div>
    </div>

    <div class="bottom-icons">
        <img src="https://img.icons8.com/color/48/000000/home--v2.png" alt="Home" title="Home">
        <img src="https://img.icons8.com/color/48/000000/medium-volume.png" alt="Sound" title="Sound">
        <img src="https://img.icons8.com/color/48/000000/settings--v2.png" alt="Settings" title="Settings">
    </div>

    <!-- Include Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Prepare data for the activity chart
        const activityData = <?php echo json_encode($user_activity); ?>;
        
        // Create the activity chart
        const ctx = document.getElementById('activityChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: activityData.map(item => item.date),
                datasets: [{
                    label: 'Active Users',
                    data: activityData.map(item => item.active_users),
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                }, {
                    label: 'Total Actions',
                    data: activityData.map(item => item.total_actions),
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    </script>
</body>
</html> 