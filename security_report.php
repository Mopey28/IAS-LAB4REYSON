<?php
session_start();
require_once 'config.php';
require_once 'logs.php';
require_once 'rbac.php';

// Check if user is admin
if (!isset($_SESSION['user_id']) || !RBAC::checkPermission('view_security_reports')) {
    header('Location: index.php');
    exit();
}

$report = generateSecurityReport();

// Get detailed statistics
$sql = "SELECT 
    COUNT(CASE WHEN action = 'LOGIN' AND status = 'success' THEN 1 END) as successful_logins,
    COUNT(CASE WHEN action = 'LOGIN' AND status = 'failed' THEN 1 END) as failed_logins,
    COUNT(CASE WHEN action = 'MFA_VERIFICATION' AND status = 'success' THEN 1 END) as successful_mfa,
    COUNT(CASE WHEN action = 'MFA_VERIFICATION' AND status = 'failed' THEN 1 END) as failed_mfa
    FROM access_logs 
    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)";
$result = mysqli_query($conn, $sql);
$stats = mysqli_fetch_assoc($result);

// Get recent security events
$sql = "SELECT al.*, u.username 
        FROM access_logs al 
        LEFT JOIN users u ON al.user_id = u.id 
        WHERE al.action IN ('LOGIN', 'MFA_VERIFICATION', 'LOGOUT') 
        ORDER BY al.timestamp DESC LIMIT 20";
$result = mysqli_query($conn, $sql);
$recent_events = mysqli_fetch_all($result, MYSQLI_ASSOC);

// Get failed login attempts by IP
$sql = "SELECT ip_address, COUNT(*) as attempt_count 
        FROM access_logs 
        WHERE action = 'LOGIN' AND status = 'failed' 
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY ip_address 
        HAVING attempt_count > 3
        ORDER BY attempt_count DESC";
$result = mysqli_query($conn, $sql);
$suspicious_ips = mysqli_fetch_all($result, MYSQLI_ASSOC);

function logActivity($user, $activity, $status, $details = '') {
    $logger = new SecurityLogger();
    $logger->logActivity($user, $activity, $status, $details);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - Security Report</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="farm-bg"></div>
    <div class="login-container" style="max-width:800px;">
        <div class="logo">G<span>R</span>OW <span>A GARDEN</span></div>
        <div class="login-title">Security Report</div>
        <div style="text-align:left;">
            <h2>24-Hour Security Overview</h2>
            <div>
                <div><b>Successful Logins:</b> <?php echo $stats['successful_logins']; ?></div>
                <div><b>Failed Logins:</b> <?php echo $stats['failed_logins']; ?></div>
                <div><b>Successful MFA:</b> <?php echo $stats['successful_mfa']; ?></div>
                <div><b>Failed MFA:</b> <?php echo $stats['failed_mfa']; ?></div>
            </div>
            <h2>Security Status</h2>
            <?php if (detectIntrusion()): ?>
                <div style="color:red;">Potential intrusion detected! Multiple failed login attempts.</div>
            <?php else: ?>
                <div style="color:green;">No intrusion detected. System is secure.</div>
            <?php endif; ?>
            <h2>Recent Security Events</h2>
            <button onclick="openModal()">View Security Events</button>
        </div>
        <div id="eventsModal" style="display:none;">
            <div>
                <h3>Recent Security Events</h3>
                <button onclick="closeModal()">&times;</button>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>Status</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recent_events as $event): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($event['timestamp']); ?></td>
                            <td><?php echo isset($event['username']) ? htmlspecialchars($event['username']) : 'N/A'; ?></td>
                            <td><?php echo htmlspecialchars($event['action']); ?></td>
                            <td><?php echo htmlspecialchars($event['status']); ?></td>
                            <td><?php echo htmlspecialchars($event['ip_address']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <div class="bottom-icons">
        <img src="https://img.icons8.com/color/48/000000/home--v2.png" alt="Home" title="Home">
        <img src="https://img.icons8.com/color/48/000000/medium-volume.png" alt="Sound" title="Sound">
        <img src="https://img.icons8.com/color/48/000000/settings--v2.png" alt="Settings" title="Settings">
    </div>
    <script>
        function openModal() {
            document.getElementById('eventsModal').style.display = 'block';
        }
        function closeModal() {
            document.getElementById('eventsModal').style.display = 'none';
        }
    </script>
</body>
</html> 