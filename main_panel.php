<?php
session_start();
require_once 'config.php';
require_once 'rbac.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit();
}

// Check if MFA is verified
if (!isset($_SESSION['mfa_verified']) || $_SESSION['mfa_verified'] !== true) {
    // Check if user has MFA set up
    $sql = "SELECT mfa_secret FROM users WHERE id = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "i", $_SESSION['user_id']);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($result);

    if (empty($user['mfa_secret'])) {
        // Redirect to MFA setup if not configured
        header('Location: mfa_setup.php');
    } else {
        // Redirect to MFA verification
        header('Location: verify_mfa.php');
    }
    exit();
}

// Redirect based on role
if ($_SESSION['role'] === 'admin') {
    header('Location: admin_dashboard.php');
} else {
    header('Location: user_dashboard.php');
}
exit();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - Dashboard</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="farm-bg"></div>
    <div class="login-container" style="max-width:700px;">
        <div class="logo">G<span>R</span>OW <span>A GARDEN</span></div>
        <div class="login-title">Dashboard</div>
        <div style="text-align:left;">
            <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
            <div class="dashboard-content">
                <h2>Your Dashboard</h2>
                <p>Role: <?php echo htmlspecialchars($_SESSION['role']); ?></p>
                <?php if (checkPermission($_SESSION['role'], 'admin')): ?>
                <div class="admin-section">
                    <h3>Admin Controls</h3>
                    <ul>
                        <li><a href="security_report.php">View Security Report</a></li>
                        <li><a href="manage_users.php">Manage Users</a></li>
                    </ul>
                </div>
                <?php endif; ?>
                <div class="user-section">
                    <h3>User Options</h3>
                    <ul>
                        <li><a href="profile.php">View Profile</a></li>
                        <li><a href="setup.php">Manage MFA</a></li>
                        <li><a href="logout.php">Logout</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    <div class="bottom-icons">
        <img src="https://img.icons8.com/color/48/000000/home--v2.png" alt="Home" title="Home">
        <img src="https://img.icons8.com/color/48/000000/medium-volume.png" alt="Sound" title="Sound">
        <img src="https://img.icons8.com/color/48/000000/settings--v2.png" alt="Settings" title="Settings">
    </div>
</body>
</html> 