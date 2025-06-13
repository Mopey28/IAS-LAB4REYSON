<?php
session_start();
require_once 'config.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}

$message = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['encryption_rest']) || isset($_POST['encryption_transit'])) {
        $encryption_rest = isset($_POST['encryption_rest']) ? 1 : 0;
        $encryption_transit = isset($_POST['encryption_transit']) ? 1 : 0;
        $sql = "INSERT INTO system_settings (setting_key, setting_value) VALUES ('encryption_rest', ?), ('encryption_transit', ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, 'ii', $encryption_rest, $encryption_transit);
        if (mysqli_stmt_execute($stmt)) {
            $message = 'Encryption settings updated successfully!';
        } else {
            $message = 'Error updating encryption settings.';
        }
    }
    if (isset($_POST['splunk_key']) || isset($_POST['openvas_key'])) {
        $splunk_key = trim($_POST['splunk_key']);
        $openvas_key = trim($_POST['openvas_key']);
        $sql = "INSERT INTO system_settings (setting_key, setting_value) VALUES ('splunk_key', ?), ('openvas_key', ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, 'ss', $splunk_key, $openvas_key);
        if (mysqli_stmt_execute($stmt)) {
            $message = 'Integration settings updated successfully!';
        } else {
            $message = 'Error updating integration settings.';
        }
    }
}

// Fetch current settings
$settings = [];
$result = mysqli_query($conn, "SELECT setting_key, setting_value FROM system_settings");
while ($row = mysqli_fetch_assoc($result)) {
    $settings[$row['setting_key']] = $row['setting_value'];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>System Settings</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/admin.css">
    <style>
        .admin-section-container {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            padding: 2rem;
            max-width: 700px;
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
        form {
            margin-bottom: 2rem;
            background: #f8f9fa;
            padding: 1.2rem 1.5rem;
            border-radius: 8px;
        }
        form h3 {
            margin-top: 0;
        }
        input[type='text'], input[type='checkbox'] {
            margin-bottom: 0.7rem;
        }
        button[type='submit'] {
            background: #27ae60;
            color: #fff;
            border: none;
            padding: 0.5rem 1.2rem;
            border-radius: 6px;
            font-weight: bold;
            cursor: pointer;
        }
        button[type='submit']:hover {
            background: #219150;
        }
    </style>
</head>
<body>
    <div class="admin-section-container">
        <div class="admin-section-header">System Settings</div>
        <a class="back-btn" href="admin_dashboard.php">&larr; Back to Dashboard</a>
        <?php if (!empty($message)) echo '<p style="color:green;font-weight:bold;">' . htmlspecialchars($message) . '</p>'; ?>
        <form method="post">
            <h3>Encryption Settings</h3>
            <label>Enable Encryption for Data at Rest: <input type="checkbox" name="encryption_rest" <?= isset($settings['encryption_rest']) && $settings['encryption_rest'] ? 'checked' : '' ?>></label><br>
            <label>Enable Encryption for Data in Transit: <input type="checkbox" name="encryption_transit" <?= isset($settings['encryption_transit']) && $settings['encryption_transit'] ? 'checked' : '' ?>></label><br>
            <button type="submit">Update Encryption Settings</button>
        </form>
        <form method="post">
            <h3>Integrations</h3>
            <label>Splunk Integration Key: <input type="text" name="splunk_key" value="<?= isset($settings['splunk_key']) ? htmlspecialchars($settings['splunk_key']) : '' ?>"></label><br>
            <label>OpenVAS Integration Key: <input type="text" name="openvas_key" value="<?= isset($settings['openvas_key']) ? htmlspecialchars($settings['openvas_key']) : '' ?>"></label><br>
            <button type="submit">Update Integrations</button>
        </form>
    </div>
</body>
</html> 