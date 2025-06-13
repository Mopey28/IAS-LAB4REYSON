<?php
session_start();
require_once 'config.php';
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}

// Helper to get/set policy
function get_policy($type, $key, $default) {
    global $conn;
    $sql = "SELECT policy_value FROM security_policies WHERE policy_type=? AND policy_key=?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, 'ss', $type, $key);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);
    return $row ? $row['policy_value'] : $default;
}
function set_policy($type, $key, $value) {
    global $conn;
    $sql = "INSERT INTO security_policies (policy_type, policy_key, policy_value) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE policy_value=?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, 'ssss', $type, $key, $value, $value);
    mysqli_stmt_execute($stmt);
}

// Defaults
$defaults = [
    'min_length' => 12,
    'require_uppercase' => 1,
    'require_lowercase' => 1,
    'require_numbers' => 1,
    'require_special_chars' => 1,
    'max_age_days' => 90,
    'session_timeout' => 30,
    'lockout_duration' => 30
];

// Handle POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['min_length'])) {
        set_policy('password', 'min_length', $_POST['min_length']);
        set_policy('password', 'require_uppercase', isset($_POST['require_uppercase']) ? 1 : 0);
        set_policy('password', 'require_lowercase', isset($_POST['require_lowercase']) ? 1 : 0);
        set_policy('password', 'require_numbers', isset($_POST['require_numbers']) ? 1 : 0);
        set_policy('password', 'require_special_chars', isset($_POST['require_special_chars']) ? 1 : 0);
        set_policy('password', 'max_age_days', $_POST['max_age_days']);
    }
    if (isset($_POST['session_timeout'])) {
        set_policy('network', 'session_timeout', $_POST['session_timeout']);
        set_policy('network', 'lockout_duration', $_POST['lockout_duration']);
    }
    $msg = 'Policy updated!';
}

// Load current values
$min_length = get_policy('password', 'min_length', $defaults['min_length']);
$require_uppercase = get_policy('password', 'require_uppercase', $defaults['require_uppercase']);
$require_lowercase = get_policy('password', 'require_lowercase', $defaults['require_lowercase']);
$require_numbers = get_policy('password', 'require_numbers', $defaults['require_numbers']);
$require_special_chars = get_policy('password', 'require_special_chars', $defaults['require_special_chars']);
$max_age_days = get_policy('password', 'max_age_days', $defaults['max_age_days']);
$session_timeout = get_policy('network', 'session_timeout', $defaults['session_timeout']);
$lockout_duration = get_policy('network', 'lockout_duration', $defaults['lockout_duration']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Policy Management</title>
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
        input[type='number'], input[type='checkbox'] {
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
        <div class="admin-section-header">Security Policy Management</div>
        <a class="back-btn" href="admin_dashboard.php">&larr; Back to Dashboard</a>
        <?php if (!empty($msg)) echo '<p style="color:green;font-weight:bold;">' . htmlspecialchars($msg) . '</p>'; ?>
        <form method="post">
            <h3>Password Policy</h3>
            Min Length: <input type="number" name="min_length" value="<?= htmlspecialchars($min_length) ?>"><br>
            Require Uppercase: <input type="checkbox" name="require_uppercase" <?= $require_uppercase ? 'checked' : '' ?>><br>
            Require Lowercase: <input type="checkbox" name="require_lowercase" <?= $require_lowercase ? 'checked' : '' ?>><br>
            Require Numbers: <input type="checkbox" name="require_numbers" <?= $require_numbers ? 'checked' : '' ?>><br>
            Require Special Chars: <input type="checkbox" name="require_special_chars" <?= $require_special_chars ? 'checked' : '' ?>><br>
            Max Age (days): <input type="number" name="max_age_days" value="<?= htmlspecialchars($max_age_days) ?>"><br>
            <button type="submit">Update Policy</button>
        </form>
        <form method="post">
            <h3>Session Settings</h3>
            Session Timeout (minutes): <input type="number" name="session_timeout" value="<?= htmlspecialchars($session_timeout) ?>"><br>
            Lockout Duration (minutes): <input type="number" name="lockout_duration" value="<?= htmlspecialchars($lockout_duration) ?>"><br>
            <button type="submit">Update Session Settings</button>
        </form>
    </div>
</body>
</html> 