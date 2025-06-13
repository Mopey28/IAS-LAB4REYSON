<?php
session_start();
require_once 'config.php';
require_once 'rbac.php';

// Helper to get policy
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

$defaults = [
    'min_length' => 12,
    'require_uppercase' => 1,
    'require_lowercase' => 1,
    'require_numbers' => 1,
    'require_special_chars' => 1
];
$min_length = get_policy('password', 'min_length', $defaults['min_length']);
$require_uppercase = get_policy('password', 'require_uppercase', $defaults['require_uppercase']);
$require_lowercase = get_policy('password', 'require_lowercase', $defaults['require_lowercase']);
$require_numbers = get_policy('password', 'require_numbers', $defaults['require_numbers']);
$require_special_chars = get_policy('password', 'require_special_chars', $defaults['require_special_chars']);

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit();
}

// Check if MFA is verified
if (!isset($_SESSION['mfa_verified']) || $_SESSION['mfa_verified'] !== true) {
    header('Location: verify_mfa.php');
    exit();
}

// Get user information
$user_id = $_SESSION['user_id'];
$sql = "SELECT username, role, email FROM users WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $user_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user = mysqli_fetch_assoc($result);
if (!isset($user['email'])) {
    $user['email'] = '';
}

// Handle profile update
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_profile'])) {
        $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $changes = false;

        // Password policy validation
        if (!empty($new_password)) {
            if (strlen($new_password) < $min_length) {
                $message .= '<div class="error">Password must be at least ' . $min_length . ' characters.</div>';
            } elseif ($require_uppercase && !preg_match('/[A-Z]/', $new_password)) {
                $message .= '<div class="error">Password must contain at least one uppercase letter.</div>';
            } elseif ($require_lowercase && !preg_match('/[a-z]/', $new_password)) {
                $message .= '<div class="error">Password must contain at least one lowercase letter.</div>';
            } elseif ($require_numbers && !preg_match('/[0-9]/', $new_password)) {
                $message .= '<div class="error">Password must contain at least one number.</div>';
            } elseif ($require_special_chars && !preg_match('/[^A-Za-z0-9]/', $new_password)) {
                $message .= '<div class="error">Password must contain at least one special character.</div>';
            }
        }

        // Update email if changed and valid
        if (!empty($email) && $email !== $user['email']) {
            // Check for duplicate email
            $check_sql = "SELECT id FROM users WHERE email = ? AND id != ?";
            $check_stmt = mysqli_prepare($conn, $check_sql);
            mysqli_stmt_bind_param($check_stmt, "si", $email, $user_id);
            mysqli_stmt_execute($check_stmt);
            $check_result = mysqli_stmt_get_result($check_stmt);
            if (mysqli_fetch_assoc($check_result)) {
                $message .= '<div class="error">Email is already in use by another account.</div>';
            } else {
                $update_sql = "UPDATE users SET email = ? WHERE id = ?";
                $update_stmt = mysqli_prepare($conn, $update_sql);
                mysqli_stmt_bind_param($update_stmt, "si", $email, $user_id);
                mysqli_stmt_execute($update_stmt);
                $message .= '<div class="success">Email updated successfully.</div>';
                $changes = true;
            }
        }
        // Update password if provided
        if (!empty($new_password)) {
            if (empty($current_password)) {
                $message .= '<div class="error">Current password is required to change your password.</div>';
            } else {
                $verify_sql = "SELECT password FROM users WHERE id = ?";
                $verify_stmt = mysqli_prepare($conn, $verify_sql);
                mysqli_stmt_bind_param($verify_stmt, "i", $user_id);
                mysqli_stmt_execute($verify_stmt);
                $verify_result = mysqli_stmt_get_result($verify_stmt);
                $user_data = mysqli_fetch_assoc($verify_result);
                if (!password_verify($current_password, $user_data['password'])) {
                    $message .= '<div class="error">Current password is incorrect.</div>';
                } else {
                    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                    $update_sql = "UPDATE users SET password = ? WHERE id = ?";
                    $update_stmt = mysqli_prepare($conn, $update_sql);
                    mysqli_stmt_bind_param($update_stmt, "si", $hashed_password, $user_id);
                    mysqli_stmt_execute($update_stmt);
                    $message .= '<div class="success">Password updated successfully.</div>';
                    $changes = true;
                }
            }
        }
        if (!$changes && empty($message)) {
            $message = '<div class="error">No changes made.</div>';
        }
        // Reload user info after update
        $sql = "SELECT username, role, email FROM users WHERE id = ?";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $user = mysqli_fetch_assoc($result);
        if (!isset($user['email'])) {
            $user['email'] = '';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - User Profile</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .profile-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 32px 32px 24px 32px;
            border-radius: 16px;
            margin: 32px auto 0 auto;
            max-width: 500px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.08);
            position: relative;
            z-index: 2;
        }
        .profile-section {
            margin-bottom: 24px;
        }
        .profile-section h3 {
            color: #2c3e50;
            margin-bottom: 12px;
        }
        .profile-info {
            margin-bottom: 18px;
        }
        .profile-info label {
            font-weight: bold;
            display: inline-block;
            width: 120px;
        }
        .success {
            color: #27ae60;
            background: #e8f5e9;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .error {
            color: #c0392b;
            background: #fdecea;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .input-group {
            margin-bottom: 18px;
            text-align: left;
        }
        .input-group label {
            color: #a86c1e;
            font-weight: bold;
            margin-bottom: 5px;
            display: block;
        }
        .input-group input {
            width: 100%;
            padding: 14px 20px;
            border-radius: 24px;
            border: 3px solid #ffe066;
            background: #fffde7;
            font-size: 1.1em;
            outline: none;
            margin-bottom: 5px;
            box-shadow: 0 2px 8px rgba(255, 224, 102, 0.15) inset, 0 1px 2px rgba(0,0,0,0.04);
            transition: border 0.2s, box-shadow 0.2s;
            color: #a86c1e;
            font-family: 'Comic Sans MS', 'Comic Sans', cursive, sans-serif;
            box-sizing: border-box;
        }
        .input-group input:focus {
            border: 3px solid #a8e063;
            box-shadow: 0 0 0 3px #e2ffb6, 0 2px 8px rgba(255, 224, 102, 0.15) inset;
            background: #fffff7;
        }
        .input-group input::placeholder {
            color: #c9a74a;
            opacity: 1;
            font-style: italic;
            font-size: 1em;
            letter-spacing: 1px;
        }
        .profile-btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(90deg, #a8e063 0%, #ffd700 100%);
            border: none;
            border-radius: 20px;
            color: #a86c1e;
            font-size: 1.2em;
            font-weight: bold;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            margin-bottom: 10px;
            transition: background 0.2s;
        }
        .profile-btn:hover {
            background: linear-gradient(90deg, #ffd700 0%, #a8e063 100%);
        }
        .back-btn {
            display:inline-block;
            padding:10px 24px;
            background:#4fc3f7;
            color:#fff;
            border-radius:8px;
            text-decoration:none;
            font-weight:bold;
            box-shadow:0 2px 8px rgba(0,0,0,0.08);
            margin-top: 18px;
        }
        .back-btn:hover {
            background: #217dbb;
        }
        .dashboard-container {
            position: relative;
            z-index: 2;
        }
        .farm-bg {
            z-index: 0;
        }
        .policy-box {
            background: #fffbe6;
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 18px;
            color: #a86c1e;
            font-size: 1em;
        }
        .policy-box ul {
            margin: 0 0 0 18px;
            padding: 0;
        }
        .policy-item {
            transition: color 0.2s;
        }
        .policy-met {
            color: #27ae60 !important;
            font-weight: bold;
        }
        .policy-status {
            font-weight: bold;
            margin-left: 8px;
        }
    </style>
</head>
<body>
    <div class="farm-bg"></div>
    <div class="dashboard-container">
        <div class="logo">G<span>R</span>OW <span>A GARDEN</span></div>
        <div class="login-title">User Profile</div>
        <?php echo $message; ?>
        <div class="profile-container">
            <div class="profile-section">
                <h3>Account Information</h3>
                <div class="profile-info">
                    <label>Username:</label>
                    <span><?php echo htmlspecialchars($user['username']); ?></span>
                </div>
                <div class="profile-info">
                    <label>Role:</label>
                    <span><?php echo htmlspecialchars($user['role']); ?></span>
                </div>
                <div class="profile-info">
                    <label>Email:</label>
                    <span><?php echo htmlspecialchars($user['email']); ?></span>
                </div>
            </div>
            <div class="profile-section">
                <h3>Update Profile</h3>
                <div class="policy-box">
                    <b>Password Policy:</b>
                    <ul>
                        <li id="policy-length" class="policy-item">Min Length: <?php echo htmlspecialchars($min_length); ?> <span class="policy-status" id="status-length">No</span></li>
                        <li id="policy-upper" class="policy-item">Require Uppercase: <?php echo $require_uppercase ? '' : 'Not Required'; ?> <span class="policy-status" id="status-upper"><?php echo $require_uppercase ? 'No' : 'Yes'; ?></span></li>
                        <li id="policy-lower" class="policy-item">Require Lowercase: <?php echo $require_lowercase ? '' : 'Not Required'; ?> <span class="policy-status" id="status-lower"><?php echo $require_lowercase ? 'No' : 'Yes'; ?></span></li>
                        <li id="policy-number" class="policy-item">Require Numbers: <?php echo $require_numbers ? '' : 'Not Required'; ?> <span class="policy-status" id="status-number"><?php echo $require_numbers ? 'No' : 'Yes'; ?></span></li>
                        <li id="policy-special" class="policy-item">Require Special Characters: <?php echo $require_special_chars ? '' : 'Not Required'; ?> <span class="policy-status" id="status-special"><?php echo $require_special_chars ? 'No' : 'Yes'; ?></span></li>
                    </ul>
                </div>
                <form method="POST" action="">
                    <div class="input-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" placeholder="Enter your email">
                    </div>
                    <div class="input-group">
                        <label for="current_password">Current Password:</label>
                        <input type="password" id="current_password" name="current_password" placeholder="Enter current password">
                    </div>
                    <div class="input-group">
                        <label for="new_password">New Password:</label>
                        <input type="password" id="new_password" name="new_password" oninput="checkPolicy()" placeholder="Enter new password">
                    </div>
                    <button type="submit" name="update_profile" class="profile-btn">Update Profile</button>
                </form>
            </div>
            <a href="user_dashboard.php" class="back-btn">Back to Dashboard</a>
        </div>
    </div>
    <script>
    function checkPolicy() {
        var pwd = document.getElementById('new_password').value;
        var minLength = <?php echo (int)$min_length; ?>;
        var requireUpper = <?php echo (int)$require_uppercase; ?>;
        var requireLower = <?php echo (int)$require_lowercase; ?>;
        var requireNumber = <?php echo (int)$require_numbers; ?>;
        var requireSpecial = <?php echo (int)$require_special_chars; ?>;

        // Length
        var metLength = pwd.length >= minLength;
        document.getElementById('policy-length').classList.toggle('policy-met', metLength);
        document.getElementById('status-length').textContent = metLength ? 'Yes' : 'No';
        // Uppercase
        var metUpper = requireUpper ? /[A-Z]/.test(pwd) : true;
        document.getElementById('policy-upper').classList.toggle('policy-met', metUpper);
        document.getElementById('status-upper').textContent = metUpper ? 'Yes' : 'No';
        // Lowercase
        var metLower = requireLower ? /[a-z]/.test(pwd) : true;
        document.getElementById('policy-lower').classList.toggle('policy-met', metLower);
        document.getElementById('status-lower').textContent = metLower ? 'Yes' : 'No';
        // Number
        var metNumber = requireNumber ? /[0-9]/.test(pwd) : true;
        document.getElementById('policy-number').classList.toggle('policy-met', metNumber);
        document.getElementById('status-number').textContent = metNumber ? 'Yes' : 'No';
        // Special char
        var metSpecial = requireSpecial ? /[^A-Za-z0-9]/.test(pwd) : true;
        document.getElementById('policy-special').classList.toggle('policy-met', metSpecial);
        document.getElementById('status-special').textContent = metSpecial ? 'Yes' : 'No';
    }
    </script>
</body>
</html> 