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
    header('Location: verify_mfa.php');
    exit();
}

// Get user information
$user_id = $_SESSION['user_id'];
$sql = "SELECT username, role FROM users WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $user_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user = mysqli_fetch_assoc($result);

// Get additional user information if columns exist
$additional_info = [];
try {
    $info_sql = "SELECT email, created_at, last_login FROM users WHERE id = ?";
    $info_stmt = mysqli_prepare($conn, $info_sql);
    mysqli_stmt_bind_param($info_stmt, "i", $user_id);
    mysqli_stmt_execute($info_stmt);
    $info_result = mysqli_stmt_get_result($info_stmt);
    $additional_info = mysqli_fetch_assoc($info_result);
} catch (Exception $e) {
    // Columns don't exist yet, that's okay
}

// Merge the information
$user = array_merge($user, $additional_info ?: []);

// Handle profile update
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_profile'])) {
        $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        
        // Verify current password if changing password
        if (!empty($new_password)) {
            $verify_sql = "SELECT password FROM users WHERE id = ?";
            $verify_stmt = mysqli_prepare($conn, $verify_sql);
            mysqli_stmt_bind_param($verify_stmt, "i", $user_id);
            mysqli_stmt_execute($verify_stmt);
            $verify_result = mysqli_stmt_get_result($verify_stmt);
            $user_data = mysqli_fetch_assoc($verify_result);
            
            if (!password_verify($current_password, $user_data['password'])) {
                $message = '<div class="error">Current password is incorrect</div>';
            } else {
                // Update password
                $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                $update_sql = "UPDATE users SET password = ? WHERE id = ?";
                $update_stmt = mysqli_prepare($conn, $update_sql);
                mysqli_stmt_bind_param($update_stmt, "si", $hashed_password, $user_id);
                mysqli_stmt_execute($update_stmt);
                $message = '<div class="success">Password updated successfully</div>';
            }
        }
        
        // Update email if column exists
        if (!empty($email) && isset($user['email']) && $email !== $user['email']) {
            try {
                $update_sql = "UPDATE users SET email = ? WHERE id = ?";
                $update_stmt = mysqli_prepare($conn, $update_sql);
                mysqli_stmt_bind_param($update_stmt, "si", $email, $user_id);
                mysqli_stmt_execute($update_stmt);
                $message = '<div class="success">Profile updated successfully</div>';
                $user['email'] = $email;
            } catch (Exception $e) {
                $message = '<div class="error">Email update is not available yet</div>';
            }
        }
    }
}

$sql = "ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS failed_attempts INT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS is_locked TINYINT(1) DEFAULT 0";
if (mysqli_query($conn, $sql)) {
    echo "Database updated successfully";
} else {
    echo "Error updating database: " . mysqli_error($conn);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - Profile</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .profile-container {
            background: rgba(255, 255, 255, 0.9);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .profile-section {
            margin-bottom: 20px;
        }
        .profile-section h3 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .profile-info {
            margin-bottom: 15px;
        }
        .profile-info label {
            font-weight: bold;
            display: inline-block;
            width: 150px;
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
        .login-container {
            max-width: 1000px !important;
            width: 100%;
            margin: 40px auto !important;
            padding: 40px 40px 30px 40px !important;
            box-sizing: border-box;
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
                <?php if (isset($user['created_at'])): ?>
                <div class="profile-info">
                    <label>Member Since:</label>
                    <span><?php echo date('F j, Y', strtotime($user['created_at'])); ?></span>
                </div>
                <?php endif; ?>
                <?php if (isset($user['last_login'])): ?>
                <div class="profile-info">
                    <label>Last Login:</label>
                    <span><?php echo date('F j, Y H:i', strtotime($user['last_login'])); ?></span>
                </div>
                <?php endif; ?>
            </div>

            <div class="profile-section">
                <h3>Update Profile</h3>
                <form method="POST" action="">
                    <?php if (isset($user['email'])): ?>
                    <div class="input-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>">
                    </div>
                    <?php endif; ?>
                    <div class="input-group">
                        <label for="current_password">Current Password:</label>
                        <input type="password" id="current_password" name="current_password">
                    </div>
                    <div class="input-group">
                        <label for="new_password">New Password:</label>
                        <input type="password" id="new_password" name="new_password">
                    </div>
                    <button type="submit" name="update_profile" class="login-btn">Update Profile</button>
                </form>
            </div>
        </div>
        
        <div style="margin-top: 20px; text-align: center;">
            <a href="main_panel.php" class="register-link">Back to Dashboard</a>
        </div>
    </div>
    <div class="bottom-icons">
        <img src="https://img.icons8.com/color/48/000000/home--v2.png" alt="Home" title="Home">
        <img src="https://img.icons8.com/color/48/000000/medium-volume.png" alt="Sound" title="Sound">
        <img src="https://img.icons8.com/color/48/000000/settings--v2.png" alt="Settings" title="Settings">
    </div>
</body>
</html> 