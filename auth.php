<?php
session_start();
require_once 'config.php';
require_once 'vendor/autoload.php';
require_once 'logs.php';

use \Firebase\JWT\JWT;

// Initialize the security logger
$logger = new SecurityLogger();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // First get the user info
    $sql = "SELECT id, username, password, role, mfa_secret FROM users WHERE username = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($result);

    if ($user) {
        // Check if there are too many failed attempts for this user
        $sql = "SELECT COUNT(*) as failed_count 
                FROM access_logs 
                WHERE user_id = ? 
                AND action = 'LOGIN' 
                AND status = 'failed' 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 15 MINUTE)";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $user['id']);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $failed_attempts = mysqli_fetch_assoc($result)['failed_count'];

        if ($failed_attempts >= 3) {
            // Log the blocked attempt
            $logger->logAccess($username, 'LOGIN', 'blocked', 'Account temporarily blocked due to multiple failed attempts');
            header('Location: index.php?error=account_blocked');
            exit();
        }

        // Verify password
        if (password_verify($password, $user['password'])) {
        // Clear any existing session data
        session_unset();
        session_destroy();
        session_start();
        
        // Set new session data
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['mfa_verified'] = false; // Explicitly set MFA as not verified
        
        // Log successful login
            $logger->logAccess($username, 'LOGIN', 'success');

        // Check if MFA is set up
        if (empty($user['mfa_secret'])) {
            // Redirect to MFA setup if not configured
            header('Location: setup.php');
        } else {
            // Redirect to MFA verification
            header('Location: verify_mfa.php');
        }
        exit();
    } else {
        // Log failed login
        $logger->logAccess($username, 'LOGIN', 'failed');
            $remaining_attempts = 3 - ($failed_attempts + 1);
            header('Location: index.php?error=invalid_credentials&attempts=' . $remaining_attempts);
            exit();
        }
    } else {
        // Log failed login attempt for non-existent user
        $logger->logAccess($username, 'LOGIN', 'failed');
        header('Location: index.php?error=invalid_credentials&attempts=2');
        exit();
    }
}
?> 