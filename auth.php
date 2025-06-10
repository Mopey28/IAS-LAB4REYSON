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

    $sql = "SELECT id, username, password, role, mfa_secret FROM users WHERE username = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($result);

    if ($user && password_verify($password, $user['password'])) {
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
        $logger->logAccess($user['username'], 'LOGIN', 'success');

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
        header('Location: index.php?error=invalid_credentials');
        exit();
    }
}
?> 