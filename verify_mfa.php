<?php
session_start();
require_once 'config.php';
require_once 'logs.php';
require_once 'vendor/autoload.php';

use RobThree\Auth\TwoFactorAuth;

if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit();
}

// Initialize the security logger
$logger = new SecurityLogger();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['code'])) {
    $tfa = new TwoFactorAuth('IAS LAB 4');

    // Get the user's MFA secret from the database
    $sql = "SELECT mfa_secret FROM users WHERE id = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "i", $_SESSION['user_id']);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($result);

    if ($user && $tfa->verifyCode($user['mfa_secret'], $_POST['code'])) {
        // MFA verification successful
        $_SESSION['mfa_verified'] = true;
        $logger->logAccess($_SESSION['username'], 'MFA_VERIFICATION', 'success');
        header('Location: main_panel.php');
    } else {
        // MFA verification failed
        $logger->logAccess($_SESSION['username'], 'MFA_VERIFICATION', 'failed');
        header('Location: setup.php?error=invalid_code');
    }
    exit();
}

// If we get here, redirect to MFA setup
header('Location: setup.php');
exit();
?> 