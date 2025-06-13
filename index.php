<?php
session_start();
require_once 'config.php';
require_once 'logs.php';

if (isset($_SESSION['user_id'])) {
    header('Location: main_panel.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - Login</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="farm-bg"></div>
    <div class="login-container">
        <div class="logo">G<span>R</span>OW <span>A GARDEN</span></div>
        <div class="login-title">Sign In</div>
        <?php if (isset($_GET['error'])): ?>
            <div style="color: red; margin-bottom: 10px;">
                <?php
                if ($_GET['error'] === 'invalid_credentials') {
                    $attempts = isset($_GET['attempts']) ? (int)$_GET['attempts'] : 2;
                    echo 'Invalid username or password. You have ' . $attempts . ' more ' . 
                         ($attempts === 1 ? 'attempt' : 'attempts') . ' before your account is temporarily blocked.';
                } elseif ($_GET['error'] === 'invalid_mfa') {
                    echo 'Invalid MFA code';
                } elseif ($_GET['error'] === 'account_blocked') {
                    echo 'This account has been temporarily blocked due to multiple failed login attempts. Please try again in 15 minutes.';
                }
                ?>
            </div>
        <?php endif; ?>
        <form action="auth.php" method="POST">
            <div class="input-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button class="login-btn" type="submit">Enter</button>
        </form>
        <div class="social-login">
            <span>or Sign in with</span><br>
            <img src="https://img.icons8.com/color/48/000000/facebook-new.png" alt="Facebook" title="Sign in with Facebook">
            <img src="https://img.icons8.com/color/48/000000/google-logo.png" alt="Google" title="Sign in with Google">
        </div>
        <a class="register-link" href="register.php">Don't have an account? Register</a>
    </div>
    <div class="bottom-icons">
        <img src="https://img.icons8.com/color/48/000000/home--v2.png" alt="Home" title="Home">
        <img src="https://img.icons8.com/color/48/000000/medium-volume.png" alt="Sound" title="Sound">
        <img src="https://img.icons8.com/color/48/000000/settings--v2.png" alt="Settings" title="Settings">
    </div>
</body>
</html> 