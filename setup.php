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

$tfa = new TwoFactorAuth('IAS LAB 4');

// Check if user already has MFA set up
$sql = "SELECT mfa_secret FROM users WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $_SESSION['user_id']);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user = mysqli_fetch_assoc($result);

// Only generate new secret if user doesn't have one
if (empty($user['mfa_secret'])) {
    $secret = $tfa->createSecret();
    // Store the secret in the database
    $sql = "UPDATE users SET mfa_secret = ? WHERE id = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "si", $secret, $_SESSION['user_id']);
    mysqli_stmt_execute($stmt);
} else {
    $secret = $user['mfa_secret'];
}

// Generate QR code
$qrCodeUrl = $tfa->getQRCodeImageAsDataUri('IAS LAB 4 - ' . $_SESSION['username'], $secret);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - Two-Step Verification</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .mfa-setup-box {
            background: #fffbe6;
            border-radius: 24px;
            box-shadow: 0 4px 18px rgba(0,0,0,0.10);
            padding: 32px 28px 24px 28px;
            margin: 0 auto 24px auto;
            max-width: 420px;
            text-align: left;
        }
        .mfa-step-title {
            color: #a86c1e;
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .mfa-qr {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-bottom: 18px;
        }
        .mfa-qr img {
            background: #fff;
            padding: 12px;
            border-radius: 18px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.10);
            margin-bottom: 8px;
        }
        .mfa-form {
            margin-top: 18px;
        }
        .mfa-error {
            color: #ef5350;
            margin-bottom: 12px;
            font-weight: bold;
        }
        .mfa-back {
            display: inline-block;
            margin-top: 18px;
            color: #1a73e8;
            text-decoration: none;
            font-weight: bold;
        }
        .mfa-back:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="farm-bg"></div>
    <div class="login-container" style="max-width:700px;">
        <div class="logo">G<span>R</span>OW <span>A GARDEN</span></div>
        <div class="login-title">Two-Step Verification</div>
        <div class="mfa-setup-box">
            <?php if (isset($_GET['error'])): ?>
                <div class="mfa-error">
                    <?php
                    if ($_GET['error'] === 'invalid_code') {
                        echo 'The code you entered is incorrect. Please try again.';
                    }
                    ?>
                </div>
            <?php endif; ?>
            <div class="mfa-step-title">1. Connect Your Authenticator</div>
            <div class="mfa-qr">
                <img src="<?php echo $qrCodeUrl; ?>" alt="Scan this QR code">
                <div style="font-size:0.98em; color:#a86c1e; margin-top:4px;">Scan this QR code using your authenticator app.</div>
            </div>
            <div class="mfa-step-title">2. Enter Your Code</div>
            <div style="font-size:0.98em; color:#a86c1e; margin-bottom:8px;">Type the 6-digit code from your app below:</div>
            <form class="mfa-form" action="verify_mfa.php" method="POST">
                <div class="input-group">
                    <label for="code">Verification Code</label>
                    <input type="text" id="code" name="code" required autocomplete="one-time-code">
                </div>
                <button class="login-btn" type="submit">Verify Code</button>
            </form>
            <a class="mfa-back" href="main_panel.php">&larr; Back to Dashboard</a>
        </div>
    </div>
    <div class="bottom-icons">
        <img src="https://img.icons8.com/color/48/000000/home--v2.png" alt="Home" title="Home">
        <img src="https://img.icons8.com/color/48/000000/medium-volume.png" alt="Sound" title="Sound">
        <img src="https://img.icons8.com/color/48/000000/settings--v2.png" alt="Settings" title="Settings">
    </div>
</body>
</html> 