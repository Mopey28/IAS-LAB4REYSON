<?php
session_start();
require_once 'config.php';
require_once 'rbac.php';

// Check if user is logged in, MFA is verified, and is a regular user
if (!isset($_SESSION['user_id']) || !isset($_SESSION['mfa_verified']) || 
    $_SESSION['mfa_verified'] !== true || $_SESSION['role'] !== 'user') {
    header('Location: index.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - User Dashboard</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/user.css">
    <style>
        .user-profile-bar {
            display: flex;
            align-items: center;
            gap: 16px;
            background: rgba(255,255,255,0.92);
            border-radius: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            padding: 10px 24px;
            margin: 0 0 28px auto;
            max-width: 340px;
            width: fit-content;
            position: relative;
            float: right;
        }
        .user-profile-avatar {
            width: 44px;
            height: 44px;
            border-radius: 50%;
            object-fit: cover;
            border: 2px solid #ffd700;
        }
        .user-profile-info {
            display: flex;
            flex-direction: column;
            align-items: flex-start;
        }
        .user-profile-name {
            font-weight: bold;
            color: #a86c1e;
            font-size: 1.15em;
        }
        .user-profile-role {
            font-size: 0.98em;
            color: #888;
        }
        .user-profile-logout {
            background: #ef5350;
            color: #fff;
            border: none;
            border-radius: 16px;
            padding: 7px 16px;
            font-size: 1em;
            font-weight: bold;
            text-decoration: none;
            margin-left: 8px;
            transition: background 0.2s, box-shadow 0.2s;
            cursor: pointer;
            box-shadow: 0 2px 6px rgba(0,0,0,0.10);
            outline: none;
        }
        .user-profile-logout:hover {
            background: #d32f2f;
            box-shadow: 0 4px 12px rgba(239,83,80,0.18);
        }
        .user-actions-cards {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 32px;
        }
        .user-action-card {
            flex: 1 1 160px;
            min-width: 160px;
            max-width: 200px;
            background: #fff;
            border-radius: 18px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.08);
            padding: 20px 14px 16px 14px;
            color: #fff;
            position: relative;
            transition: transform 0.15s, box-shadow 0.15s;
            cursor: pointer;
            text-align: left;
            overflow: hidden;
        }
        .user-action-card:hover {
            transform: translateY(-4px) scale(1.03);
            box-shadow: 0 8px 24px rgba(0,0,0,0.15);
        }
        .user-card-blue { background: #4fc3f7; }
        .user-card-green { background: #a8e063; color: #a86c1e; }
        .user-card-yellow { background: #ffd54f; color: #a86c1e; }
        .user-action-icon {
            font-size: 1.7em;
            margin-bottom: 8px;
            display: block;
        }
        .user-action-title {
            font-size: 1.05em;
            font-weight: bold;
            color: inherit;
            text-decoration: none;
        }
        .user-section {
            background: #fffbe6;
            border-radius: 18px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            padding: 22px 24px 18px 24px;
            margin-bottom: 22px;
        }
        .user-section-title {
            color: #a86c1e;
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .user-section-info {
            font-size: 1.05em;
            color: #a86c1e;
            margin-bottom: 6px;
        }
    </style>
</head>
<body>
    <div class="farm-bg"></div>
    <div class="dashboard-container">
        <div class="logo">G<span>R</span>OW <span>A GARDEN</span></div>
        <div class="login-title">User Dashboard</div>
        <div class="user-profile-bar">
            <img class="user-profile-avatar" src="https://i.pravatar.cc/40?img=5" alt="Avatar">
            <div class="user-profile-info">
                <div class="user-profile-name"><?php echo htmlspecialchars($_SESSION['username']); ?></div>
                <div class="user-profile-role"><?php echo htmlspecialchars(ucfirst($_SESSION['role'])); ?></div>
            </div>
            <a class="user-profile-logout" href="logout.php">Logout</a>
        </div>
        <div class="user-actions-cards">
            <a class="user-action-card user-card-blue" href="profile.php">
                <span class="user-action-icon">👤</span>
                <span class="user-action-title">View Profile</span>
            </a>
            <a class="user-action-card user-card-green" href="setup.php">
                <span class="user-action-icon">🔑</span>
                <span class="user-action-title">Manage MFA</span>
            </a>
        </div>
        <div class="user-section">
            <div class="user-section-title">Account Information</div>
            <div class="user-section-info"><b>Username:</b> <?php echo htmlspecialchars($_SESSION['username']); ?></div>
            <div class="user-section-info"><b>Role:</b> <?php echo htmlspecialchars($_SESSION['role']); ?></div>
            <div class="user-section-info"><b>MFA Status:</b> Active</div>
        </div>
        <div class="user-section">
            <div class="user-section-title">Security Status</div>
            <div class="user-section-info"><b>Last Login:</b> <?php echo date('Y-m-d H:i:s'); ?></div>
            <div class="user-section-info"><b>Session Status:</b> Active</div>
        </div>
    </div>
    <div class="bottom-icons">
        <img src="https://img.icons8.com/color/48/000000/home--v2.png" alt="Home" title="Home">
        <img src="https://img.icons8.com/color/48/000000/medium-volume.png" alt="Sound" title="Sound">
        <img src="https://img.icons8.com/color/48/000000/settings--v2.png" alt="Settings" title="Settings">
    </div>
</body>
</html> 