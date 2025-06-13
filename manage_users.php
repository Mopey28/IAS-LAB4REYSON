<?php
session_start();
require_once 'config.php';
require_once 'rbac.php';

// Check admin access
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}

// Handle add, edit, delete, MFA enable/disable, and role assignment actions here
// ... (for brevity, only the view and basic actions are shown)

// Fetch users
$result = mysqli_query($conn, "SELECT id, username, email, role, mfa_enabled, status FROM users");
$users = [];
while ($row = mysqli_fetch_assoc($result)) {
    $users[] = $row;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Management</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/admin.css">
    <style>
        .admin-section-container {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            padding: 2rem;
            max-width: 900px;
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
        .add-btn {
            display: inline-block;
            margin-bottom: 1.5rem;
            background: #27ae60;
            color: #fff;
            padding: 0.5rem 1.2rem;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            transition: background 0.2s;
        }
        .add-btn:hover {
            background: #219150;
        }
    </style>
</head>
<body>
    <div class="admin-section-container">
        <div class="admin-section-header">User Management</div>
        <a class="back-btn" href="admin_dashboard.php">&larr; Back to Dashboard</a>
        <a class="add-btn" href="add_user.php">+ Add New User</a>
        <div class="table-responsive">
        <table class="dashboard-table">
            <tr>
                <th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>MFA</th><th>Status</th><th>Actions</th>
            </tr>
            <?php foreach ($users as $user): ?>
            <tr>
                <td><?= $user['id'] ?></td>
                <td><?= htmlspecialchars($user['username']) ?></td>
                <td><?= htmlspecialchars($user['email']) ?></td>
                <td><?= htmlspecialchars($user['role']) ?></td>
                <td><?= $user['mfa_enabled'] ? 'Enabled' : 'Disabled' ?></td>
                <td><?= htmlspecialchars($user['status']) ?></td>
                <td>
                    <a href="edit_user.php?id=<?= $user['id'] ?>">Edit</a> |
                    <a href="delete_user.php?id=<?= $user['id'] ?>" onclick="return confirm('Delete user?')">Delete</a> |
                    <a href="toggle_mfa.php?id=<?= $user['id'] ?>">Toggle MFA</a> |
                    <a href="assign_role.php?id=<?= $user['id'] ?>">Assign Role</a>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
        </div>
    </div>
</body>
</html> 