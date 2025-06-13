<?php
session_start();
require_once 'config.php';
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}
if (!isset($_GET['id'])) {
    header('Location: manage_users.php');
    exit();
}
$id = intval($_GET['id']);
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $role = $_POST['role'];
    $status = $_POST['status'];
    $sql = "UPDATE users SET username=?, email=?, role=?, status=? WHERE id=?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, 'ssssi', $username, $email, $role, $status, $id);
    if (mysqli_stmt_execute($stmt)) {
        $message = 'User updated successfully!';
    } else {
        $message = 'Error updating user.';
    }
}
$sql = "SELECT * FROM users WHERE id=?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, 'i', $id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user = mysqli_fetch_assoc($result);
if (!$user) {
    header('Location: manage_users.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Edit User</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <h2>Edit User</h2>
    <a href="manage_users.php">Back to User Management</a>
    <?php if ($message) echo '<p>' . htmlspecialchars($message) . '</p>'; ?>
    <form method="post">
        Username: <input type="text" name="username" value="<?= htmlspecialchars($user['username']) ?>" required><br>
        Email: <input type="email" name="email" value="<?= htmlspecialchars($user['email']) ?>" required><br>
        Role: <select name="role">
            <option value="user" <?= $user['role'] === 'user' ? 'selected' : '' ?>>User</option>
            <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
            <option value="auditor" <?= $user['role'] === 'auditor' ? 'selected' : '' ?>>Auditor</option>
        </select><br>
        Status: <select name="status">
            <option value="active" <?= $user['status'] === 'active' ? 'selected' : '' ?>>Active</option>
            <option value="disabled" <?= $user['status'] === 'disabled' ? 'selected' : '' ?>>Disabled</option>
        </select><br>
        <button type="submit">Update User</button>
    </form>
</body>
</html> 