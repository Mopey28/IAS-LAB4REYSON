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
    $role = $_POST['role'];
    $sql = "UPDATE users SET role=? WHERE id=?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, 'si', $role, $id);
    if (mysqli_stmt_execute($stmt)) {
        $message = 'Role updated successfully!';
    } else {
        $message = 'Error updating role.';
    }
}
$sql = "SELECT username, role FROM users WHERE id=?";
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
    <title>Assign Role</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <h2>Assign Role to <?= htmlspecialchars($user['username']) ?></h2>
    <a href="manage_users.php">Back to User Management</a>
    <?php if ($message) echo '<p>' . htmlspecialchars($message) . '</p>'; ?>
    <form method="post">
        Role: <select name="role">
            <option value="user" <?= $user['role'] === 'user' ? 'selected' : '' ?>>User</option>
            <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
            <option value="auditor" <?= $user['role'] === 'auditor' ? 'selected' : '' ?>>Auditor</option>
        </select><br>
        <button type="submit">Update Role</button>
    </form>
</body>
</html> 