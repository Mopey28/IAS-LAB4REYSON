<?php
session_start();
require_once 'config.php';
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $role = $_POST['role'];
    $status = 'active';
    $sql = "INSERT INTO users (username, email, password, role, status) VALUES (?, ?, ?, ?, ?)";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, 'sssss', $username, $email, $password, $role, $status);
    if (mysqli_stmt_execute($stmt)) {
        $message = 'User added successfully!';
    } else {
        $message = 'Error adding user.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Add User</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <h2>Add New User</h2>
    <a href="manage_users.php">Back to User Management</a>
    <?php if ($message) echo '<p>' . htmlspecialchars($message) . '</p>'; ?>
    <form method="post">
        Username: <input type="text" name="username" required><br>
        Email: <input type="email" name="email" required><br>
        Password: <input type="password" name="password" required><br>
        Role: <select name="role">
            <option value="user">User</option>
            <option value="admin">Admin</option>
            <option value="auditor">Auditor</option>
        </select><br>
        <button type="submit">Add User</button>
    </form>
</body>
</html> 