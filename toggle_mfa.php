<?php
session_start();
require_once 'config.php';
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}
if (isset($_GET['id'])) {
    $id = intval($_GET['id']);
    $sql = "SELECT mfa_enabled FROM users WHERE id=?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, 'i', $id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($result);
    if ($user) {
        $new_mfa = $user['mfa_enabled'] ? 0 : 1;
        $sql = "UPDATE users SET mfa_enabled=? WHERE id=?";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, 'ii', $new_mfa, $id);
        mysqli_stmt_execute($stmt);
    }
}
header('Location: manage_users.php');
exit(); 