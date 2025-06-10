<?php
require_once 'config.php';

// User details
$username = 'testuser2';
$password = 'password123';
$role = 'admin';

// Check if user already exists
$check_sql = "SELECT id FROM users WHERE username = ?";
$check_stmt = mysqli_prepare($conn, $check_sql);
mysqli_stmt_bind_param($check_stmt, "s", $username);
mysqli_stmt_execute($check_stmt);
$result = mysqli_stmt_get_result($check_stmt);

if (mysqli_num_rows($result) > 0) {
    echo "User '$username' already exists. Please try a different username.";
} else {
    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Insert user into the database
    $sql = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "sss", $username, $hashed_password, $role);

    if (mysqli_stmt_execute($stmt)) {
        echo "User created successfully.<br>";
        echo "Username: $username<br>";
        echo "Password: $password<br>";
        echo "Role: $role";
    } else {
        echo "Error creating user: " . mysqli_error($conn);
    }

    mysqli_stmt_close($stmt);
}

mysqli_stmt_close($check_stmt);
mysqli_close($conn);
?> 