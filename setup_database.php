<?php
require_once 'config.php';

// Create users table if it doesn't exist
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    mfa_secret VARCHAR(32)
)";
mysqli_query($conn, $sql);

// Create access_logs table if it doesn't exist
$sql = "CREATE TABLE IF NOT EXISTS access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    timestamp DATETIME NOT NULL
)";
mysqli_query($conn, $sql);

// Check if tables were created successfully
$tables = ['users', 'access_logs'];
$success = true;

foreach ($tables as $table) {
    $result = mysqli_query($conn, "SHOW TABLES LIKE '$table'");
    if (mysqli_num_rows($result) == 0) {
        echo "Error: Table '$table' was not created successfully.<br>";
        $success = false;
    }
}

if ($success) {
    echo "Database setup completed successfully!<br>";
    echo "Tables created: " . implode(", ", $tables);
} else {
    echo "There were errors during database setup.";
}
?> 