<?php
require_once 'config.php';

// Add new columns to users table
$sql = "ALTER TABLE users 
        ADD COLUMN email VARCHAR(255) DEFAULT NULL,
        ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ADD COLUMN last_login TIMESTAMP NULL DEFAULT NULL";

if (mysqli_query($conn, $sql)) {
    echo "Database updated successfully";
} else {
    echo "Error updating database: " . mysqli_error($conn);
}
?> 