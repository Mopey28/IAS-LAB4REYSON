<?php
session_start();
require_once 'logs.php';

// Log the logout
$logger = new SecurityLogger();
if (isset($_SESSION['username'])) {
    $logger->logAccess($_SESSION['username'], 'LOGOUT', 'success');
}

// Destroy the session
session_destroy();

// Redirect to login page
header('Location: index.php');
exit();
?> 