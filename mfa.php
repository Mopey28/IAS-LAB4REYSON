<?php
require_once 'vendor/autoload.php'; // Assuming you have installed Google Authenticator library via Composer

use PHPGangsta\GoogleAuthenticator\GoogleAuthenticator;

function setupMFA($user) {
    $ga = new GoogleAuthenticator();
    $secret = $ga->createSecret();
    // Store $secret in the database for the user
    return $secret;
}

function verifyMFA($user, $code) {
    $ga = new GoogleAuthenticator();
    // Retrieve $secret from the database for the user
    $secret = 'user_secret_from_db';
    return $ga->verifyCode($secret, $code, 2);
}
?> 