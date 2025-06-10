<?php
require_once 'vendor/autoload.php';
require_once 'config.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

class JWTHandler {
    private static $key = "your-secret-key-here"; // In production, use a secure key from environment variables
    private static $algorithm = 'HS256';
    private static $tokenExpiry = 3600; // 1 hour

    public static function generateToken($userData) {
        $issuedAt = time();
        $expire = $issuedAt + self::$tokenExpiry;

        $payload = array(
            'iat' => $issuedAt,
            'exp' => $expire,
            'user_id' => $userData['id'],
            'username' => $userData['username'],
            'role' => $userData['role']
        );

        return JWT::encode($payload, self::$key, self::$algorithm);
    }

    public static function validateToken($token) {
        try {
            $decoded = JWT::decode($token, new Key(self::$key, self::$algorithm));
            return (array) $decoded;
        } catch (Exception $e) {
            return false;
        }
    }

    public static function refreshToken($token) {
        $decoded = self::validateToken($token);
        if ($decoded) {
            return self::generateToken([
                'id' => $decoded['user_id'],
                'username' => $decoded['username'],
                'role' => $decoded['role']
            ]);
        }
        return false;
    }
}
?> 