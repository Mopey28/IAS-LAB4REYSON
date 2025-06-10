<?php
require_once 'jwt_handler.php';

class RBAC {
    private static $permissions = [
        'admin' => [
            'view_dashboard' => true,
            'manage_users' => true,
            'view_logs' => true,
            'manage_mfa' => true,
            'view_security_reports' => true,
            'manage_file_permissions' => true,
            'manage_roles' => true,
            'view_system_health' => true
        ],
        'user' => [
            'view_dashboard' => true,
            'manage_mfa' => true,
            'view_profile' => true,
            'edit_profile' => true
        ],
        'guest' => [
            'view_public_content' => true
        ]
    ];

    public static function checkPermission($requiredPermission) {
        if (!isset($_SESSION['role']) || !isset($_SESSION['jwt_token'])) {
            return false;
        }

        // Validate JWT token
        $tokenData = JWTHandler::validateToken($_SESSION['jwt_token']);
        if (!$tokenData) {
            return false;
        }

        $role = $_SESSION['role'];
        
        // Check if role exists and has the required permission
        return isset(self::$permissions[$role]) && 
               isset(self::$permissions[$role][$requiredPermission]) && 
               self::$permissions[$role][$requiredPermission] === true;
    }

    public static function getRolePermissions($role) {
        return isset(self::$permissions[$role]) ? self::$permissions[$role] : [];
    }

    public static function addPermission($role, $permission) {
        if (!isset(self::$permissions[$role])) {
            self::$permissions[$role] = [];
        }
        self::$permissions[$role][$permission] = true;
    }

    public static function removePermission($role, $permission) {
        if (isset(self::$permissions[$role][$permission])) {
            unset(self::$permissions[$role][$permission]);
        }
    }
}

// Middleware function to check permissions
function requirePermission($permission) {
    if (!RBAC::checkPermission($permission)) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Permission denied']);
        exit();
    }
}
?> 