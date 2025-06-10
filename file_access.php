<?php
require_once 'config.php';
require_once 'rbac.php';

class FileAccessControl {
    private $conn;
    private $basePath;

    public function __construct($basePath = 'uploads/') {
        $this->conn = $GLOBALS['conn'];
        $this->basePath = $basePath;
        $this->initializeFilePermissionsTable();
    }

    private function initializeFilePermissionsTable() {
        $sql = "CREATE TABLE IF NOT EXISTS file_permissions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            file_path VARCHAR(255) NOT NULL,
            owner_id INT NOT NULL,
            permissions VARCHAR(10) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_file (file_path)
        )";
        mysqli_query($this->conn, $sql);
    }

    public function setFilePermissions($filePath, $ownerId, $permissions = '644') {
        // Set database permissions
        $sql = "INSERT INTO file_permissions (file_path, owner_id, permissions) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE 
                owner_id = VALUES(owner_id), 
                permissions = VALUES(permissions)";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "sis", $filePath, $ownerId, $permissions);
        mysqli_stmt_execute($stmt);

        // Set actual file permissions
        $fullPath = $this->basePath . $filePath;
        if (file_exists($fullPath)) {
            chmod($fullPath, octdec($permissions));
            chown($fullPath, $ownerId);
        }
    }

    public function checkFileAccess($filePath, $userId, $requiredPermission = 'r') {
        // Check database permissions
        $sql = "SELECT * FROM file_permissions WHERE file_path = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $filePath);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $permission = mysqli_fetch_assoc($result);

        if (!$permission) {
            return false;
        }

        // Check if user is owner
        if ($permission['owner_id'] == $userId) {
            return true;
        }

        // Check specific permission
        $permissions = $permission['permissions'];
        switch ($requiredPermission) {
            case 'r':
                return ($permissions[1] == 'r' || $permissions[2] == 'r');
            case 'w':
                return ($permissions[1] == 'w' || $permissions[2] == 'w');
            case 'x':
                return ($permissions[1] == 'x' || $permissions[2] == 'x');
            default:
                return false;
        }
    }

    public function getFilePermissions($filePath) {
        $sql = "SELECT * FROM file_permissions WHERE file_path = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $filePath);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        return mysqli_fetch_assoc($result);
    }

    public function listUserFiles($userId) {
        $sql = "SELECT file_path, permissions FROM file_permissions WHERE owner_id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $userId);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        $files = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $files[] = $row;
        }
        return $files;
    }
}

// Usage example:
// $fileAccess = new FileAccessControl();
// $fileAccess->setFilePermissions('example.txt', 1, '644');
// if ($fileAccess->checkFileAccess('example.txt', 1, 'r')) {
//     // Allow read access
// }
?> 