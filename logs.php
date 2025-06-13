<?php
require_once 'config.php';

class SecurityLogger {
    private $conn;
    private $logFile;
    private $alertThresholds = [
        'failed_logins' => 3,
        'mfa_failures' => 3,
        'file_access_denied' => 10,
        'suspicious_ips' => 3
    ];

    public function __construct($logFile = 'security_log.txt') {
        global $conn;
        $this->conn = $conn;
        $this->logFile = $logFile;
        $this->initializeLogTables();
    }

    private function initializeLogTables() {
        // Check if access_logs table exists
        $tableExists = mysqli_query($this->conn, "SHOW TABLES LIKE 'access_logs'");
        
        if (mysqli_num_rows($tableExists) == 0) {
            // Create new table with all columns
            $sql = "CREATE TABLE access_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(50) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'guest',
                action VARCHAR(50) NOT NULL,
                status VARCHAR(20) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                user_agent VARCHAR(255),
                timestamp DATETIME NOT NULL,
                details TEXT
            )";
            mysqli_query($this->conn, $sql);
        } else {
            // Check if role column exists
            $columnExists = mysqli_query($this->conn, "SHOW COLUMNS FROM access_logs LIKE 'role'");
            if (mysqli_num_rows($columnExists) == 0) {
                // Add role column with default value
                mysqli_query($this->conn, "ALTER TABLE access_logs ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'guest' AFTER user_id");
                
                // Update existing records to have a role
                mysqli_query($this->conn, "UPDATE access_logs al 
                    LEFT JOIN users u ON al.user_id = u.username 
                    SET al.role = COALESCE(u.role, 'guest') 
                    WHERE al.role = 'guest'");
            }
            
            // Check if user_agent column exists
            $columnExists = mysqli_query($this->conn, "SHOW COLUMNS FROM access_logs LIKE 'user_agent'");
            if (mysqli_num_rows($columnExists) == 0) {
                // Add user_agent column
                mysqli_query($this->conn, "ALTER TABLE access_logs ADD COLUMN user_agent VARCHAR(255) AFTER ip_address");
            }
            
            // Check if details column exists
            $detailsExists = mysqli_query($this->conn, "SHOW COLUMNS FROM access_logs LIKE 'details'");
            if (mysqli_num_rows($detailsExists) == 0) {
                // Add details column
                mysqli_query($this->conn, "ALTER TABLE access_logs ADD COLUMN details TEXT AFTER timestamp");
            }
        }

        // Security alerts table
        $sql = "CREATE TABLE IF NOT EXISTS security_alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            alert_type VARCHAR(50) NOT NULL,
            severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
            description TEXT NOT NULL,
            ip_address VARCHAR(45),
            user_id VARCHAR(50),
            timestamp DATETIME NOT NULL,
            status ENUM('new', 'investigating', 'resolved') NOT NULL DEFAULT 'new'
        )";
        mysqli_query($this->conn, $sql);
    }

    public function logAccess($username, $action, $status, $details = null, $role = null) {
        // If role is not provided, try to get it from the users table
        if ($role === null) {
            $sql = "SELECT role FROM users WHERE username = ?";
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "s", $username);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $user = mysqli_fetch_assoc($result);
            $role = $user ? $user['role'] : 'unknown';
        }

        $sql = "INSERT INTO access_logs (user_id, action, status, details, role, ip_address, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, NOW())";
        $stmt = mysqli_prepare($this->conn, $sql);
    $ip = $_SERVER['REMOTE_ADDR'];
        mysqli_stmt_bind_param($stmt, "ssssss", $username, $action, $status, $details, $role, $ip);
    mysqli_stmt_execute($stmt);

        // Check for security threats
        $this->checkSecurityThreats($username, $action, $status, $ip);
    }

    private function checkSecurityThreats($user, $action, $status, $ip) {
        // Check for multiple failed logins by role
        if ($action === 'LOGIN' && $status === 'failed') {
            $this->checkFailedLoginsByRole($ip);
        }

        // Check for MFA failures
        if ($action === 'MFA_VERIFICATION' && $status === 'failed') {
            $this->checkMFAFailures($user);
        }

        // Check for suspicious IP patterns
        $this->checkSuspiciousIPs($ip);

        // Check for file access violations
        if ($action === 'FILE_ACCESS' && $status === 'denied') {
            $this->checkFileAccessViolations($ip);
        }
    }

    private function checkFailedLoginsByRole($ip) {
        $sql = "SELECT role, COUNT(*) as failed_count 
            FROM access_logs 
                WHERE ip_address = ? 
                AND action = 'LOGIN' 
                AND status = 'failed' 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
                GROUP BY role";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $ip);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
    
        while ($row = mysqli_fetch_assoc($result)) {
        if ($row['failed_count'] >= $this->alertThresholds['failed_logins']) {
            $this->createSecurityAlert(
                'multiple_failed_logins',
                'high',
                    "Multiple failed login attempts for role: {$row['role']} from IP: $ip",
                    $ip,
                    null,
                    $row['role']
            );
            $this->blockIP($ip);
            }
    }
    }

    private function checkMFAFailures($user) {
    $sql = "SELECT COUNT(*) as failed_count 
            FROM access_logs 
                WHERE user_id = ? 
                AND action = 'MFA_VERIFICATION' 
                AND status = 'failed' 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 15 MINUTE)";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $user);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);

        if ($row['failed_count'] >= $this->alertThresholds['mfa_failures']) {
            $this->createSecurityAlert(
                'mfa_failures',
                'high',
                "Multiple MFA failures for user: $user",
                null,
                $user
            );
            $this->lockUserAccount($user);
        }
    }

    private function checkSuspiciousIPs($ip) {
        $sql = "SELECT COUNT(DISTINCT user_id) as user_count 
            FROM access_logs 
                WHERE ip_address = ? 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $ip);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);

        if ($row['user_count'] >= $this->alertThresholds['suspicious_ips']) {
            $this->createSecurityAlert(
                'suspicious_ip',
                'medium',
                "Suspicious activity from IP: $ip - Multiple user attempts",
                $ip
            );
        }
    }

    public function blockIP($ip) {
        // Implement IP blocking logic
        // Example: Add to .htaccess or firewall rules
        $blockRule = "Deny from $ip\n";
        file_put_contents('.htaccess', $blockRule, FILE_APPEND);
    }

    public function lockUserAccount($userId) {
        // Implement account locking logic
        $sql = "UPDATE users SET account_locked = 1 WHERE id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "s", $userId);
        mysqli_stmt_execute($stmt);
    }

    public function createSecurityAlert($type, $severity, $description, $ip = null, $userId = null) {
        $sql = "INSERT INTO security_alerts (alert_type, severity, description, ip_address, user_id, timestamp) 
                VALUES (?, ?, ?, ?, ?, NOW())";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "sssss", $type, $severity, $description, $ip, $userId);
        mysqli_stmt_execute($stmt);

        // Send alert to admin (implement your preferred notification method)
        $this->notifyAdmin($type, $severity, $description);
    }

    private function notifyAdmin($type, $severity, $description) {
        // Implement your preferred notification method (email, SMS, etc.)
        // Example: Send email to admin
        $to = "admin@example.com";
        $subject = "Security Alert: $type";
        $message = "Severity: $severity\nDescription: $description";
        mail($to, $subject, $message);
    }

    public function generateSecurityReport($timeframe = '24h') {
        $report = [
            'failed_logins' => $this->getFailedLoginsCount($timeframe),
            'mfa_failures' => $this->getMFAFailuresCount($timeframe),
            'suspicious_ips' => $this->getSuspiciousIPsCount($timeframe),
            'security_alerts' => $this->getSecurityAlerts($timeframe),
            'file_access_violations' => $this->getFileAccessViolations($timeframe)
        ];
    return $report;
}

    private function getFailedLoginsCount($timeframe) {
        $sql = "SELECT COUNT(*) as count 
                FROM access_logs 
                WHERE action = 'LOGIN' 
                AND status = 'failed' 
                AND timestamp > DATE_SUB(NOW(), INTERVAL ? HOUR)";
        $stmt = mysqli_prepare($this->conn, $sql);
        $hours = $this->getHoursFromTimeframe($timeframe);
        mysqli_stmt_bind_param($stmt, "i", $hours);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $row = mysqli_fetch_assoc($result);
        return $row['count'];
    }

    private function getHoursFromTimeframe($timeframe) {
        switch ($timeframe) {
            case '24h': return 24;
            case '7d': return 168;
            case '30d': return 720;
            default: return 24;
        }
    }

    // Add other report generation methods as needed

    public function getRecentSecurityEvents($limit = 20) {
        $sql = "SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $limit);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        $events = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $events[] = $row;
        }
        return $events;
    }
}

// Usage example:
// $logger = new SecurityLogger();
// $logger->logAccess('user123', 'LOGIN', 'success');

function logAccess($user, $action, $status, $details = '') {
    $logger = new SecurityLogger();
    $logger->logAccess($user, $action, $status, $details);
}
?> 