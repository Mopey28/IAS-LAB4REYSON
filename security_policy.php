<?php
require_once 'config.php';
require_once 'logs.php';

class SecurityPolicy {
    private $conn;
    private $logger;

    // Security Objectives
    const OBJECTIVES = [
        'confidentiality' => 'Protect sensitive data from unauthorized access',
        'integrity' => 'Ensure data accuracy and prevent unauthorized modifications',
        'availability' => 'Maintain system accessibility for authorized users',
        'compliance' => 'Adhere to GDPR, HIPAA, and other regulatory requirements'
    ];

    // Password Policy
    const PASSWORD_POLICY = [
        'min_length' => 12,
        'require_uppercase' => true,
        'require_lowercase' => true,
        'require_numbers' => true,
        'require_special_chars' => true
    ];

    // Session Security
    const SESSION_SECURITY = [
        'lifetime' => 7200, // 2 hours
        'regenerate_id' => true,
        'secure_cookie' => true,
        'httponly_cookie' => true
    ];

    // Access Control
    const ACCESS_CONTROL = [
        'max_login_attempts' => 5,
        'lockout_duration' => 900, // 15 minutes
        'require_mfa' => true
    ];

    // File Security
    const FILE_SECURITY = [
        'allowed_extensions' => ['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx'],
        'max_file_size' => 5242880, // 5MB
        'scan_uploads' => true
    ];

    // Network Security
    const NETWORK_SECURITY = [
        'require_ssl' => true,
        'allowed_ips' => [],
        'block_suspicious_ips' => true
    ];

    // Logging Policy
    const LOGGING_POLICY = [
        'log_level' => 'INFO',
        'retention_period' => 90, // days
        'log_events' => [
            'login_attempts',
            'password_changes',
            'file_access',
            'system_changes'
        ]
    ];

    // Data Protection Policy
    const DATA_PROTECTION = [
        'encryption_required' => true,
        'backup_frequency' => 'daily',
        'retention_period' => '7 years',
        'sensitive_data_types' => [
            'personal_info',
            'financial_data',
            'health_records',
            'credentials'
        ]
    ];

    // Role-Based Access Control (RBAC)
    const RBAC_ROLES = [
        'admin' => [
            'permissions' => ['read', 'write', 'delete', 'manage_users', 'view_logs'],
            'data_access' => 'all'
        ],
        'user' => [
            'permissions' => ['read', 'write'],
            'data_access' => 'own'
        ],
        'auditor' => [
            'permissions' => ['read', 'view_logs'],
            'data_access' => 'read_only'
        ]
    ];

    // Compliance Requirements
    const COMPLIANCE = [
        'gdpr' => [
            'data_minimization' => true,
            'right_to_forget' => true,
            'data_portability' => true
        ],
        'hipaa' => [
            'phi_protection' => true,
            'audit_logging' => true,
            'encryption_required' => true
        ]
    ];

    // Security Incident Response
    const INCIDENT_RESPONSE = [
        'detection' => [
            'monitoring_tools' => ['Splunk', 'OpenVAS'],
            'alert_thresholds' => [
                'failed_logins' => 5,
                'suspicious_activities' => 3
            ]
        ],
        'response_steps' => [
            'identify' => 'Detect and analyze the incident',
            'contain' => 'Isolate affected systems',
            'eradicate' => 'Remove the threat',
            'recover' => 'Restore normal operations',
            'learn' => 'Document and improve'
        ]
    ];

    public function __construct() {
        $this->conn = $GLOBALS['conn'];
        $this->logger = new SecurityLogger();
        $this->initializePolicyTables();
    }

    private function initializePolicyTables() {
        // Security policies table
        $sql = "CREATE TABLE IF NOT EXISTS security_policies (
            id INT AUTO_INCREMENT PRIMARY KEY,
            policy_name VARCHAR(100) NOT NULL,
            policy_type ENUM('access', 'authentication', 'file', 'network') NOT NULL,
            policy_rule TEXT NOT NULL,
            severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
            is_active BOOLEAN DEFAULT true,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )";
        mysqli_query($this->conn, $sql);

        // Policy violations table
        $sql = "CREATE TABLE IF NOT EXISTS policy_violations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            policy_id INT NOT NULL,
            user_id VARCHAR(50),
            ip_address VARCHAR(45),
            violation_details TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            status ENUM('new', 'investigating', 'resolved') NOT NULL DEFAULT 'new',
            FOREIGN KEY (policy_id) REFERENCES security_policies(id)
        )";
        mysqli_query($this->conn, $sql);
    }

    public function createPolicy($name, $type, $rule, $severity) {
        $sql = "INSERT INTO security_policies (policy_name, policy_type, policy_rule, severity) 
                VALUES (?, ?, ?, ?)";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "ssss", $name, $type, $rule, $severity);
        return mysqli_stmt_execute($stmt);
    }

    public function enforcePolicy($policyId, $context) {
        $policy = $this->getPolicy($policyId);
        if (!$policy || !$policy['is_active']) {
            return true; // Policy not found or inactive
        }

        $violation = $this->evaluatePolicy($policy, $context);
        if ($violation) {
            $this->logViolation($policyId, $context, $violation);
            $this->takeAction($policy, $violation, $context);
            return false;
        }

        return true;
    }

    private function evaluatePolicy($policy, $context) {
        switch ($policy['policy_type']) {
            case 'access':
                return $this->evaluateAccessPolicy($policy, $context);
            case 'authentication':
                return $this->evaluateAuthPolicy($policy, $context);
            case 'file':
                return $this->evaluateFilePolicy($policy, $context);
            case 'network':
                return $this->evaluateNetworkPolicy($policy, $context);
            default:
                return null;
        }
    }

    private function evaluateAccessPolicy($policy, $context) {
        // Example: Check if user has required role for resource access
        $rule = json_decode($policy['policy_rule'], true);
        if (!isset($context['user_role']) || !in_array($context['user_role'], $rule['allowed_roles'])) {
            return "User role {$context['user_role']} not authorized for this resource";
        }
        return null;
    }

    private function evaluateAuthPolicy($policy, $context) {
        // Example: Check password complexity and MFA requirements
        $rule = json_decode($policy['policy_rule'], true);
        if (isset($rule['require_mfa']) && $rule['require_mfa'] && !$context['mfa_enabled']) {
            return "MFA required but not enabled";
        }
        return null;
    }

    private function evaluateFilePolicy($policy, $context) {
        // Example: Check file access permissions
        $rule = json_decode($policy['policy_rule'], true);
        if (!isset($context['file_permissions']) || 
            !$this->checkFilePermissions($context['file_permissions'], $rule['required_permissions'])) {
            return "Insufficient file permissions";
        }
        return null;
    }

    private function evaluateNetworkPolicy($policy, $context) {
        // Example: Check IP restrictions and rate limiting
        $rule = json_decode($policy['policy_rule'], true);
        if (isset($rule['allowed_ips']) && !in_array($context['ip_address'], $rule['allowed_ips'])) {
            return "IP address not in allowed list";
        }
        return null;
    }

    private function logViolation($policyId, $context, $violation) {
        $sql = "INSERT INTO policy_violations (policy_id, user_id, ip_address, violation_details, timestamp) 
                VALUES (?, ?, ?, ?, NOW())";
        $stmt = mysqli_prepare($this->conn, $sql);
        $userId = $context['user_id'] ?? null;
        $ipAddress = $context['ip_address'] ?? null;
        mysqli_stmt_bind_param($stmt, "isss", $policyId, $userId, $ipAddress, $violation);
        mysqli_stmt_execute($stmt);

        // Log to security logger
        $this->logger->logAccess(
            $userId ?? 'SYSTEM',
            'POLICY_VIOLATION',
            'failed',
            "Policy violation: $violation"
        );
    }

    private function takeAction($policy, $violation, $context) {
        switch ($policy['severity']) {
            case 'critical':
                $this->handleCriticalViolation($context);
                break;
            case 'high':
                $this->handleHighViolation($context);
                break;
            case 'medium':
                $this->handleMediumViolation($context);
                break;
            case 'low':
                $this->handleLowViolation($context);
                break;
        }
    }

    private function handleCriticalViolation($context) {
        // Block IP, lock account, notify admin
        if (isset($context['ip_address'])) {
            $this->logger->blockIP($context['ip_address']);
            $this->logger->createSecurityAlert(
                'ip_blocked',
                'critical',
                "IP address {$context['ip_address']} has been blocked due to policy violation",
                $context['ip_address']
            );
        }
        if (isset($context['user_id'])) {
            $this->logger->lockUserAccount($context['user_id']);
            $this->logger->createSecurityAlert(
                'account_locked',
                'critical',
                "User account {$context['user_id']} has been locked due to policy violation",
                null,
                $context['user_id']
            );
        }
    }

    private function handleHighViolation($context) {
        // Lock account, notify admin
        if (isset($context['user_id'])) {
            $this->logger->lockUserAccount($context['user_id']);
            $this->logger->createSecurityAlert(
                'account_locked',
                'high',
                "User account {$context['user_id']} has been locked due to policy violation",
                null,
                $context['user_id']
            );
        }
    }

    private function handleMediumViolation($context) {
        // Log violation, notify admin
        $this->logger->createSecurityAlert(
            'policy_violation',
            'medium',
            "Policy violation detected for user: {$context['user_id']}",
            $context['ip_address'] ?? null,
            $context['user_id'] ?? null
        );
    }

    private function handleLowViolation($context) {
        // Just log the violation
        $this->logger->logAccess(
            $context['user_id'] ?? 'SYSTEM',
            'POLICY_VIOLATION',
            'warning',
            "Low severity policy violation"
        );
    }

    public function getPolicy($policyId) {
        $sql = "SELECT * FROM security_policies WHERE id = ?";
        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, "i", $policyId);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        return mysqli_fetch_assoc($result);
    }

    public function listPolicies($type = null) {
        $sql = "SELECT * FROM security_policies";
        if ($type) {
            $sql .= " WHERE policy_type = ?";
        }
        $stmt = mysqli_prepare($this->conn, $sql);
        if ($type) {
            mysqli_stmt_bind_param($stmt, "s", $type);
        }
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        $policies = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $policies[] = $row;
        }
        return $policies;
    }

    public function updatePolicy($policyId, $updates) {
        $allowedFields = ['policy_name', 'policy_rule', 'severity', 'is_active'];
        $setClause = [];
        $types = '';
        $values = [];

        foreach ($updates as $field => $value) {
            if (in_array($field, $allowedFields)) {
                $setClause[] = "$field = ?";
                $types .= 's';
                $values[] = $value;
            }
        }

        if (empty($setClause)) {
            return false;
        }

        $sql = "UPDATE security_policies SET " . implode(', ', $setClause) . " WHERE id = ?";
        $types .= 'i';
        $values[] = $policyId;

        $stmt = mysqli_prepare($this->conn, $sql);
        mysqli_stmt_bind_param($stmt, $types, ...$values);
        return mysqli_stmt_execute($stmt);
    }

    // Policy Enforcement Methods
    public static function enforcePasswordPolicy($password) {
        if (strlen($password) < self::PASSWORD_POLICY['min_length']) {
            return false;
        }
        if (self::PASSWORD_POLICY['require_uppercase'] && !preg_match('/[A-Z]/', $password)) {
            return false;
        }
        if (self::PASSWORD_POLICY['require_lowercase'] && !preg_match('/[a-z]/', $password)) {
            return false;
        }
        if (self::PASSWORD_POLICY['require_numbers'] && !preg_match('/[0-9]/', $password)) {
            return false;
        }
        if (self::PASSWORD_POLICY['require_special_chars'] && !preg_match('/[^A-Za-z0-9]/', $password)) {
            return false;
        }
        return true;
    }

    public static function checkAccessControl($user_role, $required_permission) {
        if (!isset(self::RBAC_ROLES[$user_role])) {
            return false;
        }
        return in_array($required_permission, self::RBAC_ROLES[$user_role]['permissions']);
    }

    public static function logSecurityEvent($event_type, $details) {
        $log_entry = date('Y-m-d H:i:s') . " | " . $event_type . " | " . json_encode($details) . "\n";
        file_put_contents('security_log.txt', $log_entry, FILE_APPEND);
    }
}

// Usage example:
// $policyManager = new SecurityPolicy();
// $policyManager->createPolicy(
//     'Require MFA for Admin Access',
//     'authentication',
//     json_encode(['require_mfa' => true]),
//     'high'
// );
?> 