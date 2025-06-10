<?php
require_once 'config.php';
require_once 'logs.php';

class SecurityPolicy {
    private $conn;
    private $logger;

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