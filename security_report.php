<?php
session_start();
require_once 'config.php';
require_once 'logs.php';
require_once 'rbac.php';
require_once 'security_policy.php';

// Check if user is admin
if (!isset($_SESSION['user_id']) || !RBAC::checkPermission('view_security_reports')) {
    header('Location: index.php');
    exit();
}

$report = generateSecurityReport();

// Get detailed statistics
$sql = "SELECT 
    COUNT(CASE WHEN action = 'LOGIN' AND status = 'success' THEN 1 END) as successful_logins,
    COUNT(CASE WHEN action = 'LOGIN' AND status = 'failed' THEN 1 END) as failed_logins,
    COUNT(CASE WHEN action = 'MFA_VERIFICATION' AND status = 'success' THEN 1 END) as successful_mfa,
    COUNT(CASE WHEN action = 'MFA_VERIFICATION' AND status = 'failed' THEN 1 END) as failed_mfa
    FROM access_logs 
    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)";
$result = mysqli_query($conn, $sql);
$stats = mysqli_fetch_assoc($result);

// Get recent security events
$sql = "SELECT al.*, u.username 
        FROM access_logs al 
        LEFT JOIN users u ON al.user_id = u.id 
        WHERE al.action IN ('LOGIN', 'MFA_VERIFICATION', 'LOGOUT') 
        ORDER BY al.timestamp DESC LIMIT 20";
$result = mysqli_query($conn, $sql);
$recent_events = mysqli_fetch_all($result, MYSQLI_ASSOC);

// Get failed login attempts by IP
$sql = "SELECT ip_address, COUNT(*) as attempt_count 
        FROM access_logs 
        WHERE action = 'LOGIN' AND status = 'failed' 
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY ip_address 
        HAVING attempt_count > 3
        ORDER BY attempt_count DESC";
$result = mysqli_query($conn, $sql);
$suspicious_ips = mysqli_fetch_all($result, MYSQLI_ASSOC);

function logActivity($user, $activity, $status, $details = '') {
    $logger = new SecurityLogger();
    $logger->logActivity($user, $activity, $status, $details);
}

class SecurityReport {
    private $conn;
    private $security_policy;

    public function __construct($conn) {
        $this->conn = $conn;
        $this->security_policy = new SecurityPolicy();
    }

    public function generateComplianceReport() {
        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'compliance_status' => [],
            'policy_violations' => [],
            'recommendations' => []
        ];

        // Check GDPR Compliance
        $report['compliance_status']['gdpr'] = $this->checkGDPRCompliance();
        
        // Check HIPAA Compliance
        $report['compliance_status']['hipaa'] = $this->checkHIPAACompliance();
        
        // Check Password Policy Compliance
        $report['compliance_status']['password_policy'] = $this->checkPasswordPolicyCompliance();
        
        // Check Access Control Compliance
        $report['compliance_status']['access_control'] = $this->checkAccessControlCompliance();

        // Generate Recommendations
        $report['recommendations'] = $this->generateRecommendations($report['compliance_status']);

        return $report;
    }

    private function checkGDPRCompliance() {
        $status = [
            'data_minimization' => $this->checkDataMinimization(),
            'right_to_forget' => $this->checkRightToForget(),
            'data_portability' => $this->checkDataPortability()
        ];
        return $status;
    }

    private function checkHIPAACompliance() {
        $status = [
            'phi_protection' => $this->checkPHIProtection(),
            'audit_logging' => $this->checkAuditLogging(),
            'encryption' => $this->checkEncryption()
        ];
        return $status;
    }

    private function checkPasswordPolicyCompliance() {
        $violations = [];
        $query = "SELECT username, last_password_change FROM users";
        $result = mysqli_query($this->conn, $query);

        while ($row = mysqli_fetch_assoc($result)) {
            $days_since_change = (time() - strtotime($row['last_password_change'])) / (60 * 60 * 24);
            if ($days_since_change > SecurityPolicy::PASSWORD_POLICY['max_age_days']) {
                $violations[] = [
                    'username' => $row['username'],
                    'issue' => 'Password expired',
                    'days_overdue' => round($days_since_change - SecurityPolicy::PASSWORD_POLICY['max_age_days'])
                ];
            }
        }
        return $violations;
    }

    private function checkAccessControlCompliance() {
        $violations = [];
        $query = "SELECT user_id, role, last_access FROM user_access_logs";
        $result = mysqli_query($this->conn, $query);

        while ($row = mysqli_fetch_assoc($result)) {
            if (!isset(SecurityPolicy::RBAC_ROLES[$row['role']])) {
                $violations[] = [
                    'user_id' => $row['user_id'],
                    'issue' => 'Invalid role assignment',
                    'role' => $row['role']
                ];
            }
        }
        return $violations;
    }

    private function generateRecommendations($compliance_status) {
        $recommendations = [];

        // Password Policy Recommendations
        if (!empty($compliance_status['password_policy'])) {
            $recommendations[] = "Implement password expiration notifications";
            $recommendations[] = "Enforce password complexity requirements";
        }

        // Access Control Recommendations
        if (!empty($compliance_status['access_control'])) {
            $recommendations[] = "Review and update role assignments";
            $recommendations[] = "Implement regular access reviews";
        }

        // GDPR Recommendations
        if (!$compliance_status['gdpr']['data_minimization']) {
            $recommendations[] = "Implement data minimization practices";
        }

        // HIPAA Recommendations
        if (!$compliance_status['hipaa']['encryption']) {
            $recommendations[] = "Enable encryption for all PHI data";
        }

        return $recommendations;
    }

    public function exportReport($format = 'json') {
        $report = $this->generateComplianceReport();
        
        switch ($format) {
            case 'json':
                return json_encode($report, JSON_PRETTY_PRINT);
            case 'html':
                return $this->generateHTMLReport($report);
            default:
                return json_encode($report, JSON_PRETTY_PRINT);
        }
    }

    private function generateHTMLReport($report) {
        $html = "<html><head><title>Security Compliance Report</title></head><body>";
        $html .= "<h1>Security Compliance Report</h1>";
        $html .= "<p>Generated on: " . $report['timestamp'] . "</p>";
        
        // Compliance Status
        $html .= "<h2>Compliance Status</h2>";
        foreach ($report['compliance_status'] as $category => $status) {
            $html .= "<h3>" . ucfirst($category) . "</h3>";
            $html .= "<ul>";
            foreach ($status as $item => $value) {
                $html .= "<li>" . ucfirst($item) . ": " . ($value ? "Compliant" : "Non-compliant") . "</li>";
            }
            $html .= "</ul>";
        }

        // Recommendations
        $html .= "<h2>Recommendations</h2>";
        $html .= "<ul>";
        foreach ($report['recommendations'] as $recommendation) {
            $html .= "<li>" . $recommendation . "</li>";
        }
        $html .= "</ul>";

        $html .= "</body></html>";
        return $html;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - Security Report</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="farm-bg"></div>
    <div class="login-container" style="max-width:800px;">
        <div class="logo">G<span>R</span>OW <span>A GARDEN</span></div>
        <div class="login-title">Security Report</div>
        <div style="text-align:left;">
            <h2>24-Hour Security Overview</h2>
            <div>
                <div><b>Successful Logins:</b> <?php echo $stats['successful_logins']; ?></div>
                <div><b>Failed Logins:</b> <?php echo $stats['failed_logins']; ?></div>
                <div><b>Successful MFA:</b> <?php echo $stats['successful_mfa']; ?></div>
                <div><b>Failed MFA:</b> <?php echo $stats['failed_mfa']; ?></div>
            </div>
            <h2>Security Status</h2>
            <?php if (detectIntrusion()): ?>
                <div style="color:red;">Potential intrusion detected! Multiple failed login attempts.</div>
            <?php else: ?>
                <div style="color:green;">No intrusion detected. System is secure.</div>
            <?php endif; ?>
            <h2>Recent Security Events</h2>
            <button onclick="openModal()">View Security Events</button>
        </div>
        <div id="eventsModal" style="display:none;">
            <div>
                <h3>Recent Security Events</h3>
                <button onclick="closeModal()">&times;</button>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>Status</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recent_events as $event): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($event['timestamp']); ?></td>
                            <td><?php echo isset($event['username']) ? htmlspecialchars($event['username']) : 'N/A'; ?></td>
                            <td><?php echo htmlspecialchars($event['action']); ?></td>
                            <td><?php echo htmlspecialchars($event['status']); ?></td>
                            <td><?php echo htmlspecialchars($event['ip_address']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <div class="bottom-icons">
        <img src="https://img.icons8.com/color/48/000000/home--v2.png" alt="Home" title="Home">
        <img src="https://img.icons8.com/color/48/000000/medium-volume.png" alt="Sound" title="Sound">
        <img src="https://img.icons8.com/color/48/000000/settings--v2.png" alt="Settings" title="Settings">
    </div>
    <script>
        function openModal() {
            document.getElementById('eventsModal').style.display = 'block';
        }
        function closeModal() {
            document.getElementById('eventsModal').style.display = 'none';
        }
    </script>
</body>
</html> 