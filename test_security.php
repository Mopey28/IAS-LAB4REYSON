<?php
require_once 'config.php';
require_once 'security_policy.php';
require_once 'security_report.php';
require_once 'incident_response.php';

// Initialize classes
$security_policy = new SecurityPolicy();
$security_report = new SecurityReport($conn);
$incident_response = new IncidentResponse($conn);

// Test Security Policies
echo "<h2>Security Policies Test</h2>";
echo "<h3>Password Policy Test</h3>";
$test_password = "Test123!@#";
if ($security_policy->enforcePasswordPolicy($test_password)) {
    echo "✅ Password meets policy requirements<br>";
} else {
    echo "❌ Password does not meet policy requirements<br>";
}

// Test Access Control
echo "<h3>Access Control Test</h3>";
$user_role = "admin";
$required_permission = "manage_users";
if ($security_policy->checkAccessControl($user_role, $required_permission)) {
    echo "✅ User has required permission<br>";
} else {
    echo "❌ User does not have required permission<br>";
}

// Test Security Report
echo "<h2>Security Report Test</h2>";
$report = $security_report->generateComplianceReport();
echo "<pre>";
print_r($report);
echo "</pre>";

// Test Incident Response
echo "<h2>Incident Response Test</h2>";
$incident_details = [
    'type' => 'unauthorized_access',
    'ip_address' => '192.168.1.100',
    'user_id' => 1,
    'details' => 'Multiple failed login attempts'
];

$response = $incident_response->handleIncident('unauthorized_access', $incident_details);
echo "<pre>";
print_r($response);
echo "</pre>";

// Test Security Logging
echo "<h2>Security Logging Test</h2>";
$security_policy->logSecurityEvent('TEST_EVENT', [
    'user_id' => 1,
    'action' => 'test_action',
    'details' => 'Testing security logging'
]);
echo "✅ Security event logged<br>";

// Display Security Policy Details
echo "<h2>Security Policy Details</h2>";
echo "<h3>Password Policy</h3>";
echo "<pre>";
print_r(SecurityPolicy::PASSWORD_POLICY);
echo "</pre>";

echo "<h3>Network Policy</h3>";
echo "<pre>";
print_r(SecurityPolicy::NETWORK_POLICY);
echo "</pre>";

echo "<h3>Data Protection Policy</h3>";
echo "<pre>";
print_r(SecurityPolicy::DATA_PROTECTION);
echo "</pre>";

echo "<h3>RBAC Roles</h3>";
echo "<pre>";
print_r(SecurityPolicy::RBAC_ROLES);
echo "</pre>";

echo "<h3>Compliance Requirements</h3>";
echo "<pre>";
print_r(SecurityPolicy::COMPLIANCE);
echo "</pre>";

echo "<h3>Incident Response Steps</h3>";
echo "<pre>";
print_r(SecurityPolicy::INCIDENT_RESPONSE);
echo "</pre>";
?> 