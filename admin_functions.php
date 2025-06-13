<?php
require_once 'config.php';
require_once 'logs.php';

/**
 * Get detailed user statistics
 * @return array Statistics about users
 */
function getUserStatistics() {
    global $conn;
    $stats = [];
    
    // Total users
    $sql = "SELECT COUNT(*) as total FROM users";
    $result = mysqli_query($conn, $sql);
    $stats['total_users'] = mysqli_fetch_assoc($result)['total'];
    
    // Active users (logged in last 30 days)
    $sql = "SELECT COUNT(DISTINCT user_id) as active FROM access_logs 
            WHERE action = 'LOGIN' AND status = 'success' 
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
    $result = mysqli_query($conn, $sql);
    $stats['active_users'] = mysqli_fetch_assoc($result)['active'];
    
    // Users with MFA enabled
    $sql = "SELECT COUNT(*) as mfa_enabled FROM users WHERE mfa_secret IS NOT NULL";
    $result = mysqli_query($conn, $sql);
    $stats['mfa_enabled'] = mysqli_fetch_assoc($result)['mfa_enabled'];
    
    return $stats;
}

/**
 * Get recent security events
 * @param int $limit Number of events to return
 * @return array Recent security events
 */
function getRecentSecurityEvents($limit = 10) {
    global $conn;
    $sql = "SELECT al.*, u.username 
            FROM access_logs al 
            LEFT JOIN users u ON al.user_id = u.id 
            WHERE al.action IN ('LOGIN', 'MFA_VERIFY', 'PASSWORD_CHANGE', 'MFA_SETUP')
            ORDER BY al.timestamp DESC LIMIT ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "i", $limit);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return mysqli_fetch_all($result, MYSQLI_ASSOC);
}

/**
 * Get system health status
 * @return array System health information
 */
function getSystemHealth() {
    global $conn;
    $health = [];
    
    // Database connection status
    $health['database'] = mysqli_ping($conn) ? 'Connected' : 'Disconnected';
    
    // Failed login attempts in last hour
    $sql = "SELECT COUNT(*) as failed_attempts FROM access_logs 
            WHERE action = 'LOGIN' AND status = 'failed' 
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)";
    $result = mysqli_query($conn, $sql);
    $health['failed_logins'] = mysqli_fetch_assoc($result)['failed_attempts'];
    
    // System uptime
    $health['uptime'] = shell_exec('uptime');
    
    return $health;
}

/**
 * Get user activity summary
 * @param int $days Number of days to look back
 * @return array User activity data
 */
function getUserActivitySummary($days = 7) {
    global $conn;
    $sql = "SELECT 
                DATE(timestamp) as date,
                COUNT(DISTINCT user_id) as active_users,
                COUNT(*) as total_actions
            FROM access_logs 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL ? DAY)
            GROUP BY DATE(timestamp)
            ORDER BY date DESC";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "i", $days);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    return mysqli_fetch_all($result, MYSQLI_ASSOC);
}

/**
 * Get MFA statistics
 * @return array MFA usage statistics
 */
function getMFAStatistics() {
    global $conn;
    $stats = [];
    
    // Total users with MFA
    $sql = "SELECT COUNT(*) as total FROM users WHERE mfa_secret IS NOT NULL";
    $result = mysqli_query($conn, $sql);
    $stats['total_mfa_users'] = mysqli_fetch_assoc($result)['total'];
    
    // MFA verification success rate
    $sql = "SELECT 
                COUNT(CASE WHEN status = 'success' THEN 1 END) as success,
                COUNT(*) as total
            FROM access_logs 
            WHERE action = 'MFA_VERIFY' 
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_assoc($result);
    $stats['mfa_success_rate'] = $row['total'] > 0 ? 
        round(($row['success'] / $row['total']) * 100, 2) : 0;
    
    return $stats;
}

/**
 * Get role-based statistics
 * @return array Role-based statistics
 */
function getRoleStatistics() {
    global $conn;
    $stats = [];
    
    // Get total users
    $sql = "SELECT COUNT(*) as total FROM users";
    $result = mysqli_query($conn, $sql);
    $stats['total_users'] = mysqli_fetch_assoc($result)['total'];
    
    // Check if role column exists in access_logs
    $columnExists = mysqli_query($conn, "SHOW COLUMNS FROM access_logs LIKE 'role'");
    if (mysqli_num_rows($columnExists) == 0) {
        // Add role column if it doesn't exist
        mysqli_query($conn, "ALTER TABLE access_logs ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'guest' AFTER user_id");
        
        // Update existing records with roles from users table
        mysqli_query($conn, "UPDATE access_logs al 
            LEFT JOIN users u ON al.user_id = u.username 
            SET al.role = COALESCE(u.role, 'guest') 
            WHERE al.role = 'guest'");
    }
    
    // Get active roles (roles with activity in last 30 days)
    $sql = "SELECT COUNT(DISTINCT role) as active_roles 
            FROM access_logs 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
    $result = mysqli_query($conn, $sql);
    $stats['active_roles'] = mysqli_fetch_assoc($result)['active_roles'];
    
    // Get MFA enabled users
    $sql = "SELECT COUNT(*) as mfa_enabled 
            FROM users 
            WHERE mfa_secret IS NOT NULL AND mfa_secret != ''";
    $result = mysqli_query($conn, $sql);
    $stats['mfa_enabled'] = mysqli_fetch_assoc($result)['mfa_enabled'];
    
    return $stats;
}

// Function to get role-based activity summary
function getRoleActivitySummary($days = 7) {
    global $conn;
    $activity = [];
    $sql = "SELECT 
                u.role,
                DATE(l.created_at) as date,
                COUNT(DISTINCT l.user_id) as active_users,
                COUNT(*) as total_actions
            FROM security_logs l
            LEFT JOIN users u ON l.user_id = u.id
            WHERE l.created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
            GROUP BY u.role, DATE(l.created_at)
            ORDER BY date DESC, u.role";
    
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "i", $days);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    while ($row = mysqli_fetch_assoc($result)) {
        $activity[] = $row;
    }
    return $activity;
}
?> 