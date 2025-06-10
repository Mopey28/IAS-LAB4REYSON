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
?> 