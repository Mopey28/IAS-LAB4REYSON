-- Security Policies Table
CREATE TABLE IF NOT EXISTS security_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_type VARCHAR(50) NOT NULL,
    policy_key VARCHAR(50) NOT NULL,
    policy_value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_policy (policy_type, policy_key)
);

-- Security Logs Table
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(50) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Access Logs Table
CREATE TABLE IF NOT EXISTS access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    page VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- System Status Table
CREATE TABLE IF NOT EXISTS systems (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    last_scan DATETIME,
    vulnerabilities JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- User Access Logs Table
CREATE TABLE IF NOT EXISTS user_access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    role VARCHAR(20) NOT NULL,
    last_access DATETIME NOT NULL,
    ip_address VARCHAR(45),
    status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Security Policy Compliance Table
CREATE TABLE IF NOT EXISTS policy_compliance (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    last_check DATETIME NOT NULL,
    violations JSON,
    recommendations JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Add necessary columns to existing users table
ALTER TABLE users
ADD COLUMN IF NOT EXISTS email VARCHAR(100) AFTER username,
ADD COLUMN IF NOT EXISTS last_password_change DATETIME,
ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS account_locked_until DATETIME,
ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(32);

-- Create indexes for better performance
CREATE INDEX idx_security_logs_user ON security_logs(user_id);
CREATE INDEX idx_security_logs_action ON security_logs(action);
CREATE INDEX idx_security_logs_created ON security_logs(created_at);

CREATE INDEX idx_access_logs_user ON access_logs(user_id);
CREATE INDEX idx_access_logs_page ON access_logs(page);
CREATE INDEX idx_access_logs_created ON access_logs(created_at);

CREATE INDEX idx_user_access_logs_user_id ON user_access_logs(user_id);
CREATE INDEX idx_user_access_logs_role ON user_access_logs(role);
CREATE INDEX idx_policy_compliance_type ON policy_compliance(policy_type);
CREATE INDEX idx_policy_compliance_status ON policy_compliance(status); 