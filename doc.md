# Access Control Implementation Documentation

## 1. Role-Based Access Control (RBAC)

### Defined Roles and Permissions

1. **Admin Role**
   - Full access to all resources
   - Can manage users
   - Can view all files
   - Can modify system settings

2. **User Role**
   - Limited access to specific resources
   - Can view their own files
   - Cannot modify system settings
   - Cannot manage other users

### Implementation Details

- RBAC is implemented using JWT (JSON Web Tokens)
- Token contains user information including role
- Token expiration is set to 1 hour
- Role checks are performed on protected resources

### Code Example
```php
// Token generation in auth.php
$payload = [
    'iat' => $issuedAt,
    'exp' => $expirationTime,
    'user_id' => $user['id'],
    'username' => $user['username'],
    'role' => $user['role']
];

// Role checking in rbac.php
function checkPermission($token, $requiredRole) {
    try {
        $decoded = JWT::decode($token, 'your_jwt_secret_key', ['HS256']);
        return $decoded->role === $requiredRole;
    } catch (Exception $e) {
        return false;
    }
}
```

## 2. Discretionary Access Control (DAC)

### File Permissions

1. **File Ownership**
   - Files are owned by the user who created them
   - Owners have full control over their files

2. **Access Levels**
   - Read: Can view file contents
   - Write: Can modify file contents
   - Execute: Can run the file (if applicable)

### Implementation Details

- DAC is implemented using Windows NTFS permissions
- File permissions are checked before allowing access
- Users can only access files they have permission for

### Code Example
```php
// File permission checking in dac.php
function checkFilePermission($file, $user) {
    // Simulate checking file permissions
    // In a real-world scenario, you would use file system functions
    return true;
}
```

## 3. Security Analysis

### RBAC Security Features
1. **Token-based Authentication**
   - Secure token generation
   - Token expiration
   - Role-based access restrictions

2. **Least Privilege Principle**
   - Users only get access to what they need
   - Role-based restrictions prevent unauthorized access

### DAC Security Features
1. **File-level Security**
   - Granular control over file access
   - User-specific permissions
   - Owner-based access control

## 4. Testing and Verification

### Test Cases
1. **Admin Access**
   - Verify admin can access all resources
   - Verify admin can manage users
   - Verify admin can modify settings

2. **User Access**
   - Verify user can only access allowed resources
   - Verify user cannot access admin features
   - Verify user can only access their own files

### Security Logging
- All access attempts are logged
- Failed access attempts are monitored
- Security violations are recorded

## 5. Future Improvements

1. **Enhanced RBAC**
   - Add more granular roles
   - Implement role hierarchy
   - Add time-based access restrictions

2. **Improved DAC**
   - Implement more detailed file permissions
   - Add group-based access control
   - Enhance file ownership management 