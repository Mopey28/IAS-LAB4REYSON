<?php
session_start();
require_once 'config.php';
require_once 'logs.php';

// Helper to get policy
function get_policy($type, $key, $default) {
    global $conn;
    $sql = "SELECT policy_value FROM security_policies WHERE policy_type=? AND policy_key=?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, 'ss', $type, $key);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($result);
    return $row ? $row['policy_value'] : $default;
}
$defaults = [
    'min_length' => 12,
    'require_uppercase' => 1,
    'require_lowercase' => 1,
    'require_numbers' => 1,
    'require_special_chars' => 1
];
$min_length = get_policy('password', 'min_length', $defaults['min_length']);
$require_uppercase = get_policy('password', 'require_uppercase', $defaults['require_uppercase']);
$require_lowercase = get_policy('password', 'require_lowercase', $defaults['require_lowercase']);
$require_numbers = get_policy('password', 'require_numbers', $defaults['require_numbers']);
$require_special_chars = get_policy('password', 'require_special_chars', $defaults['require_special_chars']);

if (isset($_SESSION['user_id'])) {
    header('Location: main_panel.php');
    exit();
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Email validation
    if (empty($email)) {
        $error = 'Email is required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Invalid email format';
    }
    // Password policy checks
    elseif (strlen($password) < $min_length) {
        $error = 'Password must be at least ' . $min_length . ' characters.';
    } elseif ($require_uppercase && !preg_match('/[A-Z]/', $password)) {
        $error = 'Password must contain at least one uppercase letter.';
    } elseif ($require_lowercase && !preg_match('/[a-z]/', $password)) {
        $error = 'Password must contain at least one lowercase letter.';
    } elseif ($require_numbers && !preg_match('/[0-9]/', $password)) {
        $error = 'Password must contain at least one number.';
    } elseif ($require_special_chars && !preg_match('/[^A-Za-z0-9]/', $password)) {
        $error = 'Password must contain at least one special character.';
    } elseif (empty($username) || empty($password) || empty($confirm_password)) {
        $error = 'All fields are required';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match';
    } else {
        // Check if username or email already exists
        $sql = "SELECT id FROM users WHERE username = ? OR email = ?";
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, "ss", $username, $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        if (mysqli_num_rows($result) > 0) {
            $error = 'Username or email already exists';
        } else {
            // Create new user
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $sql = "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')";
            $stmt = mysqli_prepare($conn, $sql);
            mysqli_stmt_bind_param($stmt, "sss", $username, $email, $hashed_password);

            if (mysqli_stmt_execute($stmt)) {
                $success = 'Registration successful! You can now login.';
            } else {
                $error = 'Registration failed. Please try again.';
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GROW A GARDEN - Register</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .policy-box {
            background: #fffbe6;
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 18px;
            color: #a86c1e;
            font-size: 1em;
        }
        .policy-box ul {
            margin: 0 0 0 18px;
            padding: 0;
        }
        .policy-item {
            transition: color 0.2s;
        }
        .policy-met {
            color: #27ae60 !important;
            font-weight: bold;
        }
        .policy-status {
            font-weight: bold;
            margin-left: 8px;
        }
    </style>
</head>
<body>
    <div class="farm-bg"></div>
    <div class="login-container">
        <div class="logo">G<span>R</span>OW <span>A GARDEN</span></div>
        <div class="login-title">Register</div>
        <?php if ($error): ?>
            <div style="color: red; margin-bottom: 10px;"><?php echo $error; ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div style="color: green; margin-bottom: 10px;"><?php echo $success; ?></div>
        <?php endif; ?>
        <div class="policy-box">
            <b>Password Policy:</b>
            <ul>
                <li id="policy-length" class="policy-item">Min Length: <?php echo htmlspecialchars($min_length); ?> <span class="policy-status" id="status-length">No</span></li>
                <li id="policy-upper" class="policy-item">Require Uppercase: <?php echo $require_uppercase ? '' : 'Not Required'; ?> <span class="policy-status" id="status-upper"><?php echo $require_uppercase ? 'No' : 'Yes'; ?></span></li>
                <li id="policy-lower" class="policy-item">Require Lowercase: <?php echo $require_lowercase ? '' : 'Not Required'; ?> <span class="policy-status" id="status-lower"><?php echo $require_lowercase ? 'No' : 'Yes'; ?></span></li>
                <li id="policy-number" class="policy-item">Require Numbers: <?php echo $require_numbers ? '' : 'Not Required'; ?> <span class="policy-status" id="status-number"><?php echo $require_numbers ? 'No' : 'Yes'; ?></span></li>
                <li id="policy-special" class="policy-item">Require Special Characters: <?php echo $require_special_chars ? '' : 'Not Required'; ?> <span class="policy-status" id="status-special"><?php echo $require_special_chars ? 'No' : 'Yes'; ?></span></li>
            </ul>
        </div>
        <form method="POST" action="">
            <div class="input-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="input-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required oninput="checkPolicy()">
            </div>
            <div class="input-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <button class="login-btn" type="submit">Register</button>
        </form>
        <a class="register-link" href="index.php">Already have an account? Login here</a>
    </div>
    <div class="bottom-icons">
        <img src="https://img.icons8.com/color/48/000000/home--v2.png" alt="Home" title="Home">
        <img src="https://img.icons8.com/color/48/000000/medium-volume.png" alt="Sound" title="Sound">
        <img src="https://img.icons8.com/color/48/000000/settings--v2.png" alt="Settings" title="Settings">
    </div>
    <script>
    function checkPolicy() {
        var pwd = document.getElementById('password').value;
        var minLength = <?php echo (int)$min_length; ?>;
        var requireUpper = <?php echo (int)$require_uppercase; ?>;
        var requireLower = <?php echo (int)$require_lowercase; ?>;
        var requireNumber = <?php echo (int)$require_numbers; ?>;
        var requireSpecial = <?php echo (int)$require_special_chars; ?>;

        // Length
        var metLength = pwd.length >= minLength;
        document.getElementById('policy-length').classList.toggle('policy-met', metLength);
        document.getElementById('status-length').textContent = metLength ? 'Yes' : 'No';
        // Uppercase
        var metUpper = requireUpper ? /[A-Z]/.test(pwd) : true;
        document.getElementById('policy-upper').classList.toggle('policy-met', metUpper);
        document.getElementById('status-upper').textContent = metUpper ? 'Yes' : 'No';
        // Lowercase
        var metLower = requireLower ? /[a-z]/.test(pwd) : true;
        document.getElementById('policy-lower').classList.toggle('policy-met', metLower);
        document.getElementById('status-lower').textContent = metLower ? 'Yes' : 'No';
        // Number
        var metNumber = requireNumber ? /[0-9]/.test(pwd) : true;
        document.getElementById('policy-number').classList.toggle('policy-met', metNumber);
        document.getElementById('status-number').textContent = metNumber ? 'Yes' : 'No';
        // Special char
        var metSpecial = requireSpecial ? /[^A-Za-z0-9]/.test(pwd) : true;
        document.getElementById('policy-special').classList.toggle('policy-met', metSpecial);
        document.getElementById('status-special').textContent = metSpecial ? 'Yes' : 'No';
    }
    </script>
</body>
</html> 