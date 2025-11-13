<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'gameswap');
define('DB_USER', 'root');
define('DB_PASS', 'root');

// Application configuration
define('APP_NAME', 'GameSwap');
define('BASE_URL', 'http://localhost/SOE');

// Session configuration
session_start();

// Database connection function
function getDBConnection() {
    try {
        $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch(PDOException $e) {
        die("Connection failed: " . $e->getMessage());
    }
}

// Password hashing functions
function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['current_user']);
}

// Redirect if not logged in
function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: index.php');
        exit();
    }
}

// Get current user - UPDATED to check DB for fresh status and enforce suspension
function getCurrentUser() {
    if (!isset($_SESSION['current_user']) || !isset($_SESSION['current_user']['user_id'])) {
        return null;
    }
    
    $pdo = getDBConnection();
    $userId = $_SESSION['current_user']['user_id'];
    
    // 1. Fetch fresh user data from DB
    $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        // User not found, log out for safety
        session_destroy();
        header('Location: index.php');
        exit();
    }
    
    // 2. Suspension Logic: Check complaints >= 3 and suspend if necessary
    if ((int)$user['complaints'] >= 3 && (int)$user['is_suspended'] === 0) {
        $user['is_suspended'] = 1;
        
        // Update DB to suspend account
        $stmt = $pdo->prepare("UPDATE users SET is_suspended = 1 WHERE user_id = ?");
        $stmt->execute([$userId]);
    }
    
    // 3. Update active role logic
    if (isset($user['role']) && $user['role'] === 'admin') {
        if (!isset($_SESSION['active_role'])) {
            $_SESSION['active_role'] = 'admin';
        }
    } else {
        $_SESSION['active_role'] = 'user';
    }
    
    // 4. Update session and return current user data
    $user['active_role'] = $_SESSION['active_role'];
    $_SESSION['current_user'] = $user; 
    
    return $user;
}
?>