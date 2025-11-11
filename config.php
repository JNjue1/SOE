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

// Get current user
function getCurrentUser() {
    return $_SESSION['current_user'] ?? null;
}
?>