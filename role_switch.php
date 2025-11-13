<?php
require_once 'config.php';
requireLogin();

$currentUser = getCurrentUser();

// Only allow permanent admins to use this script
if (isset($currentUser['role']) && $currentUser['role'] === 'admin') {
    $currentActiveRole = $_SESSION['active_role'] ?? 'admin';
    
    if ($currentActiveRole === 'admin') {
        // Switch from Admin View to User View
        $_SESSION['active_role'] = 'user';
        $redirectPage = 'dashboard.php';
    } else {
        // Switch from User View to Admin View
        $_SESSION['active_role'] = 'admin';
        $redirectPage = 'admin.php';
    }
    
    header('Location: ' . $redirectPage);
    exit();
} else {
    // If a non-admin tries to access this, redirect them home
    header('Location: dashboard.php');
    exit();
}
?>