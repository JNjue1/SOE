<?php
require_once 'config.php';
requireLogin();

// --- Admin Authorization Logic ---
// Ensure only permanent admins can access export data
function requireAdmin() {
    $user = getCurrentUser();
    if (!$user || $user['role'] !== 'admin') { 
        // Redirect to user dashboard if not admin, preventing data export
        header('Location: dashboard.php');
        exit();
    }
}
requireAdmin();
$pdo = getDBConnection();

$exportType = $_GET['type'] ?? '';

// Define allowed tables, their respective SQL queries (without the ORDER BY limit), and column headers
$exports = [
    'users' => [
        'query' => "SELECT user_id, username, email, first_name, last_name, location, complaints, is_suspended, role, created_at FROM users",
        'headers' => ['ID', 'Username', 'Email', 'First Name', 'Last Name', 'Location', 'Complaints', 'Is Suspended', 'Role', 'Created At'],
        'filename' => 'users_report'
    ],
    'games' => [
        'query' => "SELECT g.game_id, g.title, u.username as owner_username, g.genre, g.game_type, g.condition, g.status, g.created_at FROM games g JOIN users u ON g.user_id = u.user_id",
        'headers' => ['Game ID', 'Title', 'Owner Username', 'Genre', 'Type', 'Condition', 'Status', 'Created At'],
        'filename' => 'games_report'
    ],
    'transactions' => [
        'query' => "SELECT t.transaction_id, t.type, u1.username as from_user, u2.username as to_user, g.title as game_title, t.status, t.created_at FROM transactions t LEFT JOIN games g ON t.game_id = g.game_id LEFT JOIN users u1 ON t.from_user_id = u1.user_id LEFT JOIN users u2 ON t.to_user_id = u2.user_id",
        'headers' => ['Transaction ID', 'Type', 'From User', 'To User', 'Game Title', 'Status', 'Date'],
        'filename' => 'transactions_report'
    ]
];

if (!isset($exports[$exportType])) {
    die("Invalid report type.");
}

$export = $exports[$exportType];
$filename = $export['filename'] . '_' . date('Ymd_His') . '.csv';

// --- Set CSV Headers for Download ---
header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Pragma: no-cache');
header('Expires: 0');

$output = fopen('php://output', 'w');

// Write column headers
fputcsv($output, $export['headers']);

try {
    $stmt = $pdo->query($export['query']);
    
    // Write data rows
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        // Clean up data for readability before outputting
        if (isset($row['is_suspended'])) {
            $row['is_suspended'] = ((int)$row['is_suspended'] === 1) ? 'Yes' : 'No';
        }
        if (isset($row['game_type'])) {
            $row['game_type'] = ucwords(str_replace('_', ' ', $row['game_type']));
        }
        
        fputcsv($output, $row);
    }
} catch (PDOException $e) {
    // Optionally log the error, but die silently to prevent broken file format
    // die("Database error: " . $e->getMessage()); 
}

fclose($output);
exit();
?>