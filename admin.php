<?php
require_once 'config.php';
requireLogin();

// --- Admin Authorization Logic ---
// Checks for 'active_role' == 'admin' from the session and permanent role
function requireAdmin() {
    $user = getCurrentUser();
    // Check for both the permanent 'admin' role AND the active session view
    if (!$user || $user['active_role'] !== 'admin' || $user['role'] !== 'admin') { 
        header('Location: dashboard.php'); // Redirect to user dashboard if not actively in admin view
        exit();
    }
}
requireAdmin();
$currentUser = getCurrentUser();

$pdo = getDBConnection();
$error = '';
$success = '';

// --- Admin Actions Handler ---

// 1. Suspend/Unsuspend User
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle_suspension'])) {
    $targetUserId = $_POST['target_user_id'];
    $isSuspended = $_POST['is_suspended']; // 0 or 1
    
    // Prevent admin from suspending their own account
    if ((int)$targetUserId !== (int)$currentUser['user_id']) {
        try {
            $stmt = $pdo->prepare("UPDATE users SET is_suspended = ? WHERE user_id = ?"); 
            $stmt->execute([$isSuspended, $targetUserId]);
            $success = 'User account status updated successfully.';
        } catch (PDOException $e) {
            $error = 'Failed to update user status: ' . $e->getMessage();
        }
    } else {
         $error = 'You cannot change the suspension status of your own account.';
    }
}

// 2. Change User Role
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_user_role'])) {
    $targetUserId = $_POST['target_user_id'];
    $newRole = $_POST['new_role']; // 'user' or 'admin'
    
    // Prevent admin from changing their own role
    if ((int)$targetUserId !== (int)$currentUser['user_id']) {
        try {
            $stmt = $pdo->prepare("UPDATE users SET role = ? WHERE user_id = ?"); 
            $stmt->execute([$newRole, $targetUserId]);
            $success = 'User role updated to ' . htmlspecialchars($newRole) . ' successfully.';
        } catch (PDOException $e) {
            $error = 'Failed to update user role: ' . $e->getMessage();
        }
    } else {
         $error = 'You cannot change the role of your own account.';
    }
}

// 3. Delete Game
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_game'])) {
    $gameId = $_POST['game_id'];
    
    try {
        // Delete related transactions first (to maintain foreign key integrity)
        $stmt = $pdo->prepare("DELETE FROM transactions WHERE game_id = ?");
        $stmt->execute([$gameId]);
        
        $stmt = $pdo->prepare("DELETE FROM games WHERE game_id = ?");
        $stmt->execute([$gameId]);
        $success = 'Game and related transactions deleted successfully.';
    } catch (PDOException $e) {
        $error = 'Failed to delete game: . Error: ' . $e->getMessage();
    }
}

// 4. Update Complaint Status
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_complaint_status'])) {
    $complaintId = $_POST['complaint_id'];
    $newStatus = $_POST['new_status'];
    
    try {
        $stmt = $pdo->prepare("UPDATE complaints SET status = ? WHERE complaint_id = ?");
        $stmt->execute([$newStatus, $complaintId]);
        $success = 'Complaint status updated to ' . ucfirst($newStatus) . ' successfully.';
    } catch (PDOException $e) {
        $error = 'Failed to update complaint status: ' . $e->getMessage();
    }
}


// --- Data Fetching for Admin View ---

// 1. All Users - UPDATED: Removed 'rating' from SELECT query
$allUsers = $pdo->query("SELECT user_id, username, email, first_name, last_name, location, complaints, is_suspended, role, created_at FROM users ORDER BY user_id DESC")->fetchAll(PDO::FETCH_ASSOC);
$totalUsers = count($allUsers);

// 2. All Games
$allGames = $pdo->query("SELECT g.*, u.username as owner_username, u.first_name, u.last_name FROM games g JOIN users u ON g.user_id = u.user_id ORDER BY g.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
$totalGames = count($allGames);

// 3. All Pending Complaints
try {
    $pendingComplaints = $pdo->query("SELECT c.*, u1.username as from_username, u2.username as against_username, g.title as game_title 
                                      FROM complaints c 
                                      JOIN users u1 ON c.from_user_id = u1.user_id 
                                      JOIN users u2 ON c.against_user_id = u2.user_id
                                      LEFT JOIN transactions t ON c.transaction_id = t.transaction_id
                                      LEFT JOIN games g ON t.game_id = g.game_id
                                      WHERE c.status = 'pending'
                                      ORDER BY c.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // Complaints table might not exist
    $pendingComplaints = [];
}

// 4. All Transactions (Limited to last 100 for performance)
$allTransactions = $pdo->query("SELECT t.*, g.title as game_title, u1.username as from_username, u2.username as to_username 
                                FROM transactions t 
                                LEFT JOIN games g ON t.game_id = g.game_id 
                                LEFT JOIN users u1 ON t.from_user_id = u1.user_id 
                                LEFT JOIN users u2 ON t.to_user_id = u2.user_id 
                                ORDER BY t.created_at DESC 
                                LIMIT 100")->fetchAll(PDO::FETCH_ASSOC);


// --- Helper Functions for View (adapted from dashboard.php) ---

function getStatusBadgeClass($status) {
    switch(strtolower($status)) {
        case 'available':
        case 'resolved':
            return 'bg-success';
        case 'on_loan':
        case 'pending':
        case 'pending_exchange':
        case 'pending_borrow':
        case 'pending_sale':
            return 'bg-info';
        case 'cancelled':
        case 'dismissed':
            return 'bg-danger';
        case 'active':
            return 'bg-primary';
        default:
            return 'bg-secondary';
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GameSwap - Admin Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #dc3545; /* Admin Color - Red for Caution/Power */
            --secondary: #6c757d;
            --info: #0dcaf0;
            --dark: #212529;
            --success: #198754;
        }
        
        body {
            background-color: #f5f7fb;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .dashboard-header {
            background: linear-gradient(135deg, var(--primary), #842029);
            color: white;
            padding: 1.5rem 0;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .admin-card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .stats-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--primary);
        }
        
        .nav-pills .nav-link.active {
            background-color: var(--primary);
            color: white;
        }
        
        .table th {
            vertical-align: middle;
        }

        .complaint-item {
            border-left: 5px solid #ffc107;
            padding-left: 1rem;
            margin-bottom: 1rem;
            background-color: #fff3cd;
            border-radius: 8px;
            padding: 1rem;
        }
        
        .complaint-actions form {
            display: inline-block;
            margin-right: 5px;
        }
        
        .suspended-user {
            background-color: #f8d7da;
        }
    </style>
</head>
<body>
    <header class="dashboard-header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <h1><i class="fas fa-user-shield me-2"></i>GameSwap Admin Panel</h1>
                    <p class="mb-0">Overview and management of the GameSwap ecosystem</p>
                </div>
                <div class="col-md-6 text-end">
                    <span class="text-white me-3">Welcome, <?php echo htmlspecialchars($currentUser['username'] ?? 'Admin'); ?></span>
                    <a href="role_switch.php" class="btn btn-outline-light"><i class="fas fa-user-tag me-2"></i>Switch to User View</a>
                    <a href="logout.php" class="btn btn-outline-light"><i class="fas fa-sign-out-alt me-2"></i>Logout</a>
                </div>
            </div>
        </div>
    </header>

    <div class="container">
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <div class="row">
            <div class="col-md-4">
                <div class="admin-card text-center">
                    <i class="fas fa-users fa-3x text-primary mb-3"></i>
                    <div class="stats-number"><?php echo $totalUsers; ?></div>
                    <p class="stats-label">Total Users</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="admin-card text-center">
                    <i class="fas fa-gamepad fa-3x text-info mb-3"></i>
                    <div class="stats-number"><?php echo $totalGames; ?></div>
                    <p class="stats-label">Total Games Listed</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="admin-card text-center">
                    <i class="fas fa-exclamation-triangle fa-3x text-warning mb-3"></i>
                    <div class="stats-number"><?php echo count($pendingComplaints); ?></div>
                    <p class="stats-label">Pending Complaints</p>
                </div>
            </div>
        </div>

        <div class="admin-card">
            <ul class="nav nav-pills mb-3" id="adminTabs" role="tablist">
                <li class="nav-item">
                    <button class="nav-link active" id="users-tab" data-bs-toggle="pill" data-bs-target="#users" type="button" role="tab">
                        <i class="fas fa-users me-2"></i>User Management
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" id="games-tab" data-bs-toggle="pill" data-bs-target="#games" type="button" role="tab">
                        <i class="fas fa-gamepad me-2"></i>Game Catalog
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" id="complaints-tab" data-bs-toggle="pill" data-bs-target="#complaints" type="button" role="tab">
                        <i class="fas fa-exclamation-circle me-2"></i>Complaints (<?php echo count($pendingComplaints); ?>)
                    </button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" id="transactions-tab" data-bs-toggle="pill" data-bs-target="#transactions" type="button" role="tab">
                        <i class="fas fa-exchange-alt me-2"></i>Transactions Log
                    </button>
                </li>
            </ul>
            
            <div class="tab-content" id="adminTabContent">
                
                <div class="tab-pane fade show active" id="users" role="tabpanel" aria-labelledby="users-tab">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h4>All Users (<?php echo $totalUsers; ?>)</h4>
                        <a href="export.php?type=users" class="btn btn-sm btn-success">
                            <i class="fas fa-file-excel me-1"></i> Generate Excel Report
                        </a>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover align-middle">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Name</th>
                                    <th>Complaints</th>
                                    <th>Role</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($allUsers as $user): ?>
                                    <tr class="<?php echo $user['is_suspended'] ? 'suspended-user' : ''; ?>">
                                        <td><?php echo $user['user_id']; ?></td>
                                        <td>@<?php echo htmlspecialchars($user['username']); ?></td>
                                        <td><?php echo htmlspecialchars($user['email']); ?></td>
                                        <td><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name']); ?></td>
                                        <td><span class="badge <?php echo $user['complaints'] > 0 ? 'bg-danger' : 'bg-success'; ?>"><?php echo $user['complaints']; ?></span></td>
                                        <td>
                                            <span class="badge <?php echo $user['role'] === 'admin' ? 'bg-danger' : 'bg-primary'; ?>">
                                                <?php echo ucfirst($user['role']); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <span class="badge <?php echo $user['is_suspended'] ? 'bg-danger' : 'bg-success'; ?>">
                                                <?php echo $user['is_suspended'] ? 'Suspended' : 'Active'; ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php if ((int)$user['user_id'] !== (int)$currentUser['user_id']): // Can't change self ?>
                                                
                                                <form method="POST" class="d-inline mb-1">
                                                    <input type="hidden" name="target_user_id" value="<?php echo $user['user_id']; ?>">
                                                    <input type="hidden" name="toggle_suspension" value="1">
                                                    <input type="hidden" name="is_suspended" value="<?php echo $user['is_suspended'] ? '0' : '1'; ?>">
                                                    <button type="submit" class="btn btn-sm <?php echo $user['is_suspended'] ? 'btn-outline-success' : 'btn-outline-warning'; ?>" title="<?php echo $user['is_suspended'] ? 'Unsuspend' : 'Suspend'; ?>">
                                                        <i class="fas <?php echo $user['is_suspended'] ? 'fa-check' : 'fa-ban'; ?>"></i> 
                                                    </button>
                                                </form>

                                                <?php $newRole = $user['role'] === 'admin' ? 'user' : 'admin'; ?>
                                                <form method="POST" class="d-inline mb-1">
                                                    <input type="hidden" name="target_user_id" value="<?php echo $user['user_id']; ?>">
                                                    <input type="hidden" name="change_user_role" value="1">
                                                    <input type="hidden" name="new_role" value="<?php echo $newRole; ?>">
                                                    <button type="submit" class="btn btn-sm <?php echo $user['role'] === 'admin' ? 'btn-outline-primary' : 'btn-outline-danger'; ?>" title="Change role to <?php echo $newRole; ?>">
                                                        <i class="fas fa-user-tag"></i>
                                                    </button>
                                                </form>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="tab-pane fade" id="games" role="tabpanel" aria-labelledby="games-tab">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h4>All Games (<?php echo $totalGames; ?>)</h4>
                        <a href="export.php?type=games" class="btn btn-sm btn-success">
                            <i class="fas fa-file-excel me-1"></i> Generate Excel Report
                        </a>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover align-middle">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Title</th>
                                    <th>Owner</th>
                                    <th>Type</th>
                                    <th>Condition</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($allGames as $game): ?>
                                    <tr>
                                        <td><?php echo $game['game_id']; ?></td>
                                        <td><?php echo htmlspecialchars($game['title']); ?></td>
                                        <td><a href="mailto:<?php echo htmlspecialchars($game['owner_username']); ?>">@<?php echo htmlspecialchars($game['owner_username']); ?></a></td>
                                        <td><?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $game['game_type']))); ?></td>
                                        <td><?php echo ucfirst($game['condition']); ?></td>
                                        <td><span class="badge <?php echo getStatusBadgeClass($game['status']); ?>"><?php echo ucfirst(str_replace('_', ' ', $game['status'])); ?></span></td>
                                        <td>
                                            <form method="POST" class="d-inline" onsubmit="return confirm('Are you sure you want to permanently delete this game? This will also delete related transactions.');">
                                                <input type="hidden" name="game_id" value="<?php echo $game['game_id']; ?>">
                                                <input type="hidden" name="delete_game" value="1">
                                                <button type="submit" class="btn btn-sm btn-outline-danger">
                                                    <i class="fas fa-trash"></i> Delete
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="tab-pane fade" id="complaints" role="tabpanel" aria-labelledby="complaints-tab">
                    <h4>Pending Complaints (<?php echo count($pendingComplaints); ?>)</h4>
                    <?php if (empty($pendingComplaints)): ?>
                        <div class="alert alert-success text-center">
                            <i class="fas fa-check-circle me-2"></i>No pending complaints at this time.
                        </div>
                    <?php else: ?>
                        <?php foreach ($pendingComplaints as $complaint): ?>
                            <div class="complaint-item">
                                <div class="row">
                                    <div class="col-md-8">
                                        <h5><i class="fas fa-user-tag me-1"></i> Complaint ID #<?php echo $complaint['complaint_id']; ?></h5>
                                        <p class="mb-1"><strong>Filed By:</strong> @<?php echo htmlspecialchars($complaint['from_username']); ?></p>
                                        <p class="mb-1"><strong>Against User:</strong> @<?php echo htmlspecialchars($complaint['against_username']); ?></p>
                                        <?php if ($complaint['game_title']): ?>
                                            <p class="mb-1"><strong>Related Game:</strong> <?php echo htmlspecialchars($complaint['game_title']); ?></p>
                                        <?php endif; ?>
                                        <p class="mb-1"><strong>Date:</strong> <?php echo date('Y-m-d H:i', strtotime($complaint['created_at'])); ?></p>
                                        <p class="mt-2 mb-0"><strong>Description:</strong> <em><?php echo nl2br(htmlspecialchars($complaint['reason'])); ?></em></p>
                                    </div>
                                    <div class="col-md-4 complaint-actions text-md-end mt-3 mt-md-0">
                                        <span class="badge bg-warning mb-2 d-block d-md-inline-block">Pending Review</span>
                                        <form method="POST">
                                            <input type="hidden" name="complaint_id" value="<?php echo $complaint['complaint_id']; ?>">
                                            <input type="hidden" name="update_complaint_status" value="1">
                                            <input type="hidden" name="new_status" value="resolved">
                                            <button type="submit" class="btn btn-sm btn-success w-100 mb-2">
                                                <i class="fas fa-check"></i> Mark Resolved
                                            </button>
                                        </form>
                                        <form method="POST">
                                            <input type="hidden" name="complaint_id" value="<?php echo $complaint['complaint_id']; ?>">
                                            <input type="hidden" name="update_complaint_status" value="1">
                                            <input type="hidden" name="new_status" value="dismissed">
                                            <button type="submit" class="btn btn-sm btn-secondary w-100">
                                                <i class="fas fa-times"></i> Dismiss
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>

                <div class="tab-pane fade" id="transactions" role="tabpanel" aria-labelledby="transactions-tab">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h4>Latest 100 Transactions</h4>
                        <a href="export.php?type=transactions" class="btn btn-sm btn-success">
                            <i class="fas fa-file-excel me-1"></i> Generate Excel Report
                        </a>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover align-middle">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Type</th>
                                    <th>Game</th>
                                    <th>From User</th>
                                    <th>To User</th>
                                    <th>Status</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($allTransactions as $transaction): ?>
                                    <tr>
                                        <td><?php echo $transaction['transaction_id']; ?></td>
                                        <td><?php echo ucfirst($transaction['type']); ?></td>
                                        <td><?php echo htmlspecialchars($transaction['game_title'] ?? 'N/A'); ?></td>
                                        <td>@<?php echo htmlspecialchars($transaction['from_username']); ?></td>
                                        <td>@<?php echo htmlspecialchars($transaction['to_username']); ?></td>
                                        <td><span class="badge <?php echo getStatusBadgeClass($transaction['status']); ?>"><?php echo ucfirst($transaction['status']); ?></span></td>
                                        <td><?php echo date('Y-m-d', strtotime($transaction['created_at'])); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>