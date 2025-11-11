<?php
require_once 'config.php';
requireLogin();

$currentUser = getCurrentUser();

// Handle add game form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_game'])) {
    $pdo = getDBConnection();
    
    try {
        // Map form values to database enum values
        $gameType = ($_POST['gameType'] == 'Video Game') ? 'video_game' : 'board_game';
        $condition = strtolower($_POST['gameCondition']);
        
        // Insert game into database
        $stmt = $pdo->prepare("INSERT INTO games (user_id, title, genre, game_type, `condition`, age_years, status) VALUES (?, ?, ?, ?, ?, ?, 'available')");
        $stmt->execute([
            $currentUser['user_id'],
            $_POST['gameTitle'],
            $_POST['gameGenre'],
            $gameType,
            $condition,
            (int)$_POST['gameAge']
        ]);
        
        header('Location: dashboard.php?success=game_added');
        exit();
        
    } catch (PDOException $e) {
        $error = 'Failed to add game: ' . $e->getMessage();
    }
}

// Handle edit profile form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_profile'])) {
    $pdo = getDBConnection();
    
    try {
        $displayName = $_POST['userNameInput'];
        $email = $_POST['userEmail'];
        $location = $_POST['userLocation'];
        $bio = $_POST['userBio'];
        
        // Split display name into first and last name
        $nameParts = explode(' ', $displayName, 2);
        $firstName = $nameParts[0] ?? '';
        $lastName = $nameParts[1] ?? '';
        
        // Update user in database
        $stmt = $pdo->prepare("UPDATE users SET first_name = ?, last_name = ?, email = ?, location = ?, bio = ? WHERE user_id = ?");
        $stmt->execute([$firstName, $lastName, $email, $location, $bio, $currentUser['user_id']]);
        
        // Refresh current user data
        $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
        $stmt->execute([$currentUser['user_id']]);
        $_SESSION['current_user'] = $stmt->fetch(PDO::FETCH_ASSOC);
        
        header('Location: dashboard.php?success=profile_updated');
        exit();
        
    } catch (PDOException $e) {
        $error = 'Failed to update profile: ' . $e->getMessage();
    }
}

// Handle start exchange form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['start_exchange'])) {
    $pdo = getDBConnection();
    
    try {
        $exchangeGameId = $_POST['exchangeGame'];
        $targetUsername = $_POST['targetUsername'];
        $targetGame = $_POST['targetGame'];
        
        // Check if the game belongs to the user and is available
        $stmt = $pdo->prepare("SELECT * FROM games WHERE game_id = ? AND user_id = ? AND status = 'available'");
        $stmt->execute([$exchangeGameId, $currentUser['user_id']]);
        $userGame = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$userGame) {
            throw new Exception("Invalid game selected or game not available");
        }
        
        // Find the target user
        $stmt = $pdo->prepare("SELECT user_id, username FROM users WHERE username = ?");
        $stmt->execute([$targetUsername]);
        $targetUser = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$targetUser) {
            throw new Exception("User '$targetUsername' not found");
        }
        
        if ($targetUser['user_id'] == $currentUser['user_id']) {
            throw new Exception("Cannot exchange with yourself");
        }
        
        // Create exchange transaction
        $stmt = $pdo->prepare("INSERT INTO transactions (from_user_id, to_user_id, game_id, type, status, description) VALUES (?, ?, ?, 'exchange', 'pending', ?)");
        $stmt->execute([
            $currentUser['user_id'],
            $targetUser['user_id'],
            $exchangeGameId,
            "Exchange request: " . $userGame['title'] . " for " . $targetGame
        ]);
        
        // Update game status
        $stmt = $pdo->prepare("UPDATE games SET status = 'pending_exchange' WHERE game_id = ?");
        $stmt->execute([$exchangeGameId]);
        
        header('Location: dashboard.php?success=exchange_started');
        exit();
        
    } catch (Exception $e) {
        $error = 'Failed to start exchange: ' . $e->getMessage();
    }
}

// Handle borrow request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['borrow_request'])) {
    $pdo = getDBConnection();
    
    try {
        $gameId = $_POST['game_id'];
        $ownerUsername = $_POST['owner_username'];
        
        // Get game and owner details
        $stmt = $pdo->prepare("SELECT g.*, u.user_id as owner_id, u.username 
                              FROM games g 
                              JOIN users u ON g.user_id = u.user_id 
                              WHERE g.game_id = ? AND g.status = 'available'");
        $stmt->execute([$gameId]);
        $game = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$game) {
            throw new Exception("Game not available for borrowing");
        }
        
        if ($game['user_id'] == $currentUser['user_id']) {
            throw new Exception("Cannot borrow your own game");
        }
        
        // Create borrow request transaction
        $stmt = $pdo->prepare("INSERT INTO transactions (from_user_id, to_user_id, game_id, type, status) VALUES (?, ?, ?, 'lend', 'pending')");
        $stmt->execute([
            $currentUser['user_id'],
            $game['owner_id'],
            $gameId
        ]);
        
        // Create notification for game owner
        $notificationMessage = $currentUser['username'] . " wants to borrow your game: " . $game['title'];
        
        // If notifications table exists, create notification
        try {
            $stmt = $pdo->prepare("INSERT INTO notifications (user_id, from_user_id, game_id, type, message) VALUES (?, ?, ?, 'borrow_request', ?)");
            $stmt->execute([
                $game['owner_id'],
                $currentUser['user_id'],
                $gameId,
                $notificationMessage
            ]);
        } catch (PDOException $e) {
            // Notifications table might not exist, continue without notification
        }
        
        // Update game status
        $stmt = $pdo->prepare("UPDATE games SET status = 'pending_borrow' WHERE game_id = ?");
        $stmt->execute([$gameId]);
        
        header('Location: dashboard.php?success=borrow_request_sent');
        exit();
        
    } catch (Exception $e) {
        $error = 'Failed to send borrow request: ' . $e->getMessage();
    }
}

// Handle borrow request approval
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['approve_borrow'])) {
    $pdo = getDBConnection();
    
    try {
        $transactionId = $_POST['transaction_id'];
        
        // Update transaction status to active
        $stmt = $pdo->prepare("UPDATE transactions SET status = 'active' WHERE transaction_id = ?");
        $stmt->execute([$transactionId]);
        
        // Update game status to on_loan
        $stmt = $pdo->prepare("UPDATE games SET status = 'on_loan' WHERE game_id = (SELECT game_id FROM transactions WHERE transaction_id = ?)");
        $stmt->execute([$transactionId]);
        
        header('Location: dashboard.php?success=borrow_approved');
        exit();
        
    } catch (Exception $e) {
        $error = 'Failed to approve borrow request: ' . $e->getMessage();
    }
}

// Handle borrow request decline
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['decline_borrow'])) {
    $pdo = getDBConnection();
    
    try {
        $transactionId = $_POST['transaction_id'];
        
        // Update transaction status to cancelled
        $stmt = $pdo->prepare("UPDATE transactions SET status = 'cancelled' WHERE transaction_id = ?");
        $stmt->execute([$transactionId]);
        
        // Update game status back to available
        $stmt = $pdo->prepare("UPDATE games SET status = 'available' WHERE game_id = (SELECT game_id FROM transactions WHERE transaction_id = ?)");
        $stmt->execute([$transactionId]);
        
        header('Location: dashboard.php?success=borrow_declined');
        exit();
        
    } catch (Exception $e) {
        $error = 'Failed to decline borrow request: ' . $e->getMessage();
    }
}

// Handle borrow request cancellation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cancel_borrow'])) {
    $pdo = getDBConnection();
    
    try {
        $transactionId = $_POST['transaction_id'];
        
        // Update transaction status to cancelled
        $stmt = $pdo->prepare("UPDATE transactions SET status = 'cancelled' WHERE transaction_id = ?");
        $stmt->execute([$transactionId]);
        
        // Update game status back to available
        $stmt = $pdo->prepare("UPDATE games SET status = 'available' WHERE game_id = (SELECT game_id FROM transactions WHERE transaction_id = ?)");
        $stmt->execute([$transactionId]);
        
        header('Location: dashboard.php?success=borrow_cancelled');
        exit();
        
    } catch (Exception $e) {
        $error = 'Failed to cancel borrow request: ' . $e->getMessage();
    }
}

// Handle complaint submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_complaint'])) {
    $pdo = getDBConnection();
    
    try {
        $complaintType = $_POST['complaintType'];
        $targetUsername = $_POST['targetUsername'];
        $transactionId = $_POST['transaction_id'] ?? null;
        $description = $_POST['complaintDescription'];
        
        // Validate target user exists
        $stmt = $pdo->prepare("SELECT user_id FROM users WHERE username = ?");
        $stmt->execute([$targetUsername]);
        $targetUser = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$targetUser) {
            throw new Exception("User '$targetUsername' not found");
        }
        
        if ($targetUser['user_id'] == $currentUser['user_id']) {
            throw new Exception("Cannot file a complaint against yourself");
        }
        
        // Insert complaint into database using your schema
        $stmt = $pdo->prepare("INSERT INTO complaints (from_user_id, against_user_id, transaction_id, reason, status) VALUES (?, ?, ?, ?, 'pending')");
        $stmt->execute([
            $currentUser['user_id'],
            $targetUser['user_id'],
            $transactionId,
            $description
        ]);
        
        // Increment complaint count for the reported user
        $stmt = $pdo->prepare("UPDATE users SET complaints = complaints + 1 WHERE user_id = ?");
        $stmt->execute([$targetUser['user_id']]);
        
        header('Location: dashboard.php?success=complaint_submitted');
        exit();
        
    } catch (Exception $e) {
        $error = 'Failed to submit complaint: ' . $e->getMessage();
    }
}

// Get user's games from database
$pdo = getDBConnection();
$stmt = $pdo->prepare("SELECT * FROM games WHERE user_id = ?");
$stmt->execute([$currentUser['user_id']]);
$userGames = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get available games from other users (for lending/borrowing)
$stmt = $pdo->prepare("SELECT g.*, u.username, u.first_name, u.last_name, u.rating 
                      FROM games g 
                      JOIN users u ON g.user_id = u.user_id 
                      WHERE g.status = 'available' 
                      AND g.user_id != ? 
                      ORDER BY g.created_at DESC");
$stmt->execute([$currentUser['user_id']]);
$availableGames = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get user's transactions from database
$stmt = $pdo->prepare("SELECT t.*, g.title as game_title, u1.username as from_username, u2.username as to_username 
                      FROM transactions t 
                      LEFT JOIN games g ON t.game_id = g.game_id 
                      LEFT JOIN users u1 ON t.from_user_id = u1.user_id 
                      LEFT JOIN users u2 ON t.to_user_id = u2.user_id 
                      WHERE t.from_user_id = ? OR t.to_user_id = ? 
                      ORDER BY t.created_at DESC");
$stmt->execute([$currentUser['user_id'], $currentUser['user_id']]);
$userTransactions = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get user notifications
$notifications = [];
try {
    $stmt = $pdo->prepare("SELECT n.*, u.username as from_username, g.title as game_title 
                          FROM notifications n 
                          JOIN users u ON n.from_user_id = u.user_id 
                          JOIN games g ON n.game_id = g.game_id 
                          WHERE n.user_id = ? 
                          ORDER BY n.created_at DESC 
                          LIMIT 5");
    $stmt->execute([$currentUser['user_id']]);
    $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // Notifications table might not exist
}

// Get user's complaints
$userComplaints = [];
try {
    $stmt = $pdo->prepare("SELECT c.*, u.username as against_username 
                          FROM complaints c 
                          JOIN users u ON c.against_user_id = u.user_id 
                          WHERE c.from_user_id = ? 
                          ORDER BY c.created_at DESC 
                          LIMIT 5");
    $stmt->execute([$currentUser['user_id']]);
    $userComplaints = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // Complaints table might not exist
}

// Get community stats
$activeUsers = $pdo->query("SELECT COUNT(*) as count FROM users WHERE is_suspended = 0")->fetch()['count'];
$gamesAvailable = $pdo->query("SELECT COUNT(*) as count FROM games WHERE status = 'available'")->fetch()['count'];
$monthlyTransactions = $pdo->query("SELECT COUNT(*) as count FROM transactions WHERE MONTH(created_at) = MONTH(CURRENT_DATE()) AND YEAR(created_at) = YEAR(CURRENT_DATE())")->fetch()['count'];

// Helper function to get game icon
function getGameIcon($genre) {
    if (strpos($genre, 'Action') !== false || strpos($genre, 'Adventure') !== false) return 'fa-gamepad';
    if (strpos($genre, 'RPG') !== false || strpos($genre, 'Fantasy') !== false) return 'fa-dragon';
    if (strpos($genre, 'Sci-Fi') !== false) return 'fa-robot';
    if (strpos($genre, 'Simulation') !== false) return 'fa-paw';
    if (strpos($genre, 'Racing') !== false) return 'fa-car';
    if (strpos($genre, 'FPS') !== false || strpos($genre, 'Shooter') !== false) return 'fa-gun';
    return 'fa-gamepad';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GameSwap - Dashboard</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #4361ee;
            --secondary: #3f37c9;
            --success: #4cc9f0;
            --light: #f8f9fa;
            --dark: #212529;
            --warning: #f72585;
        }
        
        body {
            background-color: #f5f7fb;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .dashboard-header {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 1.5rem 0;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .dashboard-card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .dashboard-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
        }
        
        .profile-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background-color: var(--success);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            color: white;
            margin: 0 auto;
        }
        
        .game-card {
            border-radius: 10px;
            overflow: hidden;
            transition: transform 0.3s ease;
            height: 100%;
        }
        
        .game-card:hover {
            transform: scale(1.03);
        }
        
        .badge-status {
            padding: 0.5rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
        }
        
        .transaction-item {
            border-left: 4px solid var(--primary);
            padding-left: 1rem;
            margin-bottom: 1.5rem;
        }
        
        .stats-card {
            text-align: center;
            padding: 1.5rem;
        }
        
        .stats-number {
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary);
        }
        
        .nav-tabs .nav-link.active {
            background-color: var(--primary);
            color: white;
            border: none;
        }
        
        .nav-tabs .nav-link {
            color: var(--dark);
            border: none;
            margin-right: 5px;
            border-radius: 8px 8px 0 0;
        }
        
        .complaint-warning {
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px 15px;
            border-radius: 4px;
            margin-bottom: 1rem;
        }
        
        .action-btn {
            border-radius: 20px;
            padding: 0.5rem 1.5rem;
            font-weight: 600;
        }
        
        .game-icon {
            font-size: 3rem;
            color: var(--primary);
            margin-bottom: 1rem;
        }
        
        .available-games {
            max-height: 200px;
            overflow-y: auto;
        }
        
        .owner-info {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 0.5rem;
            margin-top: 0.5rem;
            font-size: 0.85rem;
        }
        
        .rating-stars {
            color: #ffc107;
        }
        
        .borrow-btn {
            width: 100%;
            margin-top: 0.5rem;
        }
        
        .notification-item {
            border-left: 4px solid var(--success);
            padding-left: 1rem;
            margin-bottom: 1rem;
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 1rem;
        }
        
        .notification-unread {
            background-color: #e7f3ff;
            border-left-color: var(--primary);
        }
        
        .transaction-actions {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        
        .transaction-actions form {
            margin: 0;
        }
        
        .complaint-item {
            border-left: 4px solid #dc3545;
            padding-left: 1rem;
            margin-bottom: 1rem;
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 1rem;
        }
        
        .complaint-status-pending {
            border-left-color: #ffc107;
        }
        
        .complaint-status-resolved {
            border-left-color: #198754;
        }
        
        .complaint-status-rejected {
            border-left-color: #6c757d;
        }

        .complaint-status-dismissed {
            border-left-color: #6c757d;
        }
    </style>
</head>
<body>
    <!-- Dashboard Header -->
    <header class="dashboard-header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <h1><i class="fas fa-gamepad me-2"></i>GameSwap Dashboard</h1>
                    <p class="mb-0">Manage your game collection and transactions</p>
                </div>
                <div class="col-md-6 text-end">
                    <div class="dropdown">
                        <button class="btn btn-light dropdown-toggle" type="button" id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fas fa-user-circle me-1"></i> <span id="dashboardUserName"><?php echo htmlspecialchars($currentUser['first_name'] . ' ' . $currentUser['last_name']); ?></span>
                        </button>
                        <ul class="dropdown-menu" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#editProfileModal"><i class="fas fa-user me-2"></i>Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </header>

    <div class="container">
        <!-- Error Message -->
        <?php if (isset($error)): ?>
            <div class="alert alert-danger">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <!-- Success Message -->
        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success">
                <?php
                switch($_GET['success']) {
                    case 'profile_updated':
                        echo "Profile updated successfully!";
                        break;
                    case 'game_added':
                        echo "Game added successfully!";
                        break;
                    case 'exchange_started':
                        echo "Exchange request sent successfully!";
                        break;
                    case 'borrow_request_sent':
                        echo "Borrow request sent successfully! The owner will be notified.";
                        break;
                    case 'borrow_approved':
                        echo "Borrow request approved successfully!";
                        break;
                    case 'borrow_declined':
                        echo "Borrow request declined successfully!";
                        break;
                    case 'borrow_cancelled':
                        echo "Borrow request cancelled successfully!";
                        break;
                    case 'complaint_submitted':
                        echo "Complaint submitted successfully! Our team will review it shortly.";
                        break;
                    default:
                        echo "Operation completed successfully!";
                }
                ?>
            </div>
        <?php endif; ?>

        <!-- Complaint Warning -->
        <div class="complaint-warning" id="complaintWarning" style="<?php echo $currentUser['complaints'] >= 2 ? 'display: block;' : 'display: none;'; ?>">
            <i class="fas fa-exclamation-triangle text-warning me-2"></i>
            <strong>Warning:</strong> You have <span id="complaintCount"><?php echo $currentUser['complaints']; ?></span> complaints. If you receive one more complaint, your account will be suspended.
        </div>

        <!-- Profile Summary -->
        <div class="dashboard-card">
            <div class="row">
                <div class="col-md-3 text-center">
                    <div class="profile-avatar mb-3">
                        <i class="fas fa-user"></i>
                    </div>
                    <h4 id="profileUserName"><?php echo htmlspecialchars($currentUser['first_name'] . ' ' . $currentUser['last_name']); ?></h4>
                    <span class="badge bg-success" id="verificationBadge">Verified</span>
                </div>
                <div class="col-md-9">
                    <h3 class="mb-3">Profile Summary</h3>
                    <div class="row mb-4">
                        <div class="col-md-3 stats-card">
                            <div class="stats-number" id="gamesOwned"><?php echo count($userGames); ?></div>
                            <div class="stats-label">Games Owned</div>
                        </div>
                        <div class="col-md-3 stats-card">
                            <div class="stats-number" id="totalTransactions"><?php echo count($userTransactions); ?></div>
                            <div class="stats-label">Transactions</div>
                        </div>
                        <div class="col-md-3 stats-card">
                            <div class="stats-number" id="userRating"><?php echo $currentUser['rating']; ?></div>
                            <div class="stats-label">Rating</div>
                        </div>
                        <div class="col-md-3 stats-card">
                            <?php
                            $activeLoanCount = 0;
                            foreach ($userTransactions as $transaction) {
                                if ($transaction['type'] === 'lend' && $transaction['status'] === 'active') {
                                    $activeLoanCount++;
                                }
                            }
                            ?>
                            <div class="stats-number" id="activeLoans"><?php echo $activeLoanCount; ?></div>
                            <div class="stats-label">Active Loans</div>
                        </div>
                    </div>
                    <div class="d-flex gap-2">
                        <button class="btn btn-primary action-btn" data-bs-toggle="modal" data-bs-target="#addGameModal"><i class="fas fa-plus me-1"></i> Add Game</button>
                        <button class="btn btn-outline-primary action-btn" data-bs-toggle="modal" data-bs-target="#editProfileModal"><i class="fas fa-edit me-1"></i> Edit Profile</button>
                        <button class="btn btn-outline-success action-btn" data-bs-toggle="modal" data-bs-target="#startExchangeModal"><i class="fas fa-exchange-alt me-1"></i> Start Exchange</button>
                        <button class="btn btn-outline-warning action-btn" data-bs-toggle="modal" data-bs-target="#fileComplaintModal"><i class="fas fa-exclamation-triangle me-1"></i> File Complaint</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Game Collection -->
            <div class="col-lg-8">
                <div class="dashboard-card">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h3>Game Collection</h3>
                        <div>
                            <ul class="nav nav-tabs" id="gameTabs">
                                <li class="nav-item">
                                    <a class="nav-link active" href="#" data-filter="my_games">My Games</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="#" data-filter="available">Available to Borrow</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="#" data-filter="on_loan">On Loan</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                    
                    <!-- My Games Section -->
                    <div class="game-section" id="myGamesSection">
                        <h4 class="mb-3">My Games</h4>
                        <div class="row" id="gameCollection">
                            <?php if (empty($userGames)): ?>
                                <div class="col-12 text-center py-5">
                                    <i class="fas fa-gamepad fa-3x text-muted mb-3"></i>
                                    <h4 class="text-muted">No games found</h4>
                                    <p class="text-muted">Add your first game to get started!</p>
                                    <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addGameModal">Add Your First Game</button>
                                </div>
                            <?php else: ?>
                                <?php foreach ($userGames as $game): ?>
                                    <div class="col-md-6 col-lg-4 mb-4">
                                        <div class="card game-card">
                                            <div class="card-body text-center">
                                                <div class="game-icon">
                                                    <i class="fas <?php echo getGameIcon($game['genre']); ?>"></i>
                                                </div>
                                                <h5 class="card-title"><?php echo htmlspecialchars($game['title']); ?></h5>
                                                <p class="card-text text-muted"><?php echo htmlspecialchars($game['genre']); ?></p>
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <?php
                                                    $statusBadge = '';
                                                    $actionButtons = '';
                                                    
                                                    switch($game['status']) {
                                                        case 'available':
                                                            $statusBadge = '<span class="badge bg-success badge-status">Available</span>';
                                                            $actionButtons = '
                                                                <button class="btn btn-sm btn-outline-primary me-1" onclick="sellGame(' . $game['game_id'] . ')"><i class="fas fa-dollar-sign"></i></button>
                                                                <button class="btn btn-sm btn-outline-success me-1" onclick="lendGame(' . $game['game_id'] . ')"><i class="fas fa-handshake"></i></button>
                                                                <button class="btn btn-sm btn-outline-warning" onclick="exchangeGame(' . $game['game_id'] . ')"><i class="fas fa-exchange-alt"></i></button>
                                                            ';
                                                            break;
                                                        case 'on_loan':
                                                            $statusBadge = '<span class="badge bg-warning badge-status">On Loan</span>';
                                                            $actionButtons = '<button class="btn btn-sm btn-outline-secondary" disabled><i class="fas fa-ban"></i></button>';
                                                            break;
                                                        case 'pending_sale':
                                                            $statusBadge = '<span class="badge bg-danger badge-status">Pending Sale</span>';
                                                            $actionButtons = '<button class="btn btn-sm btn-outline-secondary" disabled><i class="fas fa-ban"></i></button>';
                                                            break;
                                                        case 'pending_exchange':
                                                            $statusBadge = '<span class="badge bg-info badge-status">Pending Exchange</span>';
                                                            $actionButtons = '<button class="btn btn-sm btn-outline-secondary" disabled><i class="fas fa-ban"></i></button>';
                                                            break;
                                                        case 'pending_borrow':
                                                            $statusBadge = '<span class="badge bg-info badge-status">Pending Borrow</span>';
                                                            $actionButtons = '<button class="btn btn-sm btn-outline-secondary" disabled><i class="fas fa-ban"></i></button>';
                                                            break;
                                                    }
                                                    echo $statusBadge;
                                                    echo $actionButtons;
                                                    ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                        
                        <div class="text-center mt-3">
                            <button class="btn btn-outline-primary" data-bs-toggle="modal" data-bs-target="#addGameModal">Add More Games</button>
                        </div>
                    </div>

                    <!-- Available Games Section (Hidden by default) -->
                    <div class="game-section" id="availableGamesSection" style="display: none;">
                        <h4 class="mb-3">Games Available to Borrow</h4>
                        <div class="row">
                            <?php if (empty($availableGames)): ?>
                                <div class="col-12 text-center py-5">
                                    <i class="fas fa-gamepad fa-3x text-muted mb-3"></i>
                                    <h4 class="text-muted">No games available</h4>
                                    <p class="text-muted">Check back later for games to borrow from other users.</p>
                                </div>
                            <?php else: ?>
                                <?php foreach ($availableGames as $game): ?>
                                    <div class="col-md-6 col-lg-4 mb-4">
                                        <div class="card game-card">
                                            <div class="card-body text-center">
                                                <div class="game-icon">
                                                    <i class="fas <?php echo getGameIcon($game['genre']); ?>"></i>
                                                </div>
                                                <h5 class="card-title"><?php echo htmlspecialchars($game['title']); ?></h5>
                                                <p class="card-text text-muted"><?php echo htmlspecialchars($game['genre']); ?></p>
                                                
                                                <!-- Owner Information -->
                                                <div class="owner-info">
                                                    <div class="d-flex justify-content-between align-items-center">
                                                        <span>
                                                            <i class="fas fa-user me-1"></i>
                                                            <?php echo htmlspecialchars($game['first_name'] . ' ' . $game['last_name']); ?>
                                                        </span>
                                                        <span class="rating-stars">
                                                            <?php
                                                            $rating = $game['rating'];
                                                            for ($i = 1; $i <= 5; $i++) {
                                                                if ($i <= $rating) {
                                                                    echo '<i class="fas fa-star"></i>';
                                                                } else {
                                                                    echo '<i class="far fa-star"></i>';
                                                                }
                                                            }
                                                            ?>
                                                        </span>
                                                    </div>
                                                    <small class="text-muted">@<?php echo htmlspecialchars($game['username']); ?></small>
                                                </div>
                                                
                                                <!-- Game Details -->
                                                <div class="mt-2">
                                                    <small class="text-muted">
                                                        <i class="fas fa-tag me-1"></i><?php echo ucfirst($game['condition']); ?> Condition
                                                    </small>
                                                    <br>
                                                    <small class="text-muted">
                                                        <i class="fas fa-calendar me-1"></i><?php echo $game['age_years']; ?> years old
                                                    </small>
                                                </div>
                                                
                                                <!-- Borrow Button -->
                                                <button class="btn btn-primary borrow-btn" onclick="requestBorrow(<?php echo $game['game_id']; ?>, '<?php echo htmlspecialchars($game['username']); ?>')">
                                                    <i class="fas fa-handshake me-1"></i> Request to Borrow
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- On Loan Section (Hidden by default) -->
                    <div class="game-section" id="onLoanSection" style="display: none;">
                        <h4 class="mb-3">Games Currently on Loan</h4>
                        <div class="row">
                            <?php
                            $onLoanGames = array_filter($userGames, function($game) {
                                return $game['status'] === 'on_loan';
                            });
                            ?>
                            <?php if (empty($onLoanGames)): ?>
                                <div class="col-12 text-center py-5">
                                    <i class="fas fa-exchange-alt fa-3x text-muted mb-3"></i>
                                    <h4 class="text-muted">No games on loan</h4>
                                    <p class="text-muted">Your borrowed games will appear here.</p>
                                </div>
                            <?php else: ?>
                                <?php foreach ($onLoanGames as $game): ?>
                                    <div class="col-md-6 col-lg-4 mb-4">
                                        <div class="card game-card">
                                            <div class="card-body text-center">
                                                <div class="game-icon">
                                                    <i class="fas <?php echo getGameIcon($game['genre']); ?>"></i>
                                                </div>
                                                <h5 class="card-title"><?php echo htmlspecialchars($game['title']); ?></h5>
                                                <p class="card-text text-muted"><?php echo htmlspecialchars($game['genre']); ?></p>
                                                <span class="badge bg-warning badge-status">On Loan</span>
                                                <div class="mt-2">
                                                    <small class="text-muted">Currently borrowed</small>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Right Sidebar -->
            <div class="col-lg-4">
                <!-- Notifications Section -->
                <div class="dashboard-card">
                    <h3 class="mb-4">Notifications</h3>
                    <div id="notificationsList">
                        <?php if (empty($notifications)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-bell fa-2x text-muted mb-3"></i>
                                <h5 class="text-muted">No Notifications</h5>
                                <p class="text-muted">You'll see notifications about your transactions here</p>
                            </div>
                        <?php else: ?>
                            <?php foreach ($notifications as $notification): ?>
                                <div class="notification-item <?php echo $notification['is_read'] ? '' : 'notification-unread'; ?>">
                                    <div class="d-flex justify-content-between align-items-start mb-2">
                                        <h6><?php echo htmlspecialchars($notification['message']); ?></h6>
                                        <small class="text-muted"><?php echo date('m/d/Y H:i', strtotime($notification['created_at'])); ?></small>
                                    </div>
                                    <?php if (!$notification['is_read']): ?>
                                        <span class="badge bg-primary">New</span>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- My Complaints Section -->
                <div class="dashboard-card">
                    <h3 class="mb-4">My Complaints</h3>
                    <div id="complaintsList">
                        <?php if (empty($userComplaints)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-exclamation-triangle fa-2x text-muted mb-3"></i>
                                <h5 class="text-muted">No Complaints Filed</h5>
                                <p class="text-muted">Your filed complaints will appear here</p>
                            </div>
                        <?php else: ?>
                            <?php foreach ($userComplaints as $complaint): ?>
                                        <div class="complaint-item complaint-status-<?php echo $complaint['status']; ?>">
                                    <div class="d-flex justify-content-between align-items-start mb-2">
                                        <h6>Complaint against @<?php echo htmlspecialchars($complaint['against_username']); ?></h6>
                                        <small class="text-muted"><?php echo date('m/d/Y', strtotime($complaint['created_at'])); ?></small>
                                    </div>
                                    <p class="mb-2"><strong>Reason:</strong> <?php echo htmlspecialchars($complaint['reason']); ?></p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="badge 
                                            <?php 
                                            switch($complaint['status']) {
                                                case 'pending': echo 'bg-warning'; break;
                                                case 'resolved': echo 'bg-success'; break;
                                                case 'dismissed': echo 'bg-secondary'; break;
                                                default: echo 'bg-info';
                                            }
                                            ?>">
                                            <?php echo ucfirst($complaint['status']); ?>
                                        </span>
                                        <?php if ($complaint['status'] === 'pending'): ?>
                                            <small class="text-muted">Under review</small>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    <div class="text-center mt-3">
                        <button class="btn btn-outline-warning btn-sm" data-bs-toggle="modal" data-bs-target="#fileComplaintModal">
                            <i class="fas fa-exclamation-triangle me-1"></i> File New Complaint
                        </button>
                    </div>
                </div>

                <!-- Active Transactions -->
                <div class="dashboard-card">
                    <h3 class="mb-4">Active Transactions</h3>
                    
                    <div id="activeTransactions">
                        <?php if (empty($userTransactions)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-exchange-alt fa-2x text-muted mb-3"></i>
                                <h5 class="text-muted">No Active Transactions</h5>
                                <p class="text-muted">Start trading to see your transactions here</p>
                            </div>
                        <?php else: ?>
                            <?php foreach ($userTransactions as $transaction): ?>
                                <div class="transaction-item">
                                    <?php
                                    $statusBadge = '';
                                    $details = '';
                                    $actions = '';
                                    
                                    switch($transaction['status']) {
                                        case 'active':
                                            $statusBadge = '<span class="badge bg-warning">Active</span>';
                                            break;
                                        case 'pending':
                                            $statusBadge = '<span class="badge bg-info">Pending</span>';
                                            break;
                                        case 'completed':
                                            $statusBadge = '<span class="badge bg-success">Completed</span>';
                                            break;
                                        case 'cancelled':
                                            $statusBadge = '<span class="badge bg-danger">Cancelled</span>';
                                            break;
                                    }
                                    
                                    $isFromUser = ($transaction['from_user_id'] == $currentUser['user_id']);
                                    $otherUser = $isFromUser ? $transaction['to_username'] : $transaction['from_username'];
                                    
                                    if ($transaction['type'] === 'lend') {
                                        if ($transaction['status'] === 'pending') {
                                            $details = '
                                                <p class="text-muted mb-1">Borrow request ' . ($isFromUser ? 'sent to' : 'from') . ': ' . htmlspecialchars($otherUser) . '</p>
                                                <p class="mb-1">Game: ' . htmlspecialchars($transaction['game_title']) . '</p>
                                                <p class="mb-2">Status: Pending Approval</p>
                                            ';
                                            if ($isFromUser) {
                                                $actions = '
                                                    <form method="POST" style="display: inline;">
                                                        <input type="hidden" name="transaction_id" value="' . $transaction['transaction_id'] . '">
                                                        <input type="hidden" name="cancel_borrow" value="1">
                                                        <button type="submit" class="btn btn-sm btn-outline-danger">Cancel Request</button>
                                                    </form>
                                                ';
                                            } else {
                                                $actions = '
                                                    <div class="transaction-actions">
                                                        <form method="POST" style="display: inline;">
                                                            <input type="hidden" name="transaction_id" value="' . $transaction['transaction_id'] . '">
                                                            <input type="hidden" name="approve_borrow" value="1">
                                                            <button type="submit" class="btn btn-sm btn-outline-success">Approve</button>
                                                        </form>
                                                        <form method="POST" style="display: inline;">
                                                            <input type="hidden" name="transaction_id" value="' . $transaction['transaction_id'] . '">
                                                            <input type="hidden" name="decline_borrow" value="1">
                                                            <button type="submit" class="btn btn-sm btn-outline-danger">Decline</button>
                                                        </form>
                                                    </div>
                                                ';
                                            }
                                        } else if ($transaction['status'] === 'active') {
                                            $details = '
                                                <p class="text-muted mb-1">' . ($isFromUser ? 'To' : 'From') . ': ' . htmlspecialchars($otherUser) . '</p>
                                                <p class="mb-1">Game: ' . htmlspecialchars($transaction['game_title']) . '</p>
                                                <p class="mb-2">Status: Active Loan</p>
                                            ';
                                            $actions = $isFromUser ? '
                                                <button class="btn btn-sm btn-outline-primary">Extend</button>
                                                <button class="btn btn-sm btn-outline-success">Mark Returned</button>
                                            ' : '<button class="btn btn-sm btn-outline-primary">Contact Owner</button>';
                                        }
                                    } else if ($transaction['type'] === 'sale') {
                                        $details = '
                                            <p class="text-muted mb-1">' . ($isFromUser ? 'To' : 'From') . ': ' . htmlspecialchars($otherUser) . '</p>
                                            <p class="mb-1">Price: $' . ($transaction['price'] ?? '0') . '</p>
                                            <p class="mb-2">Status: ' . ucfirst($transaction['status']) . '</p>
                                        ';
                                        $actions = $isFromUser ? '
                                            <button class="btn btn-sm btn-outline-primary">Ship Item</button>
                                            <button class="btn btn-sm btn-outline-danger">Cancel</button>
                                        ' : '<button class="btn btn-sm btn-outline-primary">Contact Seller</button>';
                                    } else if ($transaction['type'] === 'exchange') {
                                        $details = '
                                            <p class="text-muted mb-1">With: ' . htmlspecialchars($otherUser) . '</p>
                                            <p class="mb-1">Game: ' . htmlspecialchars($transaction['game_title']) . '</p>
                                            <p class="mb-2">Status: ' . ucfirst($transaction['status']) . '</p>
                                        ';
                                        $actions = '
                                            <button class="btn btn-sm btn-outline-primary">Track</button>
                                            <button class="btn btn-sm btn-outline-success">Confirm Receipt</button>
                                        ';
                                    }
                                    ?>
                                    <div class="d-flex justify-content-between align-items-start mb-2">
                                        <h5><?php echo ucfirst($transaction['type']); ?></h5>
                                        <?php echo $statusBadge; ?>
                                    </div>
                                    <?php echo $details; ?>
                                    <div class="transaction-actions">
                                        <?php echo $actions; ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- Quick Stats -->
                <div class="dashboard-card">
                    <h4 class="mb-3">Community Stats</h4>
                    <div class="mb-3">
                        <div class="d-flex justify-content-between">
                            <span>Active Users:</span>
                            <strong id="activeUsers"><?php echo $activeUsers; ?></strong>
                        </div>
                        <div class="progress mb-2">
                            <div class="progress-bar bg-success" role="progressbar" style="width: <?php echo min(($activeUsers/1000)*100, 100); ?>%"></div>
                        </div>
                    </div>
                    <div class="mb-3">
                        <div class="d-flex justify-content-between">
                            <span>Games Available:</span>
                            <strong id="gamesAvailable"><?php echo $gamesAvailable; ?></strong>
                        </div>
                        <div class="progress mb-2">
                            <div class="progress-bar bg-primary" role="progressbar" style="width: <?php echo min(($gamesAvailable/5000)*100, 100); ?>%"></div>
                        </div>
                    </div>
                    <div class="mb-3">
                        <div class="d-flex justify-content-between">
                            <span>Transactions This Month:</span>
                            <strong id="monthlyTransactions"><?php echo $monthlyTransactions; ?></strong>
                        </div>
                        <div class="progress mb-2">
                            <div class="progress-bar bg-warning" role="progressbar" style="width: <?php echo min(($monthlyTransactions/1000)*100, 100); ?>%"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Add Game Modal -->
    <div class="modal fade" id="addGameModal" tabindex="-1" aria-labelledby="addGameModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addGameModalLabel">Add New Game</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form method="POST">
                    <input type="hidden" name="add_game" value="1">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="gameTitle" class="form-label">Game Title</label>
                            <input type="text" class="form-control" id="gameTitle" name="gameTitle" required>
                        </div>
                        <div class="mb-3">
                            <label for="gameGenre" class="form-label">Genre</label>
                            <select class="form-select" id="gameGenre" name="gameGenre" required>
                                <option value="">Select Genre</option>
                                <option value="Action">Action</option>
                                <option value="Adventure">Adventure</option>
                                <option value="RPG">RPG</option>
                                <option value="Strategy">Strategy</option>
                                <option value="Simulation">Simulation</option>
                                <option value="Sports">Sports</option>
                                <option value="Racing">Racing</option>
                                <option value="Puzzle">Puzzle</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="gameType" class="form-label">Game Type</label>
                            <select class="form-select" id="gameType" name="gameType" required>
                                <option value="">Select Type</option>
                                <option value="Video Game">Video Game</option>
                                <option value="Board Game">Board Game</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="gameCondition" class="form-label">Condition</label>
                            <select class="form-select" id="gameCondition" name="gameCondition" required>
                                <option value="">Select Condition</option>
                                <option value="Excellent">Excellent</option>
                                <option value="Good">Good</option>
                                <option value="Fair">Fair</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="gameAge" class="form-label">Game Age (years)</label>
                            <input type="number" class="form-control" id="gameAge" name="gameAge" min="0" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Game</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Edit Profile Modal -->
    <div class="modal fade" id="editProfileModal" tabindex="-1" aria-labelledby="editProfileModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="editProfileModalLabel">Edit Profile</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form method="POST">
                    <input type="hidden" name="edit_profile" value="1">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="userNameInput" class="form-label">Display Name</label>
                            <input type="text" class="form-control" id="userNameInput" name="userNameInput" value="<?php echo htmlspecialchars($currentUser['first_name'] . ' ' . $currentUser['last_name']); ?>" required>
                        </div>
                        <div class="mb-3">
                            <label for="userEmail" class="form-label">Email</label>
                            <input type="email" class="form-control" id="userEmail" name="userEmail" value="<?php echo htmlspecialchars($currentUser['email']); ?>" required>
                        </div>
                        <div class="mb-3">
                            <label for="userLocation" class="form-label">Location</label>
                            <input type="text" class="form-control" id="userLocation" name="userLocation" value="<?php echo htmlspecialchars($currentUser['location'] ?? ''); ?>">
                        </div>
                        <div class="mb-3">
                            <label for="userBio" class="form-label">Bio</label>
                            <textarea class="form-control" id="userBio" name="userBio" rows="3"><?php echo htmlspecialchars($currentUser['bio'] ?? ''); ?></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Start Exchange Modal -->
    <div class="modal fade" id="startExchangeModal" tabindex="-1" aria-labelledby="startExchangeModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="startExchangeModalLabel">Start New Exchange</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form method="POST">
                    <input type="hidden" name="start_exchange" value="1">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="exchangeGame" class="form-label">Select Your Game to Exchange</label>
                            <select class="form-select" id="exchangeGame" name="exchangeGame" required>
                                <option value="">Select a Game</option>
                                <?php foreach ($userGames as $game): ?>
                                    <?php if ($game['status'] === 'available'): ?>
                                        <option value="<?php echo $game['game_id']; ?>">
                                            <?php echo htmlspecialchars($game['title']); ?> (<?php echo htmlspecialchars($game['genre']); ?>)
                                        </option>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            </select>
                            <?php 
                            $availableGames = array_filter($userGames, function($game) {
                                return $game['status'] === 'available';
                            });
                            if (empty($availableGames)): ?>
                                <div class="text-danger mt-1">
                                    <small>You need to have available games to start an exchange.</small>
                                </div>
                            <?php endif; ?>
                        </div>
                        <div class="mb-3">
                            <label for="targetUsername" class="form-label">Username to Exchange With</label>
                            <input type="text" class="form-control" id="targetUsername" name="targetUsername" placeholder="Enter username" required>
                        </div>
                        <div class="mb-3">
                            <label for="targetGame" class="form-label">Game You Want to Receive</label>
                            <input type="text" class="form-control" id="targetGame" name="targetGame" placeholder="Enter game title" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary" <?php echo empty($availableGames) ? 'disabled' : ''; ?>>Start Exchange</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- File Complaint Modal -->
    <div class="modal fade" id="fileComplaintModal" tabindex="-1" aria-labelledby="fileComplaintModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="fileComplaintModalLabel">File a Complaint</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form method="POST">
                    <input type="hidden" name="submit_complaint" value="1">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="complaintType" class="form-label">Complaint Type</label>
                            <select class="form-select" id="complaintType" name="complaintType" required>
                                <option value="">Select Complaint Type</option>
                                <option value="late_return">Late Return</option>
                                <option value="damaged_game">Damaged Game</option>
                                <option value="wrong_game">Wrong Game Sent</option>
                                <option value="no_communication">No Communication</option>
                                <option value="fraudulent_behavior">Fraudulent Behavior</option>
                                <option value="harassment">Harassment</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="targetUsername" class="form-label">Username of User You're Complaining About</label>
                            <input type="text" class="form-control" id="targetUsername" name="targetUsername" placeholder="Enter username" required>
                        </div>
                        <div class="mb-3">
                            <label for="transaction_id" class="form-label">Related Transaction (Optional)</label>
                            <select class="form-select" id="transaction_id" name="transaction_id">
                                <option value="">Select Transaction (Optional)</option>
                                <?php foreach ($userTransactions as $transaction): ?>
                                    <option value="<?php echo $transaction['transaction_id']; ?>">
                                        <?php echo htmlspecialchars($transaction['type']); ?> - <?php echo htmlspecialchars($transaction['game_title']); ?> 
                                        (<?php echo $transaction['from_username'] == $currentUser['username'] ? 'To: ' . $transaction['to_username'] : 'From: ' . $transaction['from_username']; ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="complaintDescription" class="form-label">Complaint Description</label>
                            <textarea class="form-control" id="complaintDescription" name="complaintDescription" rows="4" placeholder="Please provide detailed information about your complaint..." required></textarea>
                            <div class="form-text">Be specific about what happened and include any relevant details.</div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-warning">Submit Complaint</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Game tab filtering
        document.getElementById('gameTabs').addEventListener('click', function(e) {
            e.preventDefault();
            if (e.target.tagName === 'A') {
                const filter = e.target.getAttribute('data-filter');
                
                // Update active tab
                const tabs = this.querySelectorAll('.nav-link');
                tabs.forEach(tab => tab.classList.remove('active'));
                e.target.classList.add('active');
                
                // Show/hide sections based on filter
                document.getElementById('myGamesSection').style.display = 'none';
                document.getElementById('availableGamesSection').style.display = 'none';
                document.getElementById('onLoanSection').style.display = 'none';
                
                switch(filter) {
                    case 'my_games':
                        document.getElementById('myGamesSection').style.display = 'block';
                        break;
                    case 'available':
                        document.getElementById('availableGamesSection').style.display = 'block';
                        break;
                    case 'on_loan':
                        document.getElementById('onLoanSection').style.display = 'block';
                        break;
                }
            }
        });

        // Game Action Functions
        function sellGame(gameId) {
            alert(`Starting sale process for game ID: ${gameId}`);
        }

        function lendGame(gameId) {
            alert(`Starting lending process for game ID: ${gameId}`);
        }

        function exchangeGame(gameId) {
            alert(`Starting exchange process for game ID: ${gameId}`);
        }

        function requestBorrow(gameId, username) {
            if (confirm(`Request to borrow this game from @${username}?`)) {
                // Create a form and submit it
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = 'dashboard.php';
                
                const gameIdInput = document.createElement('input');
                gameIdInput.type = 'hidden';
                gameIdInput.name = 'game_id';
                gameIdInput.value = gameId;
                
                const ownerInput = document.createElement('input');
                ownerInput.type = 'hidden';
                ownerInput.name = 'owner_username';
                ownerInput.value = username;
                
                const requestType = document.createElement('input');
                requestType.type = 'hidden';
                requestType.name = 'borrow_request';
                requestType.value = '1';
                
                form.appendChild(gameIdInput);
                form.appendChild(ownerInput);
                form.appendChild(requestType);
                
                document.body.appendChild(form);
                form.submit();
            }
        }

        // Auto-focus on username field when exchange modal opens
        document.getElementById('startExchangeModal').addEventListener('shown.bs.modal', function () {
            document.getElementById('targetUsername').focus();
        });

        // Auto-focus on username field when complaint modal opens
        document.getElementById('fileComplaintModal').addEventListener('shown.bs.modal', function () {
            document.getElementById('targetUsername').focus();
        });
    </script>
</body>
</html>