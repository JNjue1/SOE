<?php
require_once 'config.php';

// Handle signup form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['signup'])) {
    $firstName = $_POST['firstName'] ?? '';
    $lastName = $_POST['lastName'] ?? '';
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirmPassword'] ?? '';
    
    $errors = [];
    
    // Validation
    if (empty($firstName)) $errors['firstName'] = 'First name is required';
    if (empty($lastName)) $errors['lastName'] = 'Last name is required';
    
    if (empty($email)) {
        $errors['email'] = 'Email is required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = 'Please enter a valid email address';
    } else {
        // Check if email already exists in database
        $pdo = getDBConnection();
        $stmt = $pdo->prepare("SELECT user_id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $errors['email'] = 'Email already registered';
        }
    }
    
    if (empty($password)) {
        $errors['password'] = 'Password is required';
    } elseif (strlen($password) < 8) {
        $errors['password'] = 'Password must be at least 8 characters';
    }
    
    if (empty($confirmPassword)) {
        $errors['confirmPassword'] = 'Please confirm your password';
    } elseif ($password !== $confirmPassword) {
        $errors['confirmPassword'] = 'Passwords do not match';
    }
    
    // If no errors, create user in database
    if (empty($errors)) {
        $pdo = getDBConnection();
        
        try {
            // Generate username from email
            $username = strtolower($firstName . $lastName . rand(100, 999));
            
            // Hash password
            $passwordHash = hashPassword($password);
            
            // Insert user into database
            $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash, first_name, last_name, rating, complaints) VALUES (?, ?, ?, ?, ?, 5.0, 0)");
            $stmt->execute([$username, $email, $passwordHash, $firstName, $lastName]);
            
            // Get the newly created user - FIXED: using user_id instead of id
            $userId = $pdo->lastInsertId();
            $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
            $stmt->execute([$userId]);
            $newUser = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Store user in session
            $_SESSION['current_user'] = $newUser;
            
            header('Location: dashboard.php');
            exit();
            
        } catch (PDOException $e) {
            $errors['general'] = 'Registration failed. Please try again. Error: ' . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GameSwap - Sign Up</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Your existing CSS styles */
        :root {
            --primary: #4361ee;
            --secondary: #3f37c9;
            --success: #4cc9f0;
            --light: #f8f9fa;
            --dark: #212529;
            --warning: #f72585;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        
        .auth-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            max-width: 450px;
            width: 100%;
            margin: 2rem auto;
        }
        
        .auth-header {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .auth-body {
            padding: 2rem;
        }
        
        .form-control {
            border-radius: 10px;
            padding: 0.75rem 1rem;
            border: 1px solid #e1e5e9;
            transition: all 0.3s;
        }
        
        .form-control:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 0.2rem rgba(67, 97, 238, 0.25);
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border: none;
            border-radius: 10px;
            padding: 0.75rem;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(67, 97, 238, 0.4);
        }
        
        .auth-switch {
            text-align: center;
            margin-top: 1.5rem;
            color: #6c757d;
        }
        
        .auth-switch a {
            color: var(--primary);
            text-decoration: none;
            font-weight: 600;
        }
        
        .error-message {
            color: #dc3545;
            font-size: 0.875rem;
            margin-top: 0.25rem;
        }
    </style>
</head>
<body>
    <!-- Signup Form -->
    <div class="auth-container">
        <div class="auth-header">
            <h1><i class="fas fa-gamepad me-2"></i>GameSwap</h1>
            <p class="mb-0">Create your account to start trading games</p>
        </div>
        <div class="auth-body">
            <form id="signupForm" method="POST">
                <input type="hidden" name="signup" value="1">
                <div class="row">
                    <div class="col-md-6 mb-3">
                        <label for="firstName" class="form-label">First Name</label>
                        <input type="text" class="form-control" id="firstName" name="firstName" placeholder="First name" required value="<?php echo isset($_POST['firstName']) ? htmlspecialchars($_POST['firstName']) : ''; ?>">
                        <?php if (isset($errors['firstName'])): ?>
                            <div class="error-message"><?php echo htmlspecialchars($errors['firstName']); ?></div>
                        <?php endif; ?>
                    </div>
                    <div class="col-md-6 mb-3">
                        <label for="lastName" class="form-label">Last Name</label>
                        <input type="text" class="form-control" id="lastName" name="lastName" placeholder="Last name" required value="<?php echo isset($_POST['lastName']) ? htmlspecialchars($_POST['lastName']) : ''; ?>">
                        <?php if (isset($errors['lastName'])): ?>
                            <div class="error-message"><?php echo htmlspecialchars($errors['lastName']); ?></div>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="mb-3">
                    <label for="signupEmail" class="form-label">Email Address</label>
                    <input type="email" class="form-control" id="signupEmail" name="email" placeholder="Enter your email" required value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
                    <?php if (isset($errors['email'])): ?>
                        <div class="error-message"><?php echo htmlspecialchars($errors['email']); ?></div>
                    <?php endif; ?>
                </div>
                <div class="mb-3">
                    <label for="signupPassword" class="form-label">Password</label>
                    <input type="password" class="form-control" id="signupPassword" name="password" placeholder="Create a password" required>
                    <?php if (isset($errors['password'])): ?>
                        <div class="error-message"><?php echo htmlspecialchars($errors['password']); ?></div>
                    <?php endif; ?>
                </div>
                <div class="mb-3">
                    <label for="confirmPassword" class="form-label">Confirm Password</label>
                    <input type="password" class="form-control" id="confirmPassword" name="confirmPassword" placeholder="Confirm your password" required>
                    <?php if (isset($errors['confirmPassword'])): ?>
                        <div class="error-message"><?php echo htmlspecialchars($errors['confirmPassword']); ?></div>
                    <?php endif; ?>
                </div>
                <?php if (isset($errors['general'])): ?>
                    <div class="alert alert-danger"><?php echo htmlspecialchars($errors['general']); ?></div>
                <?php endif; ?>
                <button type="submit" class="btn btn-primary w-100">Create Account</button>
            </form>
            <div class="auth-switch">
                Already have an account? <a href="index.php">Login</a>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>