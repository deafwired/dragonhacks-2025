<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="header">
    <div class="inner-header flex">
        <div class="login">
        <h1>Register</h1>
        <form action="controllers/add-user.php" method="post" class="form login-form">
                <!-- Display error message if there's any error from the session -->
                <?php if (isset($_SESSION['error'])): ?>
                    <p class="error"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></p>
                <?php endif; ?>
                <!-- Input field for username -->
                <label class="form-label" for="email">Email</label>
                <div class="form-group">
                    <!-- SVG icon representing the username input field (Font Awesome) -->
                    <svg class="form-icon-left" width="14" height="14" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 448 512"><!--!Font Awesome Free 6.5.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2024 Fonticons, Inc.--><path d="M224 256A128 128 0 1 0 224 0a128 128 0 1 0 0 256zm-45.7 48C79.8 304 0 383.8 0 482.3C0 498.7 13.3 512 29.7 512H418.3c16.4 0 29.7-13.3 29.7-29.7C448 383.8 368.2 304 269.7 304H178.3z"/></svg>
                    <!-- Username input field, marked as required -->
                    <input class="form-input" type="email" name="email" placeholder="Email" id="email" required>
                </div>
                <!-- Input field for password -->
                <label class="form-label" for="password">Password</label>
                <div class="form-group">
                    <!-- SVG icon representing the password input field (Font Awesome) -->
                    <svg class="form-icon-left" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 448 512"><!--!Font Awesome Free 6.5.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2024 Fonticons, Inc.--><path d="M144 144v48H304V144c0-44.2-35.8-80-80-80s-80 35.8-80 80zM80 192V144C80 64.5 144.5 0 224 0s144 64.5 144 144v48h16c35.3 0 64 28.7 64 64V448c0 35.3-28.7 64-64 64H64c-35.3 0-64-28.7-64-64V256c0-35.3 28.7-64 64-64H80z"/></svg>
                    <!-- Password input field, marked as required -->
                    <input class="form-input" type="password" name="password" placeholder="Password" id="password" required>
                </div>
                <!-- Submit button for logging in -->
                <button class="btn" type="submit" name="register">Register</button>
                <!-- Link to redirect the user to the registration page if they don't have an account -->
                <p class="register-link">Already have an account? 
                <a href="login.php" class="form-link">Login</a></p>
            </form>
        </div>
    </div>
</div> 
</body>
</html>