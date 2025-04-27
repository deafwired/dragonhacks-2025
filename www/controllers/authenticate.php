<?php
// Include the database connection file for database access
require "../models/db-connection.php";
// Start session at the beginning
session_start();

// Check if both username and password are provided through the post request
if (!isset($_POST['email'], $_POST['password'])) {
    // Store the error message in session and redirect back to the login
    $_SESSION['error'] = 'Please fill both the username and password fields!';
    header('Location: ../views/index.php');
    // Ensure script stops here
    die();
}

try {
    // Prepare the SQL statement
    $stmt = $conn->prepare('SELECT * FROM users WHERE email = :email');
    // Bind the username parameter from the POST request to the statement
    $stmt->bindParam(':email', $_POST['email'], PDO::PARAM_STR);
    $stmt->execute();

    // Fetch the user data
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Check if the user exists and if the password matches the hash in the database
    if ($user && password_verify($_POST['password'], $user['password_hash'])) {
        // If the credentials are correct regenerate the session ID
        session_regenerate_id(true);
        // Store the username in the session
        $_SESSION['account_name'] = $_POST['email']; 
        // Redirect to the home page
        header('Location: /');
        exit();
    } else {
        // If the login store an error and redirect the user back to the login
        $_SESSION['error'] = 'Invalid Login';
        header('Location: /login.php');
        exit();
    }
} catch (PDOException $e) {
    // In case of a database error store the error message in the session
    $_SESSION['error'] = 'Database error: Please try again later.';
    // Redirect to the login page
    header('Location: login.php');
    exit();
}
?>