<?php
// Require the darabase connection file to access the database
require '../models/db-connection.php';

// Start a new session
session_start();

// Function to check if the username is unique
function isUsernameUnique($email) {
    global $conn;
    // Prepare a SQL query to count the number of users with the same username
    $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    // If the result is 0 it is unique 
    return $stmt->fetchColumn() == 0;
}

// Function to add the user's creds to the database
function addUser($email, $password) {
    global $conn;

    // Check if username is unique
    if (!isUsernameUnique($email)) {
        // Set and error message and redirect to the register page
        $_SESSION['error'] = 'email already registered';
        header('Location: /register.php');
        exit();
    }

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    try {
        // Prepare the SQL quert to insert the user into the user's table
        $stmt = $conn->prepare("INSERT INTO users (email, password_hash) VALUES (:email, :password)");
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->execute();

        // If successful store the username in the session and redirect to the home page
        $_SESSION['account_name'] = $email;
        header('Location: /index.php');
    } catch (PDOException $e) {
        // If an error occurs store the error message and redirect to the register page
        $_SESSION['error'] = $e->getMessage();
        header('Location: /register.php');
    }
}

// Check if the form was submitted by verifying the register field
if (isset($_POST['register'])) {
    // Get the username and password
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Call the addUser function
    addUser($email, $password);
} else { 
    // If the form was not submitted or missing data set an error message
    $_SESSION['error'] = 'fill in both username and password fields';
    // Redirect the user back to the registration page
    header('Location: /register.php');
    exit();
}
?>