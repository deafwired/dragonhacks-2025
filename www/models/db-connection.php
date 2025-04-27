<?php
global $conn;

$servername = "localhost";
$username = 'tacklebox';
$password = '#0wmEE<08{3wMw5sxS9';

try {
    $conn = new PDO("mysql:host=$servername;dbname=tacklebox", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}