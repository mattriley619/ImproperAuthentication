<?php
$secure_mode = true;
session_start();

if ($secure_mode) {
    if (!isset($_SESSION['loggedIn']) || $_SESSION['loggedIn'] !== true) {
        echo "Access denied. Please log in first.";
        exit;
    }
    $access = $_SESSION['access_level'];
} else {
    if (!isset($_COOKIE['loggedIn']) || $_COOKIE['loggedIn'] !== "true") {
        echo "Access denied. Please log in first.";
        exit;
    }
    $access = $_COOKIE['access_level'];
}

echo "Access granted. You are logged in as: <strong>" . htmlspecialchars($access) . "</strong>";
?>
