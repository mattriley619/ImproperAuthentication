<?php
if (!isset($_COOKIE['loggedIn']) || $_COOKIE['loggedIn'] !== "true") {
    echo "Access denied. Please log in first.";
    exit;
}

echo "Access granted. You are logged in as: <strong>" . htmlspecialchars($_COOKIE['access_level']) . "</strong>";
?>
