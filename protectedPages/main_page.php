<?php
$secure_mode = true;
session_start();


$servername = "localhost";
$db_username = "root";
$db_password = "";
$dbname = "authen_db";
$pepper = "pepperr23fuhvnce9uhg449vjie@#%%^U%JHBV#@r32fvb4h%$#";

$conn = new mysqli($servername, $db_username, $db_password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['register'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];
        $level = $_POST['level'];

        $salt = bin2hex(random_bytes(16));
        $peppered = hash_hmac("sha256", $password . $salt, $pepper);
        $final_hash = password_hash($peppered, PASSWORD_DEFAULT);

        $stmt = $conn->prepare("INSERT INTO users (username, salt, hashed_password, access_level) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $username, $salt, $final_hash, $level);

        if ($stmt->execute()) {
            if ($secure_mode) {
                $_SESSION['loggedIn'] = true;
                $_SESSION['access_level'] = $level;
          } else {
                setcookie("loggedIn", "true", time() + 3600, "/");
                setcookie("access_level", $level, time() + 3600, "/");
          }
            header("Location: protected.php");
            exit;

        } else {
            if ($conn->errno == 1062) {
                echo "Username already exists.";
            } else {
                echo "Error: " . $stmt->error;
            }
        }

        $stmt->close();

    } elseif (isset($_POST['login'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];

        $stmt = $conn->prepare("SELECT salt, hashed_password, access_level FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 1) {
            $stmt->bind_result($salt, $hashed_password, $access_level);
            $stmt->fetch();

            $peppered = hash_hmac("sha256", $password . $salt, $pepper);
            if (password_verify($peppered, $hashed_password)) {
                if ($secure_mode) {
                    $_SESSION['loggedIn'] = true;
                    $_SESSION['access_level'] = $access_level;
                } else {
                        setcookie("loggedIn", "true", time() + 3600, "/");
                        setcookie("access_level", $access_level, time() + 3600, "/");
                        }
                header("Location: protected.php");
                exit;

            } else {
                echo "Incorrect password.";
            }
        } else {
            echo "User not found.";
        }

        $stmt->close();
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html>
<body>

<?php if ($_GET['mode'] === 'register'): ?>
    <h2>Create Account</h2>
    <form method="POST" action="main_page.php?mode=register">
        Username: <input type="text" name="username" required><br>
        Password: <input type="text" name="password" required><br>
        <label for="level">Access level:</label>
        <select name="level" required>
            <option value="admin">Admin</option>
            <option value="worker">Worker</option>
            <option value="hr">HR</option>
        </select><br>
        <input type="submit" name="register" value="Register">
    </form>

<?php elseif ($_GET['mode'] === 'login'): ?>
    <h2>Login</h2>
    <form method="POST" action="main_page.php?mode=login">
        Username: <input type="text" name="username" required><br>
        Password: <input type="text" name="password" required><br>
        <input type="submit" name="login" value="Login">
    </form>
<?php else: ?>
    <p>Invalid mode. Go back to <a href="index.php">home page</a>.</p>
<?php endif; ?>

</body>
</html>
