<?php
// Run only from the command line after importing schema.sql and configuring config.php.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$configFile = dirname(__DIR__) . '/config.php';
if (!is_file($configFile)) {
    fwrite(STDERR, "Missing backend/config.php. Copy config.example.php and set private values first.\n");
    exit(1);
}
$config = require $configFile;
$dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s', $config['db']['host'], $config['db']['name'], $config['db']['charset'] ?? 'utf8mb4');
try {
    $db = new PDO($dsn, $config['db']['user'], $config['db']['password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
} catch (Throwable $e) {
    fwrite(STDERR, "Database connection failed. Check private config values.\n");
    exit(1);
}

$email = strtolower(trim(readline('Admin email [info@gill.ac.ug]: ') ?: 'info@gill.ac.ug'));
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Invalid email address.\n");
    exit(1);
}
$name = trim(readline('Admin display name: '));
if ($name === '') {
    fwrite(STDERR, "Display name is required.\n");
    exit(1);
}
fwrite(STDOUT, "Choose a NEW portal password (not the mailbox password).\n");
$password = readline('Portal password: ');
if (strlen($password) < 12) {
    fwrite(STDERR, "Use at least 12 characters.\n");
    exit(1);
}
$confirm = readline('Confirm portal password: ');
if (!hash_equals($password, $confirm)) {
    fwrite(STDERR, "Passwords did not match.\n");
    exit(1);
}

$stmt = $db->prepare("INSERT INTO users (email, full_name, role, password_hash, is_active) VALUES (?, ?, 'admin', ?, 1)");
try {
    $stmt->execute([$email, $name, password_hash($password, PASSWORD_DEFAULT)]);
    fwrite(STDOUT, "Admin account created. Remove this script from the server after setup.\n");
} catch (PDOException $e) {
    fwrite(STDERR, $e->getCode() === '23000' ? "That email already has an account.\n" : "Could not create admin account.\n");
    exit(1);
}
