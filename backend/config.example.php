<?php
// Copy to config.php OUTSIDE the web document root. Never commit real credentials.
return [
    'app_key' => 'REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES',
    'api_origin' => 'https://api.gill.ac.ug',
    'frontend_origin' => 'https://admin.gill.ac.ug',
    'db' => [
        'host' => 'localhost',
        'name' => 'REPLACE_WITH_DATABASE_NAME',
        'user' => 'REPLACE_WITH_DATABASE_USER',
        'password' => 'SET_PRIVATELY_ON_THE_HOST',
        'charset' => 'utf8mb4',
    ],
    'smtp' => [
        // Use the exact SMTP server, port, and encryption shown by Webuzo's
        // Email Account > Configure Mail Client screen.
        'host' => 'mail.gill.ac.ug',
        'port' => 587,
        'secure' => 'tls', // 'tls' (STARTTLS) or 'ssl'
        'username' => 'info@gill.ac.ug',
        'password' => 'SET_PRIVATELY_ON_THE_HOST',
        'from_email' => 'info@gill.ac.ug',
        'from_name' => 'Gill International School',
    ],
];
