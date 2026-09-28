<?php
declare(strict_types=1);

$configFile = dirname(__DIR__) . '/config.php';
if (!is_file($configFile)) {
    http_response_code(503);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'api_not_configured']);
    exit;
}
$config = require $configFile;
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowedOrigin = (string)($config['frontend_origin'] ?? '');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
if ($origin !== '' && hash_equals($allowedOrigin, $origin)) {
    header('Access-Control-Allow-Origin: ' . $allowedOrigin);
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
}
header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token');
header('Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS');

function respond(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

final class ApiError extends RuntimeException
{
    public function __construct(public int $status, string $message)
    {
        parent::__construct($message);
    }
}

function fail(int $status, string $message): never
{
    throw new ApiError($status, $message);
}

function body(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') return [];
    $data = json_decode($raw, true);
    if (!is_array($data)) fail(400, 'invalid_json');
    return $data;
}

function requiredString(array $data, string $key, int $max, bool $trim = true): string
{
    $value = $data[$key] ?? null;
    if (!is_string($value)) fail(422, 'invalid_' . $key);
    $value = $trim ? trim($value) : $value;
    if ($value === '' || mb_strlen($value) > $max) fail(422, 'invalid_' . $key);
    return $value;
}

function optionalString(array $data, string $key, int $max): ?string
{
    if (!array_key_exists($key, $data) || $data[$key] === null || $data[$key] === '') return null;
    if (!is_string($data[$key])) fail(422, 'invalid_' . $key);
    $value = trim($data[$key]);
    if (mb_strlen($value) > $max) fail(422, 'invalid_' . $key);
    return $value;
}

function userPublic(array $user): array
{
    return [
        'id' => (int)$user['id'], 'email' => $user['email'], 'full_name' => $user['full_name'],
        'role' => $user['role'], 'department' => $user['department'],
        'job_title' => $user['job_title'], 'phone' => $user['phone'],
    ];
}

function db(): PDO
{
    global $pdo;
    return $pdo;
}

function currentUser(): array
{
    if (empty($_SESSION['user_id']) || !isset($_SESSION['auth_version'])) fail(401, 'not_authenticated');
    $stmt = db()->prepare('SELECT id,email,full_name,role,department,job_title,phone,is_active,auth_version FROM users WHERE id = ?');
    $stmt->execute([(int)$_SESSION['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user || !(int)$user['is_active'] || (int)$user['auth_version'] !== (int)$_SESSION['auth_version']) {
        $_SESSION = [];
        session_destroy();
        fail(401, 'session_expired');
    }
    return $user;
}

function requireRole(array $user, string $role = 'admin'): void
{
    if ($user['role'] !== $role) fail(403, 'forbidden');
}

function requireCsrf(): void
{
    $received = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $expected = $_SESSION['csrf_token'] ?? '';
    if (!is_string($received) || !is_string($expected) || $expected === '' || !hash_equals($expected, $received)) {
        fail(403, 'csrf_failed');
    }
}

function logEvent(?int $actor, string $event, ?string $type = null, ?int $id = null): void
{
    $stmt = db()->prepare('INSERT INTO audit_events (actor_id,event_name,entity_type,entity_id) VALUES (?,?,?,?)');
    $stmt->execute([$actor, $event, $type, $id]);
}

function tokenRow(string $email, string $rawToken, string $purpose): ?array
{
    $stmt = db()->prepare("SELECT u.id,u.email,u.is_active,t.id AS token_id,t.expires_at FROM users u JOIN password_tokens t ON t.user_id=u.id WHERE u.email=? AND t.token_hash=? AND t.purpose=? ORDER BY t.id DESC LIMIT 1");
    $stmt->execute([strtolower($email), hash('sha256', $rawToken), $purpose]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || strtotime($row['expires_at'] . ' UTC') < time()) return null;
    return $row;
}

function sendPortalMail(array $config, string $to, string $subject, string $html): void
{
    $autoload = dirname(__DIR__) . '/vendor/autoload.php';
    if (!is_file($autoload)) throw new RuntimeException('mailer_dependency_missing');
    require_once $autoload;
    $smtp = $config['smtp'] ?? [];
    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = (string)($smtp['host'] ?? '');
    $mail->SMTPAuth = true;
    $mail->Username = (string)($smtp['username'] ?? '');
    $mail->Password = (string)($smtp['password'] ?? '');
    $mail->Port = (int)($smtp['port'] ?? 587);
    $secure = (string)($smtp['secure'] ?? 'tls');
    $mail->SMTPSecure = $secure === 'ssl' ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
    $mail->CharSet = 'UTF-8';
    $mail->setFrom((string)$smtp['from_email'], (string)($smtp['from_name'] ?? 'Gill International School'));
    $mail->addAddress($to);
    $mail->isHTML(true);
    $mail->Subject = $subject;
    $mail->Body = $html;
    $mail->AltBody = trim(strip_tags(str_replace(['</p>', '<br>'], "\n", $html)));
    $mail->send();
}

function deliverToken(array $config, int $userId, string $email, string $purpose): void
{
    $db = db();
    $db->prepare('DELETE FROM password_tokens WHERE user_id=? AND purpose=?')->execute([$userId, $purpose]);
    $raw = bin2hex(random_bytes(32));
    $expiry = $purpose === 'invite' ? '+48 hours' : '+30 minutes';
    $stmt = $db->prepare('INSERT INTO password_tokens (user_id,token_hash,purpose,expires_at) VALUES (?,?,?,?)');
    $stmt->execute([$userId, hash('sha256', $raw), $purpose, gmdate('Y-m-d H:i:s', strtotime($expiry))]);
    $url = rtrim((string)$config['frontend_origin'], '/') . '/?action=' . rawurlencode($purpose) . '&email=' . rawurlencode($email) . '&token=' . rawurlencode($raw);
    $safeUrl = htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $heading = $purpose === 'invite' ? 'Set up your portal account' : 'Reset your portal password';
    $message = '<p>' . $heading . '</p><p>This link expires ' . ($purpose === 'invite' ? 'in 48 hours' : 'in 30 minutes') . ' and can be used once.</p><p><a href="' . $safeUrl . '">Continue securely</a></p><p>If you did not request this, you can ignore this email.</p>';
    sendPortalMail($config, $email, $heading . ' — Gill International School', $message);
}

function cleanEmail(mixed $email): string
{
    if (!is_string($email)) fail(422, 'invalid_email');
    $email = strtolower(trim($email));
    if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)) fail(422, 'invalid_email');
    return $email;
}

function throttleKey(string $email, array $config): string
{
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    return hash_hmac('sha256', strtolower($email) . '|' . $ip, (string)$config['app_key']);
}

function throttleCheck(string $email, array $config): string
{
    $key = throttleKey($email, $config);
    $stmt = db()->prepare('SELECT failures,window_started_at,blocked_until FROM auth_throttle WHERE throttle_key=?');
    $stmt->execute([$key]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row && $row['blocked_until'] && strtotime($row['blocked_until'] . ' UTC') > time()) fail(429, 'too_many_attempts');
    if ($row && strtotime($row['window_started_at'] . ' UTC') < time() - 900) {
        db()->prepare('DELETE FROM auth_throttle WHERE throttle_key=?')->execute([$key]);
    }
    return $key;
}

function throttleFail(string $key): void
{
    $stmt = db()->prepare('SELECT failures,window_started_at FROM auth_throttle WHERE throttle_key=?');
    $stmt->execute([$key]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || strtotime($row['window_started_at'] . ' UTC') < time() - 900) {
        db()->prepare('REPLACE INTO auth_throttle (throttle_key,failures,window_started_at,blocked_until) VALUES (?,1,UTC_TIMESTAMP(),NULL)')->execute([$key]);
        return;
    }
    $count = (int)$row['failures'] + 1;
    $blocked = $count >= 8 ? gmdate('Y-m-d H:i:s', time() + 900) : null;
    db()->prepare('UPDATE auth_throttle SET failures=?,blocked_until=? WHERE throttle_key=?')->execute([$count, $blocked, $key]);
}

function validDate(?string $value, string $field): ?string
{
    if ($value === null) return null;
    $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value);
    if (!$date || $date->format('Y-m-d') !== $value) fail(422, 'invalid_' . $field);
    return $value;
}

try {
    if ($origin !== '' && !hash_equals($allowedOrigin, $origin)) fail(403, 'origin_not_allowed');
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
    $appKey = (string)($config['app_key'] ?? '');
    if (strlen($appKey) < 32 || str_contains($appKey, 'REPLACE_')) {
        throw new RuntimeException('app_key_not_configured');
    }
    $dbConfig = $config['db'];
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s', $dbConfig['host'], $dbConfig['name'], $dbConfig['charset'] ?? 'utf8mb4');
    $pdo = new PDO($dsn, $dbConfig['user'], $dbConfig['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    session_name('gill_portal_session');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax',
    ]);
    session_start();

    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $path = trim(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/', '/');
    $apiBase = trim((string)($config['api_path'] ?? ''), '/');
    if ($apiBase !== '' && str_starts_with($path, $apiBase . '/')) $path = substr($path, strlen($apiBase) + 1);
    elseif ($apiBase !== '' && $path === $apiBase) $path = '';
    $input = in_array($method, ['POST', 'PATCH', 'PUT'], true) ? body() : [];

    if ($method === 'GET' && $path === 'health') respond(200, ['ok' => true, 'service' => 'gill-staff-api']);

    if ($method === 'POST' && $path === 'auth/login') {
        $email = cleanEmail($input['email'] ?? null);
        $password = is_string($input['password'] ?? null) ? $input['password'] : '';
        $key = throttleCheck($email, $config);
        $stmt = db()->prepare('SELECT id,email,full_name,role,department,job_title,phone,password_hash,is_active,auth_version FROM users WHERE email=? LIMIT 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if (!$user || !(int)$user['is_active'] || !$user['password_hash'] || !password_verify($password, $user['password_hash'])) {
            throttleFail($key);
            fail(401, 'invalid_email_or_password');
        }
        db()->prepare('DELETE FROM auth_throttle WHERE throttle_key=?')->execute([$key]);
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int)$user['id'];
        $_SESSION['auth_version'] = (int)$user['auth_version'];
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        logEvent((int)$user['id'], 'auth.login');
        respond(200, ['user' => userPublic($user), 'csrf_token' => $_SESSION['csrf_token']]);
    }

    if ($method === 'GET' && $path === 'auth/me') {
        $user = currentUser();
        if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        respond(200, ['user' => userPublic($user), 'csrf_token' => $_SESSION['csrf_token']]);
    }

    if ($method === 'POST' && $path === 'auth/logout') {
        $user = currentUser(); requireCsrf();
        logEvent((int)$user['id'], 'auth.logout');
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', ['expires' => time() - 42000, 'path' => $params['path'], 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
        }
        session_destroy();
        respond(200, ['ok' => true]);
    }

    if ($method === 'POST' && $path === 'auth/forgot-password') {
        $email = cleanEmail($input['email'] ?? null);
        $stmt = db()->prepare('SELECT id,email,is_active FROM users WHERE email=? LIMIT 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if ($user && (int)$user['is_active']) {
            try { deliverToken($config, (int)$user['id'], $email, 'reset'); }
            catch (Throwable $e) { error_log('Password reset mail failed: ' . $e->getMessage()); }
        }
        respond(200, ['message' => 'If that active account exists, a reset link has been sent.']);
    }

    if ($method === 'POST' && $path === 'auth/reset-password') {
        $email = cleanEmail($input['email'] ?? null);
        $token = requiredString($input, 'token', 128);
        $password = requiredString($input, 'password', 200, false);
        if (strlen($password) < 12) fail(422, 'password_too_short');
        $row = tokenRow($email, $token, 'reset');
        if (!$row || !(int)$row['is_active']) fail(400, 'invalid_or_expired_token');
        db()->beginTransaction();
        db()->prepare('UPDATE users SET password_hash=?,auth_version=auth_version+1 WHERE id=?')->execute([password_hash($password, PASSWORD_DEFAULT), (int)$row['id']]);
        db()->prepare('DELETE FROM password_tokens WHERE user_id=?')->execute([(int)$row['id']]);
        db()->commit();
        logEvent((int)$row['id'], 'auth.password_reset');
        respond(200, ['ok' => true]);
    }

    if ($method === 'POST' && $path === 'auth/accept-invite') {
        $email = cleanEmail($input['email'] ?? null);
        $token = requiredString($input, 'token', 128);
        $password = requiredString($input, 'password', 200, false);
        if (strlen($password) < 12) fail(422, 'password_too_short');
        $row = tokenRow($email, $token, 'invite');
        if (!$row) fail(400, 'invalid_or_expired_token');
        db()->beginTransaction();
        db()->prepare('UPDATE users SET password_hash=?,is_active=1,auth_version=auth_version+1 WHERE id=?')->execute([password_hash($password, PASSWORD_DEFAULT), (int)$row['id']]);
        db()->prepare('DELETE FROM password_tokens WHERE user_id=?')->execute([(int)$row['id']]);
        db()->commit();
        logEvent((int)$row['id'], 'staff.invite_accepted');
        respond(200, ['ok' => true]);
    }

    if ($method === 'GET' && $path === 'staff') {
        $user = currentUser();
        $stmt = db()->query('SELECT id,email,full_name,role,department,job_title,phone FROM users WHERE is_active=1 ORDER BY full_name');
        respond(200, ['staff' => $stmt->fetchAll()]);
    }

    if ($method === 'POST' && $path === 'staff/invitations') {
        $actor = currentUser(); requireRole($actor); requireCsrf();
        $email = cleanEmail($input['email'] ?? null);
        $name = requiredString($input, 'full_name', 160);
        $department = optionalString($input, 'department', 120);
        $jobTitle = optionalString($input, 'job_title', 120);
        $phone = optionalString($input, 'phone', 40);
        $stmt = db()->prepare("INSERT INTO users (email,full_name,role,department,job_title,phone,is_active) VALUES (?,?, 'staff',?,?,?,0)");
        try { $stmt->execute([$email, $name, $department, $jobTitle, $phone]); }
        catch (PDOException $e) { if ($e->getCode() === '23000') fail(409, 'email_already_invited_or_registered'); throw $e; }
        $id = (int)db()->lastInsertId();
        try {
            deliverToken($config, $id, $email, 'invite');
        } catch (Throwable $e) {
            db()->prepare('DELETE FROM users WHERE id=?')->execute([$id]);
            throw $e;
        }
        logEvent((int)$actor['id'], 'staff.invited', 'user', $id);
        respond(201, ['ok' => true, 'id' => $id]);
    }

    if (preg_match('#^staff/(\d+)$#', $path, $match) && $method === 'PATCH') {
        $actor = currentUser(); requireRole($actor); requireCsrf();
        $id = (int)$match[1];
        $sets = []; $values = [];
        foreach (['full_name' => 160, 'department' => 120, 'job_title' => 120, 'phone' => 40] as $field => $max) {
            if (array_key_exists($field, $input)) { $sets[] = "$field = ?"; $values[] = optionalString($input, $field, $max); }
        }
        if (!$sets) fail(422, 'no_fields_to_update');
        $values[] = $id;
        $stmt = db()->prepare('UPDATE users SET ' . implode(', ', $sets) . ' WHERE id=? AND is_active=1');
        $stmt->execute($values);
        if (!$stmt->rowCount()) fail(404, 'staff_not_found_or_unchanged');
        logEvent((int)$actor['id'], 'staff.updated', 'user', $id);
        respond(200, ['ok' => true]);
    }

    if (preg_match('#^staff/(\d+)$#', $path, $match) && $method === 'DELETE') {
        $actor = currentUser(); requireRole($actor); requireCsrf();
        $id = (int)$match[1];
        if ($id === (int)$actor['id']) fail(422, 'cannot_deactivate_self');
        $stmt = db()->prepare('UPDATE users SET is_active=0,auth_version=auth_version+1 WHERE id=? AND is_active=1');
        $stmt->execute([$id]);
        if (!$stmt->rowCount()) fail(404, 'staff_not_found');
        logEvent((int)$actor['id'], 'staff.deactivated', 'user', $id);
        respond(200, ['ok' => true]);
    }

    if ($method === 'GET' && $path === 'announcements') {
        $user = currentUser();
        if ($user['role'] === 'admin') {
            $stmt = db()->query('SELECT a.id,a.title,a.body,a.is_published,a.created_at,a.updated_at,u.full_name AS author FROM announcements a JOIN users u ON u.id=a.created_by ORDER BY a.created_at DESC');
        } else {
            $stmt = db()->query('SELECT a.id,a.title,a.body,a.is_published,a.created_at,a.updated_at,u.full_name AS author FROM announcements a JOIN users u ON u.id=a.created_by WHERE a.is_published=1 ORDER BY a.created_at DESC');
        }
        respond(200, ['announcements' => $stmt->fetchAll()]);
    }

    if ($method === 'POST' && $path === 'announcements') {
        $actor = currentUser(); requireRole($actor); requireCsrf();
        $title = requiredString($input, 'title', 200);
        $content = requiredString($input, 'body', 20000);
        $published = array_key_exists('is_published', $input) ? (int)(bool)$input['is_published'] : 1;
        $stmt = db()->prepare('INSERT INTO announcements (title,body,created_by,is_published) VALUES (?,?,?,?)');
        $stmt->execute([$title, $content, (int)$actor['id'], $published]);
        $id = (int)db()->lastInsertId();
        logEvent((int)$actor['id'], 'announcement.created', 'announcement', $id);
        respond(201, ['ok' => true, 'id' => $id]);
    }

    if (preg_match('#^announcements/(\d+)$#', $path, $match) && $method === 'PATCH') {
        $actor = currentUser(); requireRole($actor); requireCsrf();
        $id = (int)$match[1]; $sets = []; $values = [];
        if (array_key_exists('title', $input)) { $sets[] = 'title=?'; $values[] = requiredString($input, 'title', 200); }
        if (array_key_exists('body', $input)) { $sets[] = 'body=?'; $values[] = requiredString($input, 'body', 20000); }
        if (array_key_exists('is_published', $input)) { $sets[] = 'is_published=?'; $values[] = (int)(bool)$input['is_published']; }
        if (!$sets) fail(422, 'no_fields_to_update');
        $values[] = $id;
        $stmt = db()->prepare('UPDATE announcements SET ' . implode(',', $sets) . ' WHERE id=?');
        $stmt->execute($values);
        if (!$stmt->rowCount()) fail(404, 'announcement_not_found_or_unchanged');
        logEvent((int)$actor['id'], 'announcement.updated', 'announcement', $id);
        respond(200, ['ok' => true]);
    }

    if (preg_match('#^announcements/(\d+)$#', $path, $match) && $method === 'DELETE') {
        $actor = currentUser(); requireRole($actor); requireCsrf();
        $id = (int)$match[1];
        $stmt = db()->prepare('DELETE FROM announcements WHERE id=?'); $stmt->execute([$id]);
        if (!$stmt->rowCount()) fail(404, 'announcement_not_found');
        logEvent((int)$actor['id'], 'announcement.deleted', 'announcement', $id);
        respond(200, ['ok' => true]);
    }

    if ($method === 'GET' && $path === 'requests') {
        $actor = currentUser();
        if ($actor['role'] === 'admin') {
            $stmt = db()->query('SELECT r.id,r.requester_id,r.category,r.title,r.details,r.date_from,r.date_to,r.status,r.admin_notes,r.reviewed_at,r.created_at,r.updated_at,u.full_name AS requester_name,u.email AS requester_email FROM staff_requests r JOIN users u ON u.id=r.requester_id ORDER BY r.created_at DESC');
        } else {
            $stmt = db()->prepare('SELECT id,requester_id,category,title,details,date_from,date_to,status,admin_notes,reviewed_at,created_at,updated_at FROM staff_requests WHERE requester_id=? ORDER BY created_at DESC');
            $stmt->execute([(int)$actor['id']]);
        }
        respond(200, ['requests' => $stmt->fetchAll()]);
    }

    if ($method === 'POST' && $path === 'requests') {
        $actor = currentUser(); requireCsrf();
        $category = $input['category'] ?? 'other';
        if (!in_array($category, ['leave','maintenance','it','other'], true)) fail(422, 'invalid_category');
        $title = requiredString($input, 'title', 200);
        $details = requiredString($input, 'details', 10000);
        $from = validDate(optionalString($input, 'date_from', 10), 'date_from');
        $to = validDate(optionalString($input, 'date_to', 10), 'date_to');
        if ($from && $to && $to < $from) fail(422, 'date_to_before_date_from');
        $stmt = db()->prepare('INSERT INTO staff_requests (requester_id,category,title,details,date_from,date_to) VALUES (?,?,?,?,?,?)');
        $stmt->execute([(int)$actor['id'], $category, $title, $details, $from, $to]);
        $id = (int)db()->lastInsertId();
        logEvent((int)$actor['id'], 'request.created', 'request', $id);
        respond(201, ['ok' => true, 'id' => $id]);
    }

    if (preg_match('#^requests/(\d+)$#', $path, $match) && $method === 'PATCH') {
        $actor = currentUser(); requireRole($actor); requireCsrf();
        $id = (int)$match[1];
        $status = $input['status'] ?? null;
        if (!in_array($status, ['pending','approved','rejected','closed'], true)) fail(422, 'invalid_status');
        $notes = optionalString($input, 'admin_notes', 10000);
        $stmt = db()->prepare('UPDATE staff_requests SET status=?,admin_notes=?,reviewed_by=?,reviewed_at=UTC_TIMESTAMP() WHERE id=?');
        $stmt->execute([$status, $notes, (int)$actor['id'], $id]);
        if (!$stmt->rowCount()) fail(404, 'request_not_found_or_unchanged');
        logEvent((int)$actor['id'], 'request.reviewed', 'request', $id);
        respond(200, ['ok' => true]);
    }

    fail(404, 'route_not_found');
} catch (ApiError $e) {
    respond($e->status, ['error' => $e->getMessage()]);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) $pdo->rollBack();
    error_log('Gill staff API error: ' . $e->getMessage());
    respond(500, ['error' => 'internal_server_error']);
}
