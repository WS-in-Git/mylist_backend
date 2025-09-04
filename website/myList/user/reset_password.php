<?php
// reset_password.php (Dieses File liegt im /website/renderfarm/ Ordner und ist öffentlich)
// Dieser Endpunkt verarbeitet das Zurücksetzen des Passworts mit einem Code.

// auth_middleware.php für CORS-Header und JSON-Input-Handling einbinden
// Korrigierter Pfad, da auth_middleware.php im übergeordneten /config/ Ordner liegt
require_once dirname(__DIR__, 3) . '/config/myList/myList_auth_middleware.php';
error_log("DEBUG: auth_middleware.php included in reset_password.php.");

// Die interne Logik-Datei aus dem sicheren /config/ Ordner einbinden
require_once dirname(__DIR__, 3) . '/config/myList/myList_user_management_lib.php';
error_log("DEBUG: user_management_lib.php included in reset_password.php.");

// Dieser Endpunkt benötigt KEINE requireAuth() Aufruf.

// Nur POST-Anfragen akzeptieren
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    error_log("ERROR: Invalid request method. Method: " . $_SERVER['REQUEST_METHOD']);
    http_response_code(405); // Method Not Allowed
    die(json_encode(["status" => "error", "message" => "Nur POST-Anfragen erlaubt."]));
}

error_log("DEBUG: Processing POST request in reset_password.php.");

// JSON-Input lesen
$input = getJsonInput();
$email = $input['email'] ?? '';
$code = $input['code'] ?? '';
$newPassword = $input['new_password'] ?? '';

error_log("DEBUG: Received password reset input - Email: " . $email . ", Code: " . $code); // Passwort nicht loggen!

// Grundlegende Validierung
if (empty($email) || empty($code) || empty($newPassword)) {
    error_log("ERROR: Missing fields for password reset.");
    http_response_code(400); // Bad Request
    die(json_encode(["status" => "error", "message" => "Alle Felder sind erforderlich (E-Mail, Code, neues Passwort)."]));
}

// KORRIGIERT: Passwort-Stärke prüfen (Beispiel: Mindestens 4 Zeichen)
if (strlen($newPassword) < 4) {
    error_log("ERROR: New password too short for: " . $email);
    http_response_code(400); // Bad Request
    die(json_encode(["status" => "error", "message" => "Neues Passwort muss mindestens 4 Zeichen lang sein."]));
}

// Benutzer anhand der E-Mail abrufen, um die ID zu bekommen, die für resetPassword gebraucht wird
$conn = getDbConnection();
$user = getUserByEmail($conn, $email);
$conn->close();

if (!$user) {
    error_log("WARNING: Password reset failed - User not found for email: " . $email);
    http_response_code(404); // Not Found
    die(json_encode(["status" => "error", "message" => "Benutzer nicht gefunden."]));
}

error_log("DEBUG: User found for password reset: " . $user['id']);

// Die interne Funktion zum Zurücksetzen des Passworts aufrufen
// Korrektur: Funktion 'resetUserPassword' statt 'resetPassword'
$response = resetPassword((int)$user['id'], $code, $newPassword); // Funktion aus user_management_lib.php

error_log("DEBUG: resetPassword() returned: " . json_encode($response));

// Status-Code basierend auf der Antwort setzen
if ($response['status'] === 'error') {
    http_response_code(400); // Bad Request
} else {
    http_response_code(200); // OK
}

echo json_encode($response);
?>
