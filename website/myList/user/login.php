<?php

$logFile = __DIR__ . '/error_log.txt';

// Binde die Konfigurationsdatei ein, die die ENABLE_DEBUG_LOGGING Konstante definiert.
// Die config.php muss sich im /config/ Verzeichnis befinden.
require_once dirname(__DIR__, 3) . '/config/myList/myList_config.php';

// auth_middleware.php für CORS-Header und JSON-Input-Handling einbinden
require_once dirname(__DIR__, 3) . '/config/myList/myList_auth_middleware.php';
if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: auth_middleware.php in login.php eingebunden.", 3, $logFile);
}

// Die interne Logik-Datei aus dem sicheren /config/ Ordner einbinden
require_once dirname(__DIR__, 3) . '/config/myList/myList_user_management_lib.php';
if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: user_management_lib.php in login.php eingebunden.", 3, $logFile);
}

// Dieser Endpunkt benötigt KEINEN requireAuth() Aufruf,
// da sich Benutzer hier anmelden, bevor sie eingeloggt sind.

// Nur POST-Anfragen akzeptieren
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    error_log("ERROR: Ungültige Anfragemethode in login.php. Methode: " . $_SERVER['REQUEST_METHOD'], 3, $logFile);
    http_response_code(405); // Method Not Allowed
    die(json_encode(["status" => "error", "message" => "Nur POST-Anfragen erlaubt."]));
}

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: POST-Anfrage in login.php verarbeitet.", 3, $logFile);
}

// JSON-Input lesen
$input = getJsonInput();
$identifier = $input['email'] ?? $input['username'] ?? ''; // Versuche zuerst E-Mail, dann Benutzername
$password = $input['password'] ?? '';
$rememberMe = $input['remember_me'] ?? false; // Optional, für "Angemeldet bleiben"

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: Anmeldeeingabe erhalten - Identifier: " . $identifier, 3, $logFile);
}

// Grundlegende Validierung
if (empty($identifier) || empty($password)) {
    error_log("ERROR: Fehlende Felder in der Anmeldeanfrage.", 3, $logFile);
    http_response_code(400); // Bad Request
    die(json_encode(["status" => "error", "message" => "E-Mail/Benutzername und Passwort sind erforderlich."]));
}

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: Eingabevalidierung für Anmeldung bestanden.", 3, $logFile);
}

// Die interne Funktion aufrufen
// Wir rufen processUserLogin mit dem Identifier auf.
// processUserLogin muss dann intern prüfen, ob es eine E-Mail oder ein Benutzername ist.
$response = processUserLogin($identifier, $password); // Funktion aus user_management_lib.php

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: processUserLogin() hat zurückgegeben: " . json_encode($response), 3, $logFile);
}

// Status-Code basierend auf der Antwort setzen
if ($response['status'] === 'error') {
    http_response_code(401); // Unauthorized
} else {
    http_response_code(200); // OK
}

// Die gesamte Antwort, einschließlich der user_id (falls vorhanden), als JSON zurückgeben
echo json_encode($response);
?>
