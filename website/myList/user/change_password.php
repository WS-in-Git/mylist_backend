<?php
// change_password.php (Dieses File liegt im /website/renderfarm/ Ordner und ist öffentlich)
// Dieser Endpunkt verarbeitet Anfragen zur Passwortänderung von der Flutter-App.

// Optional: Fehler in eine temporäre Datei schreiben, falls sie nicht im Apache-Log auftauchen
// Stellen Sie sicher, dass der Pfad korrekt ist und der Webserver Schreibrechte hat!
// Der Pfad ist relativ zum aktuellen Skript, welches im Ordner '/website/renderfarm/' liegt.
// Da auth_middleware und user_management_lib in /config/ liegen, zeigen wir das Log dorthin.
ini_set('error_log', dirname(dirname(__DIR__)) . '/config/php_error_debug.log');

// Binde die Konfigurationsdatei ein, die die ENABLE_DEBUG_LOGGING Konstante definiert.
// Die config.php muss sich im /config/ Verzeichnis befinden.
require_once dirname(__DIR__, 3) . '/config/myList/myList_config.php';

// auth_middleware.php für CORS-Header und JSON-Input-Handling einbinden
require_once dirname(__DIR__, 3) . '/config/myList/myList_auth_middleware.php';
if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: auth_middleware.php in change_password.php eingebunden.");
}

// Die interne Logik-Datei aus dem sicheren /config/ Ordner einbinden
require_once dirname(__DIR__, 3) . '/config/myList/myList_user_management_lib.php';
if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: user_management_lib.php in change_password.php eingebunden.");
}

// requireAuth() aufrufen, da dieser Endpunkt nur für authentifizierte Benutzer zugänglich sein sollte.
// Die Funktion `requireAuth()` sollte sicherstellen, dass `$_SESSION['user_id']` gesetzt ist.
requireAuth();
if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: Benutzer für Passwortänderung authentifiziert. Benutzer-ID: " . $_SESSION['user_id']);
}

// Nur POST-Anfragen akzeptieren
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    error_log("ERROR: Ungültige Anfragemethode in change_password.php. Methode: " . $_SERVER['REQUEST_METHOD']);
    http_response_code(405); // Method Not Allowed
    die(json_encode(["status" => "error", "message" => "Nur POST-Anfragen erlaubt."]));
}

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: POST-Anfrage in change_password.php verarbeitet.");
}

// JSON-Input lesen
$input = getJsonInput();
$oldPassword = $input['old_password'] ?? '';
$newPassword = $input['new_password'] ?? '';

// Hole die user_id aus der Session, die von requireAuth() gesetzt wurde
$userId = $_SESSION['user_id'] ?? null;

if (empty($userId)) {
    error_log("ERROR: Benutzer-ID nicht in Session für Passwortänderungsanfrage gefunden.");
    http_response_code(401); // Unauthorized
    die(json_encode(["status" => "error", "message" => "Nicht autorisiert. Bitte erneut anmelden."]));
}

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: Passwortänderungs-Eingabe für Benutzer-ID erhalten: " . $userId);
}

// Grundlegende Validierung der Passwörter
if (empty($oldPassword) || empty($newPassword)) {
    error_log("ERROR: Fehlende Felder in der Passwortänderungsanfrage für Benutzer-ID: " . $userId);
    http_response_code(400); // Bad Request
    die(json_encode(["status" => "error", "message" => "Altes und neues Passwort sind erforderlich."]));
}

if (strlen($newPassword) < 8) { // Beispiel: Mindestens 8 Zeichen lang
    error_log("ERROR: Neues Passwort zu kurz für Benutzer-ID: " . $userId);
    http_response_code(400); // Bad Request
    die(json_encode(["status" => "error", "message" => "Neues Passwort muss mindestens 8 Zeichen lang sein."]));
}

if ($oldPassword === $newPassword) {
    error_log("ERROR: Neues Passwort ist dasselbe wie altes Passwort für Benutzer-ID: " . $userId);
    http_response_code(400); // Bad Request
    die(json_encode(["status" => "error", "message" => "Neues Passwort darf nicht gleich dem alten sein."]));
}

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: Eingabevalidierung für Passwortänderung bestanden für Benutzer-ID: " . $userId);
}

// Die interne Funktion zum Ändern des Passworts aufrufen
// Die Funktion `processPasswordChange` sollte die Datenbankverbindung und das Statement
// intern verwalten und eine klare JSON-Antwort zurückgeben.
$response = processPasswordChange((int)$userId, $oldPassword, $newPassword); // Annahme: diese Funktion existiert in user_management_lib.php

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: processPasswordChange() hat zurückgegeben: " . json_encode($response));
}

// Status-Code basierend auf der Antwort setzen
if ($response['status'] === 'success') {
    http_response_code(200); // OK
} else {
    // Bei Fehlern einen passenden HTTP-Statuscode senden (z.B. 400 für Bad Request, 401 für Unauthorized)
    if (isset($response['message']) && strpos($response['message'], 'Passwort ist falsch') !== false) {
        http_response_code(401); // Unauthorized
    } else {
        http_response_code(400); // Bad Request für generische Fehler
    }
}

// Stelle sicher, dass IMMER eine JSON-Antwort gesendet wird.
echo json_encode($response);
exit(); // Wichtig, um sicherzustellen, dass keine weiteren Ausgaben erfolgen
?>
