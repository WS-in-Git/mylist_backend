<?php
// myList_auth_middleware.php
// Stellt CORS-Header, Session-Management und JSON-Input-Handling bereit.


// Optional: Fehler in eine temporäre Datei schreiben, falls sie nicht im Apache-Log auftauchen
// Stellen Sie sicher, dass der Pfad korrekt ist und der Webserver Schreibrechte hat!
// Der Pfad ist relativ zum aktuellen Skript, welches im Ordner 'config' liegt.
// Setzt das Error-Log für DIESES Skript und alle von ihm eingebundenen Skripte.
ini_set('error_log', __DIR__ . '/php_error_debug.log');

// Binde die Konfigurationsdatei ein, die die ENABLE_DEBUG_LOGGING Konstante definiert.
// Die config.php muss sich im selben Verzeichnis wie auth_middleware.php befinden.
require_once(__DIR__ . '/myList_config.php');

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: myList_auth_middleware.php gestartet.");
}

// CORS-Header setzen, um Zugriffe von anderen Domains zu erlauben (für Flutter/FastAPI)
header("Access-Control-Allow-Origin: *"); // Erlaube alle Ursprünge für Entwicklung
header("Access-Control-Allow-Methods: GET, POST, OPTIONS, DELETE, PUT");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key, X-Requested-With");
header("Access-Control-Allow-Credentials: true");

// OPTIONS-Anfragen (Preflight-Anfragen) sofort beantworten
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Session starten - Muss vor jeglicher Ausgabe erfolgen und nur einmal aufgerufen werden
if (session_status() == PHP_SESSION_NONE) {
    session_start();

    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: Session gestartet.");
    }
}

// DB-Config einbinden - NACH session_start() und HEADERN, um "headers already sent" zu vermeiden
// Wenn auth_middleware.php im /config/ Ordner liegt und db_config.php auch dort ist:
require_once __DIR__ . '/myList_db_config.php'; // KORREKTER PFAD FÜR auth_middleware.php!

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: myList_db_config.php in auth_middleware.php eingebunden.");
}

// Hilfsfunktion zum Prüfen, ob der Request-Content-Type JSON ist
function isJsonRequest() {
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: Überprüfe, ob Request JSON ist. Content-Type: " . ($_SERVER["CONTENT_TYPE"] ?? 'Nicht gesetzt'));
    }
    return isset($_SERVER["CONTENT_TYPE"]) && strpos($_SERVER["CONTENT_TYPE"], "application/json") !== false;
}

// Hilfsfunktion zum Lesen des JSON-Request-Bodys (alte Funktion beibehalten)
function getJsonInput() {
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: getJsonInput() aufgerufen.");
    }
    if (!isJsonRequest()) {
        http_response_code(400); // Bad Request
        die(json_encode(["status" => "error", "message" => "Ungültiger Content-Type. Erwarte application/json."]));
    }
    $input = file_get_contents('php://input');
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: Raw JSON Input: " . $input);
    }
    $data = json_decode($input, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("ERROR: Ungültiges JSON-Format. Fehlercode: " . json_last_error() . ". Input: " . $input);
        }
        http_response_code(400); // Bad Request
        die(json_encode(["status" => "error", "message" => "Ungültiges JSON-Format."]));
    }
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: JSON Input erfolgreich geparst.");
    }
    return $data;
}

// Funktion zur Validierung des API-Keys (für zukünftige Nutzung, z.B. wenn Flutter direkt FastAPI anspricht)
function validateApiKey($required_key) {
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: validateApiKey() aufgerufen.");
    }
    // API-Key könnte im Header "Authorization" oder "X-API-Key" erwartet werden
    $api_key = $_SERVER['HTTP_X_API_KEY'] ?? ''; // X-API-Key für FastAPI

    if (empty($api_key) || $api_key !== $required_key) {
        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("ERROR: Unautorisierter Zugriff - Ungültiger API Key. Bereitgestellt: " . $api_key . ", Erwartet: " . $required_key);
        }
        http_response_code(401); // Unauthorized
        die(json_encode(["status" => "error", "message" => "Nicht autorisiert: Ungültiger API-Schlüssel."]));
    }
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: API Key erfolgreich validiert.");
    }
}

// Funktion, um den Zugriff nur für authentifizierte Benutzer zu erlauben
function requireAuth() {
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: requireAuth() aufgerufen.");
    }
    if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("ERROR: Unautorisierter Zugriff - Benutzer nicht eingeloggt. Session ID: " . session_id() . ", User ID in Session: " . ($_SESSION['user_id'] ?? 'Nicht gesetzt'));
        }
        session_unset(); // Alle Session-Variablen entfernen
        session_destroy(); // Session zerstören
        http_response_code(401); // Unauthorized
        die(json_encode(["status" => "error", "message" => "Nicht autorisiert: Nicht eingeloggt."]));
    }
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: Benutzer authentifiziert. User ID: " . $_SESSION['user_id']);
    }
}
