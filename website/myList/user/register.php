<?php
// Dies ist der absolute Pfad zum Verzeichnis der aktuellen Datei.
$logFile = __DIR__ . '/config/error_log.txt';

// auth_middleware.php für CORS-Header und JSON-Input-Handling einbinden
// Der Pfad geht zwei Ebenen nach oben (zum htdocs-Root) und dann in den /config/ Ordner.
$auth = dirname(__DIR__, 3) . '/config/myList_auth_middleware.php';

require_once $auth;
error_log($auth, 3, $logFile);

// Die interne Logik-Datei aus dem sicheren /config/ Ordner einbinden
// Der Pfad geht zwei Ebenen nach oben (zum htdocs-Root) und dann in den /config/ Ordner.
$man = dirname(__DIR__, 3) . '/config/myList_user_management_lib.php';
require_once $man;
error_log($man, 3, $logFile);
// Dieser Endpunkt benötigt KEINEN requireAuth() Aufruf,
// da sich Benutzer hier registrieren, bevor sie eingeloggt sind.




// Die Nachricht, die Sie protokollieren möchten.
// Die Variablen werden in doppelte Anführungszeichen eingeschlossen, um sie korrekt auszuwerten.
$message = "Die Dateien wurden am " . date('Y-m-d H:i:s') . " eingebunden.\n";
$message .= "Pfad zu auth_middleware: " . $auth . "\n";
$message .= "Pfad zu user_management_lib: " . $man . "\n";

/**
 * Schreibt eine Nachricht in eine Datei.
 *
 * @param string $message Die zu protokollierende Nachricht.
 * @param int $messageType Der Typ der Nachricht. 3 bedeutet "in eine Datei schreiben".
 * @param string $destination Der Pfad zur Zieldatei.
 */
error_log($message, 3, $logFile);



// Nur POST-Anfragen akzeptieren
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    die(json_encode(["status" => "error", "message" => "Nur POST-Anfragen erlaubt."]));
}

// JSON-Input lesen
$input = getJsonInput();
$username = $input['username'] ?? '';
$password = $input['password'] ?? '';
$email = $input['email'] ?? null;
$role = $input['role'] ?? 'user';

// Die interne Funktion aufrufen
$response = processUserRegistration($username, $password, $email, $role);

// Status-Code basierend auf der Antwort setzen
if ($response['status'] === 'error') {
    if ($response['message'] === "Benutzername oder E-Mail existiert bereits.") {
        http_response_code(409); // Conflict
    } elseif ($response['message'] === "Ungültiges E-Mail-Format." || strpos($response['message'], "Passwort muss mindestens") !== false) {
        http_response_code(400); // Bad Request
    } else {
        http_response_code(500); // Interner Serverfehler für andere Fehler
    }
} else {
    http_response_code(200); // OK
}

// Die gesamte Antwort, einschließlich der user_id (falls vorhanden), als JSON zurückgeben
echo json_encode($response);
?>
