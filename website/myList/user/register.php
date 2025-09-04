<?php
// Dies ist der absolute Pfad zum Verzeichnis der aktuellen Datei.
$logFile = __DIR__ . '/error_log.txt';

// auth_middleware.php für CORS-Header und JSON-Input-Handling einbinden
// Der Pfad geht zwei Ebenen nach oben (zum htdocs-Root) und dann in den /config/ Ordner.
$auth = dirname(__DIR__, 3) . '/config/myList/myList_auth_middleware.php';
//$message = "Die Dateien wurden am " . date('Y-m-d H:i:s') . " eingebunden.\n";
//$message .= "Pfad zu auth_middleware: " . $auth . "\n";

//error_log($message, 3, $logFile);
require_once $auth;
//$message .= "Nach require once: " . $auth . "\n";
// Die interne Logik-Datei aus dem sicheren /config/ Ordner einbinden
// Der Pfad geht zwei Ebenen nach oben (zum htdocs-Root) und dann in den /config/ Ordner.
$man = dirname(__DIR__, 3) . '/config/myList/myList_user_management_lib.php';
require_once $man;



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

/* $message .= $username . "\n";
$message .= $password . "\n";
$message .= $email . "\n";
$message .= date('Y-m-d H:i:s') . "\n";
error_log($message, 3, $logFile); */

// Die interne Funktion aufrufen
$response = processUserRegistration($username, $password, $email, $role);
error_log($response['message'], 3, $logFile);

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
