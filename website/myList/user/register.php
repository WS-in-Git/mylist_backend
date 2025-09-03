<?php
// register.php (Dieses File liegt im /website/renderfarm/ Ordner und ist öffentlich)
// Dieser Endpunkt empfängt Registrierungsanfragen von der Flutter-App.

// auth_middleware.php für CORS-Header und JSON-Input-Handling einbinden
// Der Pfad geht zwei Ebenen nach oben (zum htdocs-Root) und dann in den /config/ Ordner.
require_once dirname(dirname(__DIR__)) . '/config/auth_middleware.php';

// Die interne Logik-Datei aus dem sicheren /config/ Ordner einbinden
// Der Pfad geht zwei Ebenen nach oben (zum htdocs-Root) und dann in den /config/ Ordner.
require_once dirname(dirname(__DIR__)) . '/config/user_management_lib.php';

// Dieser Endpunkt benötigt KEINEN requireAuth() Aufruf,
// da sich Benutzer hier registrieren, bevor sie eingeloggt sind.

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
