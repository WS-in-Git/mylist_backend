<?php
// verify_email.php (Dieses File liegt im /website/renderfarm/ Ordner und ist öffentlich)
// Dieser Endpunkt verarbeitet E-Mail-Verifizierungsanfragen von der Flutter-App.

// auth_middleware.php für CORS-Header und JSON-Input-Handling einbinden
require_once dirname(dirname(__DIR__)) . '/config/auth_middleware.php';
error_log("DEBUG: auth_middleware.php included in verify_email.php.");

// Die interne Logik-Datei aus dem sicheren /config/ Ordner einbinden
require_once dirname(dirname(__DIR__)) . '/config/user_management_lib.php';
error_log("DEBUG: user_management_lib.php included in verify_email.php.");

// Dieser Endpunkt benötigt KEINEN requireAuth() Aufruf,
// da sich Benutzer hier verifizieren, bevor sie eingeloggt sind.

// Nur POST-Anfragen akzeptieren
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    error_log("ERROR: Invalid request method in verify_email.php. Method: " . $_SERVER['REQUEST_METHOD']);
    http_response_code(405); // Method Not Allowed
    die(json_encode(["status" => "error", "message" => "Nur POST-Anfragen erlaubt."]));
}

error_log("DEBUG: Processing POST request in verify_email.php.");

// JSON-Input lesen
$input = getJsonInput();
$email = $input['email'] ?? '';
$code = $input['code'] ?? '';

error_log("DEBUG: Received verification input - Email: " . $email . ", Code: " . $code);

// Grundlegende Validierung
if (empty($email) || empty($code)) {
    error_log("ERROR: Missing fields in verification request.");
    http_response_code(400); // Bad Request
    die(json_encode(["status" => "error", "message" => "E-Mail und Verifizierungscode sind erforderlich."]));
}

error_log("DEBUG: Input validation passed for verification.");

// Die interne Funktion aufrufen
$response = verifyUser($email, $code); // Funktion aus user_management_lib.php

error_log("DEBUG: verifyUser() returned: " . json_encode($response));

// Status-Code basierend auf der Antwort setzen
if ($response['status'] === 'success') {
    // Bei Erfolg den Benutzer automatisch einloggen
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    $_SESSION['user_id'] = $response['user_id'];
    $_SESSION['username'] = $response['username'];
    $_SESSION['user_email'] = $response['email'];
    $_SESSION['user_role'] = 'user'; // Oder die Rolle, die von verifyUser zurückgegeben wird, falls vorhanden

    http_response_code(200); // OK
    // Die Antwort enthält jetzt auch die Benutzerinformationen für die App
    echo json_encode($response);
} elseif ($response['status'] === 'warning') {
    http_response_code(200); // Trotz Warnung erfolgreich verarbeitet
    echo json_encode($response);
} else {
    http_response_code(401); // Unauthorized oder Bad Request je nach Fehlerursache
    echo json_encode($response);
}
?>
