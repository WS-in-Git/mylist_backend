<?php
// request_password_reset.php (Dieses File liegt im /website/renderfarm/ Ordner und ist öffentlich)
// Dieser Endpunkt ermöglicht das Anfordern eines Passwort-Reset-Codes.

// auth_middleware.php für CORS-Header und JSON-Input-Handling einbinden
// Korrigierter Pfad, da auth_middleware.php im übergeordneten /config/ Ordner liegt
require_once dirname(dirname(__DIR__)) . '/config/auth_middleware.php';
error_log("DEBUG: auth_middleware.php included in request_password_reset.php.");

// Die interne Logik-Datei aus dem sicheren /config/ Ordner einbinden
require_once dirname(dirname(__DIR__)) . '/config/user_management_lib.php';
error_log("DEBUG: user_management_lib.php included in request_password_reset.php.");

// Dieser Endpunkt benötigt KEINE requireAuth() Aufruf.

// Nur POST-Anfragen akzeptieren
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    error_log("ERROR: Invalid request method. Method: " . $_SERVER['REQUEST_METHOD']);
    http_response_code(405); // Method Not Allowed
    die(json_encode(["status" => "error", "message" => "Nur POST-Anfragen erlaubt."]));
}

error_log("DEBUG: Processing POST request in request_password_reset.php.");

// JSON-Input lesen
$input = getJsonInput();
$email = $input['email'] ?? '';

error_log("DEBUG: Received password reset request for email: " . $email);

// Grundlegende Validierung
if (empty($email)) {
    error_log("ERROR: Missing email for password reset request.");
    http_response_code(400); // Bad Request
    die(json_encode(["status" => "error", "message" => "E-Mail-Adresse ist erforderlich."]));
}

// Die interne Funktion zur Passwort-Reset-Anfrage aufrufen
$response = requestPasswordReset($email); // Funktion aus user_management_lib.php

error_log("DEBUG: requestPasswordReset() returned: " . json_encode($response));

// Status-Code basierend auf der Antwort setzen
if ($response['status'] === 'error') {
    http_response_code(400); // Bad Request
} else {
    http_response_code(200); // OK
}

echo json_encode($response);
?>
