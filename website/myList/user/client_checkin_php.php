<?php
// client_checkin_php.php (Liegt im /website/renderfarm/ Ordner)
// Empfängt Client-Check-ins vom FastAPI-Server und aktualisiert die DB.

// auth_middleware.php für CORS-Header und JSON-Input-Handling einbinden
// Korrigierter Pfad, da auth_middleware.php im übergeordneten /config/ Ordner liegt
require_once dirname(dirname(__DIR__)) . '/config/auth_middleware.php';

// db_config.php wird über auth_middleware.php eingebunden
// Der Pfad in auth_middleware.php ist entscheidend für db_config.php.
$conn = getDbConnection(); // getDbConnection() ist in db_config.php definiert

// Nur POST-Anfragen akzeptieren
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die(json_encode(["status" => "error", "message" => "Nur POST-Anfragen erlaubt."]));
}

$input = getJsonInput(); // Funktion aus auth_middleware.php
$client_ip = $input['client_ip'] ?? '';

if (empty($client_ip)) {
    http_response_code(400);
    die(json_encode(["status" => "error", "message" => "Client IP ist erforderlich."]));
}

try {
    // Prüfen, ob Client existiert
    $stmt_check = $conn->prepare("SELECT id FROM clients WHERE ip_address = ?");
    $stmt_check->bind_param("s", $client_ip);
    $stmt_check->execute();
    $result_check = $stmt_check->get_result();
    $client_exists = $result_check->fetch_assoc();
    $stmt_check->close();

    if ($client_exists) {
        // Client existiert, aktualisiere Status und letzten Check-in
        $network_status_online = 'online'; // Variable für Literal
        $stmt_update = $conn->prepare("UPDATE clients SET network_status = ?, last_checkin = CURRENT_TIMESTAMP WHERE ip_address = ?");
        $stmt_update->bind_param("ss", $network_status_online, $client_ip);
        $stmt_update->execute();
        $stmt_update->close();
        echo json_encode(["status" => "success", "message" => "Client " . $client_ip . " erfolgreich eingecheckt."]);
    } else {
        // Client nicht gefunden, füge ihn mit Standardwerten ein
        $insert_name = "Client_" . str_replace('.', '_', $client_ip);
        
        // Variablen für alle Literale, die an bind_param übergeben werden
        $default_user = "N/A";
        $default_mac = "N/A";
        $default_cluster = 0;
        $network_status_online_insert = "online"; // Variable für Literal bei INSERT
        $default_rendering_status = "idle";
        $default_running_programs_json = json_encode([]);
        $default_is_dr_host = 0; // PHP bool false wird zu 0 für MySQL BOOLEAN/TINYINT
        $default_dr_spawner_ips_json = json_encode([]);
        $default_is_dr_spawner = 0; // PHP bool false wird zu 0 für MySQL BOOLEAN/TINYINT

        $stmt_insert = $conn->prepare("INSERT INTO clients (ip_address, name, user, mac_address, cluster_id, network_status, rendering_status, running_programs, is_configured_as_dr_host, dr_spawner_ips, is_configured_as_dr_spawner, last_checkin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)");
        $stmt_insert->bind_param("ssssisssiss", // Typenfolge anpassen falls JSON anders behandelt wird (s ist oft ok)
            $client_ip, 
            $insert_name, 
            $default_user, 
            $default_mac, 
            $default_cluster,
            $network_status_online_insert, // Variable verwendet
            $default_rendering_status, 
            $default_running_programs_json, 
            $default_is_dr_host, 
            $default_dr_spawner_ips_json, 
            $default_is_dr_spawner 
        );
        $stmt_insert->execute();
        $stmt_insert->close();
        echo json_encode(["status" => "success", "message" => "Neuer Client " . $client_ip . " hinzugefügt und eingecheckt."]);
    }

} catch (mysqli_sql_exception $e) {
    if ($e->getCode() == 1062) { // Duplicate entry for UNIQUE key (ip_address)
        // Race condition: Client might have been inserted by another process just now.
        // Treat as success, as the entry exists.
        http_response_code(200); // OK
        echo json_encode(["status" => "success", "message" => "Client " . $client_ip . " bereits vorhanden und eingecheckt (Race Condition)."]);
    } else {
        http_response_code(500);
        error_log("Datenbankfehler in client_checkin_php.php: " . $e->getMessage());
        echo json_encode(["status" => "error", "message" => "Ein Datenbankfehler ist aufgetreten."]);
    }
} finally {
    if ($conn) $conn->close();
}
