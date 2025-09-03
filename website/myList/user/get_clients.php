<?php
// get_clients.php (Dieses File liegt im /website/renderfarm/ Ordner und ist öffentlich)
// Ruft alle Client-Informationen aus der Datenbank ab.

// auth_middleware.php für Session-Handling, CORS und requireAuth() einbinden
// Korrigierter Pfad, da auth_middleware.php im übergeordneten /config/ Ordner liegt
require_once dirname(dirname(__DIR__)) . '/config/auth_middleware.php';

// db_config.php wird über auth_middleware.php eingebunden

// Sicherstellen, dass der Benutzer authentifiziert ist, bevor die Client-Daten abgerufen werden
requireAuth(); // Diese Funktion stellt sicher, dass der Benutzer eingeloggt ist

// Datenbankverbindung holen
$conn = getDbConnection();

$clients = [];
$stmt = null; // Statement-Variable initialisieren, um sie im finally-Block schließen zu können

try {
    $stmt = $conn->prepare("SELECT id, ip_address, name, user, mac_address, cluster_id, network_status, rendering_status, running_programs, last_checkin FROM clients");
    if (!$stmt) {
        error_log("FEHLER: Konnte SELECT-Statement für Clients nicht vorbereiten: " . $conn->error);
        http_response_code(500);
        die(json_encode(["status" => "error", "message" => "Datenbankfehler beim Abrufen der Clients."]));
    }
    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        // JSON-String für running_programs dekodieren
        $running_programs = [];
        if (!empty($row['running_programs'])) {
            $decoded_programs = json_decode($row['running_programs'], true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $running_programs = $decoded_programs;
            } else {
                error_log("Fehler beim Dekodieren von running_programs für Client " . $row['ip_address'] . ": " . $row['running_programs']);
            }
        }
        
        $clients[] = [
            "id" => (int)$row['id'],
            "ip" => $row['ip_address'],
            "name" => $row['name'],
            "user" => $row['user'],
            "mac" => $row['mac_address'],
            "cluster" => (int)$row['cluster_id'],
            "status" => $row['network_status'], // 'network_status' verwenden
            "running_programs" => $running_programs,
            "last_checkin" => $row['last_checkin'] // Letzter Check-in Zeitstempel
        ];
    }

    echo json_encode(["status" => "success", "clients" => $clients]);

} catch (mysqli_sql_exception $e) {
    http_response_code(500);
    error_log("Datenbankfehler in get_clients.php: " . $e->getMessage());
    echo json_encode(["status" => "error", "message" => "Ein Datenbankfehler ist aufgetreten."]);
} finally {
    if ($stmt) $stmt->close();
    if ($conn) $conn->close();
}
?>
