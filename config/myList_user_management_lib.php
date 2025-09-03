<?php
// user_management_lib.php (Dieses File sollte im /config/ Ordner liegen)
// Enthält interne Funktionen zur Benutzerverwaltung, die von öffentlichen APIs aufgerufen werden.

// Optional: Fehler in eine temporäre Datei schreiben, falls sie nicht im Apache-Log auftauchen
// Stellen Sie sicher, dass der Pfad korrekt ist und der Webserver Schreibrechte hat!
// Der Pfad ist relativ zum aktuellen Skript, welches im Ordner 'config' liegt.
// Setzt das Error-Log für DIESES Skript und alle von ihm eingebundenen Skripte.
ini_set('error_log', __DIR__ . '/php_error_debug.log');

// Binde die Konfigurationsdatei ein, die die ENABLE_DEBUG_LOGGING Konstante definiert.
// Die config.php muss sich im selben Verzeichnis wie user_management_lib.php befinden.
require_once(__DIR__ . '/config.php');

// Wichtig: db_config.php und send_email_lib.php müssen im gleichen Verzeichnis (oder absolut erreichbar) sein
require_once __DIR__ . '/myList_db_config.php';
require_once __DIR__ . '/myList_send_email_lib.php'; // Für E-Mail-Versand

if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
    error_log("DEBUG: user_management_lib.php geladen.");
}

// Funktion zur Generierung eines eindeutigen Verifizierungscodes
// Generiert einen rein numerischen Code für einfache Eingabe auf Smartphones
function generateVerificationCode(int $length = 6): string {
    // Generiert eine zufällige Zahl im Bereich von 0 bis 10^length - 1
    // str_pad füllt mit führenden Nullen auf die gewünschte Länge auf
    $min = pow(10, $length - 1);
    $max = pow(10, $length) - 1;
    return str_pad(random_int($min, $max), $length, '0', STR_PAD_LEFT);
}

// Funktion zur Abfrage eines Benutzers anhand der E-Mail
function getUserByEmail(mysqli $conn, string $email): ?array {
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: getUserByEmail() aufgerufen für E-Mail: " . $email);
    }
    $stmt = null;
    try {
        $stmt = $conn->prepare("SELECT id, username, password_hash, email, is_active, email_verification_code, email_verification_expires_at, role FROM users WHERE email = ?");
        if (!$stmt) {
            error_log("FEHLER: Konnte SELECT-Statement für getUserByEmail nicht vorbereiten: " . $conn->error);
            return null;
        }
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        return $user ?: null;
    } catch (Exception $e) {
        error_log("FEHLER in getUserByEmail: " . $e->getMessage());
        return null;
    } finally {
        if ($stmt) {
            try { $stmt->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt in getUserByEmail finally: " . $e->getMessage()); }
        }
    }
}

// Funktion zur Abfrage eines Benutzers anhand des Benutzernamens
function getUserByUsername(mysqli $conn, string $username): ?array {
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: getUserByUsername() aufgerufen für Benutzernamen: " . $username);
    }
    $stmt = null;
    try {
        $stmt = $conn->prepare("SELECT id, username, password_hash, email, is_active, email_verification_code, email_verification_expires_at, role FROM users WHERE username = ?");
        if (!$stmt) {
            error_log("FEHLER: Konnte SELECT-Statement für getUserByUsername nicht vorbereiten: " . $conn->error);
            return null;
        }
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        return $user ?: null;
    } catch (Exception $e) {
        error_log("FEHLER in getUserByUsername: " . $e->getMessage());
        return null;
    } finally {
        if ($stmt) {
            try { $stmt->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt in getUserByUsername finally: " . $e->getMessage()); }
        }
    }
}

// Funktion zur Benutzerregistrierung
function processUserRegistration(string $username, string $password, string $email, string $role = 'user'): array {
    $conn = getDbConnection();
    if (!$conn) {
        error_log("FEHLER: Datenbankverbindung fehlgeschlagen in processUserRegistration.");
        return ["status" => "error", "message" => "Datenbankverbindung fehlgeschlagen."];
    }

    $stmt = null;

    try {
        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("DEBUG: Eingaben für Registrierung erhalten - Benutzername: " . $username . ", E-Mail: " . $email);
        }

        // E-Mail-Format überprüfen
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ["status" => "error", "message" => "Ungültiges E-Mail-Format."];
        }

        // Passwortlänge auf 4 Zeichen geändert (für Testzwecke)
        if (strlen($password) < 4) {
            return ["status" => "error", "message" => "Passwort muss mindestens 4 Zeichen lang sein."];
        }

        // Prüfen, ob Benutzername oder E-Mail bereits existiert
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        if (!$stmt) {
            error_log("FEHLER: Konnte SELECT-Statement für processUserRegistration (Existenzprüfung) nicht vorbereiten: " . $conn->error);
            return ["status" => "error", "message" => "Datenbankfehler."];
        }
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Registrierung fehlgeschlagen - Benutzername oder E-Mail existiert bereits.");
            }
            return ["status" => "error", "message" => "Benutzername oder E-Mail existiert bereits."];
        }
        $stmt->close();
        $stmt = null;

        // Passwort hashen
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        if ($passwordHash === false) {
            error_log("FEHLER: Fehler beim Hashing des Passworts in processUserRegistration.");
            return ["status" => "error", "message" => "Fehler beim Hashing des Passworts."];
        }

        // Verifizierungscode generieren und Ablaufzeit setzen (30 Minuten)
        $verificationCode = generateVerificationCode();
        $expiresAt = date('Y-m-d H:i:s', strtotime('+30 minutes'));

        // Benutzer in die Datenbank einfügen
        $is_active_initial = 0; // Standardmäßig nicht verifiziert
        $stmt = $conn->prepare("INSERT INTO users (username, password_hash, email, role, is_active, email_verification_code, email_verification_expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)");
        if (!$stmt) {
            error_log("FEHLER: Konnte INSERT-Statement für processUserRegistration nicht vorbereiten: " . $conn->error);
            return ["status" => "error", "message" => "Datenbankfehler."];
        }
        $stmt->bind_param("ssssiss", $username, $passwordHash, $email, $role, $is_active_initial, $verificationCode, $expiresAt);

        if ($stmt->execute()) {
            $userId = $conn->insert_id;
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Benutzer erfolgreich registriert. Benutzer-ID: " . $userId);
            }

            // Verifizierungs-E-Mail senden
            if (sendVerificationEmail($email, $username, $verificationCode)) {
                return [
                    "status" => "success",
                    "message" => "Registrierung erfolgreich! Bitte überprüfen Sie Ihre E-Mails, um Ihr Konto zu verifizieren.",
                    "user_id" => $userId,
                    "username" => $username,
                    "email" => $email
                ];
            } else {
                error_log("WARN: E-Mail-Versand für Benutzer " . $email . " fehlgeschlagen.");
                return [
                    "status" => "warning",
                    "message" => "Registrierung erfolgreich, aber E-Mail-Versand fehlgeschlagen. Bitte versuchen Sie später, Ihre E-Mail zu verifizieren.",
                    "user_id" => $userId,
                    "username" => $username,
                    "email" => $email
                ];
            }
        } else {
            error_log("ERROR: Fehler bei der Registrierung des Benutzers: " . $stmt->error);
            return ["status" => "error", "message" => "Fehler bei der Registrierung des Benutzers."];
        }
    } catch (Exception $e) {
        error_log("FEHLER in processUserRegistration: " . $e->getMessage());
        return ["status" => "error", "message" => "Datenbankfehler."];
    } finally {
        if ($stmt) {
            try { $stmt->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt in processUserRegistration finally: " . $e->getMessage()); }
        }
        if ($conn) {
            try { $conn->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen der Verbindung in processUserRegistration finally: " . $e->getMessage()); }
        }
    }
}

// Funktion zur Benutzeranmeldung
function processUserLogin(string $identifier, string $password): array {
    $conn = getDbConnection();
    if (!$conn) {
        error_log("FEHLER: Datenbankverbindung fehlgeschlagen in processUserLogin.");
        return ["status" => "error", "message" => "Datenbankverbindung fehlgeschlagen."];
    }

    $user = null;

    try {
        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("DEBUG: Anmeldeversuch für Identifier: " . $identifier);
        }

        // Prüfen, ob der Identifier eine E-Mail-Adresse ist
        if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
            $user = getUserByEmail($conn, $identifier);
        } else {
            // Andernfalls als Benutzernamen behandeln
            $user = getUserByUsername($conn, $identifier);
        }

        if (!$user) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Anmeldung fehlgeschlagen - Benutzer nicht gefunden für Identifier: " . $identifier);
            }
            return ["status" => "error", "message" => "Ungültige Anmeldedaten."];
        }

        // Prüfen, ob der Account verifiziert ist (is_active)
        if ($user['is_active'] == 0) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Anmeldung fehlgeschlagen - E-Mail nicht verifiziert für Benutzer: " . $user['email']);
            }
            return ["status" => "error", "message" => "Ihr Konto ist noch nicht verifiziert. Bitte überprüfen Sie Ihre E-Mails."];
        }

        // Passwort überprüfen
        if (password_verify($password, $user['password_hash'])) {
            // Session starten und Benutzerdaten speichern
            if (session_status() == PHP_SESSION_NONE) {
                session_start();
            }
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['user_role'] = $user['role']; // Rolle in der Session speichern
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Anmeldung erfolgreich für Benutzer: " . $user['username'] . " (ID: " . $user['id'] . ")");
            }
            return ["status" => "success", "message" => "Anmeldung erfolgreich!", "username" => $user['username'], "email" => $user['email'], "user_id" => $user['id']];
        } else {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Anmeldung fehlgeschlagen - Falsches Passwort für Identifier: " . $identifier);
            }
            return ["status" => "error", "message" => "Ungültige Anmeldedaten."];
        }
    } catch (Exception $e) {
        error_log("FEHLER in processUserLogin: " . $e->getMessage());
        return ["status" => "error", "message" => "Ein Datenbankfehler ist aufgetreten."];
    } finally {
        if ($conn) {
            try { $conn->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen der Verbindung in processUserLogin finally: " . $e->getMessage()); }
        }
    }
}

// Funktion zur Passwortänderung für einen bestimmten Benutzer
function processPasswordChange(int $userId, string $oldPassword, string $newPassword): array {
    $conn = getDbConnection();
    if (!$conn) {
        error_log("FEHLER: Datenbankverbindung fehlgeschlagen in processPasswordChange.");
        return ["status" => "error", "message" => "Datenbankverbindung fehlgeschlagen."];
    }

    $stmt_select = null;
    $stmt_update = null;
    try {
        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("DEBUG: Passwortänderungsversuch für Benutzer-ID: " . $userId);
        }

        // 1. Benutzerdaten abrufen, um das alte Passwort zu überprüfen
        $stmt_select = $conn->prepare("SELECT password_hash FROM users WHERE id = ?");
        if (!$stmt_select) {
            error_log("FEHLER: Konnte SELECT-Statement für processPasswordChange nicht vorbereiten: " . $conn->error);
            return ["status" => "error", "message" => "Datenbankfehler."];
        }
        $stmt_select->bind_param("i", $userId);
        $stmt_select->execute();
        $result = $stmt_select->get_result();
        $user = $result->fetch_assoc();

        if (!$user) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Passwortänderung fehlgeschlagen - Benutzer nicht gefunden mit ID: " . $userId);
            }
            return ["status" => "error", "message" => "Benutzer nicht gefunden."];
        }

        // 2. Altes Passwort verifizieren
        if (!password_verify($oldPassword, $user['password_hash'])) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Passwortänderung fehlgeschlagen - Altes Passwort ist falsch für Benutzer-ID: " . $userId);
            }
            return ["status" => "error", "message" => "Altes Passwort ist falsch."];
        }

        // Passwortlänge prüfen (Testzwecke: < 4; Produktionssysteme: > 8 mit Komplexität)
        if (strlen($newPassword) < 4) {
            return ["status" => "error", "message" => "Neues Passwort muss mindestens 4 Zeichen lang sein."];
        }

        // 3. Neues Passwort hashen und in der Datenbank aktualisieren
        $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        $stmt_update = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        if (!$stmt_update) {
            error_log("FEHLER: Konnte UPDATE-Statement für processPasswordChange nicht vorbereiten: " . $conn->error);
            return ["status" => "error", "message" => "Datenbankfehler."];
        }
        $stmt_update->bind_param("si", $newPasswordHash, $userId);
        $stmt_update->execute();

        if ($stmt_update->affected_rows > 0) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Passwort erfolgreich geändert für Benutzer-ID: " . $userId);
            }
            return ["status" => "success", "message" => "Passwort erfolgreich geändert."];
        } else {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("WARN: Passwort konnte nicht geändert werden für Benutzer-ID " . $userId . " (möglicherweise gleiches Passwort).");
            }
            return ["status" => "warning", "message" => "Passwort konnte nicht geändert werden (möglicherweise gleiches Passwort)."];
        }
    } catch (mysqli_sql_exception $e) {
        error_log("FEHLER: Datenbankfehler in processPasswordChange: " . $e->getMessage());
        return ["status" => "error", "message" => "Ein Datenbankfehler ist aufgetreten."];
    } finally {
        if ($stmt_select) {
            try { $stmt_select->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt_select in processPasswordChange finally: " . $e->getMessage()); }
        }
        if ($stmt_update) {
            try { $stmt_update->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt_update in processPasswordChange finally: " . $e->getMessage()); }
        }
        if ($conn) {
            try { $conn->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen der Verbindung in processPasswordChange finally: " . $e->getMessage()); }
        }
    }
}

// Funktion zur Verifizierung des Benutzers mit einem Code
function verifyUser(string $email, string $code): array {
    $conn = getDbConnection();
    if (!$conn) {
        error_log("FEHLER: Datenbankverbindung fehlgeschlagen in verifyUser.");
        return ["status" => "error", "message" => "Datenbankverbindung fehlgeschlagen."];
    }

    $stmt_select_user = null;
    $stmt_update = null;

    try {
        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("DEBUG: Verifizierungseingabe erhalten - E-Mail: " . $email . ", Code: " . $code);
        }

        // Benutzer anhand der E-Mail abrufen
        $stmt_select_user = $conn->prepare("SELECT id, username, email, is_active, email_verification_code, email_verification_expires_at FROM users WHERE email = ?");
        if (!$stmt_select_user) {
            error_log("FEHLER: Konnte SELECT-Statement für verifyUser (Benutzerabruf) nicht vorbereiten: " . $conn->error);
            return ["status" => "error", "message" => "Datenbankfehler bei der Verifizierung."];
        }
        $stmt_select_user->bind_param("s", $email);
        $stmt_select_user->execute();
        $result = $stmt_select_user->get_result();
        $user = $result->fetch_assoc();

        if (!$user) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Benutzer nicht gefunden für Verifizierungs-E-Mail: " . $email);
            }
            return ["status" => "error", "message" => "Ungültige E-Mail-Adresse oder Verifizierungscode."];
        }

        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("DEBUG: Benutzer gefunden für Verifizierung: " . $user['id']);
        }

        // Prüfen, ob der Code übereinstimmt und noch gültig ist
        if ($user['email_verification_code'] === $code && strtotime($user['email_verification_expires_at']) > time()) {
            // Code ist gültig, Konto verifizieren und Code löschen
            $stmt_update = $conn->prepare("UPDATE users SET is_active = 1, email_verification_code = NULL, email_verification_expires_at = NULL WHERE id = ?");
            if (!$stmt_update) {
                error_log("FEHLER: Konnte UPDATE-Statement für verifyUser nicht vorbereiten: " . $conn->error);
                return ["status" => "error", "message" => "Datenbankfehler bei der Verifizierung."];
            }
            $stmt_update->bind_param("i", $user['id']);
            $stmt_update->execute();

            if ($stmt_update->affected_rows > 0) {
                if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                    error_log("DEBUG: E-Mail für Benutzer " . $user['id'] . " erfolgreich verifiziert. Betroffene Zeilen: " . $stmt_update->affected_rows);
                }
                return ["status" => "success", "message" => "E-Mail erfolgreich verifiziert! Sie können sich jetzt anmelden.", "username" => $user['username'], "email" => $user['email'], "user_id" => $user['id']];
            } else {
                if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                    error_log("WARN: Keine Zeilen betroffen bei der Verifizierung von Benutzer " . $user['id'] . ". Benutzer könnte bereits aktiv sein oder ein Problem ist aufgetreten. Betroffene Zeilen: " . $stmt_update->affected_rows);
                }
                return ["status" => "warning", "message" => "E-Mail konnte nicht verifiziert werden, möglicherweise bereits verifiziert oder ein Problem aufgetreten."];
            }
        } else {
            // Code falsch oder abgelaufen
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Ungültiger oder abgelaufener Verifizierungscode für Benutzer " . $user['id'] . ". Bereitgestellter Code: " . $code . ", Gespeicherter Code: " . ($user['email_verification_code'] ?? 'NULL') . ", Läuft ab: " . ($user['email_verification_expires_at'] ?? 'NULL') . ", Aktuelle Zeit: " . date('Y-m-d H:i:s'));
            }
            return ["status" => "error", "message" => "Ungültiger oder abgelaufener Verifizierungscode."];
        }
    } catch (mysqli_sql_exception $e) {
        error_log("FEHLER: Datenbankfehler in verifyUser: " . $e->getMessage());
        return ["status" => "error", "message" => "Ein Datenbankfehler ist aufgetreten."];
    } finally {
        if ($stmt_select_user) {
            try { $stmt_select_user->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt_select_user in verifyUser finally: " . $e->getMessage()); }
        }
        if ($stmt_update) {
            try { $stmt_update->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt_update in verifyUser finally: " . $e->getMessage()); }
        }
        if ($conn) {
            try { $conn->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen der Verbindung in verifyUser finally: " . $e->getMessage()); }
        }
    }
}

// Funktion zum Anfordern eines Passwort-Resets
function requestPasswordReset(string $email): array {
    $conn = getDbConnection();
    if (!$conn) {
        error_log("FEHLER: Datenbankverbindung fehlgeschlagen in requestPasswordReset.");
        return ["status" => "error", "message" => "Datenbankverbindung fehlgeschlagen."];
    }

    $stmt_update = null;

    try {
        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("DEBUG: Passwort-Reset angefordert für E-Mail: " . $email);
        }

        $user = getUserByEmail($conn, $email);

        if (!$user) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Passwort-Reset-Anfrage fehlgeschlagen - Benutzer nicht gefunden für E-Mail: " . $email);
            }
            // Aus Sicherheitsgründen geben wir hier keine spezifische Fehlermeldung zurück, ob der Benutzer existiert oder nicht.
            return ["status" => "success", "message" => "Wenn die E-Mail-Adresse in unserem System existiert, haben wir Ihnen Anweisungen zum Zurücksetzen Ihres Passworts gesendet."];
        }

        // Neuen Reset-Code generieren
        $resetCode = generateVerificationCode();
        $expiresAt = date('Y-m-d H:i:s', strtotime('+30 minutes')); // Gültigkeit 30 Minuten

        // Reset-Code und Ablaufzeit in der users-Tabelle speichern
        $stmt_update = $conn->prepare("UPDATE users SET email_verification_code = ?, email_verification_expires_at = ? WHERE id = ?");
        if (!$stmt_update) {
            error_log("FEHLER: Konnte UPDATE-Statement für requestPasswordReset nicht vorbereiten: " . $conn->error);
            return ["status" => "error", "message" => "Datenbankfehler."];
        }
        $stmt_update->bind_param("ssi", $resetCode, $expiresAt, $user['id']);
        $stmt_update->execute();

        // E-Mail mit Reset-Code senden
        if (sendPasswordResetEmail($email, $user['username'], $resetCode)) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Passwort-Reset-E-Mail erfolgreich an " . $email . " gesendet.");
            }
            return ["status" => "success", "message" => "Wenn die E-Mail-Adresse in unserem System existiert, haben wir Ihnen Anweisungen zum Zurücksetzen Ihres Passworts gesendet."];
        } else {
            error_log("ERROR: Fehler beim Senden der Passwort-Reset-E-Mail an " . $email);
            return ["status" => "error", "message" => "Fehler beim Senden der Reset-E-Mail."];
        }
    } catch (Exception $e) {
        error_log("FEHLER in requestPasswordReset: " . $e->getMessage());
        return ["status" => "error", "message" => "Datenbankfehler."];
    } finally {
        if ($stmt_update) {
            try { $stmt_update->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt_update in requestPasswordReset finally: " . $e->getMessage()); }
        }
        if ($conn) {
            try { $conn->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen der Verbindung in requestPasswordReset finally: " . $e->getMessage()); }
        }
    }
}

// Funktion zum Zurücksetzen des Passworts mit Code
function resetPassword(int $userId, string $code, string $newPassword): array {
    $conn = getDbConnection();
    if (!$conn) {
        error_log("FEHLER: Datenbankverbindung fehlgeschlagen in resetPassword.");
        return ["status" => "error", "message" => "Datenbankverbindung fehlgeschlagen."];
    }

    $stmt_select = null;
    $stmt_update = null;
    try {
        if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
            error_log("DEBUG: Passwort-Reset-Versuch für Benutzer-ID: " . $userId . ", Code: " . $code);
        }

        // Benutzerdaten abrufen, um Reset-Code und Ablaufzeit zu überprüfen
        $stmt_select = $conn->prepare("SELECT email_verification_code, email_verification_expires_at FROM users WHERE id = ?");
        if (!$stmt_select) {
            error_log("FEHLER: Konnte SELECT-Statement für resetPassword nicht vorbereiten: " . $conn->error);
            return ["status" => "error", "message" => "Datenbankfehler."];
        }
        $stmt_select->bind_param("i", $userId);
        $stmt_select->execute();
        $result = $stmt_select->get_result();
        $user = $result->fetch_assoc();

        if (!$user) {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Passwort-Reset fehlgeschlagen - Benutzer nicht gefunden mit ID: " . $userId);
            }
            return ["status" => "error", "message" => "Ungültige Anfrage."];
        }

        // Prüfen, ob der Reset-Code übereinstimmt und noch gültig ist
        if ($user['email_verification_code'] === $code && strtotime($user['email_verification_expires_at']) > time()) {
            // Code ist gültig, neues Passwort hashen und aktualisieren
            // Passwortlänge auf 4 Zeichen geändert (für Testzwecke)
            if (strlen($newPassword) < 4) {
                return ["status" => "error", "message" => "Neues Passwort muss mindestens 4 Zeichen lang sein."];
            }

            $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
            $stmt_update = $conn->prepare("UPDATE users SET password_hash = ?, email_verification_code = NULL, email_verification_expires_at = NULL WHERE id = ?");
            if (!$stmt_update) {
                error_log("FEHLER: Konnte UPDATE-Statement für resetPassword nicht vorbereiten: " . $conn->error);
                return ["status" => "error", "message" => "Datenbankfehler."];
            }
            $stmt_update->bind_param("si", $newPasswordHash, $userId);
            $stmt_update->execute();

            if ($stmt_update->affected_rows > 0) {
                if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                    error_log("DEBUG: Passwort erfolgreich zurückgesetzt für Benutzer-ID: " . $userId);
                }
                return ["status" => "success", "message" => "Passwort erfolgreich zurückgesetzt! Sie können sich jetzt anmelden."];
            } else {
                if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                    error_log("WARN: Keine Zeilen betroffen beim Zurücksetzen des Passworts für Benutzer " . $userId . ". Passwort könnte gleich sein.");
                }
                return ["status" => "warning", "message" => "Passwort konnte nicht zurückgesetzt werden (möglicherweise gleiches Passwort)."];
            }
        } else {
            if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
                error_log("DEBUG: Ungültiger oder abgelaufener Reset-Code für Benutzer " . $userId . ". Bereitgestellter Code: " . $code . ", Gespeicherter Code: " . ($user['email_verification_code'] ?? 'NULL') . ", Läuft ab: " . ($user['email_verification_expires_at'] ?? 'NULL') . ", Aktuelle Zeit: " . date('Y-m-d H:i:s'));
            }
            return ["status" => "error", "message" => "Ungültiger oder abgelaufener Reset-Code."];
        }
    } catch (mysqli_sql_exception $e) {
        error_log("FEHLER: Datenbankfehler in resetPassword: " . $e->getMessage());
        return ["status" => "error", "message" => "Ein Datenbankfehler ist aufgetreten."];
    } finally {
        if ($stmt_select) {
            try { $stmt_select->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt_select in resetPassword finally: " . $e->getMessage()); }
        }
        if ($stmt_update) {
            try { $stmt_update->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt_update in resetPassword finally: " . $e->getMessage()); }
        }
        if ($conn) {
            try { $conn->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen der Verbindung in resetPassword finally: " . $e->getMessage()); }
        }
    }
}

// Funktion zur Benutzerabmeldung
function processUserLogout(): array {
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: processUserLogout() aufgerufen.");
    }
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    session_unset(); // Alle Session-Variablen entfernen
    session_destroy(); // Session zerstören
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: Session für Logout zerstört.");
    }
    return ["status" => "success", "message" => "Erfolgreich abgemeldet."];
}

// Holen der Benutzerinformationen (nicht das Passwort-Hash zurückgeben!)
function getUserById(mysqli $conn, int $userId): ?array {
    if (defined('ENABLE_DEBUG_LOGGING') && ENABLE_DEBUG_LOGGING === true) {
        error_log("DEBUG: getUserById() aufgerufen für ID: " . $userId);
    }
    $stmt = null;
    try {
        $stmt = $conn->prepare("SELECT id, username, email, is_active, role FROM users WHERE id = ?");
        if (!$stmt) {
            error_log("FEHLER: Konnte SELECT-Statement für getUserById nicht vorbereiten: " . $conn->error);
            return null;
        }
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        return $user ?: null;
    } catch (Exception $e) {
        error_log("FEHLER in getUserById: " . $e->getMessage());
        return null;
    } finally {
        if ($stmt) {
            try { $stmt->close(); } catch (Exception $e) { error_log("WARN: Fehler beim Schließen von stmt in getUserById finally: " . $e->getMessage()); }
        }
    }
}
