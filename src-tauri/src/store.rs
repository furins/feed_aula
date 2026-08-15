use aes_gcm::{
    aead::{Aead, KeyInit, Nonce, Payload},
    Aes256Gcm,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tauri::{AppHandle, Manager, State};
use zeroize::{Zeroize, Zeroizing};

const DATA_DB_NAME: &str = "feed.db";
const IDENTITIES_DB_NAME: &str = "identities.db";
const KEY_ENVELOPE_NAME: &str = "keys.json";
const KEY_ENVELOPE_TEMP_NAME: &str = "keys.json.tmp";
const MIN_PASSWORD_LEN: usize = 12;

const KEY_ENVELOPE_VERSION: u32 = 1;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

// Parametri espliciti, memorizzati anche nell'envelope per consentire future migrazioni.
const ARGON2_M_COST_KIB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

const DATA_KEY_AAD: &[u8] = b"FEED:data-key:v1";
const IDENTITIES_KEY_AAD: &[u8] = b"FEED:identities-key:v1";

pub struct StoreState {
    inner: Mutex<Option<EncryptedStore>>,
}

impl Default for StoreState {
    /// Crea lo stato iniziale dello storage senza alcun archivio aperto.
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

struct EncryptedStore {
    _data: Connection,
    identities: Connection,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyEnvelope {
    version: u32,
    kdf: KdfConfig,
    data_key: WrappedKey,
    identities_key: WrappedKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfConfig {
    algorithm: String,
    salt: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct WrappedKey {
    nonce: String,
    ciphertext: String,
}

/// Restituisce la directory privata in cui FEED conserva i file cifrati.
fn storage_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|path| path.join("data"))
        .map_err(|error| format!("Impossibile determinare la cartella dati: {error}"))
}

/// Costruisce i percorsi dei due database SQLCipher e dell'envelope delle chiavi.
fn store_paths(app: &AppHandle) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let dir = storage_dir(app)?;
    Ok((
        dir.join(DATA_DB_NAME),
        dir.join(IDENTITIES_DB_NAME),
        dir.join(KEY_ENVELOPE_NAME),
    ))
}

/// Verifica che la password rispetti il requisito minimo definito da FEED.
fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "La password deve contenere almeno {MIN_PASSWORD_LEN} caratteri."
        ));
    }
    Ok(())
}

/// Genera byte casuali crittograficamente sicuri e li mantiene in memoria azzerabile.
fn random_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::fill(&mut *bytes)
        .map_err(|error| format!("Impossibile ottenere casualità sicura dal sistema: {error}"))?;
    Ok(bytes)
}

/// Deriva dalla password la Key Encryption Key usando Argon2id e i parametri dell'envelope.
fn derive_kek(password: &str, config: &KdfConfig) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    if config.algorithm != "argon2id" {
        return Err("Formato chiavi FEED non supportato.".to_string());
    }

    let salt = BASE64
        .decode(&config.salt)
        .map_err(|_| "Archivio FEED danneggiato: salt non valido.".to_string())?;

    if salt.len() < 8 {
        return Err("Archivio FEED danneggiato: salt troppo corto.".to_string());
    }

    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| format!("Parametri Argon2 non validi: {error}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut *kek)
        .map_err(|error| format!("Impossibile derivare la chiave di protezione: {error}"))?;

    Ok(kek)
}

/// Crea una nuova configurazione Argon2id con salt casuale per un nuovo archivio.
fn new_kdf_config() -> Result<KdfConfig, String> {
    let salt = random_bytes::<SALT_LEN>()?;
    Ok(KdfConfig {
        algorithm: "argon2id".to_string(),
        salt: BASE64.encode(&*salt),
        memory_kib: ARGON2_M_COST_KIB,
        iterations: ARGON2_T_COST,
        parallelism: ARGON2_P_COST,
    })
}

/// Cifra una chiave SQLCipher con AES-256-GCM usando la KEK e l'AAD specifico.
fn wrap_key(kek: &[u8; KEY_LEN], key: &[u8; KEY_LEN], aad: &[u8]) -> Result<WrappedKey, String> {
    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|_| "Impossibile inizializzare la protezione delle chiavi.".to_string())?;
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;

    #[allow(deprecated)]
    let nonce = Nonce::<Aes256Gcm>::from_slice(&*nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: &key[..], aad })
        .map_err(|_| "Impossibile proteggere le chiavi dell'archivio.".to_string())?;

    Ok(WrappedKey {
        nonce: BASE64.encode(&*nonce_bytes),
        ciphertext: BASE64.encode(ciphertext),
    })
}

/// Decifra e valida una chiave SQLCipher protetta nell'envelope.
fn unwrap_key(
    kek: &[u8; KEY_LEN],
    wrapped: &WrappedKey,
    aad: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let nonce_vec = BASE64
        .decode(&wrapped.nonce)
        .map_err(|_| "Archivio FEED danneggiato: nonce non valido.".to_string())?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce_vec
        .try_into()
        .map_err(|_| "Archivio FEED danneggiato: nonce non valido.".to_string())?;
    let ciphertext = BASE64
        .decode(&wrapped.ciphertext)
        .map_err(|_| "Archivio FEED danneggiato: chiave protetta non valida.".to_string())?;

    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|_| "Impossibile inizializzare la protezione delle chiavi.".to_string())?;

    #[allow(deprecated)]
    let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| "Password non valida o archivio FEED danneggiato.".to_string())?,
    );

    if plaintext.len() != KEY_LEN {
        return Err("Archivio FEED danneggiato: lunghezza chiave non valida.".to_string());
    }

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    (&mut *key).copy_from_slice(&plaintext);
    Ok(key)
}

/// Crea l'envelope che protegge separatamente le chiavi dei due database.
fn create_key_envelope(
    password: &str,
    data_key: &[u8; KEY_LEN],
    identities_key: &[u8; KEY_LEN],
) -> Result<KeyEnvelope, String> {
    let kdf = new_kdf_config()?;
    let kek = derive_kek(password, &kdf)?;

    Ok(KeyEnvelope {
        version: KEY_ENVELOPE_VERSION,
        data_key: wrap_key(&kek, data_key, DATA_KEY_AAD)?,
        identities_key: wrap_key(&kek, identities_key, IDENTITIES_KEY_AAD)?,
        kdf,
    })
}

/// Legge e valida dal disco l'envelope contenente le chiavi protette.
fn read_key_envelope(path: &Path) -> Result<KeyEnvelope, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("Impossibile leggere le chiavi dell'archivio: {error}"))?;
    let envelope: KeyEnvelope = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Archivio FEED danneggiato: envelope non valido ({error})."))?;

    if envelope.version != KEY_ENVELOPE_VERSION {
        return Err(format!(
            "Versione archivio FEED non supportata: {}.",
            envelope.version
        ));
    }

    Ok(envelope)
}

/// Scrive l'envelope in modo atomico e applica permessi restrittivi quando disponibili.
fn write_key_envelope(path: &Path, envelope: &KeyEnvelope) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Percorso dell'archivio FEED non valido.".to_string())?;
    let temp_path = parent.join(KEY_ENVELOPE_TEMP_NAME);
    let bytes = serde_json::to_vec_pretty(envelope)
        .map_err(|error| format!("Impossibile serializzare le chiavi dell'archivio: {error}"))?;

    fs::write(&temp_path, bytes)
        .map_err(|error| format!("Impossibile salvare le chiavi dell'archivio: {error}"))?;
    restrict_file_permissions(&temp_path)?;
    fs::rename(&temp_path, path)
        .map_err(|error| format!("Impossibile finalizzare le chiavi dell'archivio: {error}"))?;
    Ok(())
}

#[cfg(unix)]
/// Su sistemi Unix limita il file al solo utente proprietario (modalità 0600).
fn restrict_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|error| format!("Impossibile leggere i permessi dell'archivio: {error}"))?
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("Impossibile proteggere i permessi dell'archivio: {error}"))
}

#[cfg(not(unix))]
/// Su sistemi non Unix non modifica i permessi: la protezione è demandata al sistema operativo.
fn restrict_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Converte una chiave binaria SQLCipher nel PRAGMA raw-key senza conservarne una copia persistente.
fn raw_key_pragma(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut hex = Zeroizing::new(String::with_capacity(KEY_LEN * 2));
    for byte in key {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex.as_str()))
}

/// Apre un database SQLCipher, applica la chiave e configura le opzioni di sicurezza.
fn open_cipher_database(path: &Path, key: &[u8; KEY_LEN]) -> Result<Connection, String> {
    let connection = Connection::open(path)
        .map_err(|error| format!("Impossibile aprire il database cifrato: {error}"))?;

    let key_pragma = raw_key_pragma(key);
    connection
        .execute_batch(&key_pragma)
        .map_err(|error| format!("Impossibile impostare la chiave SQLCipher: {error}"))?;

    connection
        .execute_batch(
            "PRAGMA cipher_memory_security = ON;
             PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA synchronous = FULL;",
        )
        .map_err(|error| format!("Impossibile configurare SQLCipher: {error}"))?;

    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| "Database FEED non leggibile o chiave non valida.".to_string())?;

    Ok(connection)
}

/// Inizializza lo schema del database pseudonimizzato con questionari, sessioni e risposte.
fn create_data_schema(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS meta (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
             );
             INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1');

             CREATE TABLE IF NOT EXISTS questionnaires (
               questionnaire_uuid TEXT PRIMARY KEY,
               code TEXT,
               title TEXT NOT NULL,
               test_type TEXT NOT NULL,
               legend_json TEXT NOT NULL,
               created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
               updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );

             CREATE TABLE IF NOT EXISTS sessions (
               session_uuid TEXT PRIMARY KEY,
               questionnaire_uuid TEXT NOT NULL,
               class_uuid TEXT NOT NULL,
               questionnaire_snapshot_json TEXT NOT NULL,
               started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
               completed_at TEXT,
               FOREIGN KEY(questionnaire_uuid)
                 REFERENCES questionnaires(questionnaire_uuid)
             );

             CREATE TABLE IF NOT EXISTS responses (
               session_uuid TEXT NOT NULL,
               student_uuid TEXT NOT NULL,
               rotation INTEGER NOT NULL CHECK(rotation IN (0, 90, 180, 270)),
               observation TEXT,
               source TEXT NOT NULL DEFAULT 'marker',
               manual_override INTEGER NOT NULL DEFAULT 0
                 CHECK(manual_override IN (0, 1)),
               updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
               PRIMARY KEY(session_uuid, student_uuid),
               FOREIGN KEY(session_uuid)
                 REFERENCES sessions(session_uuid) ON DELETE CASCADE
             );

             CREATE INDEX IF NOT EXISTS idx_responses_student
               ON responses(student_uuid);
             CREATE INDEX IF NOT EXISTS idx_sessions_class
               ON sessions(class_uuid, started_at);
             COMMIT;",
        )
        .map_err(|error| format!("Impossibile inizializzare il database dati: {error}"))
}

/// Inizializza o migra lo schema separato che contiene classi e corrispondenze nominative.
fn create_identity_schema(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS classes (
               class_uuid TEXT PRIMARY KEY,
               label TEXT NOT NULL,
               school_year TEXT,
               created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );",
        )
        .map_err(|error| format!("Impossibile inizializzare il database identità: {error}"))?;

    let version = connection
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| format!("Impossibile leggere la versione delle identità: {error}"))?;

    match version.as_deref() {
        None => {
            connection
                .execute_batch(
                    "BEGIN;
                     CREATE TABLE students (
                       student_uuid TEXT PRIMARY KEY,
                       class_uuid TEXT NOT NULL,
                       roster_number INTEGER NOT NULL CHECK(roster_number > 0),
                       marker_number INTEGER CHECK(marker_number BETWEEN 1 AND 30),
                       display_name TEXT NOT NULL,
                       active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                       created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                       FOREIGN KEY(class_uuid)
                         REFERENCES classes(class_uuid) ON DELETE CASCADE
                     );

                     CREATE INDEX idx_students_class
                       ON students(class_uuid, active, roster_number);

                     CREATE UNIQUE INDEX ux_students_active_roster
                       ON students(class_uuid, roster_number)
                       WHERE active = 1;

                     CREATE UNIQUE INDEX ux_students_active_marker
                       ON students(class_uuid, marker_number)
                       WHERE active = 1 AND marker_number IS NOT NULL;

                     INSERT INTO meta(key, value)
                       VALUES ('schema_version', '2');
                     COMMIT;",
                )
                .map_err(|error| format!("Impossibile creare lo schema identità: {error}"))?;
        }
        Some("1") => migrate_identity_schema_v1_to_v2(connection)?,
        Some("2") => ensure_identity_indexes(connection)?,
        Some(other) => {
            return Err(format!(
                "Versione del database identità non supportata: {other}."
            ));
        }
    }

    Ok(())
}

/// Migra lo schema identità v1 separando il numero d'appello dal marker.
///
/// Per i dati esistenti usa inizialmente lo stesso numero come marker solo
/// nell'intervallo 1..30; l'utente potrà poi correggere le assegnazioni.
fn migrate_identity_schema_v1_to_v2(connection: &Connection) -> Result<(), String> {
    let result = connection.execute_batch(
        "BEGIN IMMEDIATE;

         CREATE TABLE students_v2 (
           student_uuid TEXT PRIMARY KEY,
           class_uuid TEXT NOT NULL,
           roster_number INTEGER NOT NULL CHECK(roster_number > 0),
           marker_number INTEGER CHECK(marker_number BETWEEN 1 AND 30),
           display_name TEXT NOT NULL,
           active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
           created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
           FOREIGN KEY(class_uuid)
             REFERENCES classes(class_uuid) ON DELETE CASCADE
         );

         INSERT INTO students_v2(
           student_uuid, class_uuid, roster_number, marker_number,
           display_name, active, created_at
         )
         SELECT
           student_uuid,
           class_uuid,
           roster_number,
           CASE WHEN roster_number BETWEEN 1 AND 30 THEN roster_number ELSE NULL END,
           display_name,
           active,
           created_at
         FROM students;

         DROP TABLE students;
         ALTER TABLE students_v2 RENAME TO students;

         CREATE INDEX idx_students_class
           ON students(class_uuid, active, roster_number);

         CREATE UNIQUE INDEX ux_students_active_roster
           ON students(class_uuid, roster_number)
           WHERE active = 1;

         CREATE UNIQUE INDEX ux_students_active_marker
           ON students(class_uuid, marker_number)
           WHERE active = 1 AND marker_number IS NOT NULL;

         UPDATE meta SET value = '2' WHERE key = 'schema_version';
         COMMIT;",
    );

    if let Err(error) = result {
        let _ = connection.execute_batch("ROLLBACK;");
        return Err(format!("Impossibile migrare il database identità: {error}"));
    }

    Ok(())
}

/// Ricrea gli indici attesi dallo schema v2 se un archivio è stato aggiornato da una build precedente.
fn ensure_identity_indexes(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_students_class
               ON students(class_uuid, active, roster_number);

             CREATE UNIQUE INDEX IF NOT EXISTS ux_students_active_roster
               ON students(class_uuid, roster_number)
               WHERE active = 1;

             CREATE UNIQUE INDEX IF NOT EXISTS ux_students_active_marker
               ON students(class_uuid, marker_number)
               WHERE active = 1 AND marker_number IS NOT NULL;",
        )
        .map_err(|error| format!("Impossibile verificare gli indici delle identità: {error}"))
}

/// Rimuove i file parziali se la creazione di un nuovo archivio non va a buon fine.
fn cleanup_store_files(data_path: &Path, identities_path: &Path, keys_path: &Path) {
    let _ = fs::remove_file(data_path);
    let _ = fs::remove_file(identities_path);
    let _ = fs::remove_file(keys_path);
    if let Some(parent) = keys_path.parent() {
        let _ = fs::remove_file(parent.join(KEY_ENVELOPE_TEMP_NAME));
    }
}

/// Crea un nuovo archivio FEED con due chiavi casuali indipendenti e relativo envelope.
fn create_new_store(app: &AppHandle, password: &str) -> Result<EncryptedStore, String> {
    validate_password(password)?;

    let dir = storage_dir(app)?;
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Impossibile creare la cartella dati: {error}"))?;

    let (data_path, identities_path, keys_path) = store_paths(app)?;
    if data_path.exists() || identities_path.exists() || keys_path.exists() {
        return Err("Un archivio FEED esiste già su questo dispositivo.".to_string());
    }

    let data_key = random_bytes::<KEY_LEN>()?;
    let identities_key = random_bytes::<KEY_LEN>()?;
    let envelope = create_key_envelope(password, &data_key, &identities_key)?;

    let result = (|| {
        let data = open_cipher_database(&data_path, &data_key)?;
        let identities = open_cipher_database(&identities_path, &identities_key)?;

        create_data_schema(&data)?;
        create_identity_schema(&identities)?;
        restrict_file_permissions(&data_path)?;
        restrict_file_permissions(&identities_path)?;
        write_key_envelope(&keys_path, &envelope)?;

        Ok(EncryptedStore {
            _data: data,
            identities,
        })
    })();

    if result.is_err() {
        cleanup_store_files(&data_path, &identities_path, &keys_path);
    }

    result
}

/// Sblocca un archivio esistente derivando la KEK e riaprendo entrambi i database cifrati.
fn open_existing_store(app: &AppHandle, password: &str) -> Result<EncryptedStore, String> {
    validate_password(password)?;

    let (data_path, identities_path, keys_path) = store_paths(app)?;
    if !data_path.exists() || !identities_path.exists() || !keys_path.exists() {
        return Err(
            "Archivio FEED non inizializzato o incompleto su questo dispositivo.".to_string(),
        );
    }

    let envelope = read_key_envelope(&keys_path)?;
    let kek = derive_kek(password, &envelope.kdf)?;
    let data_key = unwrap_key(&kek, &envelope.data_key, DATA_KEY_AAD)?;
    let identities_key = unwrap_key(&kek, &envelope.identities_key, IDENTITIES_KEY_AAD)?;

    let data = open_cipher_database(&data_path, &data_key)?;
    let identities = open_cipher_database(&identities_path, &identities_key)?;
    create_identity_schema(&identities)?;

    Ok(EncryptedStore {
        _data: data,
        identities,
    })
}

/// Limite coerente con il set di marker FEED attualmente gestito dall'applicazione.
const MAX_MARKER_NUMBER: i64 = 30;
/// Limite prudenziale per il numero d'appello inserito dall'interfaccia.
const MAX_ROSTER_NUMBER: i64 = 9_999;
/// Offset temporaneo usato per rinumerare un gruppo senza violare gli indici univoci.
const ROSTER_SHIFT: i64 = 1_000_000_000;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassRecord {
    class_uuid: String,
    label: String,
    school_year: Option<String>,
    active_students: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StudentRecord {
    student_uuid: String,
    class_uuid: String,
    roster_number: i64,
    marker_number: Option<i64>,
    display_name: String,
    active: bool,
}

/// Genera un UUID versione 4 senza introdurre una dipendenza aggiuntiva.
fn new_uuid_v4() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| format!("Impossibile generare un identificatore sicuro: {error}"))?;

    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

/// Verifica e normalizza un'etichetta obbligatoria inserita dall'utente.
fn required_text(value: String, field: &str, max_len: usize) -> Result<String, String> {
    let normalized = value.trim().to_string();
    if normalized.is_empty() {
        return Err(format!("{field} non può essere vuoto."));
    }
    if normalized.chars().count() > max_len {
        return Err(format!("{field} è troppo lungo."));
    }
    Ok(normalized)
}

/// Normalizza un campo testuale facoltativo trasformando la stringa vuota in NULL.
fn optional_text(value: Option<String>, max_len: usize) -> Result<Option<String>, String> {
    match value {
        Some(value) => {
            let normalized = value.trim().to_string();
            if normalized.is_empty() {
                Ok(None)
            } else if normalized.chars().count() > max_len {
                Err("Il testo inserito è troppo lungo.".to_string())
            } else {
                Ok(Some(normalized))
            }
        }
        None => Ok(None),
    }
}

/// Verifica che il numero d'appello sia positivo e entro un limite ragionevole.
fn validate_roster_number(roster_number: i64) -> Result<(), String> {
    if !(1..=MAX_ROSTER_NUMBER).contains(&roster_number) {
        return Err(format!(
            "Il numero d'appello deve essere compreso tra 1 e {MAX_ROSTER_NUMBER}."
        ));
    }
    Ok(())
}

/// Verifica che il numero del marker appartenga all'intervallo supportato da FEED.
fn validate_marker_number(marker_number: i64) -> Result<(), String> {
    if !(1..=MAX_MARKER_NUMBER).contains(&marker_number) {
        return Err(format!(
            "Il marker deve essere compreso tra 1 e {MAX_MARKER_NUMBER}."
        ));
    }
    Ok(())
}

/// Restituisce un accesso mutabile al database identità solo quando FEED è sbloccato.
fn with_identities<T>(
    state: State<'_, StoreState>,
    operation: impl FnOnce(&mut Connection) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state
        .inner
        .lock()
        .map_err(|_| "Stato del database non disponibile.".to_string())?;
    let store = guard
        .as_mut()
        .ok_or_else(|| "FEED è bloccato. Sblocca l'archivio per continuare.".to_string())?;
    operation(&mut store.identities)
}

/// Converte una riga della tabella studenti nel record inviato al frontend.
fn student_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StudentRecord> {
    Ok(StudentRecord {
        student_uuid: row.get(0)?,
        class_uuid: row.get(1)?,
        roster_number: row.get(2)?,
        marker_number: row.get(3)?,
        display_name: row.get(4)?,
        active: row.get::<_, i64>(5)? == 1,
    })
}

/// Controlla che una classe esista prima di modificarne gli alunni.
fn class_exists(connection: &Connection, class_uuid: &str) -> Result<bool, String> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM classes WHERE class_uuid = ?1)",
            [class_uuid],
            |row| row.get::<_, i64>(0),
        )
        .map(|value| value == 1)
        .map_err(|error| format!("Impossibile verificare la classe: {error}"))
}

/// Controlla se un marker è disponibile tra gli alunni attivi della classe.
fn marker_available(
    connection: &Connection,
    class_uuid: &str,
    marker_number: i64,
    excluding_student_uuid: Option<&str>,
) -> Result<bool, String> {
    let used = if let Some(student_uuid) = excluding_student_uuid {
        connection.query_row(
            "SELECT EXISTS(
               SELECT 1
               FROM students
               WHERE class_uuid = ?1
                 AND active = 1
                 AND marker_number = ?2
                 AND student_uuid <> ?3
             )",
            params![class_uuid, marker_number, student_uuid],
            |row| row.get::<_, i64>(0),
        )
    } else {
        connection.query_row(
            "SELECT EXISTS(
               SELECT 1
               FROM students
               WHERE class_uuid = ?1
                 AND active = 1
                 AND marker_number = ?2
             )",
            params![class_uuid, marker_number],
            |row| row.get::<_, i64>(0),
        )
    }
    .map_err(|error| format!("Impossibile verificare il marker: {error}"))?;

    Ok(used == 0)
}

/// Trova il primo marker non assegnato a un alunno attivo della classe.
fn first_free_marker(connection: &Connection, class_uuid: &str) -> Result<Option<i64>, String> {
    for marker_number in 1..=MAX_MARKER_NUMBER {
        if marker_available(connection, class_uuid, marker_number, None)? {
            return Ok(Some(marker_number));
        }
    }
    Ok(None)
}

/// Sposta in avanti i numeri d'appello a partire dalla posizione richiesta.
///
/// La rinumerazione usa un offset temporaneo per non urtare l'indice univoco
/// sugli alunni attivi durante l'UPDATE.
fn make_roster_space(
    transaction: &Transaction<'_>,
    class_uuid: &str,
    roster_number: i64,
) -> Result<(), String> {
    transaction
        .execute(
            "UPDATE students
             SET roster_number = roster_number + ?3
             WHERE class_uuid = ?1
               AND active = 1
               AND roster_number >= ?2",
            params![class_uuid, roster_number, ROSTER_SHIFT],
        )
        .map_err(|error| format!("Impossibile rinumerare la classe: {error}"))?;

    transaction
        .execute(
            "UPDATE students
             SET roster_number = roster_number - ?3 + 1
             WHERE class_uuid = ?1
               AND active = 1
               AND roster_number >= ?2 + ?3",
            params![class_uuid, roster_number, ROSTER_SHIFT],
        )
        .map_err(|error| format!("Impossibile completare la rinumerazione: {error}"))?;

    Ok(())
}

/// Sposta un alunno attivo a un nuovo numero d'appello e riordina solo l'intervallo coinvolto.
fn move_active_student(
    transaction: &Transaction<'_>,
    class_uuid: &str,
    student_uuid: &str,
    old_roster: i64,
    new_roster: i64,
) -> Result<(), String> {
    if old_roster == new_roster {
        return Ok(());
    }

    let temporary_roster = old_roster + (ROSTER_SHIFT * 2);
    transaction
        .execute(
            "UPDATE students SET roster_number = ?2 WHERE student_uuid = ?1",
            params![student_uuid, temporary_roster],
        )
        .map_err(|error| format!("Impossibile preparare la rinumerazione: {error}"))?;

    let (lower, upper, delta) = if new_roster < old_roster {
        (new_roster, old_roster - 1, 1)
    } else {
        (old_roster + 1, new_roster, -1)
    };

    if lower <= upper {
        transaction
            .execute(
                "UPDATE students
                 SET roster_number = roster_number + ?5
                 WHERE class_uuid = ?1
                   AND active = 1
                   AND student_uuid <> ?2
                   AND roster_number BETWEEN ?3 AND ?4",
                params![class_uuid, student_uuid, lower, upper, ROSTER_SHIFT],
            )
            .map_err(|error| format!("Impossibile spostare i numeri d'appello: {error}"))?;

        transaction
            .execute(
                "UPDATE students
                 SET roster_number = roster_number - ?5 + ?6
                 WHERE class_uuid = ?1
                   AND active = 1
                   AND student_uuid <> ?2
                   AND roster_number BETWEEN ?3 + ?5 AND ?4 + ?5",
                params![class_uuid, student_uuid, lower, upper, ROSTER_SHIFT, delta],
            )
            .map_err(|error| format!("Impossibile completare lo spostamento: {error}"))?;
    }

    transaction
        .execute(
            "UPDATE students SET roster_number = ?2 WHERE student_uuid = ?1",
            params![student_uuid, new_roster],
        )
        .map_err(|error| format!("Impossibile assegnare il nuovo numero d'appello: {error}"))?;

    Ok(())
}

/// Legge dal database l'alunno indicato dopo una modifica.
fn load_student(connection: &Connection, student_uuid: &str) -> Result<StudentRecord, String> {
    connection
        .query_row(
            "SELECT student_uuid, class_uuid, roster_number, marker_number, display_name, active
             FROM students
             WHERE student_uuid = ?1",
            [student_uuid],
            student_from_row,
        )
        .map_err(|error| format!("Impossibile leggere l'alunno: {error}"))
}

#[tauri::command]
/// Restituisce tutte le classi e il numero di alunni attivi in ciascuna.
pub fn list_classes(state: State<'_, StoreState>) -> Result<Vec<ClassRecord>, String> {
    with_identities(state, |connection| {
        let mut statement = connection
            .prepare(
                "SELECT c.class_uuid, c.label, c.school_year,
                        COUNT(s.student_uuid) AS active_students
                 FROM classes c
                 LEFT JOIN students s
                   ON s.class_uuid = c.class_uuid AND s.active = 1
                 GROUP BY c.class_uuid, c.label, c.school_year
                 ORDER BY c.label COLLATE NOCASE, c.school_year COLLATE NOCASE",
            )
            .map_err(|error| format!("Impossibile leggere le classi: {error}"))?;

        let rows = statement
            .query_map([], |row| {
                Ok(ClassRecord {
                    class_uuid: row.get(0)?,
                    label: row.get(1)?,
                    school_year: row.get(2)?,
                    active_students: row.get(3)?,
                })
            })
            .map_err(|error| format!("Impossibile leggere le classi: {error}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("Impossibile leggere le classi: {error}"))
    })
}

#[tauri::command]
/// Crea una nuova classe con UUID stabile nel database delle identità.
pub fn create_class(
    label: String,
    school_year: Option<String>,
    state: State<'_, StoreState>,
) -> Result<ClassRecord, String> {
    let label = required_text(label, "Il nome della classe", 80)?;
    let school_year = optional_text(school_year, 20)?;
    let class_uuid = new_uuid_v4()?;

    with_identities(state, |connection| {
        connection
            .execute(
                "INSERT INTO classes(class_uuid, label, school_year) VALUES (?1, ?2, ?3)",
                params![class_uuid, label, school_year],
            )
            .map_err(|error| format!("Impossibile creare la classe: {error}"))?;

        Ok(ClassRecord {
            class_uuid,
            label,
            school_year,
            active_students: 0,
        })
    })
}

#[tauri::command]
/// Aggiorna etichetta e anno scolastico senza cambiare l'UUID della classe.
pub fn update_class(
    class_uuid: String,
    label: String,
    school_year: Option<String>,
    state: State<'_, StoreState>,
) -> Result<ClassRecord, String> {
    let label = required_text(label, "Il nome della classe", 80)?;
    let school_year = optional_text(school_year, 20)?;

    with_identities(state, |connection| {
        let changed = connection
            .execute(
                "UPDATE classes SET label = ?2, school_year = ?3 WHERE class_uuid = ?1",
                params![class_uuid, label, school_year],
            )
            .map_err(|error| format!("Impossibile aggiornare la classe: {error}"))?;

        if changed == 0 {
            return Err("Classe non trovata.".to_string());
        }

        let active_students = connection
            .query_row(
                "SELECT COUNT(*) FROM students WHERE class_uuid = ?1 AND active = 1",
                [class_uuid.as_str()],
                |row| row.get(0),
            )
            .map_err(|error| format!("Impossibile contare gli alunni: {error}"))?;

        Ok(ClassRecord {
            class_uuid,
            label,
            school_year,
            active_students,
        })
    })
}

#[tauri::command]
/// Restituisce gli alunni della classe, inclusi quelli disattivati, ordinati per numero d'appello.
pub fn list_students(
    class_uuid: String,
    state: State<'_, StoreState>,
) -> Result<Vec<StudentRecord>, String> {
    with_identities(state, |connection| {
        if !class_exists(connection, &class_uuid)? {
            return Err("Classe non trovata.".to_string());
        }

        let mut statement = connection
            .prepare(
                "SELECT student_uuid, class_uuid, roster_number, marker_number, display_name, active
                 FROM students
                 WHERE class_uuid = ?1
                 ORDER BY active DESC, roster_number, display_name COLLATE NOCASE",
            )
            .map_err(|error| format!("Impossibile leggere gli alunni: {error}"))?;

        let rows = statement
            .query_map([class_uuid], student_from_row)
            .map_err(|error| format!("Impossibile leggere gli alunni: {error}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("Impossibile leggere gli alunni: {error}"))
    })
}

#[tauri::command]
/// Crea un alunno attivo, assegna un marker libero e inserisce il numero d'appello nella posizione richiesta.
pub fn create_student(
    class_uuid: String,
    roster_number: i64,
    marker_number: Option<i64>,
    display_name: String,
    state: State<'_, StoreState>,
) -> Result<StudentRecord, String> {
    validate_roster_number(roster_number)?;
    let display_name = required_text(display_name, "Il nominativo", 120)?;
    let student_uuid = new_uuid_v4()?;

    with_identities(state, |connection| {
        if !class_exists(connection, &class_uuid)? {
            return Err("Classe non trovata.".to_string());
        }

        let selected_marker = match marker_number {
            Some(marker_number) => {
                validate_marker_number(marker_number)?;
                if !marker_available(connection, &class_uuid, marker_number, None)? {
                    return Err(format!("Il marker {marker_number} è già assegnato."));
                }
                marker_number
            }
            None => first_free_marker(connection, &class_uuid)?
                .ok_or_else(|| "Non ci sono marker liberi tra 1 e 30.".to_string())?,
        };

        let transaction = connection
            .transaction()
            .map_err(|error| format!("Impossibile iniziare la modifica: {error}"))?;

        make_roster_space(&transaction, &class_uuid, roster_number)?;

        transaction
            .execute(
                "INSERT INTO students(
                   student_uuid, class_uuid, roster_number, marker_number, display_name, active
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                params![
                    student_uuid,
                    class_uuid,
                    roster_number,
                    selected_marker,
                    display_name
                ],
            )
            .map_err(|error| format!("Impossibile aggiungere l'alunno: {error}"))?;

        transaction
            .commit()
            .map_err(|error| format!("Impossibile salvare l'alunno: {error}"))?;

        load_student(connection, &student_uuid)
    })
}

#[tauri::command]
/// Aggiorna nominativo, numero d'appello, marker e stato senza cambiare lo UUID dell'alunno.
///
/// Quando un alunno attivo cambia numero d'appello, gli altri numeri coinvolti
/// vengono spostati automaticamente; il loro marker non viene modificato.
pub fn update_student(
    student_uuid: String,
    roster_number: i64,
    marker_number: Option<i64>,
    display_name: String,
    active: bool,
    state: State<'_, StoreState>,
) -> Result<StudentRecord, String> {
    validate_roster_number(roster_number)?;
    let display_name = required_text(display_name, "Il nominativo", 120)?;

    if let Some(marker_number) = marker_number {
        validate_marker_number(marker_number)?;
    }
    if active && marker_number.is_none() {
        return Err("Un alunno attivo deve avere un marker assegnato.".to_string());
    }

    with_identities(state, |connection| {
        let current = load_student(connection, &student_uuid)?;

        if active {
            let marker_number = marker_number.expect("verificato sopra");
            if !marker_available(
                connection,
                &current.class_uuid,
                marker_number,
                Some(&student_uuid),
            )? {
                return Err(format!("Il marker {marker_number} è già assegnato."));
            }
        }

        let transaction = connection
            .transaction()
            .map_err(|error| format!("Impossibile iniziare la modifica: {error}"))?;

        match (current.active, active) {
            (true, true) => {
                move_active_student(
                    &transaction,
                    &current.class_uuid,
                    &student_uuid,
                    current.roster_number,
                    roster_number,
                )?;
            }
            (false, true) => {
                make_roster_space(&transaction, &current.class_uuid, roster_number)?;
            }
            _ => {}
        }

        transaction
            .execute(
                "UPDATE students
                 SET roster_number = ?2,
                     marker_number = ?3,
                     display_name = ?4,
                     active = ?5
                 WHERE student_uuid = ?1",
                params![
                    student_uuid,
                    roster_number,
                    marker_number,
                    display_name,
                    if active { 1 } else { 0 }
                ],
            )
            .map_err(|error| format!("Impossibile aggiornare l'alunno: {error}"))?;

        transaction
            .commit()
            .map_err(|error| format!("Impossibile salvare l'alunno: {error}"))?;

        load_student(connection, &student_uuid)
    })
}

#[tauri::command]
/// Indica al frontend se l'archivio FEED esiste ed è composto da tutti i file previsti.
pub fn store_exists(app: AppHandle) -> Result<bool, String> {
    let (data_path, identities_path, keys_path) = store_paths(&app)?;
    let present = [
        data_path.exists(),
        identities_path.exists(),
        keys_path.exists(),
    ];
    let count = present.into_iter().filter(|exists| *exists).count();

    match count {
        0 => Ok(false),
        3 => Ok(true),
        _ => Err(
            "Archivio FEED incompleto: alcuni file risultano mancanti. Non crearne uno nuovo sopra questi dati."
                .to_string(),
        ),
    }
}

#[tauri::command]
/// Comando Tauri che crea l'archivio, azzera la password ricevuta e mantiene aperte le connessioni.
pub fn create_store(
    app: AppHandle,
    mut password: String,
    state: State<'_, StoreState>,
) -> Result<(), String> {
    let result = create_new_store(&app, &password);
    password.zeroize();
    let store = result?;

    let mut guard = state
        .inner
        .lock()
        .map_err(|_| "Stato del database non disponibile.".to_string())?;
    *guard = Some(store);
    Ok(())
}

#[tauri::command]
/// Comando Tauri che sblocca l'archivio, azzera la password ricevuta e conserva le connessioni in RAM.
pub fn unlock_store(
    app: AppHandle,
    mut password: String,
    state: State<'_, StoreState>,
) -> Result<(), String> {
    let result = open_existing_store(&app, &password);
    password.zeroize();
    let store = result?;

    let mut guard = state
        .inner
        .lock()
        .map_err(|_| "Stato del database non disponibile.".to_string())?;
    *guard = Some(store);
    Ok(())
}

#[tauri::command]
/// Comando Tauri che chiude le connessioni eliminandole dallo stato condiviso.
pub fn lock_store(state: State<'_, StoreState>) -> Result<(), String> {
    let mut guard = state
        .inner
        .lock()
        .map_err(|_| "Stato del database non disponibile.".to_string())?;
    *guard = None;
    Ok(())
}

#[tauri::command]
/// Comunica al frontend se le connessioni cifrate sono attualmente aperte.
pub fn store_unlocked(state: State<'_, StoreState>) -> Result<bool, String> {
    let guard = state
        .inner
        .lock()
        .map_err(|_| "Stato del database non disponibile.".to_string())?;
    Ok(guard.is_some())
}
