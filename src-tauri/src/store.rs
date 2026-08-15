use aes_gcm::{
    aead::{Aead, KeyInit, Nonce, Payload},
    Aes256Gcm,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rusqlite::Connection;
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
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

struct EncryptedStore {
    _data: Connection,
    _identities: Connection,
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

fn storage_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|path| path.join("data"))
        .map_err(|error| format!("Impossibile determinare la cartella dati: {error}"))
}

fn store_paths(app: &AppHandle) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let dir = storage_dir(app)?;
    Ok((
        dir.join(DATA_DB_NAME),
        dir.join(IDENTITIES_DB_NAME),
        dir.join(KEY_ENVELOPE_NAME),
    ))
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "La password deve contenere almeno {MIN_PASSWORD_LEN} caratteri."
        ));
    }
    Ok(())
}

fn random_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::fill(&mut *bytes)
        .map_err(|error| format!("Impossibile ottenere casualità sicura dal sistema: {error}"))?;
    Ok(bytes)
}

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

fn wrap_key(
    kek: &[u8; KEY_LEN],
    key: &[u8; KEY_LEN],
    aad: &[u8],
) -> Result<WrappedKey, String> {
    let cipher = Aes256Gcm::new_from_slice(kek)
        .map_err(|_| "Impossibile inizializzare la protezione delle chiavi.".to_string())?;
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;

    #[allow(deprecated)]
    let nonce = Nonce::<Aes256Gcm>::from_slice(&*nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &key[..],
                aad,
            },
        )
        .map_err(|_| "Impossibile proteggere le chiavi dell'archivio.".to_string())?;

    Ok(WrappedKey {
        nonce: BASE64.encode(&*nonce_bytes),
        ciphertext: BASE64.encode(ciphertext),
    })
}

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
fn restrict_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn raw_key_pragma(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut hex = Zeroizing::new(String::with_capacity(KEY_LEN * 2));
    for byte in key {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex.as_str()))
}

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
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))
        .map_err(|_| "Database FEED non leggibile o chiave non valida.".to_string())?;

    Ok(connection)
}

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

fn create_identity_schema(connection: &Connection) -> Result<(), String> {
    connection
        .execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS meta (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
             );
             INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '1');

             CREATE TABLE IF NOT EXISTS classes (
               class_uuid TEXT PRIMARY KEY,
               label TEXT NOT NULL,
               school_year TEXT,
               created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );

             CREATE TABLE IF NOT EXISTS students (
               student_uuid TEXT PRIMARY KEY,
               class_uuid TEXT NOT NULL,
               roster_number INTEGER NOT NULL CHECK(roster_number > 0),
               display_name TEXT NOT NULL,
               active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
               created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
               FOREIGN KEY(class_uuid)
                 REFERENCES classes(class_uuid) ON DELETE CASCADE,
               UNIQUE(class_uuid, roster_number)
             );

             CREATE INDEX IF NOT EXISTS idx_students_class
               ON students(class_uuid, roster_number);
             COMMIT;",
        )
        .map_err(|error| format!("Impossibile inizializzare il database identità: {error}"))
}

fn cleanup_store_files(data_path: &Path, identities_path: &Path, keys_path: &Path) {
    let _ = fs::remove_file(data_path);
    let _ = fs::remove_file(identities_path);
    let _ = fs::remove_file(keys_path);
    if let Some(parent) = keys_path.parent() {
        let _ = fs::remove_file(parent.join(KEY_ENVELOPE_TEMP_NAME));
    }
}

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
            _identities: identities,
        })
    })();

    if result.is_err() {
        cleanup_store_files(&data_path, &identities_path, &keys_path);
    }

    result
}

fn open_existing_store(app: &AppHandle, password: &str) -> Result<EncryptedStore, String> {
    validate_password(password)?;

    let (data_path, identities_path, keys_path) = store_paths(app)?;
    if !data_path.exists() || !identities_path.exists() || !keys_path.exists() {
        return Err("Archivio FEED non inizializzato o incompleto su questo dispositivo.".to_string());
    }

    let envelope = read_key_envelope(&keys_path)?;
    let kek = derive_kek(password, &envelope.kdf)?;
    let data_key = unwrap_key(&kek, &envelope.data_key, DATA_KEY_AAD)?;
    let identities_key = unwrap_key(&kek, &envelope.identities_key, IDENTITIES_KEY_AAD)?;

    let data = open_cipher_database(&data_path, &data_key)?;
    let identities = open_cipher_database(&identities_path, &identities_key)?;

    Ok(EncryptedStore {
        _data: data,
        _identities: identities,
    })
}

#[tauri::command]
pub fn store_exists(app: AppHandle) -> Result<bool, String> {
    let (data_path, identities_path, keys_path) = store_paths(&app)?;
    let present = [data_path.exists(), identities_path.exists(), keys_path.exists()];
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
pub fn lock_store(state: State<'_, StoreState>) -> Result<(), String> {
    let mut guard = state
        .inner
        .lock()
        .map_err(|_| "Stato del database non disponibile.".to_string())?;
    *guard = None;
    Ok(())
}

#[tauri::command]
pub fn store_unlocked(state: State<'_, StoreState>) -> Result<bool, String> {
    let guard = state
        .inner
        .lock()
        .map_err(|_| "Stato del database non disponibile.".to_string())?;
    Ok(guard.is_some())
}
