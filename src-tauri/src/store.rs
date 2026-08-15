use rusqlite::Connection;
use std::{fs, path::PathBuf, sync::Mutex};
use tauri::{AppHandle, Manager, State};

const DATA_DB_NAME: &str = "feed.db";
const IDENTITIES_DB_NAME: &str = "identities.db";
const MIN_PASSWORD_LEN: usize = 12;

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

fn storage_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|path| path.join("data"))
        .map_err(|error| format!("Impossibile determinare la cartella dati: {error}"))
}

fn database_paths(app: &AppHandle) -> Result<(PathBuf, PathBuf), String> {
    let dir = storage_dir(app)?;
    Ok((dir.join(DATA_DB_NAME), dir.join(IDENTITIES_DB_NAME)))
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "La password deve contenere almeno {MIN_PASSWORD_LEN} caratteri."
        ));
    }
    Ok(())
}

fn open_cipher_database(path: &PathBuf, password: &str) -> Result<Connection, String> {
    let connection = Connection::open(path)
        .map_err(|error| format!("Impossibile aprire il database cifrato: {error}"))?;

    connection
        .pragma_update(None, "key", password)
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

    // Forza SQLCipher a verificare la chiave anche su database già esistenti.
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))
        .map_err(|_| "Password non valida o database non leggibile.".to_string())?;

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
               source TEXT NOT NULL DEFAULT 'aruco',
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

fn open_store(app: &AppHandle, password: &str, create: bool) -> Result<EncryptedStore, String> {
    validate_password(password)?;

    let (data_path, identities_path) = database_paths(app)?;
    let dir = storage_dir(app)?;
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Impossibile creare la cartella dati: {error}"))?;

    let data_exists = data_path.exists();
    let identities_exist = identities_path.exists();

    if create && (data_exists || identities_exist) {
        return Err("Un archivio FEED esiste già su questo dispositivo.".to_string());
    }

    if !create && (!data_exists || !identities_exist) {
        return Err("Archivio FEED non inizializzato su questo dispositivo.".to_string());
    }

    let data = open_cipher_database(&data_path, password)?;
    let identities = open_cipher_database(&identities_path, password)?;

    if create {
        if let Err(error) = create_data_schema(&data).and_then(|_| create_identity_schema(&identities)) {
            drop(data);
            drop(identities);
            let _ = fs::remove_file(&data_path);
            let _ = fs::remove_file(&identities_path);
            return Err(error);
        }
    }

    Ok(EncryptedStore {
        _data: data,
        _identities: identities,
    })
}

#[tauri::command]
pub fn store_exists(app: AppHandle) -> Result<bool, String> {
    let (data_path, identities_path) = database_paths(&app)?;
    Ok(data_path.exists() && identities_path.exists())
}

#[tauri::command]
pub fn create_store(
    app: AppHandle,
    password: String,
    state: State<'_, StoreState>,
) -> Result<(), String> {
    let store = open_store(&app, &password, true)?;
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
    password: String,
    state: State<'_, StoreState>,
) -> Result<(), String> {
    let store = open_store(&app, &password, false)?;
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
