#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod store;

/// Avvia FEED, registra lo stato dell'archivio cifrato e rende disponibili
/// al frontend esclusivamente i comandi Tauri previsti per la gestione dello storage.
fn main() {
    tauri::Builder::default()
        .manage(store::StoreState::default())
        .invoke_handler(tauri::generate_handler![
            store::store_exists,
            store::create_store,
            store::unlock_store,
            store::lock_store,
            store::store_unlocked
        ])
        .run(tauri::generate_context!())
        .expect("errore durante l'avvio di FEED");
}
