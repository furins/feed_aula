#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod store;

use tauri::Manager;

/// Configura su Linux le richieste di permesso della WebView indicata.
///
/// FEED autorizza esclusivamente l'acquisizione video, nega ogni richiesta che
/// includa il microfono e consente la lettura delle informazioni sui dispositivi
/// necessaria al selettore delle videocamere.
#[cfg(target_os = "linux")]
fn configure_linux_media_permissions(webview_window: &tauri::WebviewWindow) -> Result<(), String> {
    use webkit2gtk::glib::prelude::Cast;
    use webkit2gtk::{
        DeviceInfoPermissionRequest, PermissionRequestExt, UserMediaPermissionRequest,
        UserMediaPermissionRequestExt, WebViewExt,
    };

    webview_window
        .with_webview(|webview| {
            webview.inner().connect_permission_request(|_, request| {
                if let Some(media_request) =
                    request.dynamic_cast_ref::<UserMediaPermissionRequest>()
                {
                    if media_request.is_for_video_device() && !media_request.is_for_audio_device() {
                        request.allow();
                    } else {
                        request.deny();
                    }
                    return true;
                }

                if request
                    .downcast_ref::<DeviceInfoPermissionRequest>()
                    .is_some()
                {
                    request.allow();
                    return true;
                }

                false
            });
        })
        .map_err(|error| format!("Impossibile configurare i permessi della videocamera: {error}"))
}

/// Apre la Scansione in una finestra Tauri separata dall'interfaccia di
/// amministrazione, in modo che possa essere condivisa sullo schermo da sola.
///
/// Il percorso è volutamente limitato alla pagina locale `scan.html`; FEED non
/// usa questo comando per aprire contenuti esterni o finestre arbitrarie.
#[tauri::command]
async fn open_scan_window(app: tauri::AppHandle, target: String) -> Result<(), String> {
    let target = target.trim();

    if target.len() > 8_192
        || !(target == "scan.html" || target.starts_with("scan.html?"))
        || target.contains("..")
        || target.contains('#')
    {
        return Err("Percorso della Scansione non valido.".to_string());
    }

    if let Some(existing) = app.get_webview_window("scan") {
        let _ = existing.set_focus();
        return Err(
            "Una finestra di Scansione è già aperta. Chiudila prima di avviarne un'altra."
                .to_string(),
        );
    }

    let scan_window =
        tauri::WebviewWindowBuilder::new(&app, "scan", tauri::WebviewUrl::App(target.into()))
            .title("FEED · Scansione")
            .inner_size(1320.0, 900.0)
            .min_inner_size(900.0, 650.0)
            .resizable(true)
            .center()
            .build()
            .map_err(|error| format!("Impossibile aprire la finestra di Scansione: {error}"))?;

    #[cfg(target_os = "linux")]
    configure_linux_media_permissions(&scan_window)?;

    Ok(())
}

/// Chiude la finestra dedicata alla Scansione quando l'utente usa il pulsante
/// Indietro della pagina, lasciando aperta l'interfaccia principale di FEED.
#[tauri::command]
fn close_scan_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(scan_window) = app.get_webview_window("scan") {
        scan_window
            .close()
            .map_err(|error| format!("Impossibile chiudere la finestra di Scansione: {error}"))?;
    }

    Ok(())
}

/// Avvia FEED, registra lo stato dell'archivio cifrato, configura i permessi
/// nativi necessari e rende disponibili al frontend esclusivamente i comandi
/// Tauri previsti dall'applicazione.
fn main() {
    tauri::Builder::default()
        .manage(store::StoreState::default())
        .setup(|app| {
            #[cfg(target_os = "linux")]
            {
                let main_webview = app.get_webview_window("main").ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "finestra principale FEED non disponibile",
                    )
                })?;

                configure_linux_media_permissions(&main_webview).map_err(std::io::Error::other)?;
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            store::store_exists,
            store::create_store,
            store::unlock_store,
            store::lock_store,
            store::store_unlocked,
            store::list_classes,
            store::create_class,
            store::update_class,
            store::list_students,
            store::create_student,
            store::update_student,
            store::delete_student,
            store::start_scan_session,
            store::save_scan_response,
            store::complete_scan_session,
            store::list_history_sessions,
            store::get_history_session,
            store::list_history_students,
            store::delete_history_entries,
            store::delete_student_history,
            store::delete_history_session,
            open_scan_window,
            close_scan_window
        ])
        .run(tauri::generate_context!())
        .expect("errore durante l'avvio di FEED");
}
