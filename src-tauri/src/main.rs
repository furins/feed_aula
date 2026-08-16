#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod store;

/// Configura su Linux le richieste di permesso della WebView usata da FEED.
///
/// WebKitGTK nega per impostazione predefinita le richieste `getUserMedia` non
/// gestite dall'applicazione. FEED autorizza esclusivamente l'acquisizione
/// video, nega ogni richiesta che includa il microfono e consente la lettura
/// delle informazioni sui dispositivi necessaria al selettore delle
/// videocamere. Gli altri tipi di permesso restano al comportamento predefinito.
#[cfg(target_os = "linux")]
fn configure_linux_media_permissions(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::Manager;
    use webkit2gtk::glib::prelude::Cast;
    use webkit2gtk::{
        DeviceInfoPermissionRequest, PermissionRequestExt, UserMediaPermissionRequest,
        UserMediaPermissionRequestExt, WebViewExt,
    };

    let main_webview = app.get_webview_window("main").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "finestra principale FEED non disponibile",
        )
    })?;

    main_webview.with_webview(|webview| {
        webview.inner().connect_permission_request(|_, request| {
            if let Some(media_request) = request.dynamic_cast_ref::<UserMediaPermissionRequest>() {
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
    })?;

    Ok(())
}

/// Avvia FEED, registra lo stato dell'archivio cifrato, configura i permessi
/// nativi necessari e rende disponibili al frontend esclusivamente i comandi
/// Tauri previsti per la gestione dello storage.
fn main() {
    tauri::Builder::default()
        .manage(store::StoreState::default())
        .setup(|app| {
            #[cfg(target_os = "linux")]
            configure_linux_media_permissions(app)?;

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
            store::get_history_session
        ])
        .run(tauri::generate_context!())
        .expect("errore durante l'avvio di FEED");
}
