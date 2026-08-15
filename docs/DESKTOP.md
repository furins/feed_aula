# FEED Desktop (Tauri 2)

Questa cartella aggiunge una shell desktop Tauri 2 alla versione web esistente di FEED.

## Obiettivo di questa fase

- riutilizzare `config.html` e `scan.html` senza duplicarne la logica;
- eseguire FEED su Windows, macOS e Linux tramite WebView di sistema;
- eliminare le dipendenze di rete dello scanner;
- non introdurre ancora database, dati personali persistenti o crittografia.

`docs/MANUALE.md` e `docs/PRIVACY.md` restano i documenti di riferimento del progetto.

## Dipendenze

Per lo sviluppo sono necessari:

- Node.js e npm;
- Rust e Cargo;
- i prerequisiti Tauri previsti dal sistema operativo.

Installazione delle dipendenze JavaScript:

```bash
npm install
```

Avvio desktop in sviluppo:

```bash
npm run desktop:dev
```

Build del binario Tauri:

```bash
npm run desktop:build
```

In questa prima fase il bundling degli installer è disattivato (`bundle.active = false`).
Verrà attivato quando saranno definiti icone, firma e formati di distribuzione.

## Frontend offline

`scripts/build-web.mjs` genera la cartella `dist/`:

1. copia `config.html` anche come `index.html`, che diventa la schermata iniziale;
2. copia `scan.html`;
3. sostituisce i tre riferimenti CDN a `js-aruco2` con file locali;
4. copia i marker SVG in `dist/markers/`.

I sorgenti web originali non vengono modificati. La versione GitHub Pages può quindi continuare a funzionare come prima.

## Privacy

Questa fase non introduce alcun meccanismo di persistenza dei dati.
La telecamera viene usata dallo scanner esistente e i fotogrammi restano elaborati in memoria.
Su macOS `Info.plist` contiene la motivazione del permesso camera coerente con `docs/PRIVACY.md`.

La fase successiva introdurrà lo storage locale cifrato e il modello dati pseudonimizzato.
