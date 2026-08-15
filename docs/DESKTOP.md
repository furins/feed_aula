# FEED Desktop (Tauri 2)

La versione desktop di FEED riutilizza il configuratore e la scansione web esistenti dentro una shell Tauri 2, aggiungendo uno strato Rust per persistenza, cifratura e funzioni native.

`docs/MANUALE.md` e `docs/PRIVACY.md` restano i documenti di riferimento del progetto.

## Dipendenze di sviluppo

Sono necessari:

- Node.js e npm;
- Rust e Cargo;
- i prerequisiti Tauri previsti dal sistema operativo.

Installazione:

```bash
npm install
```

Avvio desktop in sviluppo, senza file watcher Rust:

```bash
npm run desktop:dev
```

Avvio con watcher, quando i limiti del sistema lo consentono:

```bash
npm run desktop:dev:watch
```

Build del binario:

```bash
npm run desktop:build
```

Il bundling degli installer è ancora disattivato (`bundle.active = false`). Verrà attivato quando saranno definiti icone definitive, firma e formati di distribuzione.

## Home FEED

`desktop.html` è la schermata iniziale della versione desktop. `scripts/build-web.mjs` la copia in `dist/index.html`.

All'avvio:

1. FEED verifica se esiste un archivio locale;
2. al primo utilizzo propone **Crea l'archivio FEED**;
3. agli avvii successivi propone **Sblocca FEED**;
4. dopo lo sblocco mostra la home con accesso al configuratore e alla scansione;
5. **Blocca FEED** chiude le connessioni ai database e torna alla richiesta password.

La password non viene salvata nel browser, in `localStorage`, nell'URL o nei file di configurazione.

## Frontend offline

`scripts/build-web.mjs` genera `dist/`:

1. copia `desktop.html` come `index.html`;
2. copia `config.html`;
3. copia `scan.html` sostituendo i tre riferimenti CDN a `js-aruco2` con file locali;
4. copia i marker SVG in `dist/markers/`.

`js-aruco2` resta il nome tecnico della libreria interna. Nell'interfaccia FEED si parla semplicemente di scansione e marker.

I sorgenti web originali `config.html` e `scan.html` non vengono modificati, quindi la versione web può continuare a funzionare come prima.

## Archivio locale cifrato

FEED usa due database SQLCipher fisicamente separati:

- `feed.db`: questionari, sessioni e risposte pseudonimizzate;
- `identities.db`: classi, numeri d'appello, UUID e nominativi.

I file si trovano nella directory dati privata dell'applicazione, non nella cartella del progetto.

### Chiavi

La password dell'utente **non è usata direttamente come chiave SQLCipher**.

Alla creazione dell'archivio FEED genera due chiavi casuali indipendenti da 256 bit: una per `feed.db` e una per `identities.db`. SQLCipher riceve queste chiavi tramite la sintassi raw-key, evitando di riutilizzare la stessa chiave per i due archivi.

La password viene elaborata con Argon2id e produce una KEK (Key Encryption Key). La KEK protegge le due chiavi SQLCipher con AES-256-GCM. Nel file `keys.json` vengono salvati soltanto:

- salt e parametri Argon2id;
- nonce casuali;
- chiavi dei database cifrate e autenticate.

La password, la KEK e le chiavi SQLCipher in chiaro non vengono scritte su disco. I buffer gestiti dal core Rust vengono azzerati quando possibile tramite `zeroize`. Cambiare password in futuro potrà quindi limitarsi a ricifrare le piccole chiavi dei database, senza ricifrare tutto il contenuto dei database.

Su sistemi Unix FEED imposta permessi `0600` sui database e sull'envelope delle chiavi, oltre alle protezioni fornite dalla directory dati dell'applicazione.

## Core Rust

La home usa soltanto questi comandi Tauri:

- `store_exists`
- `create_store`
- `unlock_store`
- `lock_store`
- `store_unlocked`

Il frontend non riceve SQL, KEK o chiavi dei database e non ha accesso diretto alle connessioni SQLCipher.

La gestione di classi/alunni e lo storico verranno esposti con comandi Rust specifici nei milestone successivi.

## Privacy

La telecamera viene usata durante la scansione e i fotogrammi restano elaborati in memoria. Non vengono salvati video o immagini. Lo storage persistente contiene i dati previsti da `docs/PRIVACY.md`, con separazione tra dati pseudonimizzati e tabella di corrispondenza.
