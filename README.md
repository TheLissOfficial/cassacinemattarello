# cassacinemattarello

Versione autonoma del POS Cinematta, separata dal progetto originale.

## Contenuto
- `server.js`: API, login server-side, ruoli, vendite, classifica storica e pannello admin.
- `public/`: interfaccia POS.
- `prodotti.txt`: copia del catalogo originale, non modificata.
- `render.yaml`: configurazione iniziale Render + PostgreSQL.
- `.env.example`: esempio delle variabili per sviluppo locale.

## Avvio locale
È necessario Node.js 20+ e PostgreSQL.

1. Crea un database PostgreSQL.
2. Copia `.env.example` in `.env` e compila `DATABASE_URL`, `SESSION_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`.
3. Installa e avvia:

   ```bash
   npm install
   npm start
   ```

4. Apri `http://localhost:3000`.

La password iniziale dell'amministratore deve essere lunga almeno 12 caratteri. Non inserirla nel codice e non caricare `.env` su GitHub.

## Pubblicazione su Render
1. Crea una nuova repository GitHub chiamata `cassacinemattarello` e carica il contenuto di questa cartella.
2. Su Render scegli **New + > Blueprint** e collega la nuova repository.
3. Render crea il servizio web e il database PostgreSQL definiti in `render.yaml`.
4. Inserisci `ADMIN_USERNAME` e `ADMIN_PASSWORD` tra le variabili d'ambiente del servizio. `SESSION_SECRET` e `DATABASE_URL` sono gestite dalla configurazione.
5. Avvia il deploy.

Controlla il piano e i costi di Render prima di confermare la creazione del database.

## Account preesistenti
Il vecchio `utenti.txt` usa credenziali cifrate lato browser e non viene pubblicato né esposto dal nuovo server. Per ragioni di sicurezza gli account vanno ricreati dall'amministratore nel pannello Admin. Il primo amministratore è quello definito con `ADMIN_USERNAME` e `ADMIN_PASSWORD`.

## Funzioni
- Classifica storica per quantità totale venduta, indipendente dalle chiusure cassa.
- Le chiusure cassa archiviano la sessione ma non cancellano vendite o classifica.
- Pannello admin per consultare account, attivarli/disattivarli e chiudere le casse.
- Le password sono salvate come hash bcrypt; l'accesso admin viene verificato dal server.
- Il catalogo viene letto dal file `prodotti.txt` presente nella root del progetto.

## Nota sui contorni dei pulsanti
I pulsanti prodotto mantengono sfondo, colori interni e testi del progetto originale. Il bordo neutro attuale è conservato: non ho applicato una codifica colore per categoria perché non era stata confermata. Le modifiche future ai colori dei soli bordi possono essere fatte in `public/style.css`, nella regola `.product-btn`.
