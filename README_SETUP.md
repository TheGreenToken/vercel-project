# AntiSec — Einrichtung

## Schritt 1: Discord Bot erstellen

1. Gehe zu https://discord.com/developers/applications
2. Klicke **New Application** → vergib einen Namen
3. Links auf **Bot** klicken → **Add Bot**
4. Unter **Token** → **Reset Token** → Token kopieren und sicher aufbewahren (das ist `DISCORD_BOT_TOKEN`)
5. Scrolle zu **Privileged Gateway Intents** und aktiviere:
   - **Server Members Intent**
   - **Message Content Intent**
6. Links auf **OAuth2 → URL Generator**:
   - Scopes: `bot`
   - Bot Permissions: `Send Messages`, `Manage Roles`, `View Audit Log`
7. Generierten Link öffnen → Bot zu deinem Server einladen

> **Wichtig:** Die Bot-Rolle muss in den Server-Einstellungen unter Rollen **über** der Ziel-Rolle liegen, sonst kann er keine Rollen vergeben.

---

## Schritt 2: Discord IDs sammeln

In Discord: **Einstellungen → Erweitert → Entwicklermodus** aktivieren.

| Was | Wie |
|---|---|
| **Guild ID** | Rechtsklick auf Server-Icon → "Server-ID kopieren" |
| **Role ID** | Server-Einstellungen → Rollen → Rechtsklick auf deine Rolle → "Rollen-ID kopieren" |
| **User ID** | Rechtsklick auf beliebigen Nutzer → "Nutzer-ID kopieren" |

---

## Schritt 3: GitHub Token erstellen (empfohlen)

Ohne Token: max. 60 GitHub API-Anfragen/Stunde (bricht bei mehreren Nutzern).
Mit Token: 5.000 Anfragen/Stunde.

1. Gehe zu https://github.com/settings/tokens
2. **Generate new token (classic)**
3. Scopes: nur `public_repo` reicht
4. Token kopieren → wird zu `GITHUB_TOKEN`

---

## Schritt 4: Discord Webhook erstellen

1. In Discord: Rechtsklick auf einen Kanal (z.B. `#logs`) → **Integrationen → Webhooks**
2. **Neuen Webhook erstellen** → URL kopieren → wird zu `WEBHOOK_URL`

---

## Schritt 5: Session Secret generieren

Einmal ausführen, Output kopieren:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Das Ergebnis wird zu `SESSION_SECRET` (muss min. 32 Zeichen lang sein).

---

## Schritt 6: Auf Vercel deployen

1. Gehe zu https://vercel.com → **New Project**
2. GitHub-Repo importieren oder Ordner hochladen
3. Unter **Settings → Environment Variables** alle Variablen eintragen:

| Variable | Beschreibung | Beispiel |
|---|---|---|
| `DISCORD_BOT_TOKEN` | Bot-Token aus Schritt 1 | `MTA...` |
| `DISCORD_GUILD_ID` | Server-ID aus Schritt 2 | `123456789012345678` |
| `DISCORD_ROLE_ID` | Rollen-ID aus Schritt 2 | `987654321098765432` |
| `DISCORD_INVITE` | Dein Server-Einladungslink | `https://discord.gg/xxxxxx` |
| `APP_BASE_URL` | Deine Vercel-URL | `https://yourapp.vercel.app` |
| `ANTISEC_PASSWORD` | Zugangs-Passwort für das Tool | `DeinStarkesPasswort` |
| `SESSION_SECRET` | Zufälliger Schlüssel aus Schritt 5 | `a3f9...` |
| `WEBHOOK_URL` | Webhook-URL aus Schritt 4 | `https://discord.com/api/webhooks/...` |
| `GITHUB_TOKEN` | GitHub Token aus Schritt 3 | `ghp_...` |

4. **Deploy** klicken

---

## Schritt 7: Vercel KV einrichten (wichtig für Produktion)

Ohne KV speichert das Tool Tokens nur im Arbeitsspeicher — bei mehreren Vercel-Instanzen können Tokens verloren gehen.

1. Vercel-Dashboard → dein Projekt → **Storage**
2. **Create Database → KV** → Namen vergeben (z.B. `antisec-kv`) → **Create**
3. **Connect to Project** → dein Projekt auswählen
4. Vercel fügt automatisch `KV_REST_API_URL` und `KV_REST_API_TOKEN` hinzu
5. Neu deployen — fertig

---

## Nutzungs-Flow für deine Mitglieder

Damit ein Nutzer Zugang bekommt, muss er:

1. **Display-Name anpassen** — einer von zwei Formaten:
   - `ᵃⁿᵗⁱ` ans Ende des Discord-Namens → z.B. `MaxMusterᵃⁿᵗⁱ`
   - `𝐴𝐧𝐭𝐢|` an den Anfang → z.B. `𝐴𝐧𝐭𝐢|MaxMuster`
2. **Server-Invite in die Discord-Bio** eintragen (der Wert von `DISCORD_INVITE`)
3. Die Website öffnen → Discord User-ID eingeben → **Check & Verify**
4. Bot schickt eine DM mit einem Bestätigungs-Link → Link anklicken
5. Passwort eingeben → eingeloggt

Der Login bleibt **30 Tage** aktiv (localStorage). Über den **Logout-Button** kann der Nutzer den Account wechseln.

---

## Häufige Probleme

| Problem | Ursache | Lösung |
|---|---|---|
| Bot kann keine Rolle vergeben | Bot-Rolle ist unter der Ziel-Rolle | Bot-Rolle in Server-Einstellungen nach oben ziehen |
| Keine DM erhalten | Nutzer hat DMs vom Server deaktiviert | Nutzer soll in Server-Einstellungen DMs erlauben |
| Rate Limit Fehler | Kein GitHub Token gesetzt | `GITHUB_TOKEN` in Vercel env vars eintragen |
| Token verloren (nicht bestätigt) | Kein KV eingerichtet | Schritt 7 durchführen |
| `Server misconfiguration` Fehler | Env Var fehlt | Alle Variablen in Vercel prüfen, neu deployen |
