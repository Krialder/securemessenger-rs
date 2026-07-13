# Integrations-Beispiele in mehreren Sprachen

Fertige Schnipsel fuer die drei oeffentlichen Endpunkte (Token holen,
benachrichtigen, Praesenz abfragen). Sie ergaenzen den [Integrations-Leitfaden](integration-leitfaden.md) (Schritt fuer Schritt) und die [OpenAPI-Spezifikation](openapi-integrations.yaml) (maschinenlesbar). Der Token-Endpunkt ist ein standardkonformer OAuth2-Client-Credentials-Grant, deshalb bindet jede Sprache mit ihren Bordmitteln an, ohne Sonderprotokoll.

Ersetze `BASE`, `CLIENT_ID` und das Secret durch die Werte, die dir der Betrieb genannt hat. Das Secret gehoert in eine Umgebungsvariable oder einen Secret-Store, nie in den Quelltext und nie in einen Browser (der Fluss ist Server-zu-Server).

## Gemeinsame Regeln

- **Token zwischenspeichern:** Ein Token laeuft eine Stunde (`expires_in`). Hol nicht vor jedem Aufruf ein neues, sondern erst, wenn das alte fast ablaeuft. Alle Beispiele unten cachen es mit etwas Vorlauf (60 Sekunden).
- **Enges Token:** Brauchst du an einer Stelle nur `notify`, dann frag `scope=notify` an. Das ausgestellte Token kann dann keine Praesenz abfragen (Least Privilege), ein Leck bleibt begrenzt.
- **Fehler:** `401` heisst „Token weg oder falsch", dann einmal neu holen. `429` heisst „zu schnell", dann die im Header `Retry-After` genannten Sekunden warten. Entscheide bei den API-Aufrufen anhand des Feldes `code`, beim Token-Tausch anhand von `error`.

## cURL (zum Ausprobieren)

```bash
BASE=https://api.messenger.intern
TOKEN=$(curl -sS -X POST "$BASE/integrations/token" \
  -u 'azubios:<geheim>' \
  -d 'grant_type=client_credentials' | jq -r .access_token)

curl -sS -X POST "$BASE/integrations/azubios/notify" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"handle":"alice","title":"Neue Aufgabe faellig"}'

curl -sS "$BASE/integrations/azubios/presence/alice" \
  -H "Authorization: Bearer $TOKEN"
```

## Python (nur `requests`)

Kommt ohne OAuth2-Bibliothek aus. Wer automatische Token-Erneuerung will, nimmt `authlib` (`OAuth2Session` mit `grant_type="client_credentials"`); die Zugangsdaten und die Token-URL sind dieselben.

```python
import os
import time

import requests

BASE = "https://api.messenger.intern"
CLIENT_ID = "azubios"
CLIENT_SECRET = os.environ["SM_CLIENT_SECRET"]

_token = {"value": None, "expires_at": 0.0}


def get_token() -> str:
    now = time.time()
    if _token["value"] and now < _token["expires_at"] - 60:
        return _token["value"]
    resp = requests.post(
        f"{BASE}/integrations/token",
        data={"grant_type": "client_credentials"},
        auth=(CLIENT_ID, CLIENT_SECRET),  # HTTP Basic
        timeout=5,
    )
    resp.raise_for_status()
    body = resp.json()
    _token["value"] = body["access_token"]
    _token["expires_at"] = now + body["expires_in"]
    return _token["value"]


def notify(handle: str, title: str) -> dict:
    resp = requests.post(
        f"{BASE}/integrations/{CLIENT_ID}/notify",
        headers={"Authorization": f"Bearer {get_token()}"},
        json={"handle": handle, "title": title},
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()  # {"devices": N, "connected": M}


def is_online(handle: str) -> bool:
    resp = requests.get(
        f"{BASE}/integrations/{CLIENT_ID}/presence/{handle}",
        headers={"Authorization": f"Bearer {get_token()}"},
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()["online"]
```

## JavaScript / Node (ab Node 18, `fetch` eingebaut)

```javascript
const BASE = "https://api.messenger.intern";
const CLIENT_ID = "azubios";
const CLIENT_SECRET = process.env.SM_CLIENT_SECRET;

let cached = { token: null, expiresAt: 0 };

async function getToken() {
  const now = Date.now() / 1000;
  if (cached.token && now < cached.expiresAt - 60) return cached.token;

  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  const resp = await fetch(`${BASE}/integrations/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  if (!resp.ok) throw new Error(`Token-Tausch fehlgeschlagen: ${resp.status}`);

  const body = await resp.json();
  cached = { token: body.access_token, expiresAt: now + body.expires_in };
  return cached.token;
}

async function notify(handle, title) {
  const resp = await fetch(`${BASE}/integrations/${CLIENT_ID}/notify`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${await getToken()}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ handle, title }),
  });
  if (!resp.ok) throw new Error(`Benachrichtigung fehlgeschlagen: ${resp.status}`);
  return resp.json(); // { devices, connected }
}

async function isOnline(handle) {
  const resp = await fetch(
    `${BASE}/integrations/${CLIENT_ID}/presence/${handle}`,
    { headers: { Authorization: `Bearer ${await getToken()}` } },
  );
  if (!resp.ok) throw new Error(`Praesenz-Abfrage fehlgeschlagen: ${resp.status}`);
  return (await resp.json()).online;
}
```

## PHP (nur cURL, ohne Composer-Abhaengigkeit)

```php
<?php
const BASE = "https://api.messenger.intern";
const CLIENT_ID = "azubios";

function get_token(): string {
    static $cache = ["token" => null, "expires_at" => 0];
    $now = time();
    if ($cache["token"] && $now < $cache["expires_at"] - 60) {
        return $cache["token"];
    }
    $ch = curl_init(BASE . "/integrations/token");
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERPWD => CLIENT_ID . ":" . getenv("SM_CLIENT_SECRET"),
        CURLOPT_POSTFIELDS => http_build_query(["grant_type" => "client_credentials"]),
    ]);
    $body = json_decode(curl_exec($ch), true);
    curl_close($ch);
    $cache["token"] = $body["access_token"];
    $cache["expires_at"] = $now + $body["expires_in"];
    return $cache["token"];
}

function notify(string $handle, string $title): array {
    $ch = curl_init(BASE . "/integrations/" . CLIENT_ID . "/notify");
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            "Authorization: Bearer " . get_token(),
            "Content-Type: application/json",
        ],
        CURLOPT_POSTFIELDS => json_encode(["handle" => $handle, "title" => $title]),
    ]);
    $result = json_decode(curl_exec($ch), true);
    curl_close($ch);
    return $result; // ["devices" => N, "connected" => M]
}
```

## Webhook empfangen und die Signatur pruefen (Node)

Wer statt zu pollen einen Webhook registriert (siehe Leitfaden, Abschnitt Webhooks), bekommt bei jeder Praesenz-Aenderung einen signierten `POST`. Der Empfaenger holt den oeffentlichen Schluessel einmal von `GET $BASE/integrations/webhook-key`, cacht ihn und prueft damit die Ed25519-Signatur ueber die kanonische Nachricht `{timestamp}.{body}`.

```javascript
const http = require("http");
const crypto = require("crypto");

// Einmal holen und cachen: { alg: "Ed25519", public_key: "<base64>" }.
const PUBLIC_KEY_B64 = process.env.SM_WEBHOOK_PUBLIC_KEY;
const raw = Buffer.from(PUBLIC_KEY_B64, "base64"); // 32 Byte
const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
const key = crypto.createPublicKey({ key: der, format: "der", type: "spki" });

http
  .createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const ts = req.headers["x-securemessenger-timestamp"] || "";
      const sig = Buffer.from(
        (req.headers["x-securemessenger-signature"] || "").replace(/^ed25519=/, ""),
        "base64"
      );
      const message = Buffer.concat([Buffer.from(ts + "."), body]);
      const valid = crypto.verify(null, message, key, sig);
      // Zu alten (wiedereingespielten) Aufruf abweisen.
      const fresh = Math.abs(Date.now() / 1000 - Number(ts)) < 300;
      if (!valid || !fresh) {
        res.writeHead(400);
        return res.end("bad signature");
      }
      const event = JSON.parse(body.toString());
      // event.data.handle ist online/offline gegangen. Idempotent bleiben:
      // gleiche event.id kann mehrfach kommen (Best-effort-Zustellung).
      console.log(event.type, event.data.handle, event.data.online);
      res.writeHead(200);
      res.end("ok");
    });
  })
  .listen(8100);
```

## Typisierten Client generieren (jede Sprache)

Wer keinen Handschnipsel will, erzeugt aus der OpenAPI-Spezifikation einen fertigen, typisierten Client. Mit `openapi-generator` (viele Zielsprachen: Python, TypeScript, Java, Go, C#, PHP):

```bash
openapi-generator-cli generate \
  -i dokumentation/openapi-integrations.yaml \
  -g python \
  -o out/messenger-client
```

Der erzeugte Client kennt die drei Endpunkte, die Modelle (`NotifyRequest`, `NotifyResponse`, `PresenceResponse`) und die beiden Sicherheitsschemata (Bearer fuer die API, HTTP-Basic fuer den Token-Tausch) bereits. Das OAuth2-Token holst du wie oben und setzt es als Bearer.
