-- Webhooks: ein Fremdprojekt bekommt Ereignisse (heute presence.changed)
-- zugestellt (Push), statt sie abzufragen (Poll). Jeder Endpunkt gehoert
-- einem Mandanten, abonniert Ereignisse und die Handles, fuer die er sie
-- will. Das Abo je Handle haelt die Datenschutz-Flaeche genauso eng wie die
-- presence-Abfrage (F080): nur genannte Handles, nichts flaechendeckend.
--
-- tenant_name ist denormalisiert (der Name ist unveraenderlich, siehe
-- integration_tenants.name UNIQUE), damit die Zustellung ohne Join den
-- Envelope-Absender kennt. ON DELETE CASCADE: mit dem Mandanten fallen
-- seine Webhooks.
CREATE TABLE integration_webhooks (
    id          UUID PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES integration_tenants (id) ON DELETE CASCADE,
    tenant_name TEXT NOT NULL,
    url         TEXT NOT NULL,
    events      TEXT[] NOT NULL,
    handles     TEXT[] NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_integration_webhooks_tenant ON integration_webhooks (tenant_id);
-- Zustell-Suche: welche Endpunkte wollen ein Ereignis fuer einen Handle?
-- GIN ueber die Handle-Menge beschleunigt das ANY-Praedikat.
CREATE INDEX idx_integration_webhooks_handles ON integration_webhooks USING GIN (handles);
