-- Abuse-Abwehr (specs/sealed-sender-und-abuse.md): Franking-Log und
-- empfaengerseitige Blocklisten.

-- Franking-Log: das Commitment einer Nachricht, damit der Server eine
-- Meldung verifizieren kann, ohne den Inhalt je gesehen zu haben. Der
-- Absender bildet C = HMAC(K_f, Klartext) und haengt es an die Huelle; der
-- Server bewahrt hier nur C auf. Meldet der Empfaenger, deckt er
-- (Klartext, K_f) auf, und der Server rechnet nach.
CREATE TABLE franking_log (
    message_id UUID PRIMARY KEY,          -- die Huellen-ID
    commitment BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Empfaengerseitige Blockliste: wen ein Konto blockiert. Die letzte und
-- wichtigste Verteidigungslinie, weil sie beim Nutzer liegt. Handles statt
-- IDs, weil der Absender bis Sealed Sender ueber sein Handle bekannt ist.
CREATE TABLE blocks (
    owner_handle   TEXT NOT NULL,          -- wer blockiert (der Empfaenger)
    blocked_handle TEXT NOT NULL,          -- wen er blockiert (den Absender)
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_handle, blocked_handle)
);
