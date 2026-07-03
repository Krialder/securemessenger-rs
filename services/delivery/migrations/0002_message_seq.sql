-- Eingangsreihenfolge deterministisch machen. Bisher trug jede Zeile
-- received_at plus einen Mikrosekunden-Offset je Batch-Position; das ist
-- Fliesskomma-Arithmetik mit Rundung in to_timestamp, und bei einer
-- Kollision entschied die zufaellige UUID die Reihenfolge (flackernder
-- Test roundtrip_dedupe_and_ack, real: Zustellung innerhalb eines Batches
-- in zufaelliger Folge). Eine Sequenz zaehlt in Einreichungsreihenfolge
-- und ist der einzige Sortierschluessel, den fetch braucht.
CREATE SEQUENCE message_seq;

ALTER TABLE messages
    ADD COLUMN seq BIGINT NOT NULL DEFAULT nextval('message_seq');
