-- MLS-KeyPackages als fuenfte Prekey-Art. Ein KeyPackage ist wie ein
-- Einmal-Prekey einmal nutzbar (es gehoert zu genau einem Gruppenbeitritt),
-- teilt also die vorhandene Pool-Maschinerie (Upload, atomare Konsumierung
-- ueber FOR UPDATE SKIP LOCKED, Nachfuell-Zaehler). Es gehoert aber nicht
-- ins PQXDH-Buendel und wird ueber einen eigenen Endpunkt geclaimt.
ALTER TABLE prekeys
    DROP CONSTRAINT prekeys_kind_check,
    ADD CONSTRAINT prekeys_kind_check
        CHECK (kind IN ('signed', 'one_time', 'pq_signed', 'pq_one_time', 'mls_key_package'));
