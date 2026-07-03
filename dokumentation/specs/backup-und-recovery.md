# Spec: Backup und Recovery (Skizze)

Eine Skizze, keine fertige Spec. Sie steht hier, weil die Recovery-Story das Schlüsselmodell von Phase 1 prägt. Eine später nachgerüstete Lösung bricht das Modell sonst wieder auf.

## Das Problem

Der lokale Verlauf hängt am Recovery-Key beziehungsweise an der Passphrase. Geht beides verloren, ist der Verlauf weg, und in der Praxis verlieren damit viele Nutzer ihre History. Eine bequemere Lösung darf dem Server aber nicht das Geheimnis zeigen, sonst ist Zero-Knowledge hin.

## Der Ansatz: Secure Value Recovery

Nach dem Vorbild von Signal (SVR2, SVR3): Ein Recovery-Secret, das den Backup-Schlüssel entsperrt, liegt in einer abgesicherten Enclave. Der Nutzer entsperrt es mit einer niedrig-entropen PIN. Das harte Limit gegen Raten erzwingt der Counter-State der Enclave, nicht der Server, also kann der Betreiber die PIN nicht durchprobieren.

## Enclave-Realität

Das ist nicht hypothetisch, sondern hat eine konkrete Hardware-Frage. Intels SGX ist auf Client-CPUs abgekündigt und damit für einen Neubau keine Basis mehr. Realistisch bleiben AWS Nitro Enclaves oder Azure Confidential Computing. SVR3 verteilt das Vertrauen über mehrere Enclaves oder Anbieter (Threshold), damit eine einzelne Kompromittierung nicht reicht. Welche Kombination, ist offen, Tendenz Nitro.

Hier liegt ein Zielkonflikt mit dem On-Premise-Gebot (NF120): Eine vertrauenswürdige Enclave gibt es heute praktisch nur als Cloud-Angebot. Die Auflösung steht in NF120 und im Pflichtenheft (8.4): SVR ist optional und aufgeschoben, wird nur unter Threshold-Vertrauen über mehrere unabhängige Anbieter und mit ausdrücklicher Genehmigung der Ausbildungsleitung gebaut. Bis dahin bleibt der nutzergehaltene Recovery-Key der Standard, und der On-Premise-Anspruch bleibt für die Kern-Dienste unangetastet.

## Wo die Backups wohnen

Die verschlüsselten Backups liegen im Objektspeicher des Betreibers. Das ist unkritisch, solange der Schlüssel zu ihrer Entschlüsselung nur über die SVR-Enclave und die PIN herauskommt. Der Betreiber hat die Blobs, aber nicht den Schlüssel.

## Was Phase 1 offenhalten muss

Die wichtigste Konsequenz für jetzt: Die Schlüsselableitung darf nicht festschreiben, dass nur die Passphrase den lokalen Master-Key erzeugt. Es braucht von Anfang an einen Platz für ein zweites Entsperr-Geheimnis, das später aus der Enclave kommt. Gebaut wird SVR nach Phase 1, der Platz dafür bleibt schon jetzt frei.

## Offen

- Enclave-Wahl und Threshold-Aufteilung.
- PIN-Politik und das genaue Brute-Force-Limit über den Counter-State.
- Replikation des Counter-States, ohne das Limit zu unterlaufen.
- Schützt SVR nur den Backup-Schlüssel oder auch den Konto-Identitätsschlüssel?
