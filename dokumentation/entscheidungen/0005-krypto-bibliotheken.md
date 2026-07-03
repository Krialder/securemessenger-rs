# 0005: Krypto-Bibliotheken und ein gemeinsamer Rust-Core

**Status:** akzeptiert

## Kontext

Die Wahl der Krypto-Bibliothek entscheidet einen Großteil der Architektur. "Keine Eigenkrypto" allein reicht nicht, man muss sagen, woher die Verfahren kommen, und dieselbe Krypto soll auf vier Client-Plattformen laufen.

## Entscheidung

PQXDH, Double Ratchet und SPQR aus libsignal, MLS aus OpenMLS. Beide sind Rust. Daraus bauen wir einen gemeinsamen Krypto-Core, geteilt über alle Clients, als WebAssembly im Web und als native Bibliothek über FFI. Beide Abhängigkeiten werden auf einen konkreten Commit gepinnt, mit signed commit im Lockfile. Eine schwimmende Version nehmen wir nicht.

## Konsequenzen

Die heiklen Teile existieren einmal, in geprüftem Code, ein Fix gilt überall. Der Aufwand liegt im Tooling: WASM- und FFI-Builds, eine saubere Schnittstelle zwischen Core und UI-Sprache, und die Pflege der Bindings. Die Bindung an die Release-Zyklen von libsignal und OpenMLS ist beim Thema PQ-MLS sogar ein Vorteil, weil wir nachziehen, sobald OpenMLS es unterstützt.
