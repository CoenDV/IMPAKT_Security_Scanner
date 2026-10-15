# Syscollector

Verzamelt updategegevens in JSON, met aparte secties `installed` en `available`, bron, afbakening (`scope`), status, items, metadata-actualiteit en foutinformatie. Het programma installeert geen updates. Een fout in één bron verhindert het opslaan van de andere sectie niet.

Het rapport wordt als JSON naar bestand (`patches-<host>.json`) én `stdout` geschreven. Diagnostische tekstlogging gaat naar `stderr` én `patches-<host>.log`. Configuratie verloopt via YAML (`-c, --config <pad.yml>` of `--write-config`).

```sh
dotnet run --project src/Syscollector -- --write-config config.yml
dotnet run --project src/Syscollector -- --output results/patches.json
dotnet run --project src/Syscollector -- --scan --timeout 600 --max-cache-age-days 7
```

| Platform | Geïnstalleerd | Beschikbaar |
| --- | --- | --- |
| Windows | Software-updates die de lokale Windows Update Agent store als geïnstalleerd kent (`Online = false`); standaard zonder superseded updates. | Toepasselijke, niet-verborgen software-updates via de ingestelde updateservice, inclusief WSUS. |
| Linux: Debian/Ubuntu | Geïnstalleerde pakketten en versies via `dpkg-query`. | `apt list --upgradable` op basis van bestaande lokale indexen, inclusief controle op ouderdom van de metadata-cache. |
| Linux: RHEL/Fedora | Geïnstalleerde pakketten en versies via `rpm`. | `dnf --cacheonly check-update` op basis van bestaande lokale metadata (inclusief ondersteuning voor `Obsoleting Packages` en controle op cache-ouderdom). |
| macOS | Installatiehistorie via `system_profiler`, inclusief oude versies en installerregistraties van derden. | Updates die Apple Software Update aanbiedt. |

De bronnen leveren verschillende soorten bewijs. Linux geeft de huidige pakketversies, geen patchhistorie. De macOS-historie bewijst niet dat ieder genoemd pakket nog aanwezig is. Windows Update levert geen volledige inventaris van software van derden. Homebrew en andere app-updaters vallen buiten de beschikbare-updatecontrole op macOS. Andere Linux-pakketbeheerders geven een expliciete foutstatus.

APT- en DNF-metadata worden niet vernieuwd door `Syscollector`. Wel controleert `Syscollector` de datum van de lokale pakketcache (`metadataTimestampUtc` en `isMetadataStale`) en logt een waarschuwing als de lokale metadata ouder is dan `--max-cache-age-days` (standaard 7 dagen).

`--timeout` geldt per opdracht; standaard 300 seconden. Een timeout of onherkenbaar antwoord levert status `error`, geen geslaagde lege updatelijst. Exit `0` betekent dat beide secties succesvol zijn verzameld; exit `1` betekent een fout of onvolledige verzameling. De aanwezigheid van beschikbare updates levert op zichzelf geen foutcode op.
