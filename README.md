# IMPAKT Security Scanner

Een repository met zelfstandige C# console-applicaties voor compliance, patchinventarisatie en rapportverzending. Vereist .NET SDK 10 voor ontwikkeling; gepubliceerde pakketten zijn self-contained.

| Applicatie | Doel |
| --- | --- |
| [Compliance_Scanner](src/Compliance_Scanner/README.md) | Systeemconfiguratie toetsen aan Wazuh SCA YAML-policies; JSON-rapportage en tekstlogging. |
| [Syscollector](src/Syscollector/README.md) | Geïnstalleerde en beschikbare updates verzamelen op Windows, Linux en macOS; JSON-rapportage en tekstlogging. |
| [Sftp_Uploader](src/Sftp_Uploader/README.md) | Rapportbestanden van iedere applicatie zelfstandig verzenden via SFTP. |

Elk project heeft een eigen executable en eigen afhankelijkheden. De scanners hebben geen referentie naar de uploader.

## Standaarden (Configuratie & Output)

- **Configuratie:** Alle applicaties gebruiken **YAML** als configuratieformaat (`-c, --config <pad.yml>` en `--write-config [pad.yml]`).
- **Output:** Alle scanners produceren gestructureerde **JSON** (naar `.json`-bestand én `stdout`, bedoeld als input voor een downstream ESB/Pipeline-package) en **tekst in de vorm van logging** (naar `stderr` én `.log`-bestand).

## Ontwikkelen

```sh
dotnet build IMPAKT_Security_Scanner.sln --configuration Release
dotnet test IMPAKT_Security_Scanner.sln --configuration Release

dotnet run --project src/Compliance_Scanner -- --help
dotnet run --project src/Syscollector -- --help
dotnet run --project src/Sftp_Uploader -- --help
```

Voorbeeldworkflow, uit te voeren vanuit de repository-root:

```sh
dotnet run --project src/Compliance_Scanner -- --output-dir results/compliance src/Compliance_Scanner/Policies/
dotnet run --project src/Syscollector -- --output results/patches.json
dotnet run --project src/Sftp_Uploader -- --config sftp-config.yml --directory results/compliance --file results/patches.json
```

Voer de scan en verzending als afzonderlijke stappen uit. Een compliancescan kan code 1 teruggeven bij afwijkingen terwijl rapporten wel zijn geschreven. Laat een scheduler of pipeline expliciet bepalen of die rapporten vervolgens worden verzonden. Gebruik `--file` om uitsluitend de gewenste JSON-rapporten te verzenden; `--directory` verstuurt ook logbestanden in die map.

## Pakketten bouwen

```sh
./build.sh                         # Release-build van de solution
./build.sh win-x64                 # Alle applicaties voor Windows
./build.sh linux-x64 Syscollector  # Eén applicatie voor Linux
./build.sh osx-arm64               # Alle applicaties voor Apple Silicon
```

PowerShell-equivalent:

```powershell
.\build.ps1 -Runtime win-x64
.\build.ps1 -Runtime linux-x64 -Application Syscollector
```

Uitvoer staat per applicatie in `artifacts/publish/<Application>/<Runtime>/`. Distribueer de volledige map, inclusief de `Policies`-map bij `Compliance_Scanner`.

## Structuur uitbreiden

```text
IMPAKT_Security_Scanner.sln
Directory.Build.props
global.json
src/
  Compliance_Scanner/
  Sftp_Uploader/
  Syscollector/
tests/
  IMPAKT_Security_Scanner.Tests/
```

Nieuwe console-applicaties komen in `src/<Naam>/<Naam>.csproj` en worden toegevoegd met `dotnet sln add src/<Naam>/<Naam>.csproj`. De buildscripts nemen alle consoleprojecten onder `src` automatisch mee.
