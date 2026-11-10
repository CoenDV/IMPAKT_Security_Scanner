# IMPAKT Security Scanner

Een repository met zelfstandige C# console-applicaties voor compliance en rapportverzending. Vereist .NET SDK 10 voor ontwikkeling; gepubliceerde pakketten zijn self-contained.

| Applicatie | Doel |
| --- | --- |
| [Compliance_Scanner](src/Compliance_Scanner/README.md) | Systeemconfiguratie toetsen aan Wazuh SCA YAML-policies; JSON-rapportage en tekstlogging. |
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
dotnet run --project src/Sftp_Uploader -- --help
```

Voorbeeldworkflow, uit te voeren vanuit de repository-root:

```sh
dotnet run --project src/Compliance_Scanner -- --output-dir results/compliance src/Compliance_Scanner/Policies/
dotnet run --project src/Sftp_Uploader -- --config sftp-config.yml --directory results/compliance
```

Voer de scan en verzending als afzonderlijke stappen uit. Een compliancescan kan code 1 teruggeven bij afwijkingen terwijl rapporten wel zijn geschreven. Laat een scheduler of pipeline expliciet bepalen of die rapporten vervolgens worden verzonden. Gebruik `--file` om uitsluitend de gewenste JSON-rapporten te verzenden; `--directory` verstuurt ook logbestanden in die map.

## Pakketten bouwen

```sh
./build.sh                         # Release-build van de solution
./build.sh win-x64                 # Alle applicaties voor Windows
./build.sh linux-x64 Sftp_Uploader # Eén applicatie voor Linux
./build.sh osx-arm64               # Alle applicaties voor Apple Silicon
```

PowerShell-equivalent:

```powershell
.\build.ps1 -Runtime win-x64
.\build.ps1 -Runtime linux-x64 -Application Sftp_Uploader
```

Uitvoer staat per applicatie in `artifacts/publish/<Application>/<Runtime>/`. Distribueer de volledige map, inclusief de `Policies`-map bij `Compliance_Scanner`.

## Automatische builds en releases

Iedere push naar `main` start de GitHub Actions-workflow `Build and release`, ook bij uitsluitend documentatiewijzigingen. De workflow bouwt de solution zonder waarschuwingen en voert de tests uit op Windows, Linux en macOS. Daarna publiceert hij alle applicaties als self-contained pakketten voor `win-x64`, `linux-x64` en `osx-arm64`; op de doelmachine is geen aparte .NET-installatie nodig.

Als alle platformbuilds en tests slagen, verschijnt onder [Releases](https://github.com/J0113/IMPAKT_Security_Scanner/releases) een release met tag `build-<runnummer>`, gekoppeld aan de exacte gebouwde commit. Elke applicatie heeft een eigen download per platform: `.zip` voor Windows en `.tar.gz` voor Linux/macOS. De pakketten bevatten de volledige publish-uitvoer en de applicatie-README. De release bevat ook `SHA256SUMS.txt`. Externe CIS-policies worden niet meegeleverd; voeg die indien nodig zelf toe.

Een push met meerdere commits levert één build en release op van de laatste commit in die push. Lopende builds worden niet geannuleerd door een volgende push. Een mislukte build of test publiceert geen release. Een gepubliceerde release blijft bij opnieuw uitvoeren van dezelfde workflow behouden; een nog niet gepubliceerde draft wordt afgemaakt. De pakketten zijn daarnaast zeven dagen als workflow-artifact beschikbaar.

De workflow gebruikt het ingebouwde `GITHUB_TOKEN` en vraagt alleen voor de release-job `contents: write` aan ([GitHub-documentatie](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)). Er zijn geen extra secrets nodig. GitHub Actions moet ingeschakeld zijn voor de repository. Via **Actions → Build and release → Run workflow** kan de workflow ook handmatig worden gestart; alleen op `main` wordt een release gepubliceerd.

## Structuur uitbreiden

```text
IMPAKT_Security_Scanner.sln
Directory.Build.props
global.json
src/
  Compliance_Scanner/
  Sftp_Uploader/
tests/
  IMPAKT_Security_Scanner.Tests/
```

Nieuwe console-applicaties komen in `src/<Naam>/<Naam>.csproj` en worden toegevoegd met `dotnet sln add src/<Naam>/<Naam>.csproj`. De buildscripts nemen alle consoleprojecten onder `src` automatisch mee.
