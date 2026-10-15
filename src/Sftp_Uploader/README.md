# Sftp_Uploader

Zelfstandige SFTP-client voor het verzenden van gegenereerde rapporten van alle scanners. Ondersteunt wachtwoordauthenticatie via `SFTP_PASS` en authenticatie met een SSH-private-keybestand via `--key`.

Kopieer `sftp-config.example.yml` naar een lokaal `sftp-config.yml` (of genereer een template met `--write-config`) en vul de verbinding, private key en SHA256-serverfingerprint in. Lokale configuratiebestanden en keys worden door `.gitignore` uitgesloten. Verkrijg de fingerprint via de beheerder van de SFTP-server.

```sh
dotnet run --project src/Sftp_Uploader -- --write-config sftp-config.yml
dotnet run --project src/Sftp_Uploader -- --config sftp-config.yml --file results/patches.json --dry-run
dotnet run --project src/Sftp_Uploader -- --config sftp-config.yml --directory results/compliance --file results/patches.json
```

CLI-opties overschrijven de YAML-configuratie. Omgevingsvariabelen: `SFTP_HOST`, `SFTP_USER`, `SFTP_PASS`, `SFTP_HOST_KEY`, `SFTP_PATH`. Er worden geen wachtwoorden in commandoregelargumenten of YAML-configuratie opgeslagen. De client controleert de serverfingerprint vóór authenticatie.

Operationele voortgang en foutmeldingen worden als tekst gelogd naar `stderr` en optioneel naar een tekstlogbestand (`-l, --log <pad>` of `log_file` in YAML).

`--directory` neemt alle bestanden direct in de map mee, zonder submappen. `--file` mag herhaald worden. Ontbrekende bestanden en dubbele doelbestandsnamen worden vóór verbinding afgewezen. De remote map moet absoluut zijn; de uploader kan deze aanmaken als de bovenliggende map bestaat. Bestaande remote bestanden worden overschreven.

Exit `0` betekent dat alle geselecteerde bestanden zijn verzonden (of de dry-run slaagt). Exit `1` betekent een configuratie-, verbindings- of uploadfout. Bij gedeeltelijk succes blijven reeds verzonden bestanden op de server staan; een volgende run kan ze opnieuw verzenden.

De client gebruikt [SSH.NET](https://github.com/sshnet/SSH.NET).
