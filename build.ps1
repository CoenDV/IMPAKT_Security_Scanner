param(
    [string]$Runtime,
    [string]$Application
)
$ErrorActionPreference = 'Stop'

if (-not $Runtime) {
    dotnet build (Join-Path $PSScriptRoot 'IMPAKT_Security_Scanner.sln') --configuration Release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    exit 0
}

$projects = @(Get-ChildItem (Join-Path $PSScriptRoot 'src/*/*.csproj') |
    Where-Object { -not $Application -or $_.BaseName -eq $Application })
if ($projects.Count -eq 0) { throw "Unknown application: $Application" }

foreach ($project in $projects) {
    $output = Join-Path $PSScriptRoot "artifacts/publish/$($project.BaseName)/$Runtime"
    dotnet publish $project.FullName --configuration Release --runtime $Runtime `
        --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=false --output $output
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
