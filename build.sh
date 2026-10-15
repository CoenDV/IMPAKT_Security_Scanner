#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
runtime="${1:-}"
application="${2:-}"

if [[ -z "$runtime" ]]; then
  dotnet build "$repo_dir/IMPAKT_Security_Scanner.sln" --configuration Release
  exit 0
fi

found=false
for project in "$repo_dir"/src/*/*.csproj; do
  name="$(basename -- "$project" .csproj)"
  if [[ -n "$application" && "$application" != "$name" ]]; then continue; fi
  found=true
  dotnet publish "$project" --configuration Release --runtime "$runtime" \
    --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=false \
    --output "$repo_dir/artifacts/publish/$name/$runtime"
done
if [[ "$found" == false ]]; then
  echo "Unknown application: $application" >&2
  exit 1
fi
