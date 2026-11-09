# Build only. -Production selects a separate output and fixed HTTPS origin.
param([switch]$Production)
$ErrorActionPreference='Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
  $go=(Get-Command go -ErrorAction Stop).Source
  & (Join-Path $PSScriptRoot 'build-resources.ps1') -GoPath $go
  $version=(Get-Content -LiteralPath 'VERSION' -Raw).Trim()
  $directory=if($Production){'build/prod'}else{'build'}
  $output=[IO.Path]::GetFullPath((Join-Path $PWD $directory))
  New-Item -ItemType Directory -Path $output -Force | Out-Null
  $origin=if($Production){'https://alanpn.ru'}else{'https://127.0.0.1:13002'}
  $flags='-H=windowsgui -X alanpn/windows/internal/setupconfig.Origin='+$origin
  foreach($target in @('alanpn','tray')) {
    $name=if($target -eq 'alanpn'){'alanpn-client.exe'}else{'alanpn-tray.exe'}
    & $go build -trimpath -ldflags $flags -o (Join-Path $output $name) ('./cmd/'+$target)
    if($LASTEXITCODE -ne 0){throw 'Client build failed'}
  }
  & $go build -trimpath -o (Join-Path $output 'alanpn-netcheck.exe') ./cmd/netcheck
  if($LASTEXITCODE -ne 0){throw 'Netcheck build failed'}
  & build/tools/nsis-3.13/makensis.exe /INPUTCHARSET UTF8 "/DBUILD_DIR=$output" "/DAPP_VERSION=$version" /V2 installer/alanpn.nsi
  if($LASTEXITCODE -ne 0){throw 'Installer build failed'}
  New-Item -ItemType Directory cmd/bootstrap/payload -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $output 'AlanPN-Windows-Setup.exe') -Destination cmd/bootstrap/payload/installer.exe
  & $go build -trimpath -ldflags $flags -o (Join-Path $output 'AlanPN-Connect-Template.exe') ./cmd/bootstrap
  if($LASTEXITCODE -ne 0){throw 'Bootstrap build failed'}
  Write-Output ('Built '+$origin+'; nothing installed or connected.')
} finally {Pop-Location}
