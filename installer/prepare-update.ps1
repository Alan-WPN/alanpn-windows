# Called elevated by NSIS before replacing any installed payload.
param([Parameter(Mandatory=$true)][string]$InstallDirectory)
$ErrorActionPreference = 'Stop'
try {
  $target = [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
  $service = Get-CimInstance Win32_Service -Filter "Name='AlanPNClient'"
  if (!$service) { exit 0 }
  $expected = '"' + (Join-Path $target 'alanpn-client.exe') + '" --service'
  if ($service.PathName -ne $expected) { throw 'Existing service belongs to a different installation directory' }
  $backup = Join-Path $target ('rollback\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
  New-Item -ItemType Directory -Path $backup -Force | Out-Null
  foreach ($name in @('alanpn-client.exe','alanpn-tray.exe','alanpn-netcheck.exe','client.json','xray.exe','wintun.dll','payload-manifest.json')) {
    $source = Join-Path $target $name
    if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $backup }
  }
  if ((Get-Service AlanPNClient).Status -ne 'Stopped') {
    Stop-Service AlanPNClient
    (Get-Service AlanPNClient).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
  }
  $trayPath=Join-Path $target 'alanpn-tray.exe'
  Get-CimInstance Win32_Process -Filter "Name='alanpn-tray.exe'" | Where-Object { $_.ExecutablePath -eq $trayPath } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }
  # Verify locks are gone; never terminate other programs or skip a locked file.
  foreach ($name in @('alanpn-client.exe','alanpn-tray.exe','alanpn-netcheck.exe','xray.exe','wintun.dll')) {
    $file = Join-Path $target $name
    if (Test-Path -LiteralPath $file) {
      $handle = [IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
      $handle.Dispose()
    }
  }
  exit 0
} catch {
  # The saved payload/config are intact. Attempt to restore the previous idle service.
  try { Start-Service AlanPNClient -ErrorAction Stop } catch {}
  [Console]::Error.WriteLine('Cannot prepare AlanPN update: ' + $_.Exception.Message)
  exit 1
}
