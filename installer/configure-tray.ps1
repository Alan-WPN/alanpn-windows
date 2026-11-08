param([Parameter(Mandatory=$true)][string]$InstallDirectory,[switch]$Remove)
$ErrorActionPreference='Stop'
try {
  $target=[IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
  $config=Get-Content -LiteralPath (Join-Path $target 'client.json') -Raw | ConvertFrom-Json
  $owner=[Security.Principal.SecurityIdentifier]::new($config.ownerSID)
  if (!$owner.Value.StartsWith('S-1-5-21-')) { throw 'Invalid owner' }
  $hive=[Microsoft.Win32.Registry]::Users.OpenSubKey($owner.Value,$true)
  if (!$hive) { throw 'Installation owner session is not available' }
  try {
    $run=$hive.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Run')
    try {
      if($Remove) { $run.DeleteValue('AlanPN',$false) }
      else { $run.SetValue('AlanPN','"'+(Join-Path $target 'alanpn-tray.exe')+'"',[Microsoft.Win32.RegistryValueKind]::String) }
    } finally { $run.Dispose() }
  } finally { $hive.Dispose() }
  if($Remove) {
    $expected=Join-Path $target 'alanpn-tray.exe'
    Get-CimInstance Win32_Process -Filter "Name='alanpn-tray.exe'" | Where-Object { $_.ExecutablePath -eq $expected } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }
  }
  exit 0
} catch { [Console]::Error.WriteLine('Cannot configure AlanPN tray');exit 1 }
