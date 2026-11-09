# Build PE metadata without installing or running AlanPN.
param([Parameter(Mandatory=$true)][string]$GoPath)
$ErrorActionPreference='Stop'
$clientRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$version=(Get-Content -LiteralPath (Join-Path $clientRoot 'VERSION') -Raw).Trim()
if($version -notmatch '^\d+\.\d+\.\d+\.\d+$'){throw 'VERSION must have four numeric components'}
$parts=@($version.Split('.') | ForEach-Object {[int]$_})
if(@($parts | Where-Object {$_ -gt 65535}).Count){throw 'VERSION component exceeds Windows limits'}
$numeric=@{Major=$parts[0];Minor=$parts[1];Patch=$parts[2];Build=$parts[3]}
$resourceDirectory=Join-Path $clientRoot 'build/resources'
New-Item -ItemType Directory -Path $resourceDirectory -Force | Out-Null
$components=@{
  alanpn=@('alanpn-client.exe','AlanPN Windows service')
  tray=@('alanpn-tray.exe','AlanPN tray controls')
  netcheck=@('alanpn-netcheck.exe','AlanPN tunnel connectivity check')
  bootstrap=@('AlanPN-Connect-Template.exe','AlanPN connection setup')
}
foreach($component in $components.Keys){
  $metadata=@{
    FixedFileInfo=@{FileVersion=$numeric;ProductVersion=$numeric;FileFlagsMask='3f';FileFlags='00';FileOS='040004';FileType='01';FileSubType='00'}
    StringFileInfo=@{CompanyName='AlanPN contributors';ProductName='AlanPN';ProductVersion=$version;FileVersion=$version;FileDescription=$components[$component][1];OriginalFilename=$components[$component][0];InternalName=$components[$component][0];LegalCopyright='Copyright (c) 2026 AlanPN contributors';Comments='Experimental unsigned build'}
    VarFileInfo=@{Translation=@{LangID='0409';CharsetID='04B0'}}
    IconPath=(Join-Path $clientRoot 'cmd/tray/alanpn.ico')
  }
  if($component -eq 'bootstrap'){$metadata.ManifestPath=Join-Path $clientRoot 'cmd/bootstrap/bootstrap.manifest'}
  $configPath=Join-Path $resourceDirectory ($component+'.json')
  [IO.File]::WriteAllText($configPath,($metadata | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
  $resourcePath=Join-Path $clientRoot ('cmd/'+$component+'/rsrc_windows_amd64.syso')
  & $GoPath run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.7.0 -64 -o $resourcePath $configPath
  if($LASTEXITCODE -ne 0){throw ('Metadata generation failed: '+$component)}
}
Write-Output ('Prepared AlanPN Windows metadata '+$version)
