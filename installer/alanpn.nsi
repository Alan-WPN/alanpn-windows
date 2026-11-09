Unicode True
!include "LogicLib.nsh"
!include "FileFunc.nsh"
Name "AlanPN Windows - local prototype"
!ifndef APP_VERSION
!define APP_VERSION "0.1.0.0"
!endif
VIProductVersion "${APP_VERSION}"
VIAddVersionKey /LANG=1033 "ProductName" "AlanPN"
VIAddVersionKey /LANG=1033 "CompanyName" "AlanPN contributors"
VIAddVersionKey /LANG=1033 "FileDescription" "AlanPN Windows installer"
VIAddVersionKey /LANG=1033 "FileVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Copyright (c) 2026 AlanPN contributors"
!ifndef BUILD_DIR
!define BUILD_DIR "..\build"
!endif
OutFile "${BUILD_DIR}\AlanPN-Windows-Setup.exe"
InstallDir "$PROGRAMFILES64\AlanPN"
RequestExecutionLevel admin
SilentInstall silent
AutoCloseWindow true
ShowInstDetails nevershow
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles
Var ExistingService
Var OwnerSID

Function .onInit
  SetErrorLevel 1
  ${GetParameters} $0
  ${GetOptions} $0 "/OWNER_SID=" $OwnerSID
FunctionEnd

Section "AlanPN"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "${BUILD_DIR}\alanpn-client.exe"
  ; Stop and back up an existing service BEFORE attempting to overwrite its exe.
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query AlanPNClient'
  Pop $ExistingService
  Pop $1
  File "prepare-update.ps1"
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\prepare-update.ps1" -InstallDirectory "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Не удалось безопасно остановить установленный AlanPN. Обновление отменено; прежние файлы сохранены."
    Abort
  ${EndIf}
  SetOutPath "$INSTDIR"
  File "${BUILD_DIR}\alanpn-client.exe"
  File "${BUILD_DIR}\alanpn-tray.exe"
  File "configure-tray.ps1"
  File "..\vendor-assets\xray.exe"
  File "${BUILD_DIR}\alanpn-netcheck.exe"
  File "..\vendor-assets\wintun.dll"
  File "..\vendor-assets\payload-manifest.json"
  File /r "..\vendor-assets\licenses"
  nsExec::ExecToStack '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    Abort "Не удалось защитить каталог клиента"
  ${EndIf}
  SetShellVarContext all
  CreateDirectory "$APPDATA\AlanPN"
  nsExec::ExecToStack '"$SYSDIR\icacls.exe" "$APPDATA\AlanPN" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    Abort "Не удалось защитить хранилище клиента"
  ${EndIf}
  ; Retain the owner SID, backend origin and DPAPI device credentials during upgrades.
  IfFileExists "$INSTDIR\client.json" configured
    ${If} $OwnerSID == ""
      ExecWait '"$INSTDIR\alanpn-client.exe" --setup' $0
    ${Else}
      ExecWait '"$INSTDIR\alanpn-client.exe" --setup-owner=$OwnerSID' $0
    ${EndIf}
    ${If} $0 != 0
      Abort "Не удалось подготовить настройки клиента"
    ${EndIf}
  configured:
  ExecWait '"$INSTDIR\alanpn-client.exe" --update-origin' $0
  ${If} $0 != 0
    Abort "Не удалось настроить адрес управления AlanPN"
  ${EndIf}
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\configure-tray.ps1" -InstallDirectory "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    Abort "Не удалось настроить значок AlanPN для пользователя"
  ${EndIf}
  ${If} $ExistingService == 0
    nsExec::ExecToStack '"$SYSDIR\sc.exe" config AlanPNClient binPath= "\"$INSTDIR\alanpn-client.exe\" --service" start= auto'
    Pop $0
    Pop $1
  ${Else}
    nsExec::ExecToStack '"$SYSDIR\sc.exe" create AlanPNClient binPath= "\"$INSTDIR\alanpn-client.exe\" --service" start= auto obj= LocalSystem DisplayName= "AlanPN Client"'
    Pop $0
    Pop $1
  ${EndIf}
  ${If} $0 != 0
    Abort "Не удалось зарегистрировать службу AlanPN. Копия предыдущего выпуска сохранена в rollback."
  ${EndIf}
  nsExec::ExecToStack '"$SYSDIR\sc.exe" failure AlanPNClient reset= 86400 actions= restart/3000/restart/5000/restart/10000'
  Pop $0
  Pop $1
  nsExec::ExecToStack '"$SYSDIR\sc.exe" failureflag AlanPNClient 1'
  Pop $0
  Pop $1
  WriteRegStr HKLM "Software\Classes\alanpn" "" "URL:AlanPN Protocol"
  WriteRegStr HKLM "Software\Classes\alanpn" "URL Protocol" ""
  WriteRegStr HKLM "Software\Classes\alanpn\shell\open\command" "" '"$INSTDIR\alanpn-client.exe" "%1"'
  CreateDirectory "$SMPROGRAMS\AlanPN"
  CreateShortcut "$SMPROGRAMS\AlanPN\Отключить VPN.lnk" "$INSTDIR\alanpn-client.exe" "--disconnect"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AlanPN" "DisplayName" "AlanPN local prototype"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AlanPN" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  nsExec::ExecToStack '"$SYSDIR\sc.exe" start AlanPNClient'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Служба AlanPN не запустилась. Копия предыдущих файлов сохранена в rollback."
    Abort
  ${EndIf}
  SetErrorLevel 0
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  ExecWait '"$INSTDIR\alanpn-client.exe" --cleanup' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Сначала восстановите службу AlanPN и отключите VPN. Удаление остановлено, чтобы не оставить блокирующие правила."
    Abort
  ${EndIf}
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\configure-tray.ps1" -InstallDirectory "$INSTDIR" -Remove'
  Pop $0
  Pop $1
  ${If} $0 != 0
    Abort "Не удалось убрать автозапуск AlanPN. Файлы клиента сохранены."
  ${EndIf}
  nsExec::ExecToStack '"$SYSDIR\sc.exe" stop AlanPNClient'
  Pop $0
  Pop $1
  Sleep 3000
  nsExec::ExecToStack '"$SYSDIR\sc.exe" delete AlanPNClient'
  Pop $0
  Pop $1
  DeleteRegKey HKLM "Software\Classes\alanpn"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AlanPN"
  Delete "$SMPROGRAMS\AlanPN\Отключить VPN.lnk"
  RMDir "$SMPROGRAMS\AlanPN"
  Delete "$APPDATA\AlanPN\credentials.bin"
  RMDir "$APPDATA\AlanPN"
  Delete "$INSTDIR\alanpn-client.exe"
  Delete "$INSTDIR\alanpn-tray.exe"
  Delete "$INSTDIR\configure-tray.ps1"
  Delete "$INSTDIR\client.json"
  Delete "$INSTDIR\xray.exe"
  Delete "$INSTDIR\alanpn-netcheck.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\payload-manifest.json"
  Delete "$INSTDIR\licenses\*.*"
  RMDir "$INSTDIR\licenses"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
