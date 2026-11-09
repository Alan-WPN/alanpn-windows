# AlanPN for Windows

Experimental open-source Windows 10/11 x64 client controlled from an AlanPN web account. Maintainer: [Alan-WPN](https://github.com/Alan-WPN). Contact: support@alanpn.ru.

## Status

Prototype, currently unsigned. SignPath Foundation approval has not been obtained. Full clean-machine, crash/leak, sleep/wake and uninstall acceptance testing is incomplete. Do not treat this as a production-ready VPN client.

## What it does

A Go Windows service starts the bundled Xray-core VLESS/TUN engine, protects device credentials using Windows DPAPI and ACLs, and receives authenticated commands through outbound HTTPS. A small user-session tray provides disconnect and disconnect-and-exit. No public localhost HTTP API is opened.

One tunnel at a time. Authenticated device synchronization renews a bounded five-minute authorization; closing the browser does not disconnect a healthy connection. Explicit disconnect, revocation, disabled access or expiry of authorization stops the tunnel and removes AlanPN protection. Xray failures trigger reconnect attempts while protection remains enabled. This is not an unconditional always-on kill switch: full service-crash, sleep/wake, IPv6 leak and clean-machine acceptance testing remains incomplete.

Version 0.1.2.1 adds fresh tray-launch acknowledgement, relaunch after disconnect-and-exit, and independent HTTPS DNS bootstrap for the GeoDNS endpoint. The endpoint hostname and imported TLS/WebSocket parameters are preserved. The website must offer installation again when a paired device is offline or tray startup is not confirmed; this UI and its backend live in the separate website repository.

## Install and remove

Use the account subscription button at https://alanpn.ru/. A newly installed service requires Windows administrator consent. The installer explains its components and paths before requesting consent. Program files: Program Files/AlanPN. Protected device data: ProgramData/AlanPN. Startup includes the Windows service and the owning user's tray. Use Windows Installed apps to uninstall; disconnect first. Existing third-party VPNs are not removed.

## Build

Requirements: Windows x64, Go version from go.mod, Python 3 and NSIS 3.13. Run python scripts/fetch_payload.py, python scripts/fetch_build_tools.py, then scripts/build-local-setup.ps1 -Production. Builds do not install or connect the VPN. Generated payloads and build outputs are excluded from source control.

The administrator-only `--network-test` diagnostic additionally requires an explicitly armed, short-lived local recovery permit. It is not invoked by installation, CI or ordinary account-managed connections. Tests run by CI do not create a real VPN.

The current backend appends a short-lived enrollment footer to a bootstrap template. This scheme must change to an immutable installer plus a separate secure enrollment channel before signed distribution. Do not modify a signed executable or ship a broken signature.

## Policies and components

- [Privacy](docs/PRIVACY.md)
- [Code signing policy](docs/CODE_SIGNING.md)
- Own source is MIT licensed; upstream Xray/Wintun and Go dependencies retain their own licenses. Official prebuilt Wintun signatures are retained. No upstream binary is claimed as AlanPN-authored code.
- The AlanPN name identifies this project; forks must not imply official affiliation.

The website backend and infrastructure are separate and are not included. There are no account credentials or real subscription configurations in this repository.
