# Privacy

When authorized by the user, the Windows service contacts the configured AlanPN HTTPS control backend to enroll a device and exchange device authentication, command acknowledgements, selected subscription identifiers, connection state, tray-launch correlation values and bounded diagnostic codes. Authenticated device synchronization renews a bounded connection authorization independently of whether an account page remains open. The backend sees ordinary request network metadata such as the source IP. Subscription configurations are fetched from the provider endpoint. These operations are necessary for the requested account-managed VPN and are not a claim of zero network communication.

To bootstrap a connection without depending on Windows DNS already redirected into the tunnel, Xray resolves only the VPN endpoint hostname using Cloudflare DNS-over-HTTPS at 1.1.1.1. Other configured DNS queries are routed through the VPN. The DNS resolver receives the requested hostname and ordinary connection metadata; it does not receive device tokens or subscription URLs.

Device credentials are stored locally using DPAPI with restricted filesystem permissions. Tokens and subscription secrets are not intended for logs or command-line arguments. The current downloaded bootstrap contains short-lived enrollment credentials; keep it private and discard it after use.

The VPN carries application traffic through the selected provider servers. This client does not make a guarantee about server retention or third-party destinations. Service policies: https://alanpn.ru/legal.

Installing registers the service, user tray startup and a custom protocol handler. Connecting creates AlanPN TUN/routing and Windows Filtering Platform rules. Disconnect removes the AlanPN engine/adapter and its protection; it does not uninstall other VPNs. Network behavior and failure limitations are described in README.

Contact support@alanpn.ru for privacy or security questions.
