# Testing from a phone or tablet

This guide sets up an Android or iOS device to send its traffic through ProxyMind and trust ProxyMind's CA, so you can
inspect the HTTPS traffic of **your own devices and apps, or ones you are authorised to test**. It also shows how to tell
devices apart in history and record only one of them.

Anyone who can reach the proxy can send traffic through it, and anyone who holds ProxyMind's CA key can read the HTTPS
traffic of a device that trusts the CA. Use a test device or a test profile, a network you trust, and remove the
certificate and the proxy setting when the engagement ends.

## 1. Let the phone reach the proxy

By default ProxyMind's proxy listens on `127.0.0.1`, which only this computer can reach. Add a listener on all
interfaces: on the **Proxy setup** page, under *Proxy listeners*, add `0.0.0.0:8081` (or any free port) and save. Or
start the UI with `proxymind ui --proxy 0.0.0.0:8080`. Then check:

- The computer and the phone are on the same Wi-Fi network (guest networks often isolate devices from each other).
- This computer's firewall allows incoming connections on that port.

The **Phone or tablet** section of the Proxy setup page then shows the address to open on the phone and a QR code for
it, for example `http://192.168.1.5:8081/`, and the address to enter as the phone's proxy (`192.168.1.5:8081`).

If the page shows no address, ProxyMind could not find this computer's network address (it finds it from the system's
network interfaces). Inside a container, or with a VPN that hides it, give it by hand:
`PROXYMIND_LAN_ADDR=192.168.1.5 proxymind ui …` (several addresses separated by commas).

## 2. The setup page

Open the address (or scan the QR code with the camera) on the phone. ProxyMind's proxy answers by itself with a small
page that has the certificate as a download, its SHA-256 fingerprint, and short steps for Android and iOS. The page
works in two ways:

- **By address:** `http://<computer address>:<port>/`, before the phone has any proxy setting. This is what the QR code
  holds.
- **By name:** `http://proxymind.setup/` (or `http://proxymind/`) once the phone's proxy is set. The proxy answers this
  name itself and never forwards it anywhere.

The page holds only public things: the certificate (not its key), its fingerprint and the proxy address. These requests
are not recorded as traffic and are not touched by match-and-replace rules or the intercept queue. Two downloads are
offered: `/ca.crt` (DER, the form phones install) and `/ca.pem` (PEM).

Compare the fingerprint on the phone's page, and on the phone after installing, with the one on the ProxyMind setup page.

## 3. Android (14 and later)

Menu names differ a little between makers; the steps are the same.

1. On the phone, open the setup page and download the **.crt** file. The phone needs a screen lock (PIN, pattern or
   password) before it will install certificates.
2. Install it: **Settings, Security and privacy, More security settings, Encryption and credentials, Install a
   certificate, CA certificate** (on some phones the path starts with *Security* or *Biometrics and security*). Android
   warns about CA certificates; choose **Install anyway**, then pick the downloaded file. Opening the file from the
   notification or Downloads app takes you to the same place.
3. Check it: **Encryption and credentials, Trusted credentials, User** lists *ProxyMind CA*; tapping it shows the
   fingerprint.
4. Set the Wi-Fi proxy: **Settings, Network and internet, Wi-Fi**, open your network's details (the gear), **Edit** (the
   pencil), **Advanced options, Proxy: Manual**. Enter the computer's address as host and the proxy port, then save.
   Reconnect if the phone asks.

### What trusts the certificate

Android keeps two stores. The **system** store holds the CAs that ship with the phone. The **user** store holds what you
install as above.

- **Chrome and most browsers** use Android's trust and accept user certificates, so web browsing works. Firefox has its
  own switch (Settings, *Use third party CA certificates*).
- **Apps that target Android 7 (API 24) or later ignore user certificates** unless the app opts in with a network
  security configuration. That is a protection by design, not a fault in ProxyMind: such an app shows connection errors
  through the proxy.
- **Apps you build yourself:** for a debug build, opt in to user certificates in a debug-only network security
  configuration (`res/xml/network_security_config.xml` referenced from the manifest's `android:networkSecurityConfig`):

  ```xml
  <network-security-config>
    <debug-overrides>
      <trust-anchors>
        <certificates src="user" />
      </trust-anchors>
    </debug-overrides>
  </network-security-config>
  ```

  `debug-overrides` applies only to debuggable builds, so release builds are unchanged.
- **The system store** cannot be changed on a normal phone. On Android 14 the system CAs also moved into an updatable
  system component, so the old tricks of remounting `/system` no longer work. For your own testing, use an emulator
  image without Google Play (`adb root` is available there) or a device you have rooted for this purpose, and follow
  the documentation of that tool. Do this only for devices and apps you own or are authorised to test. This guide does
  not cover bypassing the certificate pinning or trust settings of other people's apps.
- **Apps that ignore the Wi-Fi proxy** (they open their own connections) do not reach ProxyMind at all. The Wi-Fi proxy
  is a setting that well-behaved apps read; it is not enforced. For those, an extra ProxyMind listener with a redirect
  (for clients that cannot be told where to go) is the next step; see *Proxy listeners* on the setup page.

Remove it when you finish: **Encryption and credentials, User credentials, ProxyMind CA, Remove**, and set the Wi-Fi
proxy back to *None*.

## 4. iOS and iPadOS

1. Open the setup page **in Safari** (other browsers cannot install profiles) and tap the **.crt** download. Tap
   **Allow** when it asks to download a configuration profile.
2. **Settings, General, VPN and Device Management**, tap the downloaded profile (*ProxyMind CA*), **Install**, enter
   the passcode and confirm. On older versions the profile shows at the top of the Settings app.
3. **Settings, General, About, Certificate Trust Settings**: under *Enable full trust for root certificates*, switch on
   **ProxyMind CA**. Without this step iOS installs the certificate but does not trust it for HTTPS.
4. Set the Wi-Fi proxy: **Settings, Wi-Fi**, the (i) next to your network, **Configure Proxy, Manual**. Enter the
   computer's address as *Server* and the proxy port as *Port*; leave *Authentication* off. Save.

Safari and apps that use the system networking follow the proxy and trust the CA. Apps that pin their certificates, or
open their own connections, fail or bypass the proxy; that is how those apps protect their users.

Remove it when you finish: **Settings, General, VPN and Device Management**, the profile, **Remove Profile**, and set
the Wi-Fi proxy back to *Off*.

## 5. Telling devices apart

ProxyMind records the address each proxied request came from (the IP address only, no port).

- **History** has a **Client** column and a *device* filter, and the query language has `client:`:
  `client:192.168.1.23`, `client:"Pixel 8"`, `-client:"Pixel 8"`. Rows from before this was recorded, and requests
  ProxyMind sent itself (Replay, scans), have no client.
- **Names:** on the Proxy setup page, under *What to record*, the *Devices* table lists the addresses seen. Type a name
  next to an address (for example *Pixel 8*) and press Enter. A name works in the filter and in `client:` wherever an
  address does. Phone addresses can change (DHCP); rename when they do.
- **Record only one device:** tick *record only* on one or more devices. Other devices' traffic is still proxied, just
  not saved, which is useful on a shared network. Nothing ticked means every device is recorded. It combines with
  *record only in-scope traffic*: both must hold.

The same things are in the API: `GET /api/v1/setup/mobile`, `GET /api/v1/devices`, `PUT` and `DELETE`
`/api/v1/devices/{addr}`, `record_devices` on `/api/v1/history/recording`, and `client` on `/api/v1/exchanges`.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| The page does not open on the phone | Different networks or an isolated guest Wi-Fi; a firewall on this computer; the listener is on `127.0.0.1` only |
| The page opens, browsing fails | The phone's proxy is not set, or has the wrong port |
| Browsing works, HTTPS shows certificate errors | The certificate is not installed, or on iOS *full trust* is not switched on |
| Chrome works, an app does not | The app ignores user certificates (Android 7 and later) or pins its certificate |
| Nothing from the phone in History | *Record only* is set for another device, or the app ignores the Wi-Fi proxy |
| No address on the setup page | Set `PROXYMIND_LAN_ADDR` |
