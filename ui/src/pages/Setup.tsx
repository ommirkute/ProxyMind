import { useState } from "react";
import { api, openBrowser, toast } from "../api";
import { Icon } from "../icons";
import { Empty, ErrorBox, Panel, useAction, useLoad, useNav } from "../components";
import type { DeviceView, DevicesView, MobileSetup, RecordingSettings } from "../api-types.gen";
import Listeners from "./Listeners";

const MOBILE_GUIDE = "https://github.com/ommirkute/ProxyMind/blob/main/docs/mobile.md";

interface SetupInfo {
  proxy: string | null;
  ca_available: boolean;
  ca_sha256: string | null;
  browser_available?: boolean;
}

type Os = "macos" | "windows" | "linux" | "firefox" | "cli";

const guess = (): Os => {
  const p = navigator.userAgent;
  if (/Mac/.test(p)) return "macos";
  if (/Win/.test(p)) return "windows";
  return "linux";
};

/** How to send a browser's traffic through ProxyMind and trust its CA for HTTPS. */
export default function Setup() {
  const info = useLoad(() => api.get<SetupInfo>("/setup"), []);
  const { counters } = useNav();
  const [os, setOs] = useState<Os>(guess());
  const [startUrl, setStartUrl] = useState("");
  const proxy = info.data?.proxy ?? "127.0.0.1:8080";
  const [host, port] = proxy.includes(":") ? [proxy.slice(0, proxy.lastIndexOf(":")), proxy.slice(proxy.lastIndexOf(":") + 1)] : [proxy, "8080"];

  return (
    <div className="content">
      <ErrorBox error={info.error} />
      {info.data?.browser_available && (
        <div className="hero">
          <span className="hero-icon"><Icon name="globe" size={22} /></span>
          <div>
            <h2>The easy way: ProxyMind's browser</h2>
            <p className="small">
              A Chromium window that already goes through the proxy and trusts ProxyMind's CA, for that window only:
              nothing to configure, nothing installed on your system. It keeps its own logins and cookies between launches.
            </p>
          </div>
          <div className="actions">
            <input aria-label="Start page" placeholder="start page (default: scope)" value={startUrl} onChange={(e) => setStartUrl(e.target.value)} style={{ width: 240 }} />
            <button
              className="btn primary"
              data-testid="setup-open-browser"
              onClick={() =>
                openBrowser(startUrl.trim() || undefined)
                  .then((b) => toast(`Browser opened at ${b.url}`))
                  .catch((e) => toast(e.message, "bad"))
              }
            >
              <Icon name="globe" size={15} /> Launch browser
            </button>
          </div>
        </div>
      )}
      <p className="small muted" style={{ margin: "0 0 12px" }}>Or set up your own browser:</p>
      <div className="split">
        <Panel title="1. Send traffic through the proxy">
          {info.data && !info.data.proxy ? (
            <Empty>This process doesn't run the proxy (started with --no-proxy). Start <code>proxymind ui</code> or <code>proxymind proxy</code>.</Empty>
          ) : (
            <>
              <p>Set your browser or system HTTP and HTTPS proxy to:</p>
              <pre className="raw" data-testid="setup-proxy">{proxy}</pre>
              <p className="small muted">
                For clients that speak SOCKS5 (curl <code>--socks5-hostname</code>, Android SOCKS apps) or that can't be
                given proxy settings at all (Linux traffic redirected by iptables), add a SOCKS5 or transparent listener
                under "3. Proxy listeners" below.
              </p>
              <p className="small muted">
                Tip: use a separate browser profile for testing, so only that profile's traffic goes through ProxyMind. For
                Chromium: <code>chromium --proxy-server=http://{proxy} --user-data-dir=/tmp/pm-profile</code>
              </p>
              <p className="small">{counters ? `${counters.exchanges} exchanges recorded so far: browse a page in scope and this number goes up.` : null}</p>
            </>
          )}
        </Panel>
        <Panel title="2. Trust the ProxyMind CA (for HTTPS)">
          {info.data?.ca_available ? (
            <>
              <p>
                <a className="btn primary" href="/api/v1/ca.pem" download="proxymind-ca.pem" data-testid="ca-download">Download CA certificate</a>
              </p>
              <p className="small">
                SHA-256 fingerprint (check it matches when you install): <br />
                <code className="mono" data-testid="ca-fingerprint" style={{ wordBreak: "break-all" }}>{info.data.ca_sha256}</code>
              </p>
              <p className="small muted">
                This CA is created for you on this machine and its key never leaves it. Anyone with the key can intercept your
                HTTPS traffic, so trust it only in a testing profile, and remove it when the engagement ends.
              </p>
              <div className="row" role="tablist" style={{ marginTop: 8 }}>
                {(["macos", "windows", "linux", "firefox", "cli"] as Os[]).map((o) => (
                  <button key={o} role="tab" aria-selected={os === o} className={`tab ${os === o ? "active" : ""}`} onClick={() => setOs(o)}>
                    {{ macos: "macOS", windows: "Windows", linux: "Linux", firefox: "Firefox", cli: "curl, Python…" }[o]}
                  </button>
                ))}
              </div>
              <Instructions os={os} host={host} port={port} />
            </>
          ) : (
            <Empty>No CA here: this process doesn't run the proxy.</Empty>
          )}
        </Panel>
      </div>
      <Phone />
      <div id="listeners"><Listeners /></div>
      <Recording />
    </div>
  );
}

function Instructions({ os, host, port }: { os: Os; host: string; port: string }) {
  const steps: Record<Os, JSX.Element> = {
    macos: (
      <>
        <p>Add it to your login keychain and trust it for SSL (asks for your password):</p>
        <pre className="raw">security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ~/Downloads/proxymind-ca.pem</pre>
        <p className="small">To remove later: Keychain Access → login → Certificates → "ProxyMind" → Delete.</p>
      </>
    ),
    windows: (
      <>
        <p>Add it to your user's Trusted Root store (Windows asks you to confirm):</p>
        <pre className="raw">certutil -user -addstore Root %USERPROFILE%\Downloads\proxymind-ca.pem</pre>
        <p className="small">To remove later: <code>certmgr.msc</code> → Trusted Root Certification Authorities → "ProxyMind" → Delete.</p>
      </>
    ),
    linux: (
      <>
        <p>Chrome and Chromium on Linux use your NSS database:</p>
        <pre className="raw">certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n ProxyMind -i ~/Downloads/proxymind-ca.pem</pre>
        <p className="small">(<code>certutil</code> is in <code>libnss3-tools</code> / <code>nss-tools</code>.) For system-wide tools, Debian/Ubuntu:</p>
        <pre className="raw">sudo cp ~/Downloads/proxymind-ca.pem /usr/local/share/ca-certificates/proxymind-ca.crt && sudo update-ca-certificates</pre>
      </>
    ),
    firefox: (
      <>
        <p>Firefox has its own certificate store: Settings → Privacy &amp; Security → Certificates → View Certificates → Authorities → Import, choose the file and tick "Trust this CA to identify websites".</p>
        <p>Proxy: Settings → Network Settings → Manual proxy configuration: HTTP proxy <code>{host}</code>, port <code>{port}</code>, and "Also use this proxy for HTTPS".</p>
      </>
    ),
    cli: (
      <>
        <pre className="raw">{`curl --proxy http://${host}:${port} --cacert proxymind-ca.pem https://target.example/
export HTTPS_PROXY=http://${host}:${port} REQUESTS_CA_BUNDLE=$PWD/proxymind-ca.pem   # Python requests
export NODE_EXTRA_CA_CERTS=$PWD/proxymind-ca.pem                                   # Node.js`}</pre>
      </>
    ),
  };
  return <div className="small" data-testid="ca-instructions" style={{ marginTop: 8 }}>{steps[os]}</div>;
}

/** An SVG string as an image source (shown through <img>, so nothing in it can run). */
const svgSrc = (svg: string) => `data:image/svg+xml;base64,${btoa(unescape(encodeURIComponent(svg)))}`;

/** Phones and tablets: the page to open (with a QR code) to install the CA, and whether they can reach the proxy. */
function Phone() {
  const m = useLoad(() => api.get<MobileSetup>("/setup/mobile"), []);
  const d = m.data;
  return (
    <Panel title="Phone or tablet" actions={<a className="small" href={MOBILE_GUIDE} target="_blank" rel="noreferrer" data-testid="mobile-guide">Android and iOS guide</a>}>
      <ErrorBox error={m.error} />
      {d && !d.proxy_running && <Empty>This process doesn't run the proxy, so there is nothing for a phone to connect to.</Empty>}
      {d?.proxy_running && !d.listener_reachable && (
        <div data-testid="mobile-unreachable">
          <p>
            The proxy listens only on this computer ({d.listeners.join(", ")}), so a phone can't reach it. Add a listener on all
            interfaces, for example <code>0.0.0.0:8081</code>, and use it only on a network you trust: anyone on it can send
            traffic through the proxy.
          </p>
          <button className="btn" onClick={() => document.getElementById("listeners")?.scrollIntoView({ behavior: "smooth" })}>Go to the proxy listeners</button>
        </div>
      )}
      {d?.proxy_running && d.listener_reachable && d.urls.length === 0 && (
        <p data-testid="mobile-no-address">
          The proxy listens beyond this computer ({d.listeners.join(", ")}) but no local network address was found. Connect
          to Wi-Fi or Ethernet, or open the proxy's address on this computer from the phone.
        </p>
      )}
      {d && d.urls.length > 0 && (
        <div className="split" style={{ alignItems: "center" }}>
          <div>
            <p>With the phone on the same network, open this page on it (or scan the code), and install the certificate from there:</p>
            <pre className="raw" data-testid="mobile-url">{d.urls[0]}</pre>
            {d.urls.length > 1 && (
              <p className="small muted">Other addresses of this computer: {d.urls.slice(1).map((u) => <code key={u} style={{ marginRight: 8 }}>{u}</code>)}</p>
            )}
            <p className="small">
              Then set the phone's Wi-Fi proxy to <code data-testid="mobile-proxy">{d.proxy_addresses[0]}</code> (manual, host
              and port). Once that is set, <code>{d.setup_host_url}</code> opens the same page.
            </p>
            {d.ca_fingerprint && (
              <p className="small muted">The page shows the same fingerprint: <code className="mono" style={{ wordBreak: "break-all" }}>{d.ca_fingerprint}</code></p>
            )}
          </div>
          {d.qr_svg && (
            <img data-testid="mobile-qr" alt={`QR code for ${d.qr_url ?? d.urls[0]}`} src={svgSrc(d.qr_svg)} width={196} height={196} style={{ justifySelf: "center", background: "#fff", borderRadius: 8 }} />
          )}
        </div>
      )}
    </Panel>
  );
}

/** What the proxy keeps in HTTP history. */
function Recording() {
  const rec = useLoad(() => api.get<RecordingSettings>("/history/recording"), []);
  const devs = useLoad(() => api.get<DevicesView>("/devices"), []);
  const action = useAction();
  const only = rec.data?.record_devices ?? [];
  const save = (next: RecordingSettings) => {
    const before = rec.data;
    rec.setData(next); // show the change at once; undo if saving fails
    action.run(() => api.put<RecordingSettings>("/history/recording", next)).then((r) => {
      rec.setData(r ?? before);
      devs.reload();
    });
  };
  const toggleDevice = (addr: string, on: boolean) =>
    save({ in_scope_only: !!rec.data?.in_scope_only, record_devices: on ? [...only.filter((a) => a !== addr), addr] : only.filter((a) => a !== addr) });
  return (
    <Panel title="4. What to record">
      <label className="row small" style={{ gap: 6 }}>
        <input type="checkbox" data-testid="record-in-scope" checked={!!rec.data?.in_scope_only} disabled={!rec.data} onChange={(e) => save({ in_scope_only: e.target.checked, record_devices: only })} />
        Record only in-scope traffic in HTTP history. Everything is still proxied; out-of-scope requests (and their
        WebSocket messages) just aren't saved, which keeps big projects small and fast.
      </label>
      <h3 style={{ margin: "14px 0 4px", fontSize: 13 }}>Devices</h3>
      <p className="small muted" style={{ marginTop: 0 }} data-testid="record-devices-note">
        {only.length
          ? `Only traffic from ${only.length === 1 ? "the ticked device" : `the ${only.length} ticked devices`} is recorded; other devices are still proxied but not saved.`
          : "Every device's traffic is recorded. Tick \"record only\" on one or more devices to save just their traffic (everything is still proxied)."}
      </p>
      <Devices devices={devs.data?.devices ?? []} only={only} onToggle={toggleDevice} onChanged={devs.reload} />
      <ErrorBox error={rec.error ?? devs.error ?? action.error} />
    </Panel>
  );
}

/** Client addresses seen in history: give each a name, and pick the ones to record. */
function Devices({ devices, only, onToggle, onChanged }: { devices: DeviceView[]; only: string[]; onToggle: (addr: string, on: boolean) => void; onChanged: () => void }) {
  const [addr, setAddr] = useState("");
  const [name, setName] = useState("");
  const action = useAction();
  const add = () =>
    action.run(() => api.put(`/devices/${encodeURIComponent(addr.trim())}`, { name: name.trim() })).then((r) => {
      if (r) {
        setAddr("");
        setName("");
        onChanged();
      }
    });
  return (
    <div data-testid="devices">
      {devices.length === 0 ? (
        <p className="small muted">No device has used the proxy yet. Phones and tablets show up here once their traffic goes through it.</p>
      ) : (
        <table className="grid small">
          <thead>
            <tr><th>Address</th><th>Name</th><th>Requests</th><th>Last seen</th><th>Record only</th></tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <DeviceRow key={d.addr} d={d} checked={only.includes(d.addr)} onToggle={onToggle} onChanged={onChanged} />
            ))}
          </tbody>
        </table>
      )}
      <div className="row small" style={{ gap: 6, marginTop: 8 }}>
        <input aria-label="Device address" placeholder="192.168.1.23" value={addr} onChange={(e) => setAddr(e.target.value)} style={{ width: 150 }} />
        <input aria-label="Device name" placeholder="Pixel 8" value={name} onChange={(e) => setName(e.target.value)} style={{ width: 150 }} />
        <button className="btn" data-testid="device-add" disabled={!addr.trim() || !name.trim() || action.busy} onClick={add}>Name a device</button>
      </div>
      <ErrorBox error={action.error} />
    </div>
  );
}

function DeviceRow({ d, checked, onToggle, onChanged }: { d: DeviceView; checked: boolean; onToggle: (addr: string, on: boolean) => void; onChanged: () => void }) {
  const [name, setName] = useState(d.name ?? "");
  const action = useAction();
  const commit = () => {
    const next = name.trim();
    if (next === (d.name ?? "")) return;
    action
      .run(() => (next ? api.put(`/devices/${encodeURIComponent(d.addr)}`, { name: next }) : api.del(`/devices/${encodeURIComponent(d.addr)}`)))
      .then(() => onChanged());
  };
  return (
    <tr data-testid={`device-${d.addr}`}>
      <td className="mono">{d.addr}</td>
      <td>
        <input aria-label={`Name for ${d.addr}`} data-testid={`device-name-${d.addr}`} placeholder="name it" value={name} onChange={(e) => setName(e.target.value)} onBlur={commit} onKeyDown={(e) => e.key === "Enter" && commit()} style={{ width: 150 }} />
        <ErrorBox error={action.error} />
      </td>
      <td>{d.exchanges}</td>
      <td className="muted">{d.last_seen_ms ? new Date(d.last_seen_ms).toLocaleString() : ""}</td>
      <td><input type="checkbox" aria-label={`Record only ${d.name ?? d.addr}`} data-testid={`device-record-${d.addr}`} checked={checked} onChange={(e) => onToggle(d.addr, e.target.checked)} /></td>
    </tr>
  );
}
