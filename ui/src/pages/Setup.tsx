import { useState } from "react";
import { api } from "../api";
import { Empty, ErrorBox, Panel, useLoad, useNav } from "../components";

interface SetupInfo {
  proxy: string | null;
  ca_available: boolean;
  ca_sha256: string | null;
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
  const proxy = info.data?.proxy ?? "127.0.0.1:8080";
  const [host, port] = proxy.includes(":") ? [proxy.slice(0, proxy.lastIndexOf(":")), proxy.slice(proxy.lastIndexOf(":") + 1)] : [proxy, "8080"];

  return (
    <div className="content">
      <ErrorBox error={info.error} />
      <div className="split">
        <Panel title="1. Send traffic through the proxy">
          {info.data && !info.data.proxy ? (
            <Empty>This process doesn't run the proxy (started with --no-proxy). Start <code>proxymind ui</code> or <code>proxymind proxy</code>.</Empty>
          ) : (
            <>
              <p>Set your browser or system HTTP and HTTPS proxy to:</p>
              <pre className="raw" data-testid="setup-proxy">{proxy}</pre>
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
