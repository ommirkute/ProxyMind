import { api, toast } from "../api";
import { ErrorBox, Panel, useAction, useLoad } from "../components";

export interface UpdateStatus {
  current: string;
  enabled: boolean;
  checked_at?: number;
  latest?: string;
  url?: string;
  available: boolean;
}

const RELEASES = "https://github.com/ommirkute/ProxyMind/releases";

/** Version, links and the opt-in update check. */
export default function About() {
  const st = useLoad(() => api.get<UpdateStatus>("/update"), []);
  const action = useAction();
  const set = (enabled: boolean) =>
    action.run(async () => st.setData(await api.put<UpdateStatus>("/update", { enabled })));
  const check = () =>
    action.run(async () => {
      const r = await api.post<UpdateStatus>("/update/check", { force: true });
      st.setData(r);
      toast(r.available ? `ProxyMind ${r.latest} is available` : "You're up to date");
    });
  const s = st.data;
  return (
    <div className="content">
      <Panel title="About ProxyMind">
        <p>
          Version <b data-testid="about-version">{s?.current ?? "…"}</b>. Open source under AGPL-3.0.
        </p>
        <p className="small">
          <a href="https://github.com/ommirkute/ProxyMind" target="_blank" rel="noreferrer">Repository</a> ·{" "}
          <a href={RELEASES} target="_blank" rel="noreferrer">Releases</a> ·{" "}
          <a href="https://github.com/ommirkute/ProxyMind/issues/new/choose" target="_blank" rel="noreferrer">Report a bug</a> ·{" "}
          <a href="https://github.com/ommirkute/ProxyMind/security/advisories/new" target="_blank" rel="noreferrer">Report a vulnerability</a>
        </p>
      </Panel>
      <Panel title="Updates">
        <ErrorBox error={st.error ?? action.error} />
        <p className="small muted">
          Off unless you turn it on: ProxyMind then asks GitHub's public releases list once a day while the UI is open.
          Nothing about you or your projects is sent, the request uses your upstream proxy settings, and each check is
          in the audit log. The setting applies to all your projects.
        </p>
        <div className="row">
          <label>
            <input type="checkbox" checked={s?.enabled ?? false} disabled={!s || action.busy} onChange={(e) => set(e.target.checked)} data-testid="update-toggle" />{" "}
            Check for updates daily
          </label>
          <button className="btn" onClick={check} disabled={action.busy} data-testid="update-check">Check now</button>
        </div>
        {s?.latest && (
          <p data-testid="update-result">
            {s.available ? (
              <>A newer release is out: <a href={s.url ?? RELEASES} target="_blank" rel="noreferrer"><b>{s.latest}</b></a>.</>
            ) : (
              <>Up to date (newest release: {s.latest}).</>
            )}
            {s.checked_at && <span className="muted small"> Checked {new Date(s.checked_at * 1000).toLocaleString()}.</span>}
          </p>
        )}
      </Panel>
    </div>
  );
}
