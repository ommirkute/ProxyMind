import { useState } from "react";
import { api, fmtDateTime, toast } from "../api";
import type { ReviewItem, TrustView } from "../api-types.gen";
import { Chip, Empty, ErrorBox, Panel, useAction, useLoad, useNav } from "../components";

function Items({ title, items, testid }: { title: string; items: ReviewItem[]; testid: string }) {
  if (items.length === 0) return null;
  return (
    <Panel title={title}>
      <table className="grid" data-testid={testid}>
        <tbody>
          {items.map((i, n) => (
            <tr key={n}>
              <td>{i.what}</td>
              <td className="muted small">{i.detail}</td>
              <td className="muted small">{i.claimed_by ? `the file says: ${i.claimed_by}` : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}

/** Settings → Project trust: what a project file would switch on, and the one button that lets it. */
export default function Trust() {
  // Confirming is audited, so the audit counter (live) says when the answer may have changed: no polling.
  const { counters } = useNav();
  const view = useLoad(() => api.get<TrustView>("/project/trust"), [counters?.audit_records]);
  const action = useAction();
  const [sure, setSure] = useState(false);
  const v = view.data;
  const confirm = () =>
    action.run(async () => {
      if (!v) return;
      await api.post<TrustView>("/project/trust", { digest: v.digest });
      toast("Project trusted: its settings now apply", "ok");
      window.dispatchEvent(new Event("pm-status-changed"));
      view.reload();
    });

  return (
    <div className="content">
      <p className="muted small" style={{ marginTop: 0 }}>
        A project file can carry listeners, upstream proxies, rewrite rules, scheduled scans, workflow triggers, session
        macros, a model server address and the rules of engagement that decide what is in scope. A project this
        installation made is trusted. One that came from somewhere else (a download, a colleague, a client) opens in safe
        mode: none of that runs until you have read it here and trusted it. Only you can; agents can read this page, not
        confirm it.
      </p>
      <ErrorBox error={view.error ?? action.error} />
      {v && (
        <Panel title="Status" actions={<Chip value={v.safe_mode ? "safe mode" : "trusted"} />}>
          {v.safe_mode ? (
            <>
              <p data-testid="trust-summary">
                {v.changed_since_trust
                  ? "This project was trusted here, but its settings changed since (another program edited the file, or a different file was put in its place)."
                  : "This installation has not trusted this project."}{" "}
                Held back until you trust it:
              </p>
              <ul data-testid="held-back">
                {v.held_back.map((h, n) => (
                  <li key={n}>
                    <b>{h.what}</b> <span className="muted small">{h.why}</span>
                  </li>
                ))}
              </ul>
              <p className="muted small">
                Not held back: reading the project, what you do yourself (Replay, scans you start, editing settings), the
                proxy's main listener. Scheduled scans and triggers you allow run as you, whatever the file says.
              </p>
            </>
          ) : (
            <p data-testid="trust-summary">
              Trusted ({v.basis}) by {v.trusted_by}
              {v.trusted_at_ms ? `, ${fmtDateTime(v.trusted_at_ms)}` : ""}. Nothing is held back.
            </p>
          )}
        </Panel>
      )}
      {v && v.safe_mode && (
        <>
          <Panel title="Rules of engagement from this file">
            <p className="muted small">
              The scope the policy gate enforces is whatever this file says. Read it: agents, plugins and the AI scan
              cannot send anything until you confirm it.
            </p>
            {v.review.roe_text ? <pre data-testid="review-roe" style={{ whiteSpace: "pre-wrap" }}>{v.review.roe_text}</pre> : <Empty>No rules saved.</Empty>}
          </Panel>
          <Items title="Proxy listeners" items={v.review.listeners} testid="review-listeners" />
          <Items title="Upstream proxy rules" items={v.review.upstream_rules} testid="review-upstream" />
          <Items title="Other network settings" items={v.review.network_other} testid="review-network" />
          <Items title="Match-and-replace rules" items={v.review.rewrite_rules} testid="review-rewrite" />
          <Items title="Scan schedules" items={v.review.schedules} testid="review-schedules" />
          <Items title="Workflow triggers" items={v.review.triggers} testid="review-triggers" />
          <Items title="Session rules and macros" items={v.review.session} testid="review-session" />
          <Items title="Assistant" items={v.review.assistant} testid="review-assistant" />
          <Panel title="Trust this project">
            <label>
              <input type="checkbox" aria-label="I have read this" checked={sure} onChange={(e) => setSure(e.target.checked)} /> I have
              read the rules of engagement and everything above, and I want it to run as me.
            </label>
            <p>
              <button className="btn primary" data-testid="trust-confirm" disabled={!sure || action.busy} onClick={confirm}>
                Trust this project
              </button>
            </p>
          </Panel>
        </>
      )}
    </div>
  );
}
