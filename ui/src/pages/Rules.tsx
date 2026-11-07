import { useState } from "react";
import { api } from "../api";
import { Empty, ErrorBox, Panel, useAction, useLoad } from "../components";

type Part =
  | "request_first_line"
  | "request_header"
  | "request_body"
  | "response_first_line"
  | "response_header"
  | "response_body";

interface Rule {
  enabled: boolean;
  part: Part;
  match: string;
  replace: string;
  regex: boolean;
  in_scope_only: boolean;
  comment: string;
}

const PARTS: { id: Part; label: string }[] = [
  { id: "request_header", label: "Request header" },
  { id: "request_body", label: "Request body" },
  { id: "request_first_line", label: "Request first line" },
  { id: "response_header", label: "Response header" },
  { id: "response_body", label: "Response body" },
  { id: "response_first_line", label: "Response first line" },
];

const blank = (): Rule => ({
  enabled: true,
  part: "request_header",
  match: "",
  replace: "",
  regex: false,
  in_scope_only: true,
  comment: "",
});

export default function Rules() {
  const saved = useLoad(() => api.get<{ rules: Rule[] }>("/match-replace"), []);
  const presets = useLoad(() => api.get<{ id: string; title: string; description: string; rules: Rule[] }[]>("/match-replace/presets"), []);
  const [draft, setDraft] = useState<Rule[] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const action = useAction();
  const rules = draft ?? saved.data?.rules ?? [];

  const edit = (i: number, patch: Partial<Rule>) => {
    setNotice(null);
    setDraft(rules.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  };
  const remove = (i: number) => setDraft(rules.filter((_, j) => j !== i));
  const save = () =>
    action.run(async () => {
      const r = await api.put<{ rules: Rule[] }>("/match-replace", { rules });
      saved.setData(r);
      setDraft(null);
      setNotice(`Saved ${r.rules.length} rule(s). The proxy uses them right away.`);
    });

  return (
    <div className="content">
      <Panel
        title="Match and replace"
        actions={
          <>
            <select
              aria-label="Add a preset"
              data-testid="rules-preset"
              value=""
              onChange={(e) => {
                const p = presets.data?.find((x) => x.id === e.target.value);
                if (!p) return;
                const same = (a: Rule, b: Rule) => a.part === b.part && a.match === b.match && a.replace === b.replace;
                setDraft([...rules, ...p.rules.filter((r) => !rules.some((x) => same(x, r)))]);
                setNotice(`Added “${p.title}”. ${p.description} Save to apply.`);
              }}
            >
              <option value="">Add a preset…</option>
              {presets.data?.map((p) => <option key={p.id} value={p.id} title={p.description}>{p.title}</option>)}
            </select>
            <button className="btn" onClick={() => setDraft([...rules, blank()])}>Add rule</button>
            <button className="btn primary" data-testid="rules-save" disabled={!draft || action.busy} onClick={save}>
              Save
            </button>
            {draft && <button className="btn" onClick={() => setDraft(null)}>Discard changes</button>}
          </>
        }
      >
        <p className="small muted" style={{ marginTop: 0 }}>
          The proxy applies these rules, in order, to live traffic before the intercept queue sees it. Header rules work line by
          line: an empty match adds the replacement as a new header, and a header replaced by nothing is removed. Body rules
          update Content-Length; compressed bodies are skipped. With <em>regex</em>, use <code>$1</code> for groups. History
          keeps the request as sent and the response as the server sent it. Changes are recorded in the audit log.
        </p>
        <ErrorBox error={saved.error ?? action.error} />
        {notice && <div className="notice" role="status">{notice}</div>}
        {rules.length === 0 && !saved.loading && <Empty>No rules. Traffic passes through unchanged.</Empty>}
        {rules.length > 0 && (
          <table className="grid" data-testid="rules">
            <thead>
              <tr>
                <th>On</th>
                <th>Applies to</th>
                <th>Match</th>
                <th>Replace with</th>
                <th title="Treat the match as a regular expression">Regex</th>
                <th title="Only for targets in the rules of engagement">In scope only</th>
                <th>Comment</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rules.map((r, i) => (
                <tr key={i}>
                  <td>
                    <input type="checkbox" aria-label={`Rule ${i + 1} enabled`} checked={r.enabled} onChange={(e) => edit(i, { enabled: e.target.checked })} />
                  </td>
                  <td>
                    <select aria-label={`Rule ${i + 1} part`} value={r.part} onChange={(e) => edit(i, { part: e.target.value as Part })}>
                      {PARTS.map((p) => (
                        <option key={p.id} value={p.id}>{p.label}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <input
                      className="mono wide"
                      aria-label={`Rule ${i + 1} match`}
                      placeholder={r.part.endsWith("header") ? "(empty: add a header)" : ""}
                      value={r.match}
                      onChange={(e) => edit(i, { match: e.target.value })}
                    />
                  </td>
                  <td>
                    <input
                      className="mono wide"
                      aria-label={`Rule ${i + 1} replace`}
                      placeholder={r.part.endsWith("header") ? "(empty: remove)" : ""}
                      value={r.replace}
                      onChange={(e) => edit(i, { replace: e.target.value })}
                    />
                  </td>
                  <td>
                    <input type="checkbox" aria-label={`Rule ${i + 1} regex`} checked={r.regex} onChange={(e) => edit(i, { regex: e.target.checked })} />
                  </td>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`Rule ${i + 1} in scope only`}
                      checked={r.in_scope_only}
                      onChange={(e) => edit(i, { in_scope_only: e.target.checked })}
                    />
                  </td>
                  <td>
                    <input aria-label={`Rule ${i + 1} comment`} value={r.comment} onChange={(e) => edit(i, { comment: e.target.value })} />
                  </td>
                  <td>
                    <button className="btn" aria-label={`Delete rule ${i + 1}`} onClick={() => remove(i)}>✕</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {rules.some((r) => !r.in_scope_only && r.enabled) && (
          <div className="notice" style={{ marginTop: 10 }}>
            Some rules apply to every host. A rule that adds a credential will send it to third-party sites too.
          </div>
        )}
      </Panel>
    </div>
  );
}
