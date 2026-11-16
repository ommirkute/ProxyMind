import { useEffect, useRef, useState, type RefObject } from "react";
import { api } from "./api";
import { TRANSFORMS, transform, type TransformResult } from "./transforms";

// Transform menu for a text editor (a textarea): pick an operation, see the selection before and after, then Apply.
//
// Apply and Undo both go through `replaceRange`, which uses document.execCommand("insertText") so the browser's own
// undo stack records the change (Ctrl+Z then undoes an Apply like typing), and falls back to setRangeText when a
// browser refuses. The Undo button does not depend on that: it uses this component's own stack of
// { start, inserted, original } entries, which is exact and survives browsers that merge or drop native history
// entries. An entry is only undone while the text it inserted is still where it was left; edits elsewhere in the
// editor are kept.

interface Selection {
  start: number;
  end: number;
  text: string;
}

interface Entry {
  start: number;
  inserted: string;
  original: string;
}

const MAX_UNDO = 20;
const SMART = "smart_decode";
const GROUPS = [...new Set(TRANSFORMS.map((o) => o.group))];
const clip = (s: string) => (s.length > 400 ? `${s.slice(0, 400)}…` : s);

/** Replaces [start, end) with `text` through the editing pipeline and leaves the new text selected. */
function replaceRange(ta: HTMLTextAreaElement, start: number, end: number, text: string) {
  const before = ta.value;
  ta.focus();
  ta.setSelectionRange(start, end);
  let done = false;
  try {
    done = document.execCommand("insertText", false, text);
  } catch {
    done = false;
  }
  // Only when nothing happened: a half-applied execCommand must not be applied twice.
  if (!done && ta.value === before) {
    ta.setRangeText(text, start, end, "select");
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  }
  ta.setSelectionRange(start, start + text.length);
}

type Preview = { state: "idle" } | { state: "busy" } | { state: "done"; result: TransformResult; note?: string };

export default function TransformMenu({
  target,
  disabled = false,
  resetKey,
}: {
  target: RefObject<HTMLTextAreaElement>;
  disabled?: boolean;
  /** Changes when the editor shows a different document (a Replay tab, a held message): clears undo, closes the menu. */
  resetKey?: string | number;
}) {
  const [open, setOpen] = useState(false);
  const [focusTick, setFocusTick] = useState(0);
  const [sel, setSel] = useState<Selection>({ start: 0, end: 0, text: "" });
  const [op, setOp] = useState("");
  const [preview, setPreview] = useState<Preview>({ state: "idle" });
  const [depth, setDepth] = useState(0);
  const [note, setNote] = useState("");
  const stack = useRef<Entry[]>([]);
  const select = useRef<HTMLSelectElement>(null);

  const capture = () => {
    const ta = target.current;
    if (!ta) return;
    const { selectionStart: start, selectionEnd: end } = ta;
    setSel({ start, end, text: ta.value.slice(start, end) });
    setOp("");
    setNote("");
  };

  const openMenu = () => {
    capture();
    setOpen(true);
    setFocusTick((n) => n + 1);
  };

  // Ctrl+Shift+T (Cmd on a Mac) opens the menu for the current selection. Browsers keep that chord for "reopen
  // closed tab" and may not pass it to the page, so Alt+Shift+T does the same everywhere.
  useEffect(() => {
    const ta = target.current;
    if (!ta || disabled) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.code === "KeyT" && e.shiftKey && (e.ctrlKey || e.metaKey || e.altKey)) {
        e.preventDefault();
        capture();
        setOpen(true);
        setFocusTick((n) => n + 1);
      }
    };
    ta.addEventListener("keydown", onKey);
    return () => ta.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, disabled]);

  useEffect(() => {
    if (open && sel.text) select.current?.focus();
  }, [focusTick]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    stack.current = [];
    setDepth(0);
    setOpen(false);
    setNote("");
  }, [resetKey]);

  // Compute the preview whenever the operation or the selected text changes.
  useEffect(() => {
    if (!open || !op || !sel.text) {
      setPreview({ state: "idle" });
      return;
    }
    let live = true;
    setPreview({ state: "busy" });
    const run = async (): Promise<Preview> => {
      if (op !== SMART) return { state: "done", result: await transform(op, sel.text) };
      try {
        const r = await api.post<{ steps: { op: string; output: string }[] }>("/tools/decode", { input: sel.text, ops: [] });
        const last = r.steps[r.steps.length - 1];
        if (!last) return { state: "done", result: { ok: false, error: "Nothing to decode: no known encoding was recognised." } };
        return { state: "done", result: { ok: true, value: last.output }, note: `Steps: ${r.steps.map((s) => s.op).join(" → ")}` };
      } catch (e) {
        return { state: "done", result: { ok: false, error: e instanceof Error ? e.message : String(e) } };
      }
    };
    run().then((p) => live && setPreview(p));
    return () => {
      live = false;
    };
  }, [open, op, sel.text]);

  if (disabled) return null;

  const apply = () => {
    const ta = target.current;
    if (!ta || preview.state !== "done" || !preview.result.ok) return;
    if (ta.value.slice(sel.start, sel.end) !== sel.text) {
      setNote("The text changed since the menu was opened: select it again.");
      return;
    }
    const value = preview.result.value;
    replaceRange(ta, sel.start, sel.end, value);
    stack.current = [...stack.current, { start: sel.start, inserted: value, original: sel.text }].slice(-MAX_UNDO);
    setDepth(stack.current.length);
    // The result stays selected, so the next operation chains onto it.
    setSel({ start: sel.start, end: sel.start + value.length, text: value });
    setOp("");
    setNote("");
  };

  const undo = () => {
    const ta = target.current;
    const entry = stack.current[stack.current.length - 1];
    if (!ta || !entry) return;
    const end = entry.start + entry.inserted.length;
    if (ta.value.slice(entry.start, end) !== entry.inserted) {
      stack.current = [];
      setDepth(0);
      setNote("That text was edited since: use Ctrl+Z in the editor.");
      return;
    }
    replaceRange(ta, entry.start, end, entry.original);
    stack.current = stack.current.slice(0, -1);
    setDepth(stack.current.length);
    setSel({ start: entry.start, end: entry.start + entry.original.length, text: entry.original });
    setOp("");
    setNote("");
  };

  const close = () => {
    setOpen(false);
    target.current?.focus();
  };

  const chosen = TRANSFORMS.find((o) => o.id === op);
  const result = preview.state === "done" ? preview.result : null;

  return (
    <div className="transform-bar">
      <button
        type="button"
        className="btn sm"
        data-testid="transform-open"
        aria-haspopup="dialog"
        aria-expanded={open}
        title="Transform the selected text: encode, decode, escape, hash (Ctrl+Shift+T or Alt+Shift+T in the editor)"
        onClick={() => (open ? close() : openMenu())}
      >
        Transform
      </button>
      <button
        type="button"
        className="btn sm"
        data-testid="transform-undo"
        disabled={depth === 0}
        title="Undo the last applied transform (Ctrl+Z in the editor also works)"
        onClick={undo}
      >
        Undo{depth > 1 ? ` (${depth})` : ""}
      </button>
      {note && !open && <span className="small muted">{note}</span>}
      {open && (
        <div
          className="transform-pop"
          role="dialog"
          aria-label="Transform selection"
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.stopPropagation();
              close();
            }
          }}
        >
          {!sel.text ? (
            <p className="small muted" style={{ margin: 0 }} data-testid="transform-need-selection">
              Select some text in the editor first, then open Transform. The operations apply to the selection only.
            </p>
          ) : (
            <>
              <label className="small row" style={{ gap: 6 }}>
                Operation
                <select ref={select} aria-label="Transform operation" data-testid="transform-op" value={op} onChange={(e) => setOp(e.target.value)}>
                  <option value="">Choose…</option>
                  {GROUPS.map((g) => (
                    <optgroup key={g} label={g}>
                      {TRANSFORMS.filter((o) => o.group === g).map((o) => (
                        <option key={o.id} value={o.id}>{o.label}</option>
                      ))}
                    </optgroup>
                  ))}
                  <optgroup label="Server">
                    <option value={SMART}>Smart decode (detects the encoding)</option>
                  </optgroup>
                </select>
              </label>
              <div className="small muted">Before ({sel.text.length} characters)</div>
              <pre data-testid="transform-before">{clip(sel.text)}</pre>
              {op && (
                <>
                  <div className="small muted">
                    After{result?.ok ? ` (${result.value.length} characters)` : ""}
                    {chosen && !chosen.reversible ? ": a hash cannot be decoded back, only Undo restores the text" : ""}
                  </div>
                  {preview.state === "busy" && <pre className="muted">…</pre>}
                  {result?.ok && <pre data-testid="transform-after">{clip(result.value)}</pre>}
                  {result && !result.ok && <div className="error small" data-testid="transform-error" style={{ margin: 0 }}>{result.error}</div>}
                  {preview.state === "done" && preview.note && <div className="small muted">{preview.note}</div>}
                </>
              )}
            </>
          )}
          {note && <div className="small muted">{note}</div>}
          <div className="row">
            <button type="button" className="btn primary sm" data-testid="transform-apply" disabled={!result?.ok} onClick={apply}>
              Apply
            </button>
            <button type="button" className="btn sm" data-testid="transform-close" onClick={close}>Close</button>
            <span className="small muted">Apply keeps the result selected, so you can chain.</span>
          </div>
        </div>
      )}
    </div>
  );
}
