import { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "./icons";

export interface PaletteItem {
  id: string;
  label: string;
  group: string;
  icon: string;
  run: () => void;
}

/** Ctrl+K / ⌘K: jump to any page by typing part of its name. */
export function CommandPalette({ items, open, onClose }: { items: PaletteItem[]; open: boolean; onClose: () => void }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const shown = useMemo(() => {
    const t = q.trim().toLowerCase();
    return t ? items.filter((i) => `${i.label} ${i.group}`.toLowerCase().includes(t)) : items;
  }, [q, items]);

  useEffect(() => {
    if (open) {
      setQ("");
      setSel(0);
      setTimeout(() => input.current?.focus(), 0);
    }
  }, [open]);
  useEffect(() => setSel(0), [q]);

  if (!open) return null;
  const pick = (i: PaletteItem | undefined) => {
    if (!i) return;
    onClose();
    i.run();
  };
  return (
    <div className="palette-backdrop" onMouseDown={onClose}>
      <div className="palette" role="dialog" aria-label="Command palette" onMouseDown={(e) => e.stopPropagation()}>
        <div className="palette-search">
          <Icon name="search" size={16} />
          <input
            ref={input}
            aria-label="Go to"
            placeholder="Go to a page…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, shown.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
              else if (e.key === "Enter") { e.preventDefault(); pick(shown[sel]); }
              else if (e.key === "Escape") onClose();
            }}
          />
          <kbd>Esc</kbd>
        </div>
        <div className="palette-list" role="listbox">
          {shown.length === 0 && <div className="small muted" style={{ padding: 14 }}>Nothing matches.</div>}
          {shown.map((i, n) => (
            <div
              key={i.id}
              role="option"
              aria-selected={n === sel}
              className={`palette-item ${n === sel ? "on" : ""}`}
              onMouseEnter={() => setSel(n)}
              onClick={() => pick(i)}
            >
              <Icon name={i.icon} size={16} />
              <span className="grow">{i.label}</span>
              <span className="small muted">{i.group}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
