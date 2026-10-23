import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { AnimatePresence, motion, useDragControls, type PanInfo } from "motion/react";
import { Check, CircleCheck, CircleX, Info, X, Minus } from "lucide-react";
import { spring } from "../lib/motion";
import { avatarColor, initials, ms as fmtMs } from "../lib/format";
import type { Step } from "../lib/pipeline";

// ------------------------------------------------------------------ Sheet
/**
 * Modal sheet. Enters and exits along the same path with blur + scale together.
 * It can be dragged down by its header and dismissed with a flick, and the spring
 * starts from wherever the finger let go, so it never jumps.
 */
export function Sheet({ open, onClose, title, subtitle, icon, wide, footer, children }: {
  open: boolean; onClose: () => void; title: ReactNode; subtitle?: ReactNode; icon?: ReactNode;
  wide?: boolean; footer?: ReactNode; children: ReactNode;
}) {
  const controls = useDragControls();
  const labelId = useId();
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); prev?.focus?.(); };
  }, [open, onClose]);

  const onDragEnd = (_: unknown, info: PanInfo) => {
    // Project where the flick would come to rest and dismiss if that is far enough down.
    const projected = info.offset.y + info.velocity.y * 0.2;
    if (projected > 160) onClose();
  };

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div className="scrim" onClick={onClose}
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} />
          <div className="sheet-wrap">
            <motion.div
              ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={labelId}
              className={`sheet${wide ? " wide" : ""}`}
              initial={{ opacity: 0, scale: 0.96, y: 16, filter: "blur(6px)" }}
              animate={{ opacity: 1, scale: 1, y: 0, filter: "blur(0px)" }}
              exit={{ opacity: 0, scale: 0.97, y: 16, filter: "blur(6px)" }}
              transition={spring.sheet}
              drag="y" dragListener={false} dragControls={controls}
              dragConstraints={{ top: 0, bottom: 0 }} dragElastic={{ top: 0.04, bottom: 0.55 }}
              onDragEnd={onDragEnd}
              style={{ outline: "none" }}
            >
              <div onPointerDown={(e) => controls.start(e)} style={{ touchAction: "none" }}>
                <div className="grabber" />
                <div className="sheet-head">
                  {icon}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <h2 id={labelId} className="t-headline" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{title}</h2>
                    {subtitle && <div className="t-caption" style={{ marginTop: 2 }}>{subtitle}</div>}
                  </div>
                  <button className="btn icon plain" aria-label="Close" onClick={onClose} onPointerDown={(e) => e.stopPropagation()}>
                    <X size={17} strokeWidth={2} color="var(--label-2)" />
                  </button>
                </div>
              </div>
              <div className="sheet-body">{children}</div>
              {footer && <div className="sheet-foot">{footer}</div>}
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}

// ------------------------------------------------------------------ Segmented control
export function Segmented<T extends string | number>({ value, options, onChange, label }: {
  value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void; label: string;
}) {
  const id = useId();
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button key={String(o.value)} role="radio" aria-checked={value === o.value} onClick={() => onChange(o.value)}>
          {value === o.value && <motion.div layoutId={`seg-${id}`} className="seg-thumb" transition={spring.snappy} />}
          <span>{o.label}</span>
        </button>
      ))}
    </div>
  );
}

// ------------------------------------------------------------------ Switch
export function Switch({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return (
    <button className="switch" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange(!checked)}>
      <motion.span className="knob" animate={{ x: checked ? 15 : 0 }} transition={spring.snappy} />
    </button>
  );
}

// ------------------------------------------------------------------ Avatar
export function Avatar({ name, size = 32 }: { name: string; size?: number }) {
  return (
    <span className="avatar" style={{ width: size, height: size, background: avatarColor(name), fontSize: size * 0.36 }} aria-hidden>
      {initials(name)}
    </span>
  );
}

// ------------------------------------------------------------------ File glyph
const KIND: Record<string, string> = { txt: "TXT", md: "MD", csv: "CSV", pdf: "PDF", png: "PNG", jpg: "JPG", jpeg: "JPG", json: "JSON", docx: "DOC" };
export function FileGlyph({ name, locked }: { name: string; locked?: boolean }) {
  const ext = name.split(".").pop()?.toLowerCase() ?? "";
  return (
    <svg className="file-icon" viewBox="0 0 34 40" aria-hidden>
      <path d="M4 1.5h18.5L32.5 11.5V36a2.5 2.5 0 0 1-2.5 2.5H4A2.5 2.5 0 0 1 1.5 36V4A2.5 2.5 0 0 1 4 1.5Z"
        fill="var(--bg-elevated)" stroke="var(--separator-strong)" />
      <path d="M22.5 1.5V9a2.5 2.5 0 0 0 2.5 2.5h7.5" fill="var(--bg-inset)" stroke="var(--separator-strong)" />
      <text x="17" y="31" textAnchor="middle" fontSize="7.5" fontWeight="700" fill="var(--label-3)" fontFamily="var(--font)" letterSpacing="0.02em">
        {KIND[ext] ?? (ext.slice(0, 4).toUpperCase() || "FILE")}
      </text>
      {locked && (
        <g transform="translate(10 9)">
          <rect x="1" y="5.5" width="12" height="9" rx="2" fill="var(--label-3)" />
          <path d="M3.8 5.5V4a3.2 3.2 0 0 1 6.4 0v1.5" fill="none" stroke="var(--label-3)" strokeWidth="1.6" />
        </g>
      )}
    </svg>
  );
}

// ------------------------------------------------------------------ Pipeline
export function Pipeline({ steps }: { steps: Step[] }) {
  return (
    <div className="pipeline" role="list">
      {steps.map((s) => (
        <motion.div key={s.id} className="step" data-state={s.state} role="listitem">
          <div className="step-dot">
            {s.state === "active" && <span className="spinner" />}
            {s.state === "done" && <Check size={13} strokeWidth={3} />}
            {s.state === "fail" && <X size={13} strokeWidth={3} />}
            {s.state === "skip" && <Minus size={12} strokeWidth={2.5} />}
          </div>
          <div style={{ minWidth: 0 }}>
            <div className="step-title">{s.title}</div>
            <AnimatePresence initial={false}>
              {s.detail && (
                <motion.div className="step-detail" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} transition={spring.item}>
                  {s.detail}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
          <div className="step-ms">{s.ms != null && s.state !== "skip" ? fmtMs(s.ms) : ""}</div>
        </motion.div>
      ))}
    </div>
  );
}

export function useSteps(initial: () => Step[]) {
  const [steps, setSteps] = useState<Step[]>(initial);
  const report = useCallback((id: string, patch: Partial<Step>) => {
    setSteps((prev) => prev.map((s) => (s.id === id ? { ...s, ...patch } : s)));
  }, []);
  return { steps, setSteps, report };
}

// ------------------------------------------------------------------ Toasts
type Tone = "ok" | "error" | "info";
interface Toast { id: number; text: string; tone: Tone }
const ToastCtx = createContext<(text: string, tone?: Tone) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: Tone = "ok") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-2), { id, text, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3600);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toast-stack" aria-live="polite">
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div key={t.id} className="toast" layout
              initial={{ opacity: 0, y: 16, scale: 0.96, filter: "blur(4px)" }}
              animate={{ opacity: 1, y: 0, scale: 1, filter: "blur(0px)" }}
              exit={{ opacity: 0, y: 8, scale: 0.97, filter: "blur(4px)" }}
              transition={spring.sheet}>
              {t.tone === "ok" && <CircleCheck size={16} color="var(--green)" />}
              {t.tone === "error" && <CircleX size={16} color="var(--red)" />}
              {t.tone === "info" && <Info size={16} color="var(--accent)" />}
              {t.text}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastCtx.Provider>
  );
}

// ------------------------------------------------------------------ misc
export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div style={{ textAlign: "center", padding: "48px 24px", color: "var(--label-2)" }}>
      <div style={{ color: "var(--label-4)", marginBottom: 10, display: "flex", justifyContent: "center" }}>{icon}</div>
      <div className="t-headline" style={{ color: "var(--label)" }}>{title}</div>
      {children && <div style={{ marginTop: 6, fontSize: "0.8125rem" }}>{children}</div>}
    </div>
  );
}

export function PageHead({ title, children, actions }: { title: string; children?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1 className="t-large">{title}</h1>
        {children && <p>{children}</p>}
      </div>
      {actions && <div className="hstack">{actions}</div>}
    </div>
  );
}

/** Fades list rows in with a short stagger when they first mount. */
export const rowMotion = (i: number) => ({
  initial: { opacity: 0, y: 6 },
  animate: { opacity: 1, y: 0 },
  transition: { ...spring.item, delay: Math.min(i, 10) * 0.025 },
});
