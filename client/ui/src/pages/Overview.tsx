import { useEffect, useMemo, useState } from "react";
import { motion } from "motion/react";
import { ArrowRight, CircleCheck, CircleX, Fingerprint, KeyRound } from "lucide-react";
import { api, type AuditEntry, type FileItem } from "../lib/api";
import { useSession } from "../lib/session";
import { clock, prettyToken } from "../lib/format";
import { spring } from "../lib/motion";
import { Avatar, PageHead } from "../components/ui";
import type { Route } from "../App";

function greeting() {
  const h = new Date().getHours();
  return h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
}

const LAYERS = [
  { n: "1", title: "File", sub: "AES-256-GCM with a fresh 256-bit key", tone: "var(--label)" },
  { n: "2", title: "File key", sub: "CP-ABE: locked to an attribute policy", tone: "var(--accent)" },
  { n: "3", title: "File key, again", sub: "RSA-OAEP: bound to one person's device", tone: "var(--label-2)" },
];

export default function Overview({ go }: { go: (r: Route) => void }) {
  const { user, sk, device, health } = useSession();
  const [files, setFiles] = useState<FileItem[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [chain, setChain] = useState<{ valid: boolean; entries: number } | null>(null);

  useEffect(() => {
    api<FileItem[]>("/files").then(setFiles).catch(() => {});
    api<AuditEntry[]>("/audit?limit=6").then(setAudit).catch(() => {});
    api<{ valid: boolean; entries: number }>("/audit/verify").then(setChain).catch(() => {});
  }, []);

  // Group key attributes by base name: cardiology → [v1, v2]
  const keyAttrs = useMemo(() => {
    const m = new Map<string, number[]>();
    for (const a of sk?.attributes ?? []) {
      const [, base, v] = a.match(/^(.*?)(?:_v(\d+))?$/) ?? [];
      if (!m.has(base)) m.set(base, []);
      if (v) m.get(base)!.push(Number(v));
    }
    return Array.from(m.entries()).filter(([, v]) => v.length);
  }, [sk]);

  if (!user) return null;
  const canOpen = files.filter((f) => f.decision?.decision === "Permit").length;
  const stale = files.filter((f) => f.stale).length;
  const first = user.display_name.replace(/^Dr\.?\s+/, "").split(" ")[0];

  return (
    <>
      <PageHead title={`${greeting()}, ${first}`}>
        You can open {canOpen} of {files.length} files in the vault. Here is the key that decides that.
      </PageHead>

      <div className="grid-3" style={{ marginBottom: 16 }}>
        <motion.div className="card stat" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring.move}>
          <div className="stat-value">{canOpen}<span className="faint" style={{ fontWeight: 500 }}> / {files.length}</span></div>
          <div className="stat-label">Files your attributes unlock</div>
        </motion.div>
        <motion.div className="card stat" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring.move, delay: 0.04 }}>
          <div className="stat-value">{stale}</div>
          <div className="stat-label">Keys waiting for lazy re-wrap</div>
        </motion.div>
        <motion.div className="card stat" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring.move, delay: 0.08 }}>
          <div className="stat-value hstack" style={{ gap: 8 }}>
            {chain ? (chain.valid ? <CircleCheck size={24} color="var(--green)" /> : <CircleX size={24} color="var(--red)" />) : null}
            {chain?.entries ?? "–"}
          </div>
          <div className="stat-label">Audit entries · chain {chain ? (chain.valid ? "intact" : "broken") : "checking"}</div>
        </motion.div>
      </div>

      <div className="grid-2" style={{ alignItems: "start" }}>
        <div className="card">
          <div className="hstack" style={{ marginBottom: 14 }}>
            <span className="icon-tile" style={{ background: "var(--label)", color: "var(--bg-elevated)" }}><KeyRound size={16} /></span>
            <div>
              <h3 className="t-headline">Your attribute key</h3>
              <div className="t-caption">Issued at sign-in by the attribute authority</div>
            </div>
          </div>
          <div className="hstack wrap" style={{ gap: 6 }}>
            {keyAttrs.map(([base, versions]) => (
              <span key={base} className="chip" style={{ color: "var(--label)", height: 26, padding: "0 10px" }}>
                {prettyToken(base)}
                <span className="faint" style={{ fontWeight: 400 }}>v{versions.sort().join(", v")}</span>
              </span>
            ))}
          </div>
          <div className="divider" />
          <div className="hstack" style={{ gap: 10 }}>
            <Fingerprint size={16} color="var(--label-2)" />
            <div className="row-main">
              <div style={{ fontWeight: 500 }}>Device key</div>
              <div className="t-caption">{device ? <span className="mono">RSA-2048 · {device.fingerprint}</span> : "Not available in this browser"}</div>
            </div>
            <span className="chip">{health?.abe_mode === "simulated" ? "Simulated CP-ABE" : "Charm BSW07"}</span>
          </div>
        </div>

        <div className="card">
          <h3 className="t-headline">How each file is protected</h3>
          <p className="t-caption" style={{ margin: "4px 0 14px" }}>Three independent layers. The server only ever holds the outer shells.</p>
          <div className="tiers">
            {LAYERS.map((l, i) => (
              <motion.div key={l.n} className="tier" initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ ...spring.move, delay: 0.1 + i * 0.05 }}>
                <span className="tier-num" style={{ color: l.tone }}>{l.n}</span>
                <div>
                  <div style={{ fontWeight: 600 }}>{l.title}</div>
                  <div className="t-caption">{l.sub}</div>
                </div>
              </motion.div>
            ))}
          </div>
          <div className="t-caption" style={{ marginTop: 12 }}>
            Access is checked by the policy engine first, which can revoke instantly. If that layer were bypassed, the CP-ABE layer still refuses.
          </div>
        </div>
      </div>

      <div className="section" style={{ marginTop: 28 }}>
        <div className="hstack" style={{ justifyContent: "space-between", marginBottom: 6 }}>
          <div className="t-section" style={{ margin: "0 0 0 14px" }}>Recent activity</div>
          <button className="btn plain" onClick={() => go("audit")}>Audit trail <ArrowRight size={13} /></button>
        </div>
        <div className="group">
          {audit.map((e) => (
            <div key={e.seq} className="row inset-icon">
              <Avatar name={e.actor} size={28} />
              <div className="row-main">
                <div className="row-title" style={{ fontWeight: 400 }}><b style={{ fontWeight: 600 }}>{e.actor}</b> {e.action.replace(/_/g, " ")}</div>
                <div className="row-sub">{e.detail || e.resource || "—"}</div>
              </div>
              {e.decision === "deny" && <span className="chip red">Denied</span>}
              <span className="t-caption tnum">{clock(e.ts)}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
