import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { CircleCheck, CircleX, Link2 } from "lucide-react";
import { api, type AuditEntry } from "../lib/api";
import { clock } from "../lib/format";
import { spring } from "../lib/motion";
import { Avatar, Empty, PageHead, Segmented } from "../components/ui";
import type { Route } from "../App";

type Filter = "all" | "deny" | "keys";
const KEY_ACTIONS = new Set(["revoke_attribute", "lazy_rewrap", "suspend_user", "reinstate_user", "bind_device_key", "policy_toggle", "policy_upsert", "demo_reset"]);

export default function Audit(_: { go: (r: Route) => void }) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [verify, setVerify] = useState<{ valid: boolean; entries: number; broken_at: number | null; head?: string } | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => { api<AuditEntry[]>("/audit?limit=300").then(setEntries).catch(() => setEntries([])); }, []);

  async function runVerify() {
    setChecking(true);
    setVerify(null);
    const [r] = await Promise.all([
      api<{ valid: boolean; entries: number; broken_at: number | null; head?: string }>("/audit/verify"),
      new Promise((res) => setTimeout(res, 450)), // let the sweep read as work being done
    ]);
    setVerify(r);
    setChecking(false);
  }

  const shown = useMemo(() => (entries ?? []).filter((e) =>
    filter === "all" ? true : filter === "deny" ? e.decision === "deny" : KEY_ACTIONS.has(e.action)), [entries, filter]);

  return (
    <>
      <PageHead title="Audit Trail" actions={<button className="btn primary" onClick={runVerify} disabled={checking}>{checking ? <span className="spinner" /> : <Link2 size={14} />} Verify chain</button>}>
        Every decision and key operation is appended to a hash chain. Each entry's hash covers the one before it, so editing or deleting any past entry breaks every link after it.
      </PageHead>

      <AnimatePresence>
        {verify && (
          <motion.div className={`callout ${verify.valid ? "green" : "red"}`} style={{ marginBottom: 18 }}
            initial={{ opacity: 0, y: -6, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0 }} transition={spring.sheet}>
            {verify.valid ? <CircleCheck size={18} color="var(--green)" /> : <CircleX size={18} color="var(--red)" />}
            <div>
              <b>{verify.valid ? `All ${verify.entries} entries verified.` : `Chain broken at entry #${verify.broken_at}.`}</b>
              <div className="t-caption mono" style={{ color: "inherit", opacity: 0.8 }}>
                {verify.valid ? `head ${verify.head}` : "An entry was modified or removed after it was written."}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div style={{ marginBottom: 12 }}>
        <Segmented label="Filter" value={filter} onChange={setFilter} options={[
          { value: "all", label: "All" }, { value: "deny", label: "Denied" }, { value: "keys", label: "Keys & policies" },
        ]} />
      </div>

      <div className="group" style={{ position: "relative" }}>
        {checking && (
          <motion.div aria-hidden style={{ position: "absolute", left: 0, right: 0, height: 60, zIndex: 2, pointerEvents: "none",
            background: "linear-gradient(to bottom, transparent, var(--accent-soft), transparent)" }}
            initial={{ top: -60 }} animate={{ top: "100%" }} transition={{ duration: 0.45, ease: "linear" }} />
        )}
        {entries === null ? (
          <div style={{ padding: 40, display: "grid", placeItems: "center", color: "var(--label-3)" }}><span className="spinner" /></div>
        ) : shown.length === 0 ? (
          <Empty icon={<Link2 size={28} strokeWidth={1.5} />} title="No entries" />
        ) : shown.map((e) => (
          <div key={e.seq} className="row" style={{ alignItems: "flex-start" }}>
            <div style={{ width: 54, flex: "none", paddingTop: 2 }}>
              <div className="tnum" style={{ fontWeight: 600, fontSize: "0.8125rem" }}>#{e.seq}</div>
              <div className="t-caption tnum">{clock(e.ts)}</div>
            </div>
            <Avatar name={e.actor} size={28} />
            <div className="row-main">
              <div><b style={{ fontWeight: 600 }}>{e.actor}</b> <span>{e.action.replace(/_/g, " ")}</span>
                {e.decision === "deny" && <span className="chip red" style={{ marginLeft: 8 }}>Denied</span>}
                {e.decision === "permit" && <span className="chip green" style={{ marginLeft: 8 }}>Permitted</span>}
              </div>
              {(e.detail || e.resource) && <div className="t-caption" style={{ marginTop: 2, overflowWrap: "anywhere" }}>{e.detail || e.resource}</div>}
              <div className="t-caption mono hide-sm" style={{ marginTop: 4, color: "var(--label-3)" }}>
                {e.prev_hash.slice(0, 10)} → <span style={{ color: verify?.valid ? "var(--green)" : "var(--label-2)" }}>{e.hash.slice(0, 10)}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
