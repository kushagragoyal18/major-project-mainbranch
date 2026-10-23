import { Fragment, useEffect, useMemo, useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ShieldCheck, ShieldX } from "lucide-react";
import { api, type Condition, type Decision, type FileItem, type Policy, type User } from "../lib/api";
import { useSession } from "../lib/session";
import { spring } from "../lib/motion";
import { PageHead, Segmented, Switch, useToast } from "../components/ui";
import type { Route } from "../App";

const OPS: Record<string, string> = { in: "is one of", eq: "is", neq: "is not", gt: ">", gte: "≥", lt: "<", lte: "≤" };

function pathLabel(p: unknown): ReactNode {
  if (typeof p !== "string") return <b>{String(p)}</b>;
  const ref = p.startsWith("$");
  const [scope, ...rest] = p.replace(/^\$/, "").split(".");
  const name = rest.join(".").replace(/_/g, " ").replace("local hour", "hour");
  const who = { subject: "requester's", resource: "file's", environment: "current", action: "action" }[scope] ?? scope;
  return <span className="chip" style={{ color: ref ? "var(--accent)" : "var(--label)" }}>{who} {name}</span>;
}

function ConditionView({ c }: { c: Condition }): ReactNode {
  const [op, val] = Object.entries(c)[0] ?? [];
  if (!op) return <span className="faint">always</span>;
  if (op === "and" || op === "or") {
    return (
      <span className="hstack wrap" style={{ gap: 5 }}>
        {(val as Condition[]).map((x, i) => (
          <Fragment key={i}>
            {i > 0 && <span className="faint" style={{ fontSize: "0.75rem" }}>{op}</span>}
            <ConditionView c={x} />
          </Fragment>
        ))}
      </span>
    );
  }
  if (op === "not") return <span className="hstack" style={{ gap: 5 }}><span className="faint">not</span><ConditionView c={val as Condition} /></span>;
  const [path, target] = val as [string, unknown];
  return (
    <span className="hstack" style={{ gap: 5 }}>
      {pathLabel(path)}
      <span className="faint" style={{ fontSize: "0.8125rem" }}>{OPS[op] ?? op}</span>
      {typeof target === "string" && target.startsWith("$") ? pathLabel(target) : <b style={{ fontWeight: 600 }}>{String(target)}</b>}
    </span>
  );
}

export default function Access(_: { go: (r: Route) => void }) {
  const { isAdmin, user } = useSession();
  const toast = useToast();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [subject, setSubject] = useState(user?.username ?? "");
  const [fileId, setFileId] = useState("");
  const [hour, setHour] = useState(new Date().getHours());
  const [status, setStatus] = useState<"active" | "suspended">("active");
  const [result, setResult] = useState<Decision | null>(null);

  const load = () => api<Policy[]>("/policies").then(setPolicies);
  useEffect(() => {
    load();
    api<User[]>("/users").then(setUsers);
    api<FileItem[]>("/files").then((f) => { setFiles(f); setFileId((x) => x || f[0]?.file_id || ""); });
  }, []);

  const subj = users.find((u) => u.username === subject);
  const file = files.find((f) => f.file_id === fileId);

  useEffect(() => {
    if (!subj || !file) return;
    const t = setTimeout(() => {
      api<Decision>("/abac/simulate", {
        body: {
          subject: { ...subj.attributes, id: subj.username, status },
          resource: { owner: file.owner, department: file.department, clearance_required: file.clearance_required, recipients: file.recipients },
          environment: { local_hour: hour, hour },
        },
      }).then(setResult).catch(() => setResult(null));
    }, 120);
    return () => clearTimeout(t);
  }, [subj, file, hour, status, policies]);

  async function toggle(p: Policy, enabled: boolean) {
    setPolicies((ps) => ps.map((x) => (x.policy_id === p.policy_id ? { ...x, enabled } : x)));
    try {
      await api(`/policies/${p.policy_id}`, { method: "PATCH", body: { enabled } });
      toast(`${p.title ?? p.policy_id} ${enabled ? "enabled" : "disabled"}`);
    } catch (e) {
      toast(e instanceof Error ? e.message : "Failed", "error");
      load();
    }
  }

  const matched = useMemo(() => new Set(result?.matched.map((m) => m.policy_id)), [result]);

  return (
    <>
      <PageHead title="Access Policies">
        The policy engine (ABAC) checks every request against these rules in real time. Any matching deny wins; with no matching permit, the answer is deny.
      </PageHead>

      <div className="grid-2" style={{ alignItems: "start" }}>
        <div className="stack">
          {policies.map((p) => {
            const on = p.enabled !== false;
            const deny = p.rules.some((r) => r.effect === "deny");
            return (
              <motion.div key={p.policy_id} className="card" layout transition={spring.move}
                animate={{ opacity: on ? 1 : 0.6, boxShadow: matched.has(p.policy_id) ? "0 0 0 2px var(--accent)" : "var(--shadow-card)" }}>
                <div className="hstack" style={{ alignItems: "flex-start", gap: 12 }}>
                  <span className="icon-tile" style={{ background: deny ? "var(--red)" : "var(--green)" }}>
                    {deny ? <ShieldX size={16} /> : <ShieldCheck size={16} />}
                  </span>
                  <div className="row-main">
                    <h3 className="t-headline">{p.title ?? p.policy_id}</h3>
                    <div className="t-caption" style={{ marginTop: 2 }}>{p.description}</div>
                  </div>
                  <Switch label={`Enable ${p.title ?? p.policy_id}`} checked={on} disabled={!isAdmin} onChange={(v) => toggle(p, v)} />
                </div>
                {p.rules.map((r, i) => (
                  <div key={i} className="hstack wrap" style={{ marginTop: 12, gap: 6, fontSize: "0.8125rem" }}>
                    <span className={`chip ${r.effect === "deny" ? "red" : "green"}`}>{r.effect === "deny" ? "Deny" : "Permit"} when</span>
                    <ConditionView c={r.condition} />
                  </div>
                ))}
              </motion.div>
            );
          })}
          {!isAdmin && <p className="t-caption" style={{ margin: "0 4px" }}>Only administrators can change policies. Sign in as Dana to try it.</p>}
        </div>

        <div className="card" style={{ position: "sticky", top: 68 }}>
          <h3 className="t-headline">Try a request</h3>
          <p className="t-caption" style={{ margin: "4px 0 16px" }}>Ask the decision point what it would answer. Nothing is logged.</p>
          <div className="stack" style={{ gap: 12 }}>
            <label className="field"><span>Requester</span>
              <select className="input" value={subject} onChange={(e) => setSubject(e.target.value)}>
                {users.map((u) => <option key={u.username} value={u.username}>{u.display_name} — {u.attributes.role}, {u.attributes.department}, L{u.attributes.clearance}</option>)}
              </select>
            </label>
            <label className="field"><span>File</span>
              <select className="input" value={fileId} onChange={(e) => setFileId(e.target.value)}>
                {files.map((f) => <option key={f.file_id} value={f.file_id}>{f.filename} — {f.department}, L{f.clearance_required}</option>)}
              </select>
            </label>
            <div className="field"><span>Hour of day · {String(hour).padStart(2, "0")}:00</span>
              <input type="range" min={0} max={23} value={hour} onChange={(e) => setHour(Number(e.target.value))} style={{ accentColor: "var(--accent)" }} aria-label="Hour of day" />
            </div>
            <div className="field"><span>Account</span>
              <Segmented label="Account status" value={status} onChange={setStatus} options={[{ value: "active", label: "Active" }, { value: "suspended", label: "Suspended" }]} />
            </div>
          </div>
          <div className="divider" />
          <AnimatePresence mode="wait">
            {result && (
              <motion.div key={result.decision + result.matched.length} initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }} transition={spring.snappy}
                className={`callout ${result.decision === "Permit" ? "green" : "red"}`}>
                {result.decision === "Permit" ? <ShieldCheck size={18} color="var(--green)" /> : <ShieldX size={18} color="var(--red)" />}
                <div>
                  <div style={{ fontWeight: 600, fontSize: "0.9375rem" }}>{result.decision}</div>
                  <div className="t-caption" style={{ color: "inherit", opacity: 0.85 }}>
                    {result.matched.length ? result.matched.map((m) => `${m.policy_id} → ${m.effect}`).join(" · ") : "No rule matched — deny by default"}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </>
  );
}
