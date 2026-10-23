import { useCallback, useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ArrowRight, Clock, Zap } from "lucide-react";
import { api, type FileItem, type User } from "../lib/api";
import { useSession } from "../lib/session";
import { bytes, prettyToken } from "../lib/format";
import { spring } from "../lib/motion";
import { Avatar, Empty, FileGlyph, PageHead, Segmented, Sheet, Switch, rowMotion, useToast } from "../components/ui";
import type { Route } from "../App";

interface RevokeResult { username: string; lost_tokens: string[]; bumped: Record<string, number>; stale_files: string[] }
type Field = "department" | "clearance" | "role";

const DEPARTMENTS = ["Cardiology", "Oncology", "Radiology", "Neurology", "Pharmacy", "Security"];
const ROLES = ["Doctor", "Nurse", "Researcher", "Admin"];

export default function Revocation({ go }: { go: (r: Route) => void }) {
  const { isAdmin, user: me, refresh } = useSession();
  const toast = useToast();
  const [users, setUsers] = useState<User[]>([]);
  const [versions, setVersions] = useState<Record<string, number>>({});
  const [files, setFiles] = useState<FileItem[]>([]);
  const [target, setTarget] = useState<User | null>(null);
  const [field, setField] = useState<Field>("department");
  const [value, setValue] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<(RevokeResult & { name: string }) | null>(null);

  const load = useCallback(() => {
    api<User[]>("/users").then(setUsers);
    api<Record<string, number>>("/abe/versions").then(setVersions);
    api<FileItem[]>("/files").then(setFiles);
  }, []);
  useEffect(() => { load(); }, [load]);

  function openFor(u: User) {
    setTarget(u);
    setField("department");
    setValue(DEPARTMENTS.find((d) => d !== u.attributes.department) ?? "");
  }

  useEffect(() => {
    if (!target) return;
    if (field === "department") setValue(DEPARTMENTS.find((d) => d !== target.attributes.department) ?? "");
    if (field === "role") setValue(ROLES.find((r) => r !== target.attributes.role) ?? "");
    if (field === "clearance") setValue(String(Math.max(1, target.attributes.clearance - 1)));
  }, [field, target]);

  async function revoke() {
    if (!target) return;
    setBusy(true);
    try {
      const r = await api<RevokeResult>("/admin/revoke", { body: { username: target.username, field, value: field === "clearance" ? Number(value) : value } });
      setResult({ ...r, name: target.display_name });
      setTarget(null);
      load();
      await refresh();
    } catch (e) {
      toast(e instanceof Error ? e.message : "Revocation failed", "error");
    }
    setBusy(false);
  }

  async function setActive(u: User, active: boolean) {
    setUsers((us) => us.map((x) => (x.username === u.username ? { ...x, active } : x)));
    try {
      await api(`/admin/users/${u.username}/active`, { body: { active } });
      toast(active ? `${u.display_name} reinstated` : `${u.display_name} suspended — effective on their next request`);
    } catch (e) {
      toast(e instanceof Error ? e.message : "Failed", "error");
      load();
    }
  }

  const stale = files.filter((f) => f.stale);
  const current = target && (field === "clearance" ? `L${target.attributes.clearance}` : target.attributes[field]);
  const bumpedTokens = Object.entries(versions).filter(([, v]) => v > 1);

  return (
    <>
      <PageHead title="Revocation">
        Revoking an attribute takes effect twice. The policy engine refuses the person on their very next request. The attribute's version is bumped, and each affected file's 32-byte key is re-wrapped the next time someone authorised opens it. The file itself is never re-encrypted.
      </PageHead>

      <AnimatePresence>
        {result && (
          <motion.div className="card" style={{ marginBottom: 20 }} initial={{ opacity: 0, y: -8, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, scale: 0.98 }} transition={spring.sheet}>
            <div className="hstack" style={{ justifyContent: "space-between", marginBottom: 12 }}>
              <h3 className="t-headline">{result.name} lost {result.lost_tokens.map(prettyToken).join(", ") || "no attributes"}</h3>
              <button className="btn plain" onClick={() => setResult(null)}>Dismiss</button>
            </div>
            <div className="grid-2" style={{ gap: 12 }}>
              <div className="callout green">
                <Zap size={16} color="var(--green)" />
                <div><b>Policy engine · now.</b> The directory is updated, so every request from here on is evaluated with the new attributes.</div>
              </div>
              <div className="callout blue">
                <Clock size={16} color="var(--accent)" />
                <div>
                  <b>Cryptography · lazily.</b>{" "}
                  {Object.keys(result.bumped).length
                    ? <>{Object.entries(result.bumped).map(([t, v]) => `${prettyToken(t)} v${v - 1} → v${v}`).join(", ")}. {result.stale_files.length} file key{result.stale_files.length === 1 ? "" : "s"} queued for re-wrap.</>
                    : "No attribute versions needed to change."}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="t-section">People</div>
      <div className="group">
        {users.map((u, i) => (
          <motion.div key={u.username} className="row inset-icon" {...rowMotion(i)}>
            <Avatar name={u.display_name} />
            <div className="row-main">
              <div className="row-title">{u.display_name} {u.username === me?.username && <span className="faint" style={{ fontWeight: 400 }}>· you</span>}</div>
              <div className="row-sub">{u.attributes.role} · {u.attributes.department} · Clearance {u.attributes.clearance}</div>
            </div>
            {!u.active && <span className="chip red">Suspended</span>}
            {isAdmin && u.username !== me?.username && (
              <>
                <button className="btn hide-sm" onClick={() => openFor(u)}>Revoke attribute…</button>
                <Switch label={`${u.display_name} account active`} checked={u.active} onChange={(v) => setActive(u, v)} />
              </>
            )}
          </motion.div>
        ))}
      </div>
      {!isAdmin && <p className="t-caption" style={{ margin: "8px 14px 0" }}>Only administrators can revoke. Sign in as Dana Kapoor to try it.</p>}

      <div className="grid-2" style={{ marginTop: 28, alignItems: "start" }}>
        <div>
          <div className="t-section">Lazy re-wrap queue</div>
          <div className="group">
            {stale.length === 0 ? (
              <Empty icon={<Clock size={28} strokeWidth={1.5} />} title="Nothing waiting">Every file key matches the current attribute versions.</Empty>
            ) : stale.map((f) => (
              <button key={f.file_id} className="row clickable" onClick={() => go("vault")}>
                <FileGlyph name={f.filename} />
                <div className="row-main">
                  <div className="row-title">{f.filename}</div>
                  <div className="row-sub">32 bytes to re-wrap · {bytes(f.size_bytes)} untouched</div>
                </div>
                <ArrowRight size={14} color="var(--label-4)" />
              </button>
            ))}
          </div>
        </div>
        <div>
          <div className="t-section">Attribute versions</div>
          <div className="group">
            {bumpedTokens.length === 0 ? (
              <div className="row"><span className="muted">All attributes are at version 1.</span></div>
            ) : bumpedTokens.map(([t, v]) => (
              <div key={t} className="row">
                <span className="row-main">{prettyToken(t)}</span>
                <span className="chip blue tnum">v{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <Sheet open={!!target} onClose={() => setTarget(null)} title={`Revoke an attribute from ${target?.display_name ?? ""}`}
        subtitle="Choose what changes. The old value is revoked."
        icon={target && <Avatar name={target.display_name} />}
        footer={<>
          <button className="btn" onClick={() => setTarget(null)}>Cancel</button>
          <button className="btn primary" disabled={busy || !value} onClick={revoke} style={{ background: "var(--red)" }}>{busy ? <span className="spinner" /> : "Revoke"}</button>
        </>}>
        {target && (
          <div className="stack" style={{ gap: 16 }}>
            <Segmented label="Attribute" value={field} onChange={setField} options={[
              { value: "department", label: "Department" }, { value: "clearance", label: "Clearance" }, { value: "role", label: "Role" },
            ]} />
            <div className="group">
              <div className="row"><span className="row-main muted">Currently</span><b>{current}</b></div>
              <div className="row">
                <span className="row-main muted">Change to</span>
                {field === "clearance" ? (
                  <Segmented label="New clearance" value={value} onChange={setValue}
                    options={Array.from({ length: Math.max(0, target.attributes.clearance - 1) }, (_, i) => ({ value: String(i + 1), label: `L${i + 1}` }))} />
                ) : (
                  <select className="input" style={{ width: 180 }} value={value} onChange={(e) => setValue(e.target.value)}>
                    {(field === "department" ? DEPARTMENTS : ROLES).filter((x) => x !== target.attributes[field]).map((x) => <option key={x}>{x}</option>)}
                  </select>
                )}
              </div>
            </div>
            <p className="t-caption" style={{ margin: 0 }}>
              {field === "clearance" && target.attributes.clearance <= 1 ? "Clearance is already at the lowest level." :
                "Files guarded by the revoked attribute keep their ciphertext. Only their 32-byte keys are re-wrapped, lazily."}
            </p>
          </div>
        )}
      </Sheet>
    </>
  );
}
