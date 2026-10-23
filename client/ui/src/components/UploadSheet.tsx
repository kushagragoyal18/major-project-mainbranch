import { useEffect, useMemo, useRef, useState, type DragEvent } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Check, CloudUpload, TriangleAlert } from "lucide-react";
import { api, type User } from "../lib/api";
import { useSession } from "../lib/session";
import { runUpload, uploadSteps } from "../lib/pipeline";
import { composePolicy, eligible } from "../lib/policy";
import { bytes } from "../lib/format";
import { spring } from "../lib/motion";
import { Avatar, FileGlyph, Pipeline, Segmented, Sheet, Switch, useSteps, useToast } from "./ui";
import { PolicyChips } from "./PolicyChips";

const ROLES = ["Doctor", "Nurse", "Admin", "Researcher"];

export function UploadSheet({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const { user, device } = useSession();
  const toast = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [department, setDepartment] = useState(user?.attributes.department ?? "Cardiology");
  const [clearance, setClearance] = useState(2);
  const [roles, setRoles] = useState<string[]>([]);
  const [custom, setCustom] = useState(false);
  const [expr, setExpr] = useState("");
  const [recipients, setRecipients] = useState<string[]>([]);
  const [compiled, setCompiled] = useState<{ compiled: string; unknown: string[] } | null>(null);
  const [phase, setPhase] = useState<"compose" | "running" | "done" | "failed">("compose");
  const { steps, setSteps, report } = useSteps(uploadSteps);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    api<User[]>("/users").then(setUsers).catch(() => {});
    setFile(null); setPhase("compose"); setSteps(uploadSteps()); setRecipients([]); setRoles([]); setCustom(false);
    setDepartment(user?.attributes.department ?? "Cardiology");
  }, [open, user, setSteps]);

  const departments = useMemo(() => Array.from(new Set(users.map((u) => u.attributes.department).concat(department))).sort(), [users, department]);
  const policy = custom ? expr : composePolicy(department, clearance, roles);
  const who = useMemo(() => eligible(policy, users), [policy, users]);

  useEffect(() => {
    if (!policy.trim()) { setCompiled(null); return; }
    const t = setTimeout(() => api<{ compiled: string; unknown: string[] }>("/abe/compile", { body: { policy } }).then(setCompiled).catch(() => setCompiled(null)), 180);
    return () => clearTimeout(t);
  }, [policy]);

  const onDrop = (e: DragEvent) => {
    e.preventDefault(); setOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) setFile(f);
  };

  async function start() {
    if (!file) return;
    setPhase("running");
    try {
      await runUpload({
        file, policyDisplay: policy, department, clearance, device,
        recipients: users.filter((u) => recipients.includes(u.username)),
      }, report);
      setPhase("done");
      toast(`${file.name} encrypted and stored`);
      onDone();
    } catch (e) {
      setPhase("failed");
      toast(e instanceof Error ? e.message : "Upload failed", "error");
    }
  }

  const footer = phase === "compose" || phase === "failed" ? (
    <>
      <button className="btn" onClick={onClose}>Cancel</button>
      <button className="btn primary" disabled={!file || !policy.trim() || file.size > 50 * 1024 * 1024} onClick={start}>Encrypt and upload</button>
    </>
  ) : phase === "done" ? <button className="btn primary" onClick={onClose}>Done</button> : null;

  return (
    <Sheet open={open} onClose={onClose} title="Upload a file" subtitle="Encrypted on this device before it leaves" wide footer={footer}
      icon={<span className="icon-tile" style={{ background: "var(--accent)" }}><CloudUpload size={17} /></span>}>
      {/* Plain cross-fade: the next view never waits on the previous one's exit animation. */}
      {phase === "compose" ? (
          <motion.div key="compose" className="stack" style={{ gap: 20 }} initial={false} animate={{ opacity: 1 }} transition={{ duration: 0.15 }}>
            <div className={`dropzone${over ? " over" : ""}`} onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={onDrop}>
              <input ref={input} type="file" hidden onChange={(e) => e.target.files?.[0] && setFile(e.target.files[0])} />
              {file ? (
                <div className="hstack" style={{ justifyContent: "center", gap: 12 }}>
                  <FileGlyph name={file.name} />
                  <div style={{ textAlign: "left" }}>
                    <div style={{ fontWeight: 600 }}>{file.name}</div>
                    <div className="t-caption">{bytes(file.size)}{file.size > 50 * 1024 * 1024 ? " · over the 50 MB demo limit" : ""}</div>
                  </div>
                  <button className="btn plain" onClick={() => input.current?.click()}>Replace</button>
                </div>
              ) : (
                <>
                  <div style={{ fontWeight: 600, marginBottom: 4 }}>Drop a file here</div>
                  <div className="t-caption" style={{ marginBottom: 12 }}>Any type up to 50 MB. Nothing is sent until you choose Encrypt.</div>
                  <button className="btn" onClick={() => input.current?.click()}>Choose file…</button>
                </>
              )}
            </div>

            <div>
              <div className="hstack" style={{ justifyContent: "space-between", marginBottom: 10 }}>
                <h3 className="t-headline">Who can open it</h3>
                <label className="hstack t-caption" style={{ gap: 8 }}>
                  Write expression
                  <Switch label="Write policy expression" checked={custom} onChange={(v) => { setCustom(v); if (v) setExpr(policy); }} />
                </label>
              </div>

              {custom ? (
                <textarea className="input mono" rows={2} value={expr} onChange={(e) => setExpr(e.target.value)} placeholder="(cardiology and level3) or (oncology and doctor)" />
              ) : (
                <div className="group">
                  <div className="row" style={{ flexWrap: "wrap" }}>
                    <span className="row-main" style={{ minWidth: 120 }}>Department</span>
                    <div className="hstack wrap" style={{ gap: 6 }}>
                      {departments.map((d) => (
                        <button key={d} className="choice" aria-pressed={d === department} onClick={() => setDepartment(d)}>{d}</button>
                      ))}
                    </div>
                  </div>
                  <div className="row">
                    <span className="row-main">Minimum clearance</span>
                    <Segmented label="Minimum clearance" value={clearance} onChange={setClearance} options={[1, 2, 3, 4].map((n) => ({ value: n, label: `L${n}` }))} />
                  </div>
                  <div className="row" style={{ flexWrap: "wrap" }}>
                    <span className="row-main" style={{ minWidth: 120 }}>Role <span className="faint">· optional</span></span>
                    <div className="hstack wrap" style={{ gap: 6 }}>
                      {ROLES.map((r) => (
                        <button key={r} className="choice" aria-pressed={roles.includes(r)} onClick={() => setRoles((x) => x.includes(r) ? x.filter((y) => y !== r) : [...x, r])}>{r}</button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              <div className="card" style={{ marginTop: 12, background: "var(--bg-inset)", boxShadow: "none" }}>
                <div className="t-caption" style={{ marginBottom: 6 }}>CP-ABE policy</div>
                {policy.trim() ? <PolicyChips policy={policy} /> : <span className="faint">Empty policy</span>}
                {compiled && (
                  <div className="t-caption mono" style={{ marginTop: 8 }}>compiles to {compiled.compiled}</div>
                )}
                {compiled && compiled.unknown.length > 0 && (
                  <div className="hstack t-caption" style={{ marginTop: 8, color: "var(--orange)" }}>
                    <TriangleAlert size={13} /> No one currently holds: {compiled.unknown.join(", ")}
                  </div>
                )}
                <div className="divider" />
                <div className="hstack" style={{ justifyContent: "space-between" }}>
                  <span className="t-caption">{who.length === 0 ? "Nobody on staff can open this" : `${who.length} ${who.length === 1 ? "person" : "people"} can open this`}</span>
                  <div className="hstack" style={{ gap: 0 }}>
                    <AnimatePresence initial={false}>
                      {who.map((u) => (
                        <motion.span key={u.username} title={u.display_name} layout initial={{ opacity: 0, scale: 0.6 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.6 }} transition={spring.snappy}
                          style={{ marginLeft: -6, borderRadius: "50%", boxShadow: "0 0 0 2px var(--bg-inset)" }}>
                          <Avatar name={u.display_name} size={24} />
                        </motion.span>
                      ))}
                    </AnimatePresence>
                  </div>
                </div>
              </div>
              <p className="t-caption" style={{ margin: "8px 2px 0" }}>
                The file is also tagged <b>{department}</b> at clearance <b>L{clearance}</b> for the ABAC policy engine, so access is checked twice.
              </p>
            </div>

            <div>
              <h3 className="t-headline" style={{ marginBottom: 4 }}>Bind to a device <span className="faint" style={{ fontWeight: 400 }}>· optional</span></h3>
              <p className="t-caption" style={{ margin: "0 0 10px" }}>Tier 3 wraps the file key to each person's RSA device key as well.</p>
              <div className="hstack wrap" style={{ gap: 6 }}>
                {users.filter((u) => u.pub_key_pem && u.username !== user?.username).map((u) => (
                  <button key={u.username} className="choice" aria-pressed={recipients.includes(u.username)}
                    onClick={() => setRecipients((x) => x.includes(u.username) ? x.filter((y) => y !== u.username) : [...x, u.username])}>
                    {recipients.includes(u.username) && <Check size={12} strokeWidth={3} style={{ marginRight: 4, verticalAlign: -1 }} />}
                    {u.display_name}
                  </button>
                ))}
              </div>
            </div>
          </motion.div>
        ) : (
          <motion.div key="run" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.15 }}>
            <div className="hstack" style={{ gap: 12, margin: "4px 0 14px" }}>
              {file && <FileGlyph name={file.name} locked={phase === "done"} />}
              <div>
                <div style={{ fontWeight: 600 }}>{file?.name}</div>
                <div className="t-caption"><PolicyChips policy={policy} /></div>
              </div>
            </div>
            <Pipeline steps={steps} />
          </motion.div>
        )}
    </Sheet>
  );
}
