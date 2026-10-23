import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Download, LockOpen, ShieldAlert, ShieldCheck, ShieldX, Trash2 } from "lucide-react";
import { api, ApiError, type FileItem } from "../lib/api";
import { useSession } from "../lib/session";
import { downloadSteps, isDenied, runBreach, runDownload, type UnwrapMode } from "../lib/pipeline";
import { bytes, relTime } from "../lib/format";
import { spring } from "../lib/motion";
import { FileGlyph, Pipeline, Segmented, Sheet, useSteps, useToast } from "./ui";
import { PolicyChips } from "./PolicyChips";

type Breach = Awaited<ReturnType<typeof runBreach>>;

export function FileSheet({ file, onClose, onChanged }: { file: FileItem | null; onClose: () => void; onChanged: () => void }) {
  const { sk, device, user, isAdmin, health, refresh } = useSession();
  const toast = useToast();
  const [mode, setMode] = useState<UnwrapMode>("outsourced");
  const [phase, setPhase] = useState<"idle" | "running" | "done" | "denied" | "failed">("idle");
  const [result, setResult] = useState<{ plaintext: Uint8Array; mime: string } | null>(null);
  const [breach, setBreach] = useState<Breach | null>(null);
  const [breaching, setBreaching] = useState(false);
  const { steps, setSteps, report } = useSteps(() => []);

  const permitted = file?.decision?.decision === "Permit";
  const boundToMe = !!file && !!user && file.recipients.includes(user.username) && !!device;

  useEffect(() => {
    if (!file) return;
    setPhase("idle"); setResult(null); setBreach(null);
    setMode("outsourced");
    setSteps(downloadSteps(file, "outsourced"));
  }, [file, setSteps]);

  useEffect(() => { if (file && phase === "idle") setSteps(downloadSteps(file, mode)); }, [mode, file, phase, setSteps]);

  async function decrypt() {
    if (!file || !sk) return;
    setPhase("running");
    setSteps(downloadSteps(file, mode));
    try {
      // Fetch a freshly issued key so attribute version bumps (revocation) are picked up.
      const freshKey = await refresh().catch(() => sk);
      const r = await runDownload(file, mode, freshKey, device, report);
      setResult({ plaintext: r.plaintext, mime: file.mime_type || "application/octet-stream" });
      setPhase("done");
      if (file.stale) { toast("Key re-wrapped under the new attribute versions"); onChanged(); }
    } catch (e) {
      if (isDenied(e)) {
        report("abac", { state: "fail", detail: (e as ApiError).message });
        setPhase("denied");
      } else setPhase("failed");
    }
  }

  async function simulateBreach() {
    if (!file || !sk) return;
    setBreaching(true);
    try { setBreach(await runBreach(file, await refresh().catch(() => sk))); } catch (e) { toast(e instanceof Error ? e.message : "Failed", "error"); }
    setBreaching(false);
  }

  async function remove() {
    if (!file) return;
    try {
      await api(`/files/${file.file_id}`, { method: "DELETE" });
      toast(`${file.filename} deleted`);
      onChanged(); onClose();
    } catch (e) { toast(e instanceof Error ? e.message : "Delete failed", "error"); }
  }

  function save() {
    if (!file || !result) return;
    const url = URL.createObjectURL(new Blob([result.plaintext as BlobPart], { type: result.mime }));
    const a = Object.assign(document.createElement("a"), { href: url, download: file.filename });
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  const preview = useMemo(() => {
    if (!result) return null;
    if (result.mime.startsWith("image/")) return { kind: "image" as const, url: URL.createObjectURL(new Blob([result.plaintext as BlobPart], { type: result.mime })) };
    const isText = result.mime.startsWith("text/") || /json|xml|csv|markdown/.test(result.mime);
    if (isText && result.plaintext.length < 400_000) return { kind: "text" as const, text: new TextDecoder().decode(result.plaintext) };
    return null;
  }, [result]);

  const canDelete = !!file && (file.owner === user?.username || isAdmin);

  const footer = file && (
    <>
      {canDelete && <button className="btn danger" onClick={remove} style={{ marginRight: "auto" }}><Trash2 size={14} /> Delete</button>}
      {phase === "done" ? (
        <button className="btn primary" onClick={save}><Download size={14} /> Save decrypted copy</button>
      ) : (
        <button className="btn primary" disabled={phase === "running"} onClick={decrypt}>
          {phase === "running" ? <span className="spinner" /> : <LockOpen size={14} />} {phase === "denied" || phase === "failed" ? "Try again" : "Decrypt"}
        </button>
      )}
    </>
  );

  return (
    <Sheet open={!!file} onClose={onClose} wide footer={footer}
      title={file?.filename} subtitle={file && `${file.owner} · ${relTime(file.uploaded_at)} · ${bytes(file.plain_size ?? file.size_bytes)}`}
      icon={file && <FileGlyph name={file.filename} locked={phase !== "done"} />}>
      {file && (
        <div className="grid-2" style={{ gap: 22, alignItems: "start" }}>
          <div className="stack" style={{ gap: 18 }}>
            <div>
              <div className="t-section" style={{ marginLeft: 0 }}>Cryptographic policy</div>
              <PolicyChips policy={file.policy_display} />
              <div className="t-caption mono" style={{ marginTop: 6 }}>{file.policy}</div>
            </div>

            <div>
              <div className="t-section" style={{ marginLeft: 0 }}>Policy engine decision for you</div>
              <div className={`callout ${permitted ? "green" : "red"}`}>
                {permitted ? <ShieldCheck size={16} color="var(--green)" /> : <ShieldX size={16} color="var(--red)" />}
                <div>
                  <b>{permitted ? "Permit" : "Deny"}</b>
                  <div className="t-caption" style={{ color: "inherit", opacity: 0.85 }}>
                    {file.decision?.matched.length
                      ? `Matched: ${file.decision.matched.map((m) => `${m.policy_id} (${m.effect})`).join(", ")}`
                      : "No permit rule applies, so access is denied by default."}
                  </div>
                </div>
              </div>
            </div>

            {file.stale && (
              <div className="callout orange">
                <ShieldAlert size={16} color="var(--orange)" />
                <div>An attribute in this policy was revoked. The next authorised reader re-wraps the 32-byte key; the {bytes(file.size_bytes)} ciphertext stays as it is.</div>
              </div>
            )}

            <div className="group">
              <div className="row"><span className="row-main muted">Resource attributes</span><span>{file.department} · L{file.clearance_required}</span></div>
              <div className="row"><span className="row-main muted">Stored ciphertext</span><span className="tnum">{bytes(file.size_bytes)}</span></div>
              <div className="row"><span className="row-main muted">Author signature</span><span>{file.signed ? "RSA-PSS" : "None"}</span></div>
              <div className="row"><span className="row-main muted">Device-bound for</span><span>{file.recipients.length ? file.recipients.join(", ") : "Nobody"}</span></div>
              <div className="row"><span className="row-main muted">Key re-wraps</span><span className="tnum">{file.rewrap_count}</span></div>
            </div>
          </div>

          <div className="stack" style={{ gap: 14 }}>
            <div>
              <div className="t-section" style={{ marginLeft: 0 }}>Unwrap the key using</div>
              <Segmented label="Key unwrap method" value={mode} onChange={(v) => phase !== "running" && setMode(v)}
                options={[
                  { value: "outsourced", label: "Outsourced" },
                  { value: "local", label: "On device" },
                  ...(boundToMe ? [{ value: "device" as UnwrapMode, label: "Device key" }] : []),
                ]} />
            </div>
            <Pipeline steps={steps} />

            <AnimatePresence>
              {phase === "done" && result && (
                <motion.div initial={{ opacity: 0, y: 8, filter: "blur(4px)" }} animate={{ opacity: 1, y: 0, filter: "blur(0px)" }} transition={spring.move}>
                  {preview?.kind === "text" && <div className="doc-view">{preview.text}</div>}
                  {preview?.kind === "image" && <img src={preview.url} alt={file.filename} style={{ maxWidth: "100%", borderRadius: 10 }} />}
                  {!preview && <div className="callout green">Decrypted {bytes(result.plaintext.length)}. Save it to open it.</div>}
                </motion.div>
              )}

              {phase === "denied" && health?.demo_mode && (
                <motion.div className="card" style={{ background: "var(--bg-inset)", boxShadow: "none" }} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring.move}>
                  <h4 className="t-headline">What if the server were compromised?</h4>
                  <p className="t-caption" style={{ margin: "4px 0 12px" }}>
                    Skip the policy engine and take the raw ciphertext, as a malicious insider could. Then try to open it with your own attribute key.
                  </p>
                  {!breach ? (
                    <button className="btn" onClick={simulateBreach} disabled={breaching}>{breaching ? <span className="spinner" /> : null} Bypass the policy engine</button>
                  ) : breach.opened ? (
                    <div className="callout orange">Your key satisfies the cryptographic policy, so only the policy engine was stopping you. This is where revocation and the second layer matter.</div>
                  ) : (
                    <div className="stack" style={{ gap: 10 }}>
                      <div className="cipher-view">{breach.ciphertext.slice(0, 420)}</div>
                      <div className="callout red">
                        <ShieldX size={16} color="var(--red)" />
                        <div><b>CP-ABE refused.</b> {breach.reason} The ciphertext above is all the attacker gets.</div>
                      </div>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      )}
    </Sheet>
  );
}
