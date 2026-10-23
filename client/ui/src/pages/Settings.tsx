import { useState } from "react";
import { Fingerprint, LogOut, Monitor, Moon, RotateCcw, Server, Sun } from "lucide-react";
import { api } from "../lib/api";
import { useSession } from "../lib/session";
import { resetPkCache } from "../lib/pipeline";
import { Avatar, PageHead, Segmented, useToast } from "../components/ui";
import type { Route } from "../App";

type Theme = "system" | "light" | "dark";

function readTheme(): Theme {
  try { return (localStorage.getItem("tessera.theme") as Theme) || "system"; } catch { return "system"; }
}

export default function Settings({ go }: { go: (r: Route) => void }) {
  const { user, device, health, isAdmin, signOut, rotateDeviceKey } = useSession();
  const toast = useToast();
  const [theme, setTheme] = useState<Theme>(readTheme);
  const [busy, setBusy] = useState<string | null>(null);

  function applyTheme(t: Theme) {
    setTheme(t);
    try { localStorage.setItem("tessera.theme", t); } catch { /* per-viewer convenience only */ }
    if (t === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = t;
  }

  async function rotate() {
    setBusy("rotate");
    try { await rotateDeviceKey(); toast("New device key generated and bound"); }
    catch (e) { toast(e instanceof Error ? e.message : "Failed", "error"); }
    setBusy(null);
  }

  async function resetDemo() {
    if (!confirm("Restore the demo hospital? This deletes every uploaded file and the audit trail.")) return;
    setBusy("reset");
    try {
      await api("/admin/reset-demo", { body: {} });
      resetPkCache();
      toast("Demo data restored");
      go("vault");
    } catch (e) { toast(e instanceof Error ? e.message : "Reset failed", "error"); }
    setBusy(null);
  }

  if (!user) return null;

  return (
    <>
      <PageHead title="Settings" />

      <div className="group">
        <div className="row" style={{ padding: "16px" }}>
          <Avatar name={user.display_name} size={44} />
          <div className="row-main">
            <div className="t-headline">{user.display_name}</div>
            <div className="row-sub">@{user.username} · {user.attributes.role} · {user.attributes.department} · Clearance {user.attributes.clearance}</div>
          </div>
          <button className="btn" onClick={signOut}><LogOut size={14} /> Sign out</button>
        </div>
      </div>

      <div className="section" style={{ marginTop: 24 }}>
        <div className="t-section">Appearance</div>
        <div className="group">
          <div className="row">
            <span className="row-main">Theme</span>
            <Segmented label="Theme" value={theme} onChange={applyTheme} options={[
              { value: "system", label: <span className="hstack" style={{ gap: 5 }}><Monitor size={13} /> Auto</span> },
              { value: "light", label: <span className="hstack" style={{ gap: 5 }}><Sun size={13} /> Light</span> },
              { value: "dark", label: <span className="hstack" style={{ gap: 5 }}><Moon size={13} /> Dark</span> },
            ]} />
          </div>
        </div>
      </div>

      <div className="section" style={{ marginTop: 24 }}>
        <div className="t-section">This device</div>
        <div className="group">
          <div className="row inset-icon">
            <span className="icon-tile" style={{ background: "var(--label)", color: "var(--bg-elevated)" }}><Fingerprint size={16} /></span>
            <div className="row-main">
              <div className="row-title">Device key</div>
              <div className="row-sub">{device ? <span className="mono">RSA-2048 · {device.fingerprint} · private half is non-extractable</span> : "Unavailable in this browser"}</div>
            </div>
            <button className="btn" onClick={rotate} disabled={busy === "rotate"}>{busy === "rotate" ? <span className="spinner" /> : "Rotate"}</button>
          </div>
        </div>
        <p className="t-caption" style={{ margin: "8px 14px 0" }}>Used to sign what you upload and to receive files bound to you. Rotating it means files bound to the old key must be re-shared.</p>
      </div>

      <div className="section" style={{ marginTop: 24 }}>
        <div className="t-section">Server</div>
        <div className="group">
          <div className="row inset-icon">
            <span className="icon-tile" style={{ background: "var(--green)" }}><Server size={16} /></span>
            <div className="row-main">
              <div className="row-title">{health ? "Connected" : "Offline"}</div>
              <div className="row-sub">test:202 {health?.version}</div>
            </div>
          </div>
          <div className="row"><span className="row-main muted">CP-ABE engine</span><span>{health?.abe_mode === "simulated" ? "Simulated (same interface as BSW07)" : "Charm-Crypto BSW07"}</span></div>
          <div className="row"><span className="row-main muted">Metadata store</span><span>{health?.metadata_backend === "mongo" ? "MongoDB" : "Local file store"}</span></div>
          <div className="row"><span className="row-main muted">Object store</span><span>{health?.storage_backend === "s3" ? "Amazon S3" : "Local directory"}</span></div>
        </div>
        {health?.abe_mode === "simulated" && (
          <p className="t-caption" style={{ margin: "8px 14px 0" }}>
            Charm-Crypto needs the PBC library, which is built in the Docker image. Without it the server uses a simulated CP-ABE module with the same interface and policy semantics. The pairing-based scheme runs with <span className="mono">ABE_MODE=real</span> in Docker.
          </p>
        )}
      </div>

      {isAdmin && (
        <div className="section" style={{ marginTop: 24 }}>
          <div className="t-section">Demonstration</div>
          <div className="group">
            <div className="row inset-icon">
              <span className="icon-tile" style={{ background: "var(--orange)" }}><RotateCcw size={16} /></span>
              <div className="row-main">
                <div className="row-title">Restore demo hospital</div>
                <div className="row-sub">Re-seeds staff, policies and the five sample records</div>
              </div>
              <button className="btn danger" onClick={resetDemo} disabled={busy === "reset"}>{busy === "reset" ? <span className="spinner" /> : "Restore"}</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
