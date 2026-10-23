import { useState, type FormEvent } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ArrowRight, ChevronRight } from "lucide-react";
import { api, ApiError } from "../lib/api";
import { useSession } from "../lib/session";
import { spring } from "../lib/motion";
import { Avatar, Segmented, useToast } from "../components/ui";
import { Logo } from "../components/Logo";

// Seeded by usecase/healthcare_demo.py for the local showcase build.
const DEMO_PASSWORD = "tessera-demo";
const PERSONAS = [
  { username: "alice", name: "Dr. Alice Mehra", line: "Doctor · Cardiology · Clearance 3" },
  { username: "bob", name: "Bob Fernandes", line: "Nurse · Cardiology · Clearance 2" },
  { username: "carol", name: "Dr. Carol Iyer", line: "Doctor · Oncology · Clearance 3" },
  { username: "dana", name: "Dana Kapoor", line: "Administrator · Security · Clearance 4" },
];

const TIERS = [
  ["1", "AES-256-GCM", "Each file gets its own fresh 256-bit key."],
  ["2", "CP-ABE", "That key is locked to a policy over attributes."],
  ["3", "RSA-OAEP", "Optionally bound to a specific person's device."],
];

export default function SignIn() {
  const { signIn, health } = useSession();
  const toast = useToast();
  const [mode, setMode] = useState<"signin" | "register">("signin");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [form, setForm] = useState({ display_name: "", username: "", password: "", role: "Doctor", department: "Cardiology", clearance: 2 });
  const set = (k: keyof typeof form) => (v: string | number) => setForm((f) => ({ ...f, [k]: v }));

  async function attempt(username: string, password: string, key: string) {
    setBusy(key);
    setError("");
    try {
      await signIn(username, password);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the test:202 server.");
      setBusy(null);
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (mode === "signin") return attempt(form.username, form.password, "form");
    setBusy("form");
    setError("");
    try {
      await api("/register", { body: form });
      toast("Account created");
      await attempt(form.username, form.password, "form");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Registration failed.");
      setBusy(null);
    }
  }

  return (
    <div className="signin">
      <section className="signin-story">
        <div className="hstack" style={{ gap: 10 }}>
          <Logo size={30} />
          <span className="brand-name" style={{ fontSize: "1.0625rem" }}>test:202</span>
        </div>

        <div style={{ maxWidth: 520, margin: "48px 0" }}>
          <h1 className="hero-title">Cloud storage that can't read your files.</h1>
          <p style={{ fontSize: "1.0625rem", lineHeight: 1.5, color: "var(--label-2)", margin: "18px 0 32px", letterSpacing: "-0.012em" }}>
            Files are encrypted in your browser before upload. Who can open them is decided by
            attributes like role, department and clearance, and that rule is enforced twice:
            by a policy engine, and by the mathematics of the key itself.
          </p>
          <div className="tiers">
            {TIERS.map(([n, name, text], i) => (
              <motion.div key={n} className="tier" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ ...spring.move, delay: 0.08 + i * 0.06 }}>
                <span className="tier-num">{n}</span>
                <div>
                  <div style={{ fontWeight: 600 }}>{name}</div>
                  <div className="t-caption">{text}</div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        <div className="t-caption" style={{ lineHeight: 1.6 }}>
          Privacy-Preserving Secure Cloud Storage with Hybrid Encryption and Attribute-Based Access Control<br />
          Vansh Sharma · Kushagra Goyal · Geetanshi Singh · Himanshi Kumar — Department of Computer Science &amp; Engineering
        </div>
      </section>

      <section className="signin-form">
        <div style={{ width: "min(380px, 100%)" }}>
          <h2 className="t-title" style={{ marginBottom: 4 }}>{mode === "signin" ? "Sign in" : "Create an account"}</h2>
          <p className="muted" style={{ margin: "0 0 20px" }}>
            {mode === "signin" ? "Your attribute key is issued when you sign in." : "Attributes you choose here become part of your key."}
          </p>

          <form onSubmit={submit} className="stack" style={{ gap: 12 }}>
            <AnimatePresence initial={false}>
              {mode === "register" && (
                <motion.label className="field" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} transition={spring.move}>
                  <span>Full name</span>
                  <input className="input" value={form.display_name} onChange={(e) => set("display_name")(e.target.value)} autoComplete="name" />
                </motion.label>
              )}
            </AnimatePresence>
            <label className="field">
              <span>Username</span>
              <input className="input" value={form.username} onChange={(e) => set("username")(e.target.value)} autoComplete="username" autoCapitalize="none" required />
            </label>
            <label className="field">
              <span>Password</span>
              <input className="input" type="password" value={form.password} onChange={(e) => set("password")(e.target.value)}
                autoComplete={mode === "signin" ? "current-password" : "new-password"} required minLength={mode === "register" ? 6 : undefined} />
            </label>
            <AnimatePresence initial={false}>
              {mode === "register" && (
                <motion.div className="stack" style={{ gap: 12, overflow: "hidden" }} initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} transition={spring.move}>
                  <div className="grid-2" style={{ gap: 10 }}>
                    <label className="field"><span>Role</span>
                      <select className="input" value={form.role} onChange={(e) => set("role")(e.target.value)}>
                        {["Doctor", "Nurse", "Researcher", "Pharmacist"].map((r) => <option key={r}>{r}</option>)}
                      </select>
                    </label>
                    <label className="field"><span>Department</span>
                      <select className="input" value={form.department} onChange={(e) => set("department")(e.target.value)}>
                        {["Cardiology", "Oncology", "Radiology", "Neurology", "Pharmacy"].map((d) => <option key={d}>{d}</option>)}
                      </select>
                    </label>
                  </div>
                  <div className="field"><span>Clearance</span>
                    <Segmented label="Clearance" value={form.clearance} onChange={set("clearance")} options={[1, 2, 3, 4].map((n) => ({ value: n, label: `L${n}` }))} />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <AnimatePresence>
              {error && (
                <motion.div role="alert" className="callout red" initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={spring.snappy}>
                  {error}
                </motion.div>
              )}
            </AnimatePresence>

            <button className="btn primary large" disabled={!!busy} style={{ marginTop: 4 }}>
              {busy === "form" ? <span className="spinner" /> : mode === "signin" ? "Sign in" : "Create account"}
            </button>
            <button type="button" className="btn plain" onClick={() => { setMode(mode === "signin" ? "register" : "signin"); setError(""); }}>
              {mode === "signin" ? "New here? Create an account" : "Already have an account? Sign in"}
            </button>
          </form>

          <div style={{ margin: "28px 0 8px" }} className="t-section">Demo hospital staff</div>
          <div className="group">
            {PERSONAS.map((p) => (
              <button key={p.username} className="row clickable inset-icon" disabled={!!busy} onClick={() => attempt(p.username, DEMO_PASSWORD, p.username)}>
                <Avatar name={p.name} />
                <div className="row-main">
                  <div className="row-title">{p.name}</div>
                  <div className="row-sub">{p.line}</div>
                </div>
                {busy === p.username ? <span className="spinner" style={{ color: "var(--label-3)" }} /> : <ChevronRight size={16} color="var(--label-4)" />}
              </button>
            ))}
          </div>
          <p className="t-caption" style={{ margin: "14px 4px 0", display: "flex", alignItems: "center", gap: 6 }}>
            <ArrowRight size={12} />
            {health ? `Server online · CP-ABE engine: ${health.abe_mode} · metadata: ${health.metadata_backend}` : "Connecting to server…"}
          </p>
        </div>
      </section>
    </div>
  );
}
