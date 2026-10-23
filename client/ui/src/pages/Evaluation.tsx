import { useCallback, useEffect, useState } from "react";
import { motion } from "motion/react";
import { Play } from "lucide-react";
import { api } from "../lib/api";
import { aesEncrypt, randomBytes } from "../lib/crypto";
import { bytes, compact, ms } from "../lib/format";
import { spring } from "../lib/motion";
import { PageHead } from "../components/ui";
import { LineChart } from "../components/LineChart";
import type { Route } from "../App";

interface Bench {
  engine: string;
  aes: { size_kb: number; encrypt_ms: number; decrypt_ms: number; throughput_mb_s: number }[];
  cpabe: { attributes: number; wrap_ms: number; server_transform_ms: number; client_decrypt_ms: number }[];
  rsa: { wrap_ms: number; unwrap_ms: number; sign_ms: number };
  end_to_end: { size_kb: number; upload_prepare_ms: number }[];
  revocation: { file_mb: number; files: number; full_reencrypt_bytes: number; lazy_rewrap_bytes: number; full_reencrypt_s: number; lazy_rewrap_s: number; reduction_x: number }[];
}

/** AES-GCM in this browser via WebCrypto, same sizes as the server sweep. */
async function browserAes(sizesKb: number[]) {
  const key = randomBytes(32);
  const out = [];
  for (const kb of sizesKb) {
    const data = randomBytes(Math.min(kb * 1024, 65536));
    const full = new Uint8Array(kb * 1024);
    for (let i = 0; i < full.length; i += data.length) full.set(data.subarray(0, Math.min(data.length, full.length - i)), i);
    await aesEncrypt(key, full); // warm-up
    const samples = [];
    for (let r = 0; r < 3; r++) {
      const t0 = performance.now();
      await aesEncrypt(key, full);
      samples.push(performance.now() - t0);
    }
    samples.sort((a, b) => a - b);
    out.push({ x: kb, y: Math.max(samples[1], 0.005) });
  }
  return out;
}

/** Decimal byte units for log axes, so decades land on round labels (1 MB, 10 GB…). */
const decBytes = (v: number) => {
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${v >= 100 ? Math.round(v) : +v.toPrecision(2)} ${units[i]}`;
};

const kb = (v: number) => (v >= 1024 ? `${v / 1024} MB` : `${v} KB`);

export default function Evaluation(_: { go: (r: Route) => void }) {
  const [data, setData] = useState<Bench | null>(null);
  const [browser, setBrowser] = useState<{ x: number; y: number }[]>([]);
  const [running, setRunning] = useState(false);

  const run = useCallback(async () => {
    setRunning(true);
    try {
      const b = await api<Bench>("/bench");
      setData(b);
      setBrowser(await browserAes(b.aes.map((r) => r.size_kb)));
    } finally {
      setRunning(false);
    }
  }, []);
  useEffect(() => { run(); }, [run]);

  const ten = data?.revocation.find((r) => r.file_mb === 10);

  return (
    <>
      <PageHead title="Evaluation" actions={<button className="btn primary" onClick={run} disabled={running}>{running ? <span className="spinner" /> : <Play size={13} fill="currentColor" />} Run again</button>}>
        Measured live on this machine. The server sweep uses Python's <span className="mono">cryptography</span> library and the {data?.engine ?? "…"} CP-ABE engine; the browser line is WebCrypto in this tab.
      </PageHead>

      {ten && (
        <motion.div className="card" style={{ marginBottom: 16, padding: "22px 24px" }} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring.move}>
          <div className="grid-3" style={{ alignItems: "end" }}>
            <div className="stat">
              <div className="stat-value" style={{ fontSize: "2.75rem" }}>{compact(ten.reduction_x)}×</div>
              <div className="stat-label">less data re-processed when revoking an attribute that guards 1,000 files of 10 MB</div>
            </div>
            <div className="stat">
              <div className="stat-value">{bytes(ten.lazy_rewrap_bytes)}</div>
              <div className="stat-label">Lazy re-wrap · 32-byte keys only · {ten.lazy_rewrap_s < 1 ? ms(ten.lazy_rewrap_s * 1000) : `${ten.lazy_rewrap_s} s`}</div>
            </div>
            <div className="stat">
              <div className="stat-value">{bytes(ten.full_reencrypt_bytes)}</div>
              <div className="stat-label">Re-encrypting every file · ≥ {ten.full_reencrypt_s.toFixed(1)} s of AES alone</div>
            </div>
          </div>
        </motion.div>
      )}

      {data ? (
        <div className="grid-2" style={{ alignItems: "start" }}>
          <div className="card">
            <h3 className="t-headline">File encryption · AES-256-GCM</h3>
            <p className="t-caption" style={{ margin: "2px 0 12px" }}>Latency grows linearly with size; both runtimes use hardware AES.</p>
            <LineChart xLog yLog xLabel="File size" yLabel="Latency" xFormat={kb} yFormat={ms}
              series={[
                { name: "Server · Python", color: "var(--series-1)", points: data.aes.map((r) => ({ x: r.size_kb, y: Math.max(r.encrypt_ms, 0.005) })) },
                ...(browser.length ? [{ name: "This browser · WebCrypto", color: "var(--series-2)", points: browser }] : []),
              ]} />
          </div>

          <div className="card">
            <h3 className="t-headline">Key wrapping vs. policy size · CP-ABE</h3>
            <p className="t-caption" style={{ margin: "2px 0 12px" }}>With outsourcing, the client's share stays flat as policies grow.</p>
            <LineChart xLabel="Attributes in policy" yLabel="Latency" xFormat={(v) => String(v)} yFormat={ms}
              series={[
                { name: "Wrap", color: "var(--series-1)", points: data.cpabe.map((r) => ({ x: r.attributes, y: r.wrap_ms })) },
                { name: "Server transform", color: "var(--series-2)", points: data.cpabe.map((r) => ({ x: r.attributes, y: r.server_transform_ms })) },
                { name: "Client decrypt", color: "var(--series-3)", points: data.cpabe.map((r) => ({ x: r.attributes, y: r.client_decrypt_ms })) },
              ]} />
          </div>

          <div className="card">
            <h3 className="t-headline">Revocation cost · 1,000 files</h3>
            <p className="t-caption" style={{ margin: "2px 0 12px" }}>Bytes that must be re-processed after one attribute is revoked.</p>
            <LineChart xLog yLog xLabel="Average file size" yLabel="Bytes" xFormat={(v) => (v < 1 ? `${v * 1000} KB` : v >= 1000 ? `${v / 1000} GB` : `${v} MB`)} yFormat={decBytes}
              series={[
                { name: "Re-encrypt every file", color: "var(--series-2)", points: data.revocation.map((r) => ({ x: r.file_mb, y: r.full_reencrypt_bytes })) },
                { name: "Lazy key re-wrap", color: "var(--series-1)", points: data.revocation.map((r) => ({ x: r.file_mb, y: r.lazy_rewrap_bytes })) },
              ]} />
          </div>

          <div className="card">
            <h3 className="t-headline">Per-file overheads</h3>
            <p className="t-caption" style={{ margin: "2px 0 12px" }}>Median of repeated runs on the server.</p>
            <div className="group" style={{ boxShadow: "none", background: "var(--bg-inset)" }}>
              <div className="row"><span className="row-main">RSA-OAEP wrap of the 32-byte key</span><span className="tnum">{ms(data.rsa.wrap_ms)}</span></div>
              <div className="row"><span className="row-main">RSA-OAEP unwrap</span><span className="tnum">{ms(data.rsa.unwrap_ms)}</span></div>
              <div className="row"><span className="row-main">RSA-PSS signature</span><span className="tnum">{ms(data.rsa.sign_ms)}</span></div>
              {data.end_to_end.map((r) => (
                <div key={r.size_kb} className="row"><span className="row-main">Full upload envelope · {kb(r.size_kb)}</span><span className="tnum">{ms(r.upload_prepare_ms)}</span></div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="card" style={{ display: "grid", placeItems: "center", padding: 60, color: "var(--label-3)" }}>
          <span className="spinner" />
          <div className="t-caption" style={{ marginTop: 10 }}>Running benchmarks…</div>
        </div>
      )}
    </>
  );
}
