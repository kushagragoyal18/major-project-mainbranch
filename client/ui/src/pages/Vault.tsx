import { useCallback, useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { FolderLock, Plus, Search } from "lucide-react";
import { api, type FileItem } from "../lib/api";
import { bytes, relTime } from "../lib/format";
import { spring } from "../lib/motion";
import { Empty, FileGlyph, PageHead, Segmented, rowMotion } from "../components/ui";
import { UploadSheet } from "../components/UploadSheet";
import { FileSheet } from "../components/FileSheet";
import type { Route } from "../App";

type Filter = "all" | "open" | "restricted";

export function StatusChip({ f }: { f: FileItem }) {
  if (f.stale) return <span className="chip orange">Re-wrap pending</span>;
  return f.decision?.decision === "Permit" ? <span className="chip green">Can open</span> : <span className="chip">Restricted</span>;
}

export default function Vault(_: { go: (r: Route) => void }) {
  const [files, setFiles] = useState<FileItem[] | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [upload, setUpload] = useState(false);
  const [selected, setSelected] = useState<FileItem | null>(null);

  const load = useCallback(() => api<FileItem[]>("/files").then(setFiles).catch(() => setFiles([])), []);
  useEffect(() => { load(); }, [load]);

  const shown = useMemo(() => (files ?? []).filter((f) => {
    if (filter === "open" && f.decision?.decision !== "Permit") return false;
    if (filter === "restricted" && f.decision?.decision === "Permit") return false;
    const q = query.trim().toLowerCase();
    return !q || f.filename.toLowerCase().includes(q) || f.owner.includes(q) || f.policy_display.toLowerCase().includes(q);
  }), [files, query, filter]);

  const counts = useMemo(() => ({
    open: (files ?? []).filter((f) => f.decision?.decision === "Permit").length,
    total: files?.length ?? 0,
  }), [files]);

  return (
    <>
      <PageHead title="Vault" actions={<button className="btn primary" onClick={() => setUpload(true)}><Plus size={15} strokeWidth={2.2} /> Upload</button>}>
        Every file here is ciphertext. The server stores it, but only people whose attributes satisfy its policy can turn it back into a document.
      </PageHead>

      <div className="hstack wrap" style={{ justifyContent: "space-between", marginBottom: 14, gap: 12 }}>
        <div style={{ position: "relative", flex: "1 1 260px", maxWidth: 360 }}>
          <Search size={14} color="var(--label-3)" style={{ position: "absolute", left: 10, top: 10 }} />
          <input className="input" style={{ paddingLeft: 30 }} placeholder="Search files, people, attributes" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search files" />
        </div>
        <Segmented label="Filter" value={filter} onChange={setFilter} options={[
          { value: "all", label: `All ${counts.total}` },
          { value: "open", label: `Can open ${counts.open}` },
          { value: "restricted", label: `Restricted ${counts.total - counts.open}` },
        ]} />
      </div>

      <div className="group">
        {files === null ? (
          <div style={{ padding: 40, display: "grid", placeItems: "center", color: "var(--label-3)" }}><span className="spinner" /></div>
        ) : shown.length === 0 ? (
          <Empty icon={<FolderLock size={34} strokeWidth={1.5} />} title={files.length ? "No matching files" : "The vault is empty"}>
            {files.length ? "Try a different search or filter." : "Upload a file to encrypt it under an access policy."}
          </Empty>
        ) : (
          <AnimatePresence initial={false}>
            {shown.map((f, i) => (
              <motion.button key={f.file_id} className="row clickable" onClick={() => setSelected(f)} layout="position"
                {...rowMotion(i)} exit={{ opacity: 0 }} transition={{ ...spring.item, delay: Math.min(i, 10) * 0.02 }}>
                <FileGlyph name={f.filename} locked={f.decision?.decision !== "Permit"} />
                <div className="row-main">
                  <div className="row-title">{f.filename}</div>
                  <div className="row-sub">{f.policy_display} · {f.owner} · {relTime(f.uploaded_at)}</div>
                </div>
                <span className="t-caption tnum hide-sm" style={{ width: 70, textAlign: "right" }}>{bytes(f.plain_size ?? f.size_bytes)}</span>
                <StatusChip f={f} />
              </motion.button>
            ))}
          </AnimatePresence>
        )}
      </div>

      <UploadSheet open={upload} onClose={() => setUpload(false)} onDone={load} />
      <FileSheet file={selected} onClose={() => setSelected(null)} onChanged={load} />
    </>
  );
}
