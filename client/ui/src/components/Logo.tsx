/** Four tiles of a mosaic — a tessera — with one tile lit: the one your attributes unlock. */
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden>
      <rect width="64" height="64" rx="14" fill="var(--label)" />
      <rect x="15" y="15" width="15" height="15" rx="3.5" fill="var(--bg-elevated)" />
      <rect x="34" y="15" width="15" height="15" rx="3.5" fill="var(--bg-elevated)" opacity=".5" />
      <rect x="15" y="34" width="15" height="15" rx="3.5" fill="var(--bg-elevated)" opacity=".5" />
      <rect x="34" y="34" width="15" height="15" rx="3.5" fill="#0a84ff" />
    </svg>
  );
}
