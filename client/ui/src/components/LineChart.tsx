import { useLayoutEffect, useMemo, useRef, useState } from "react";

export interface Series { name: string; color: string; points: { x: number; y: number }[] }

interface Props {
  series: Series[];
  xLog?: boolean;
  yLog?: boolean;
  height?: number;
  xFormat: (v: number) => string;
  yFormat: (v: number) => string;
  xLabel: string;
  yLabel: string;
}

const PAD = { top: 12, right: 64, bottom: 34, left: 52 };

function niceTicks(min: number, max: number, count = 4): number[] {
  const span = max - min || 1;
  const step0 = span / count;
  const mag = 10 ** Math.floor(Math.log10(step0));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => span / s <= count) ?? step0;
  const out = [];
  // Always end on the first tick at or above max, so no data rises past the top gridline.
  for (let v = Math.ceil(min / step) * step; ; v += step) {
    out.push(+v.toFixed(10));
    if (v >= max - step * 1e-9) break;
  }
  return out;
}

function logTicks(min: number, max: number): number[] {
  const lo = Math.floor(Math.log10(min));
  const hi = Math.ceil(Math.log10(max));
  // Keep at most ~5 gridlines: step by 2 or 3 decades on wide ranges.
  const step = Math.max(1, Math.ceil((hi - lo) / 5));
  const out = [];
  for (let e = lo; e <= hi; e += step) out.push(10 ** e);
  if (Math.log10(out[out.length - 1]) < hi) out.push(10 ** (out.length ? Math.log10(out[out.length - 1]) + step : hi));
  return out.length >= 2 ? out : [10 ** lo, 10 ** hi];
}

/** Nudges end-of-line labels apart so two series ending close together stay legible. */
function spreadLabels(ys: number[], gap = 12): number[] {
  const order = ys.map((y, i) => ({ y, i })).sort((a, b) => a.y - b.y);
  for (let k = 1; k < order.length; k++) {
    if (order[k].y - order[k - 1].y < gap) order[k].y = order[k - 1].y + gap;
  }
  const out = new Array(ys.length);
  order.forEach((o) => { out[o.i] = o.y; });
  return out;
}

/**
 * Small, honest line chart: one y-axis, 2px lines, ringed markers, hairline grid,
 * crosshair tooltip on hover, legend above, and a table view for screen readers.
 */
export function LineChart({ series, xLog, yLog, height = 220, xFormat, yFormat, xLabel, yLabel }: Props) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(520);
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);

  useLayoutEffect(() => {
    if (!wrap.current) return;
    const ro = new ResizeObserver(([e]) => setWidth(Math.max(280, e.contentRect.width)));
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  const xs = useMemo(() => Array.from(new Set(series.flatMap((s) => s.points.map((p) => p.x)))).sort((a, b) => a - b), [series]);
  const ys = series.flatMap((s) => s.points.map((p) => p.y)).filter((y) => !yLog || y > 0);
  const xMin = Math.min(...xs), xMax = Math.max(...xs);
  const yMinRaw = yLog ? Math.min(...ys) : 0;
  const yMaxRaw = Math.max(...ys);
  const yTicks = yLog ? logTicks(10 ** Math.floor(Math.log10(yMinRaw)), 10 ** Math.ceil(Math.log10(yMaxRaw))) : niceTicks(0, yMaxRaw);
  const yMin = yLog ? yTicks[0] : 0;
  const yMax = yLog ? yTicks[yTicks.length - 1] : yTicks[yTicks.length - 1];
  const xTicks = xLog ? xs : xs;

  const iw = width - PAD.left - PAD.right;
  const ih = height - PAD.top - PAD.bottom;
  const sx = (v: number) => PAD.left + (xLog ? (Math.log10(v) - Math.log10(xMin)) / (Math.log10(xMax) - Math.log10(xMin) || 1) : (v - xMin) / (xMax - xMin || 1)) * iw;
  const sy = (v: number) => PAD.top + ih - (yLog ? (Math.log10(Math.max(v, yMin)) - Math.log10(yMin)) / (Math.log10(yMax) - Math.log10(yMin) || 1) : (v - yMin) / (yMax - yMin || 1)) * ih;

  const ends = series.map((s) => {
    const pts = s.points.filter((p) => !yLog || p.y > 0);
    return pts[pts.length - 1];
  });
  const labelY = spreadLabels(ends.map((p) => (p ? sy(p.y) + 3.5 : 0)));

  function onMove(e: React.PointerEvent<SVGRectElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * iw + PAD.left;
    let best = 0;
    xs.forEach((x, i) => { if (Math.abs(sx(x) - px) < Math.abs(sx(xs[best]) - px)) best = i; });
    setHover(best);
  }

  const hx = hover != null ? xs[hover] : null;

  return (
    <div ref={wrap}>
      <div className="hstack" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        {series.length > 1 ? (
          <div className="legend">{series.map((s) => <span key={s.name}><i style={{ background: s.color }} />{s.name}</span>)}</div>
        ) : <span />}
        <button className="btn plain" style={{ height: 24, fontSize: "0.75rem" }} onClick={() => setTable((t) => !t)}>{table ? "Chart" : "Table"}</button>
      </div>

      {table ? (
        <div className="group" style={{ boxShadow: "none", background: "var(--bg-inset)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.75rem" }}>
            <thead><tr><th style={th}>{xLabel}</th>{series.map((s) => <th key={s.name} style={th}>{s.name}</th>)}</tr></thead>
            <tbody>{xs.map((x) => (
              <tr key={x}><td style={td}>{xFormat(x)}</td>{series.map((s) => <td key={s.name} style={td} className="tnum">{(() => { const p = s.points.find((q) => q.x === x); return p ? yFormat(p.y) : "—"; })()}</td>)}</tr>
            ))}</tbody>
          </table>
        </div>
      ) : (
        <div style={{ position: "relative" }}>
          <svg className="chart" width="100%" height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${yLabel} by ${xLabel}`}>
            <g className="grid">
              {yTicks.map((t) => <line key={t} x1={PAD.left} x2={PAD.left + iw} y1={sy(t)} y2={sy(t)} />)}
            </g>
            {yTicks.map((t) => <text key={t} x={PAD.left - 8} y={sy(t) + 3.5} textAnchor="end">{yFormat(t)}</text>)}
            {xTicks.map((t) => <text key={t} x={sx(t)} y={height - PAD.bottom + 16} textAnchor="middle">{xFormat(t)}</text>)}
            <text className="axis-label" x={PAD.left + iw / 2} y={height - 4} textAnchor="middle">{xLabel}</text>
            <text className="axis-label" transform={`translate(12 ${PAD.top + ih / 2}) rotate(-90)`} textAnchor="middle">{yLabel}</text>

            {hx != null && <line x1={sx(hx)} x2={sx(hx)} y1={PAD.top} y2={PAD.top + ih} stroke="var(--separator-strong)" strokeWidth={1} />}

            {series.map((s, si) => {
              const pts = s.points.filter((p) => !yLog || p.y > 0);
              const d = pts.map((p, i) => `${i ? "L" : "M"}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join("");
              const last = pts[pts.length - 1];
              return (
                <g key={s.name}>
                  <path d={d} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
                  {pts.map((p) => (
                    <circle key={p.x} cx={sx(p.x)} cy={sy(p.y)} r={hx === p.x ? 5 : 3.5} fill={s.color} stroke="var(--bg-grouped)" strokeWidth={2} />
                  ))}
                  {last && <text x={sx(last.x) + 8} y={labelY[si]} style={{ fill: "var(--label-2)", fontWeight: 500 }}>{yFormat(last.y)}</text>}
                </g>
              );
            })}
            <rect x={PAD.left} y={PAD.top} width={iw} height={ih} fill="transparent" onPointerMove={onMove} onPointerLeave={() => setHover(null)} />
          </svg>

          {hx != null && (
            <div className="chart-tip" style={{ left: Math.min(sx(hx) + 12, width - 170), top: PAD.top }}>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>{xFormat(hx)}</div>
              {series.map((s) => {
                const p = s.points.find((q) => q.x === hx);
                return p && (
                  <div key={s.name} className="tip-row">
                    <span><i style={{ background: s.color, marginRight: 6 }} />{s.name}</span>
                    <b className="tnum" style={{ fontWeight: 600 }}>{yFormat(p.y)}</b>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const th: React.CSSProperties = { textAlign: "left", padding: "8px 12px", fontWeight: 600, color: "var(--label-2)", borderBottom: "0.5px solid var(--separator)" };
const td: React.CSSProperties = { padding: "6px 12px", borderBottom: "0.5px solid var(--separator)" };
