import { policyTokens } from "../lib/policy";
import { prettyToken } from "../lib/format";

/** Renders "cardiology_v2 and (doctor or nurse)" as readable chips with quiet operators. */
export function PolicyChips({ policy, raw }: { policy: string; raw?: boolean }) {
  return (
    <span className="hstack wrap" style={{ gap: 4 }}>
      {policyTokens(policy).map((t, i) =>
        t.kind === "attr" ? (
          <span key={i} className={`chip${raw ? " mono" : ""}`} style={{ color: "var(--label)" }}>{raw ? t.text : prettyToken(t.text)}</span>
        ) : (
          <span key={i} style={{ fontSize: "0.75rem", color: "var(--label-3)", fontWeight: t.kind === "op" ? 500 : 400 }}>{t.text}</span>
        ),
      )}
    </span>
  );
}
