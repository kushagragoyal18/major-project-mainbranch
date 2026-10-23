import type { Attributes, User } from "./api";
import { evaluatePolicy } from "./crypto";

/** Same normalisation as server/revocation/versioning.slug. */
export const slug = (v: unknown) => String(v).trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");

/** Plain (unversioned) tokens a user's key carries — clearance is a ladder. */
export function tokensFor(a: Attributes): string[] {
  const t = [slug(a.role), slug(a.department)];
  for (let i = 1; i <= a.clearance; i++) t.push(`level${i}`);
  return t;
}

/** Who among `users` would satisfy a human (unversioned) policy. */
export function eligible(policy: string, users: User[]): User[] {
  return users.filter((u) => u.active && evaluatePolicy(policy, tokensFor(u.attributes)));
}

export function composePolicy(department: string, clearance: number, roles: string[]): string {
  const parts = [slug(department), `level${clearance}`];
  if (roles.length === 1) parts.push(slug(roles[0]));
  if (roles.length > 1) parts.push(`(${roles.map(slug).join(" or ")})`);
  return parts.join(" and ");
}

/** Splits a policy into tokens for chip rendering. */
export function policyTokens(policy: string): { kind: "attr" | "op" | "paren"; text: string }[] {
  return (policy.match(/[a-zA-Z0-9_\-:]+|\(|\)/g) ?? []).map((t) => {
    const low = t.toLowerCase();
    if (t === "(" || t === ")") return { kind: "paren", text: t };
    if (low === "and" || low === "or") return { kind: "op", text: low };
    return { kind: "attr", text: t };
  });
}
