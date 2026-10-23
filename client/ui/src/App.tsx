import { useEffect, useState, type ComponentType } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ChartColumn, FolderLock, LayoutGrid, ScrollText, Settings as SettingsIcon, ShieldCheck, UserX } from "lucide-react";
import { useSession } from "./lib/session";
import { spring } from "./lib/motion";
import { Avatar } from "./components/ui";
import { Logo } from "./components/Logo";
import SignIn from "./pages/SignIn";
import Overview from "./pages/Overview";
import Vault from "./pages/Vault";
import Access from "./pages/Access";
import Revocation from "./pages/Revocation";
import Audit from "./pages/Audit";
import Evaluation from "./pages/Evaluation";
import Settings from "./pages/Settings";

export type Route = "overview" | "vault" | "access" | "revocation" | "audit" | "evaluation" | "settings";

const NAV: { id: Route; label: string; short: string; icon: ComponentType<{ size?: number; strokeWidth?: number }>; group: string }[] = [
  { id: "overview", label: "Overview", short: "Home", icon: LayoutGrid, group: "Workspace" },
  { id: "vault", label: "Vault", short: "Vault", icon: FolderLock, group: "Workspace" },
  { id: "access", label: "Access Policies", short: "Policies", icon: ShieldCheck, group: "Control" },
  { id: "revocation", label: "Revocation", short: "Revoke", icon: UserX, group: "Control" },
  { id: "audit", label: "Audit Trail", short: "Audit", icon: ScrollText, group: "Control" },
  { id: "evaluation", label: "Evaluation", short: "Results", icon: ChartColumn, group: "Research" },
  { id: "settings", label: "Settings", short: "Settings", icon: SettingsIcon, group: "Research" },
];

function readRoute(): Route {
  const h = location.hash.replace(/^#\/?/, "") as Route;
  return NAV.some((n) => n.id === h) ? h : "overview";
}

export default function App() {
  const { user, ready } = useSession();
  const [route, setRoute] = useState<Route>(readRoute);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onHash = () => setRoute(readRoute());
    const onScroll = () => setScrolled(window.scrollY > 8);
    window.addEventListener("hashchange", onHash);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => { window.removeEventListener("hashchange", onHash); window.removeEventListener("scroll", onScroll); };
  }, []);

  const go = (r: Route) => {
    if (r !== route) { location.hash = `/${r}`; window.scrollTo({ top: 0 }); }
  };

  if (!ready) return null;
  if (!user) return <SignIn />;

  const current = NAV.find((n) => n.id === route)!;
  const Page = { overview: Overview, vault: Vault, access: Access, revocation: Revocation, audit: Audit, evaluation: Evaluation, settings: Settings }[route];
  let lastGroup = "";

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Sections">
        <div className="brand"><Logo size={26} /><span className="brand-name">test:202</span></div>
        {NAV.map((n) => {
          const header = n.group !== lastGroup ? <div className="nav-label" key={`g-${n.group}`}>{n.group}</div> : null;
          lastGroup = n.group;
          const Icon = n.icon;
          return [
            header,
            <button key={n.id} className={`nav-item${route === n.id ? " active" : ""}`} aria-current={route === n.id ? "page" : undefined} onClick={() => go(n.id)}>
              {route === n.id && <motion.div layoutId="nav-pill" className="nav-pill" transition={spring.snappy} />}
              <Icon size={16} strokeWidth={1.9} />
              <span className="nav-long">{n.label}</span>
              <span className="nav-short">{n.short}</span>
            </button>,
          ];
        })}
        <div className="sidebar-foot">
          <button className="nav-item" onClick={() => go("settings")} style={{ padding: "8px 10px" }}>
            <Avatar name={user.display_name} size={26} />
            <span style={{ minWidth: 0 }}>
              <span style={{ display: "block", fontWeight: 600, fontSize: "0.8125rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{user.display_name}</span>
              <span style={{ display: "block", fontSize: "0.6875rem", color: "var(--label-2)", fontWeight: 400 }}>
                {user.attributes.role} · {user.attributes.department}
              </span>
            </span>
          </button>
        </div>
      </nav>

      <div className="main">
        <header className={`toolbar${scrolled ? " scrolled" : ""}`}>
          <div className="toolbar-title">{current.label}</div>
          <div className="toolbar-spacer" />
        </header>
        <AnimatePresence mode="wait" initial={false}>
          <motion.main key={route} className="page"
            initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            transition={{ opacity: { duration: 0.14 }, y: spring.move }}>
            <Page go={go} />
          </motion.main>
        </AnimatePresence>
      </div>
    </div>
  );
}
