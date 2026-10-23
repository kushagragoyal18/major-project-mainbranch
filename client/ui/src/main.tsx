import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MotionConfig } from "motion/react";
import "@fontsource-variable/inter";
import "./styles.css";
import App from "./App";
import { SessionProvider } from "./lib/session";
import { ToastProvider } from "./components/ui";

// Apply the saved appearance before first paint to avoid a flash.
try {
  const theme = localStorage.getItem("tessera.theme");
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
} catch { /* storage unavailable — follow the system */ }

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {/* reducedMotion="user": springs become cross-fades when the OS asks for less motion. */}
    <MotionConfig reducedMotion="user">
      <SessionProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </SessionProvider>
    </MotionConfig>
  </StrictMode>,
);
