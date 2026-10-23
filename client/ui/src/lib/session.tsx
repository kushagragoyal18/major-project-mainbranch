import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, setToken, type Health, type LoginResult, type User } from "./api";
import * as C from "./crypto";
import { resetPkCache } from "./pipeline";

interface Session {
  user: User | null;
  sk: C.AbeKey | null;
  device: C.DeviceKey | null;
  health: Health | null;
  isAdmin: boolean;
  ready: boolean;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => void;
  refresh: () => Promise<C.AbeKey>;
  rotateDeviceKey: () => Promise<void>;
}

const Ctx = createContext<Session>(null as unknown as Session);
export const useSession = () => useContext(Ctx);

const STORE = "tessera.session";

/** Makes sure this browser holds a device key and that the server knows its public half. */
async function ensureDeviceKey(user: User, rotate = false): Promise<C.DeviceKey> {
  let key = rotate ? null : await C.loadDeviceKey(user.username);
  if (!key) {
    key = await C.generateDeviceKey();
    await C.saveDeviceKey(user.username, key);
  }
  if (user.pub_key_pem !== key.publicPem) {
    await api("/me/device-key", { method: "PUT", body: { pub_key_pem: key.publicPem } });
  }
  return key;
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [sk, setSk] = useState<C.AbeKey | null>(null);
  const [device, setDevice] = useState<C.DeviceKey | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [ready, setReady] = useState(false);

  const signOut = useCallback(() => {
    sessionStorage.removeItem(STORE);
    setToken(null);
    setUser(null);
    setSk(null);
    setDevice(null);
  }, []);

  const refresh = useCallback(async () => {
    // Re-issues the CP-ABE key so attribute version bumps (revocation) take effect.
    const me = await api<{ user: User; abe_sk: C.AbeKey }>("/me");
    setUser(me.user);
    setSk(me.abe_sk);
    const saved = JSON.parse(sessionStorage.getItem(STORE) ?? "{}");
    sessionStorage.setItem(STORE, JSON.stringify({ ...saved, user: me.user }));
    return me.abe_sk;
  }, []);

  useEffect(() => {
    api<Health>("/health").then(setHealth).catch(() => setHealth(null));
    const saved = sessionStorage.getItem(STORE);
    if (!saved) { setReady(true); return; }
    const { token } = JSON.parse(saved);
    setToken(token);
    api<{ user: User; abe_sk: C.AbeKey }>("/me")
      .then(async (me) => {
        setUser(me.user);
        setSk(me.abe_sk);
        setDevice(await ensureDeviceKey(me.user).catch(() => null));
      })
      .catch(() => signOut())
      .finally(() => setReady(true));
  }, [signOut]);

  const signIn = useCallback(async (username: string, password: string) => {
    const res = await api<LoginResult>("/login", { body: { username, password } });
    setToken(res.token);
    sessionStorage.setItem(STORE, JSON.stringify({ token: res.token, user: res.user }));
    resetPkCache();
    const key = await ensureDeviceKey(res.user).catch(() => null);
    setSk(res.abe_sk);
    setDevice(key);
    setUser({ ...res.user, pub_key_pem: key?.publicPem ?? res.user.pub_key_pem });
  }, []);

  const rotateDeviceKey = useCallback(async () => {
    if (!user) return;
    const key = await ensureDeviceKey(user, true);
    setDevice(key);
    setUser({ ...user, pub_key_pem: key.publicPem });
  }, [user]);

  const isAdmin = (user?.attributes.role ?? "").toLowerCase() === "admin";

  return (
    <Ctx.Provider value={{ user, sk, device, health, isAdmin, ready, signIn, signOut, refresh, rotateDeviceKey }}>
      {children}
    </Ctx.Provider>
  );
}
