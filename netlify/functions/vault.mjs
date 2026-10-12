// Nightvault sync endpoint: /api/vault
// Stores only the encrypted vault. Each vault is filed under sha256(access token); the token is
// derived on the device from username + password, so this server never sees either one.
import { getStore } from "@netlify/blobs";
import { createHash } from "node:crypto";

const MAX = 3_000_000;            // largest encrypted vault accepted (~3 MB)
const MIN_GAP_MS = 1000;          // one write per vault per second at most
const NEW_VAULTS_PER_IP_DAY = 5;  // new vaults one network address can create per day

const sha = (s) => createHash("sha256").update(s).digest("hex");
const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...extra } });
const b64 = (s) => typeof s === "string" && s.length > 0 && s.length < MAX && /^[A-Za-z0-9+/]+=*$/.test(s);

// Accept only something shaped like an encrypted Nightvault blob.
function looksEncrypted(raw) {
  let b;
  try { b = JSON.parse(raw); } catch { return false; }
  if (!b || typeof b !== "object" || !b64(b.iv) || !b64(b.ct)) return false;
  if (b.v === 2) return !!(b.pw && b64(b.pw.salt) && b64(b.pw.iv) && b64(b.pw.ct));
  return b64(b.salt);
}

export default async (req, context) => {
  const url = new URL(req.url);
  if (url.searchParams.has("ping")) return json({ ok: "nightvault" });
  if (!["GET", "PUT", "DELETE"].includes(req.method)) return json({ error: "method_not_allowed" }, 405);

  const token = req.headers.get("x-vault-token") || "";
  if (!/^[a-f0-9]{64}$/.test(token)) return json({ error: "bad_token" }, 400);
  const id = sha(token);
  const store = getStore({ name: "nightvault", consistency: "strong" });
  const meta = await store.get(`${id}/meta`, { type: "json" });

  if (req.method === "GET") {
    if (!meta) return json({ error: "not_found" }, 404);
    if (url.searchParams.has("meta")) return json(meta);
    const blob = meta.off || meta.moved ? null : await store.get(`${id}/blob`, { type: "text" });
    return json({ ...meta, blob });
  }

  if (req.method === "DELETE") {
    if (!meta) return new Response(null, { status: 204 });
    await store.delete(`${id}/blob`);
    await store.delete(`${id}/meta`);
    return new Response(null, { status: 204 });
  }

  // PUT
  if (Number(req.headers.get("content-length") || 0) > MAX + 4000) return json({ error: "too_large" }, 413);
  const now = Date.now();
  if (meta && meta.serverAt && now - meta.serverAt < MIN_GAP_MS) return json({ error: "slow_down" }, 429, { "retry-after": "2" });

  let body;
  try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
  const at = Number(body.at) || now;
  const dev = String(body.dev || "").slice(0, 40);

  if (body.moved || body.off) {
    if (!meta) return json({ error: "not_found" }, 404);   // markers only replace an existing vault
    await store.delete(`${id}/blob`);
    const m = { [body.moved ? "moved" : "off"]: true, at, dev, rev: 0, serverAt: now };
    await store.setJSON(`${id}/meta`, m);
    return json(m);
  }

  if (typeof body.blob !== "string" || body.blob.length > MAX || !Number.isFinite(body.rev)) return json({ error: "bad_body" }, 400);
  if (!looksEncrypted(body.blob)) return json({ error: "not_encrypted" }, 400);

  // Limit how many brand-new vaults one network address can create per day.
  if (!meta) {
    const ip = (context && context.ip) || req.headers.get("x-nf-client-connection-ip") || "unknown";
    const key = `limits/${sha(ip)}/${new Date(now).toISOString().slice(0, 10)}`;
    const n = Number(await store.get(key, { type: "text" })) || 0;
    if (n >= NEW_VAULTS_PER_IP_DAY) return json({ error: "too_many_new_vaults" }, 429);
    await store.set(key, String(n + 1));
  }

  await store.set(`${id}/blob`, body.blob);
  const m = { rev: body.rev, at, dev, size: body.blob.length, serverAt: now };
  await store.setJSON(`${id}/meta`, m);
  return json(m);
};

export const config = {
  path: "/api/vault",
  // Netlify's built-in limiter: at most 120 requests a minute from one visitor.
  rateLimit: { windowLimit: 120, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
