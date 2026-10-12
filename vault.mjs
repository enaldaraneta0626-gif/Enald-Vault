// Nightvault sync endpoint: /api/vault
// Stores only the encrypted vault. Each vault is filed under sha256(access token); the token is
// derived on the device from username + password, so this server never sees either one.
import { getStore } from "@netlify/blobs";
import { createHash } from "node:crypto";

const MAX = 5_000_000; // ~5 MB of encrypted vault
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

export default async (req) => {
  const url = new URL(req.url);
  if (url.searchParams.has("ping")) return json({ ok: "nightvault" });

  const token = req.headers.get("x-vault-token") || "";
  if (!/^[a-f0-9]{64}$/.test(token)) return json({ error: "bad_token" }, 400);
  const id = createHash("sha256").update(token).digest("hex");
  const store = getStore({ name: "nightvault", consistency: "strong" });

  if (req.method === "GET") {
    const meta = await store.get(`${id}/meta`, { type: "json" });
    if (!meta) return json({ error: "not_found" }, 404);
    if (url.searchParams.has("meta")) return json(meta);
    const blob = meta.off ? null : await store.get(`${id}/blob`, { type: "text" });
    return json({ ...meta, blob });
  }

  if (req.method === "PUT") {
    if (Number(req.headers.get("content-length") || 0) > MAX + 2000) return json({ error: "too_large" }, 413);
    let body;
    try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
    const at = Number(body.at) || Date.now();
    const dev = String(body.dev || "").slice(0, 40);
    if (body.moved) {
      // The password changed, so the vault now lives under a new token. Leave a marker so
      // devices still using the old password know to sign in again instead of re-uploading.
      await store.delete(`${id}/blob`);
      await store.setJSON(`${id}/meta`, { moved: true, at, dev, rev: 0 });
      return json({ ok: true, moved: true, at });
    }
    if (body.off) {
      await store.delete(`${id}/blob`);
      await store.setJSON(`${id}/meta`, { off: true, at, dev, rev: 0 });
      return json({ ok: true, off: true, at });
    }
    if (typeof body.blob !== "string" || body.blob.length > MAX || !Number.isFinite(body.rev)) return json({ error: "bad_body" }, 400);
    // Refuse anything that isn't an encrypted Nightvault blob.
    try { const b = JSON.parse(body.blob); if (!b.iv || !b.ct) throw new Error(); } catch { return json({ error: "not_encrypted" }, 400); }
    await store.set(`${id}/blob`, body.blob);
    const meta = { rev: body.rev, at, dev, size: body.blob.length };
    await store.setJSON(`${id}/meta`, meta);
    return json(meta);
  }

  if (req.method === "DELETE") {
    await store.delete(`${id}/blob`);
    await store.delete(`${id}/meta`);
    return new Response(null, { status: 204 });
  }

  return json({ error: "method_not_allowed" }, 405);
};

export const config = { path: "/api/vault" };
