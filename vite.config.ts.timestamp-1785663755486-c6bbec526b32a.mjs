// vite.config.ts
import { defineConfig, loadEnv } from "file:///home/project/node_modules/vite/dist/node/index.js";

// src/api/server.ts
import express from "file:///home/project/node_modules/express/index.js";
import cookieParser from "file:///home/project/node_modules/cookie-parser/index.js";
import multer from "file:///home/project/node_modules/multer/index.js";

// src/api/db.ts
import { createClient } from "file:///home/project/node_modules/@supabase/supabase-js/dist/index.mjs";
function readEnv() {
  const url = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
  const anonKey = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY;
  return { url, anonKey };
}
var _client = null;
function getDb() {
  if (_client) return _client;
  const { url, anonKey } = readEnv();
  if (!url || !anonKey) {
    throw new Error("Supabase env vars missing \u2014 set SUPABASE_URL / SUPABASE_ANON_KEY");
  }
  _client = createClient(url, anonKey, {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  return _client;
}
var db = new Proxy({}, {
  get(_t, prop) {
    const client = getDb();
    const value = client[prop];
    return typeof value === "function" ? value.bind(client) : value;
  }
});

// src/api/auth.ts
import bcrypt from "file:///home/project/node_modules/bcryptjs/index.js";
var COOKIE = "kc_session";
var SESSION_DAYS = 7;
async function createSession(res, userId) {
  const token = await bcrypt.genSalt(32).then((s) => s.replace(/\//g, "x"));
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
  const { error } = await db.from("sessions").insert({ token, user_id: userId, expires_at: expiresAt });
  if (error) throw error;
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: SESSION_DAYS * 864e5,
    path: "/"
  });
}
async function destroySession(req, res) {
  const token = req.cookies?.[COOKIE];
  if (token) {
    await db.from("sessions").delete().eq("token", token);
  }
  res.clearCookie(COOKIE, { path: "/" });
}
async function currentUser(req) {
  const token = req.cookies?.[COOKIE];
  if (!token) return null;
  const { data } = await db.from("sessions").select("*, user:users(*)").eq("token", token).maybeSingle();
  if (!data) return null;
  if (new Date(data.expires_at).getTime() < Date.now()) {
    await db.from("sessions").delete().eq("token", token);
    return null;
  }
  return data.user ?? null;
}
function requireAuth(req, res, next) {
  (async () => {
    const user = await currentUser(req);
    if (!user) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    req.user = user;
    next();
  })().catch((e) => {
    console.error("requireAuth error", e);
    res.status(500).json({ error: "server_error" });
  });
}
function requireRole(...roles) {
  return (req, res, next) => {
    (async () => {
      const user = await currentUser(req);
      if (!user) {
        res.status(401).json({ error: "unauthorized" });
        return;
      }
      if (!roles.includes(user.role)) {
        res.status(403).json({ error: "forbidden" });
        return;
      }
      req.user = user;
      next();
    })().catch((e) => {
      console.error("requireRole error", e);
      res.status(500).json({ error: "server_error" });
    });
  };
}
async function verifyPin(user, pin) {
  try {
    return await bcrypt.compare(pin, user.pin_hash);
  } catch {
    return false;
  }
}
async function hashPin(pin) {
  return bcrypt.hash(pin, 10);
}

// src/api/server.ts
function createApiRouter() {
  const api = express.Router();
  api.use(express.json({ limit: "1mb" }));
  api.use(cookieParser());
  const uploadMiddleware = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
  const OTP_TTL_MINUTES = 10;
  const OTP_COOLDOWN_SEC = 30;
  function generateOtp() {
    return String(Math.floor(1e3 + Math.random() * 9e3));
  }
  function isValidNepalPhone(phone) {
    const p = phone.replace(/[\s-]/g, "");
    return /^9\d{9}$/.test(p);
  }
  async function sendOtp(phone, purpose) {
    await db.from("otp_codes").update({ used: true }).eq("phone", phone).eq("purpose", purpose).eq("used", false);
    const code = generateOtp();
    const expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 6e4).toISOString();
    const { error } = await db.from("otp_codes").insert({ phone, code, purpose, expires_at: expiresAt });
    if (error) throw error;
    return { code, cooldown: OTP_COOLDOWN_SEC };
  }
  async function verifyOtp(phone, code, purpose) {
    const { data } = await db.from("otp_codes").select("*").eq("phone", phone).eq("purpose", purpose).eq("used", false).order("created_at", { ascending: false }).limit(1).maybeSingle();
    if (!data) return false;
    if (new Date(data.expires_at).getTime() < Date.now()) return false;
    if (data.code !== code) return false;
    await db.from("otp_codes").update({ used: true }).eq("id", data.id);
    return true;
  }
  api.post("/auth/send-otp", async (req, res) => {
    try {
      const { phone, purpose } = req.body || {};
      if (!phone || !purpose) return res.status(400).json({ error: "missing_fields" });
      if (!["register", "reset_pin"].includes(purpose)) return res.status(400).json({ error: "invalid_purpose" });
      if (!isValidNepalPhone(phone)) return res.status(400).json({ error: "invalid_phone" });
      if (purpose === "register") {
        const { data: existing } = await db.from("users").select("id").eq("phone", phone).maybeSingle();
        if (existing) return res.status(409).json({ error: "exists" });
      }
      if (purpose === "reset_pin") {
        const { data: existing } = await db.from("users").select("id").eq("phone", phone).maybeSingle();
        if (!existing) return res.status(404).json({ error: "not_found" });
      }
      const { data: recent } = await db.from("otp_codes").select("created_at").eq("phone", phone).eq("purpose", purpose).order("created_at", { ascending: false }).limit(1).maybeSingle();
      if (recent) {
        const elapsed = (Date.now() - new Date(recent.created_at).getTime()) / 1e3;
        if (elapsed < OTP_COOLDOWN_SEC) {
          return res.status(429).json({ error: "cooldown", retry_after: Math.ceil(OTP_COOLDOWN_SEC - elapsed) });
        }
      }
      const { code, cooldown } = await sendOtp(phone, purpose);
      return res.json({ ok: true, cooldown, demo_code: code });
    } catch (e) {
      console.error("send-otp error", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/auth/verify-otp", async (req, res) => {
    try {
      const { phone, code, purpose } = req.body || {};
      if (!phone || !code || !purpose) return res.status(400).json({ error: "missing_fields" });
      const ok = await verifyOtp(phone, String(code), purpose);
      if (!ok) return res.status(400).json({ error: "invalid_otp" });
      return res.json({ ok: true, verified: true });
    } catch (e) {
      console.error("verify-otp error", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/auth/register", async (req, res) => {
    try {
      const { full_name, phone, pin, confirm_pin, role, business_name, otp_code } = req.body || {};
      if (!full_name || !phone || !pin || !role) {
        return res.status(400).json({ error: "missing_fields" });
      }
      if (!isValidNepalPhone(phone)) return res.status(400).json({ error: "invalid_phone" });
      if (!["farmer", "wholesaler"].includes(role)) {
        return res.status(400).json({ error: "invalid_role" });
      }
      if (!/^\d{4}$/.test(String(pin))) {
        return res.status(400).json({ error: "invalid_pin" });
      }
      if (confirm_pin !== void 0 && String(confirm_pin) !== String(pin)) {
        return res.status(400).json({ error: "pin_mismatch" });
      }
      if (role === "wholesaler" && !business_name) {
        return res.status(400).json({ error: "missing_business_name" });
      }
      if (!otp_code) return res.status(400).json({ error: "otp_required" });
      const otpOk = await verifyOtp(phone, String(otp_code), "register");
      if (!otpOk) return res.status(400).json({ error: "invalid_otp" });
      const { data: existing } = await db.from("users").select("id").eq("phone", phone).maybeSingle();
      if (existing) return res.status(409).json({ error: "exists" });
      const pin_hash = await hashPin(String(pin));
      const { data, error } = await db.from("users").insert({
        full_name,
        phone,
        pin_hash,
        role,
        phone_verified: true,
        business_name: role === "wholesaler" ? business_name : null,
        status: "active"
      }).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      await createSession(res, data.id);
      return res.json({ user: sanitize(data) });
    } catch (e) {
      console.error("register error", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/auth/login", async (req, res) => {
    try {
      const { phone, pin } = req.body || {};
      if (!phone || !pin) return res.status(400).json({ error: "missing_fields" });
      const { data: user } = await db.from("users").select("*").eq("phone", phone).maybeSingle();
      if (!user) return res.status(401).json({ error: "invalid_creds" });
      const ok = await verifyPin(user, String(pin));
      if (!ok) return res.status(401).json({ error: "invalid_creds" });
      if (user.status !== "active") return res.status(403).json({ error: "suspended" });
      if (!user.phone_verified) return res.status(401).json({ error: "invalid_creds" });
      await createSession(res, user.id);
      return res.json({ user: sanitize(user) });
    } catch (e) {
      console.error("login error", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/auth/reset-pin", async (req, res) => {
    try {
      const { phone, otp_code, new_pin, confirm_pin } = req.body || {};
      if (!phone || !otp_code || !new_pin) return res.status(400).json({ error: "missing_fields" });
      if (!/^\d{4}$/.test(String(new_pin))) return res.status(400).json({ error: "invalid_pin" });
      if (confirm_pin !== void 0 && String(confirm_pin) !== String(new_pin)) {
        return res.status(400).json({ error: "pin_mismatch" });
      }
      const otpOk = await verifyOtp(phone, String(otp_code), "reset_pin");
      if (!otpOk) return res.status(400).json({ error: "invalid_otp" });
      const { data: user } = await db.from("users").select("id").eq("phone", phone).maybeSingle();
      if (!user) return res.status(404).json({ error: "not_found" });
      const pin_hash = await hashPin(String(new_pin));
      const { error } = await db.from("users").update({ pin_hash, phone_verified: true }).eq("id", user.id);
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ ok: true });
    } catch (e) {
      console.error("reset-pin error", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/auth/logout", async (req, res) => {
    try {
      await destroySession(req, res);
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/auth/me", async (req, res) => {
    const user = await currentUser(req);
    if (!user) return res.status(200).json({ user: null });
    return res.json({ user: sanitize(user) });
  });
  api.get("/crops", async (req, res) => {
    try {
      const status = req.query.status || "approved";
      let q = db.from("crops").select("*, farmer:users!crops_farmer_id_fkey(*), images:crop_images(*)").order("created_at", { ascending: false });
      if (status === "approved") q = q.eq("status", "approved");
      else if (status === "mine") {
      } else {
        q = q.eq("status", status);
      }
      const { data, error } = await q;
      if (error) return res.status(500).json({ error: "server_error" });
      let rows = data ?? [];
      if (status === "mine") {
        const me = await currentUser(req);
        if (!me) return res.status(401).json({ error: "unauthorized" });
        rows = rows.filter((c) => c.farmer_id === me.id);
      }
      return res.json({ crops: rows.map((c) => ({ ...sanitizeCrop(c), images: (c.images || []).sort((a, b) => a.sort_order - b.sort_order) })) });
    } catch (e) {
      console.error("GET /crops", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  const CROP_MAX_IMAGES = 5;
  const CROP_MAX_IMAGE_SIZE = 5 * 1024 * 1024;
  const CROP_ALLOWED_TYPES = ["image/jpeg", "image/png", "image/webp"];
  const CROP_BUCKET = "crop-images";
  async function uploadCropImages(cropId, files) {
    if (!files.length) return [];
    const rows = [];
    const { data: existing } = await db.from("crop_images").select("sort_order").eq("crop_id", cropId);
    let nextOrder = existing && existing.length ? Math.max(...existing.map((i) => i.sort_order)) + 1 : 0;
    for (const file of files) {
      const ext = file.originalname.split(".").pop()?.toLowerCase() || "jpg";
      const filePath = `${cropId}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
      const { error: upErr } = await db.storage.from(CROP_BUCKET).upload(filePath, file.buffer, { contentType: file.mimetype, upsert: false });
      if (upErr) {
        console.error("crop image upload", upErr);
        continue;
      }
      const { data: pub } = db.storage.from(CROP_BUCKET).getPublicUrl(filePath);
      const { data: imgRow } = await db.from("crop_images").insert({ crop_id: cropId, image_url: pub.publicUrl, sort_order: nextOrder }).select("*").single();
      if (imgRow) rows.push(imgRow);
      nextOrder++;
    }
    return rows;
  }
  async function deleteCropStorageFile(publicUrl) {
    try {
      const url = new URL(publicUrl);
      const parts = url.pathname.split(`/storage/v1/object/public/${CROP_BUCKET}/`);
      if (parts.length < 2) return;
      await db.storage.from(CROP_BUCKET).remove([decodeURIComponent(parts[1])]);
    } catch (e) {
      console.error("deleteCropStorageFile", e);
    }
  }
  api.get("/crops/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { data, error } = await db.from("crops").select("*, farmer:users!crops_farmer_id_fkey(*), images:crop_images(*)").eq("id", id).maybeSingle();
      if (error) return res.status(500).json({ error: "server_error" });
      if (!data) return res.status(404).json({ error: "not_found" });
      const c = data;
      c.images = (c.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ crop: { ...sanitizeCrop(c), images: c.images } });
    } catch (e) {
      console.error("GET /crops/:id", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/crops", requireRole("farmer"), uploadMiddleware.any(), async (req, res) => {
    try {
      const me = req.user;
      const body = req.body || {};
      const files = req.files ?? [];
      const { name, category, price, quantity_available, unit, location, harvest_date, description } = body;
      if (!name || price == null || quantity_available == null) {
        return res.status(400).json({ error: "missing_fields" });
      }
      if (files.length > CROP_MAX_IMAGES) return res.status(400).json({ error: "too_many_images" });
      for (const f of files) {
        if (!CROP_ALLOWED_TYPES.includes(f.mimetype)) return res.status(400).json({ error: "invalid_image_type" });
        if (f.size > CROP_MAX_IMAGE_SIZE) return res.status(400).json({ error: "image_too_large" });
      }
      const { data, error } = await db.from("crops").insert({
        farmer_id: me.id,
        name,
        category: category || null,
        price: Number(price),
        quantity_available: Number(quantity_available),
        unit: unit || "kg",
        location: location || null,
        harvest_date: harvest_date || null,
        description: description || null,
        status: "pending"
      }).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      const crop = data;
      await uploadCropImages(crop.id, files);
      const { data: full } = await db.from("crops").select("*, images:crop_images(*)").eq("id", crop.id).single();
      const result = full;
      result.images = (result.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ crop: { ...sanitizeCrop(result), images: result.images } });
    } catch (e) {
      console.error("POST /crops", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.patch("/crops/:id", requireRole("farmer", "admin"), uploadMiddleware.any(), async (req, res) => {
    try {
      const me = req.user;
      const { id } = req.params;
      const body = req.body || {};
      const files = req.files ?? [];
      const { data: crop } = await db.from("crops").select("*").eq("id", id).maybeSingle();
      if (!crop) return res.status(404).json({ error: "not_found" });
      if (me.role === "farmer" && crop.farmer_id !== me.id) {
        return res.status(403).json({ error: "forbidden" });
      }
      let removeIds = [];
      if (body.remove_images) {
        try {
          removeIds = JSON.parse(body.remove_images);
        } catch {
          removeIds = [];
        }
      }
      const { data: existingImgs } = await db.from("crop_images").select("id").eq("crop_id", id);
      const existingCount = existingImgs?.length ?? 0;
      const remainingAfterRemove = existingCount - removeIds.length;
      if (remainingAfterRemove + files.length > CROP_MAX_IMAGES) {
        return res.status(400).json({ error: "too_many_images" });
      }
      for (const f of files) {
        if (!CROP_ALLOWED_TYPES.includes(f.mimetype)) return res.status(400).json({ error: "invalid_image_type" });
        if (f.size > CROP_MAX_IMAGE_SIZE) return res.status(400).json({ error: "image_too_large" });
      }
      const allowed = ["name", "category", "price", "quantity_available", "unit", "location", "harvest_date", "description", "status"];
      const patch = {};
      for (const k of allowed) {
        if (body[k] !== void 0) patch[k] = body[k];
      }
      if (me.role !== "admin" && "status" in patch) delete patch.status;
      if (Object.keys(patch).length) {
        const { error } = await db.from("crops").update(patch).eq("id", id);
        if (error) return res.status(500).json({ error: "server_error" });
      }
      if (removeIds.length > 0) {
        const { data: imgsToRemove } = await db.from("crop_images").select("image_url").in("id", removeIds).eq("crop_id", id);
        if (imgsToRemove && imgsToRemove.length) {
          await Promise.all(imgsToRemove.map((img) => deleteCropStorageFile(img.image_url)));
          await db.from("crop_images").delete().in("id", removeIds).eq("crop_id", id);
        }
      }
      await uploadCropImages(id, files);
      const { data: full } = await db.from("crops").select("*, images:crop_images(*)").eq("id", id).single();
      const result = full;
      result.images = (result.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ crop: { ...sanitizeCrop(result), images: result.images } });
    } catch (e) {
      console.error("PATCH /crops", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.delete("/crops/:id", requireRole("farmer"), async (req, res) => {
    try {
      const me = req.user;
      const { id } = req.params;
      const { data: crop } = await db.from("crops").select("*").eq("id", id).maybeSingle();
      if (!crop) return res.status(404).json({ error: "not_found" });
      if (crop.farmer_id !== me.id) return res.status(403).json({ error: "forbidden" });
      const { data: images } = await db.from("crop_images").select("image_url").eq("crop_id", id);
      if (images && images.length) {
        await Promise.all(images.map((img) => deleteCropStorageFile(img.image_url)));
      }
      const { error } = await db.from("crops").delete().eq("id", id);
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ ok: true });
    } catch (e) {
      console.error("DELETE /crops/:id", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/orders", requireAuth, async (req, res) => {
    try {
      const me = req.user;
      let q = db.from("orders").select("*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*), wholesaler:users!orders_wholesaler_id_fkey(*)").order("created_at", { ascending: false });
      const { data, error } = await q;
      if (error) return res.status(500).json({ error: "server_error" });
      let rows = data ?? [];
      if (me.role === "farmer") rows = rows.filter((o) => o.farmer_id === me.id);
      else if (me.role === "wholesaler") rows = rows.filter((o) => o.wholesaler_id === me.id);
      return res.json({ orders: rows });
    } catch (e) {
      console.error("GET /orders", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/orders", requireRole("wholesaler"), async (req, res) => {
    try {
      const me = req.user;
      const { crop_id, quantity } = req.body || {};
      if (!crop_id || !quantity) return res.status(400).json({ error: "missing_fields" });
      const { data: crop } = await db.from("crops").select("*").eq("id", crop_id).maybeSingle();
      if (!crop) return res.status(404).json({ error: "not_found" });
      if (crop.status !== "approved") return res.status(400).json({ error: "not_approved" });
      const { data, error } = await db.from("orders").insert({
        wholesaler_id: me.id,
        farmer_id: crop.farmer_id,
        crop_id: crop.id,
        quantity: Number(quantity),
        status: "pending"
      }).select("*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*)").single();
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ order: data });
    } catch (e) {
      console.error("POST /orders", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.patch("/orders/:id", requireAuth, async (req, res) => {
    try {
      const me = req.user;
      const { id } = req.params;
      const { status } = req.body || {};
      if (!["pending", "completed", "cancelled"].includes(status)) {
        return res.status(400).json({ error: "invalid_status" });
      }
      const { data: order } = await db.from("orders").select("*").eq("id", id).maybeSingle();
      if (!order) return res.status(404).json({ error: "not_found" });
      if (me.role !== "admin" && order.farmer_id !== me.id && order.wholesaler_id !== me.id) {
        return res.status(403).json({ error: "forbidden" });
      }
      const { data, error } = await db.from("orders").update({ status }).eq("id", id).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ order: data });
    } catch (e) {
      console.error("PATCH /orders", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/prices", async (_req, res) => {
    try {
      const { data, error } = await db.from("market_prices").select("*").order("product");
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ prices: data });
    } catch (e) {
      console.error("GET /prices", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/prices", requireRole("admin"), async (req, res) => {
    try {
      const { product, unit, min_price, max_price, avg_price, trend } = req.body || {};
      if (!product || min_price == null || max_price == null || avg_price == null) {
        return res.status(400).json({ error: "missing_fields" });
      }
      const { data, error } = await db.from("market_prices").insert({
        product,
        unit: unit || "kg",
        min_price: Number(min_price),
        max_price: Number(max_price),
        avg_price: Number(avg_price),
        trend: trend || "stable",
        updated_at: (/* @__PURE__ */ new Date()).toISOString()
      }).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ price: data });
    } catch (e) {
      console.error("POST /prices", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.patch("/prices/:id", requireRole("admin"), async (req, res) => {
    try {
      const { id } = req.params;
      const { product, unit, min_price, max_price, avg_price, trend } = req.body || {};
      const patch = { updated_at: (/* @__PURE__ */ new Date()).toISOString() };
      if (product !== void 0) patch.product = product;
      if (unit !== void 0) patch.unit = unit;
      if (min_price !== void 0) patch.min_price = Number(min_price);
      if (max_price !== void 0) patch.max_price = Number(max_price);
      if (avg_price !== void 0) patch.avg_price = Number(avg_price);
      if (trend !== void 0) patch.trend = trend;
      const { data, error } = await db.from("market_prices").update(patch).eq("id", id).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ price: data });
    } catch (e) {
      console.error("PATCH /prices", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.delete("/prices/:id", requireRole("admin"), async (req, res) => {
    try {
      const { id } = req.params;
      const { error } = await db.from("market_prices").delete().eq("id", id);
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ ok: true });
    } catch (e) {
      console.error("DELETE /prices", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/contacts", async (req, res) => {
    try {
      const { name, email, message } = req.body || {};
      if (!name || !email || !message) return res.status(400).json({ error: "missing_fields" });
      const { error } = await db.from("contacts").insert({ name, email, message });
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ ok: true });
    } catch (e) {
      console.error("POST /contacts", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/admin/users", requireRole("admin"), async (_req, res) => {
    const { data, error } = await db.from("users").select("*").order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: "server_error" });
    return res.json({ users: data.map(sanitize) });
  });
  api.patch("/admin/users/:id", requireRole("admin"), async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body || {};
      if (!["active", "suspended", "banned"].includes(status)) {
        return res.status(400).json({ error: "invalid_status" });
      }
      const { data, error } = await db.from("users").update({ status }).eq("id", id).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ user: sanitize(data) });
    } catch (e) {
      console.error("PATCH /admin/users", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/admin/crops/pending", requireRole("admin"), async (_req, res) => {
    const { data, error } = await db.from("crops").select("*, farmer:users!crops_farmer_id_fkey(*)").eq("status", "pending").order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: "server_error" });
    return res.json({ crops: data.map(sanitizeCrop) });
  });
  api.get("/admin/orders", requireRole("admin"), async (_req, res) => {
    const { data, error } = await db.from("orders").select("*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*), wholesaler:users!orders_wholesaler_id_fkey(*)").order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: "server_error" });
    return res.json({ orders: data });
  });
  const PROFILE_BUCKET = "profile-images";
  const PROFILE_MAX_SIZE = 5 * 1024 * 1024;
  const PROFILE_ALLOWED_TYPES = ["image/jpeg", "image/png", "image/webp"];
  api.post("/me/avatar", requireAuth, uploadMiddleware.single("avatar"), async (req, res) => {
    try {
      const me = req.user;
      const file = req.file;
      if (!file) return res.status(400).json({ error: "missing_file" });
      if (!PROFILE_ALLOWED_TYPES.includes(file.mimetype)) {
        return res.status(400).json({ error: "invalid_image_type" });
      }
      if (file.size > PROFILE_MAX_SIZE) {
        return res.status(400).json({ error: "image_too_large" });
      }
      const ext = file.originalname.split(".").pop()?.toLowerCase() || "jpg";
      const filePath = `profiles/${me.id}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
      const { error: upErr } = await db.storage.from(PROFILE_BUCKET).upload(filePath, file.buffer, { contentType: file.mimetype, upsert: false });
      if (upErr) {
        console.error("avatar upload", upErr);
        return res.status(500).json({ error: "server_error" });
      }
      const { data: pub } = db.storage.from(PROFILE_BUCKET).getPublicUrl(filePath);
      const newAvatarUrl = pub.publicUrl;
      const oldAvatarUrl = me.avatar_url;
      const { data, error } = await db.from("users").update({ avatar_url: newAvatarUrl }).eq("id", me.id).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      if (oldAvatarUrl) {
        try {
          const url = new URL(oldAvatarUrl);
          const parts = url.pathname.split(`/storage/v1/object/public/${PROFILE_BUCKET}/`);
          if (parts.length === 2 && parts[1]) {
            await db.storage.from(PROFILE_BUCKET).remove([decodeURIComponent(parts[1])]);
          }
        } catch (e) {
        }
      }
      return res.json({ user: sanitize(data) });
    } catch (e) {
      console.error("POST /me/avatar", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.patch("/me", requireAuth, async (req, res) => {
    try {
      const me = req.user;
      const allowed = [
        "full_name",
        "phone",
        "business_name",
        "farm_location",
        "years_experience",
        "about_farm",
        "business_location",
        "years_in_business",
        "storage_capacity_tons",
        "avatar_url"
      ];
      const patch = {};
      for (const k of allowed) {
        if (req.body[k] !== void 0) patch[k] = req.body[k];
      }
      if (patch.years_experience !== void 0) patch.years_experience = patch.years_experience === "" ? null : Number(patch.years_experience);
      if (patch.years_in_business !== void 0) patch.years_in_business = patch.years_in_business === "" ? null : Number(patch.years_in_business);
      if (patch.storage_capacity_tons !== void 0) patch.storage_capacity_tons = patch.storage_capacity_tons === "" ? null : Number(patch.storage_capacity_tons);
      const { data, error } = await db.from("users").update(patch).eq("id", me.id).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ user: sanitize(data) });
    } catch (e) {
      console.error("PATCH /me", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/reviews", async (req, res) => {
    try {
      const userId = req.query.user_id;
      if (!userId) return res.status(400).json({ error: "missing_user" });
      const { data, error } = await db.from("reviews").select("*, reviewer:users!reviews_reviewer_id_fkey(*), order:orders(*)").eq("reviewee_id", userId).order("created_at", { ascending: false });
      if (error) return res.status(500).json({ error: "server_error" });
      const rows = data ?? [];
      const avg = rows.length ? rows.reduce((s, r) => s + Number(r.rating), 0) / rows.length : 0;
      return res.json({ reviews: rows.map(sanitizeReview), average: Math.round(avg * 10) / 10, count: rows.length });
    } catch (e) {
      console.error("GET /reviews", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/reviews/mine", requireAuth, async (req, res) => {
    try {
      const me = req.user;
      const { data, error } = await db.from("reviews").select("*, reviewee:users!reviews_reviewee_id_fkey(*), order:orders(*)").eq("reviewer_id", me.id).order("created_at", { ascending: false });
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ reviews: data.map(sanitizeReview) });
    } catch (e) {
      console.error("GET /reviews/mine", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/reviews/eligible", requireAuth, async (req, res) => {
    try {
      const me = req.user;
      const { data: orders, error } = await db.from("orders").select("*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*), wholesaler:users!orders_wholesaler_id_fkey(*)").eq("status", "completed").order("created_at", { ascending: false });
      if (error) return res.status(500).json({ error: "server_error" });
      const mine = orders ?? [];
      const participated = mine.filter((o) => o.farmer_id === me.id || o.wholesaler_id === me.id);
      const { data: mineReviews } = await db.from("reviews").select("order_id, reviewer_id").eq("reviewer_id", me.id);
      const reviewed = new Set((mineReviews ?? []).map((r) => r.order_id));
      const eligible = participated.filter((o) => !reviewed.has(o.id));
      return res.json({ orders: eligible });
    } catch (e) {
      console.error("GET /reviews/eligible", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/reviews", requireAuth, async (req, res) => {
    try {
      const me = req.user;
      const { order_id, rating, comment } = req.body || {};
      if (!order_id || !rating) return res.status(400).json({ error: "missing_fields" });
      const r = Number(rating);
      if (!Number.isInteger(r) || r < 1 || r > 5) return res.status(400).json({ error: "invalid_rating" });
      const trimmedComment = comment ? String(comment).slice(0, 500) : null;
      const { data: order } = await db.from("orders").select("*").eq("id", order_id).maybeSingle();
      if (!order) return res.status(404).json({ error: "order_not_found" });
      if (order.status !== "completed") return res.status(400).json({ error: "order_not_completed" });
      let reviewerRole = null;
      let revieweeId = null;
      if (order.farmer_id === me.id && me.role === "farmer") {
        reviewerRole = "farmer";
        revieweeId = order.wholesaler_id;
      } else if (order.wholesaler_id === me.id && me.role === "wholesaler") {
        reviewerRole = "wholesaler";
        revieweeId = order.farmer_id;
      }
      if (!reviewerRole || !revieweeId) return res.status(403).json({ error: "forbidden" });
      const { data: existing } = await db.from("reviews").select("id").eq("order_id", order_id).eq("reviewer_role", reviewerRole).maybeSingle();
      if (existing) return res.status(409).json({ error: "already_reviewed" });
      const { data, error } = await db.from("reviews").insert({
        order_id,
        reviewer_id: me.id,
        reviewee_id: revieweeId,
        reviewer_role: reviewerRole,
        rating: r,
        comment: trimmedComment
      }).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ review: sanitizeReview(data) });
    } catch (e) {
      console.error("POST /reviews", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/statement", requireAuth, async (req, res) => {
    try {
      const me = req.user;
      const from = req.query.from;
      const to = req.query.to;
      const status = req.query.status;
      let q = db.from("orders").select("*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*), wholesaler:users!orders_wholesaler_id_fkey(*)").order("created_at", { ascending: false });
      if (status && ["pending", "completed", "cancelled"].includes(status)) {
        q = q.eq("status", status);
      }
      if (from) q = q.gte("created_at", new Date(from).toISOString());
      if (to) {
        const toDate = new Date(to);
        toDate.setHours(23, 59, 59, 999);
        q = q.lte("created_at", toDate.toISOString());
      }
      const { data, error } = await q;
      if (error) return res.status(500).json({ error: "server_error" });
      let rows = data ?? [];
      if (me.role === "farmer") rows = rows.filter((o) => o.farmer_id === me.id);
      else if (me.role === "wholesaler") rows = rows.filter((o) => o.wholesaler_id === me.id);
      let running = 0;
      const enriched = rows.map((o) => {
        const amount = o.crop ? Number(o.crop.price) * Number(o.quantity) : 0;
        if (o.status === "completed") running += amount;
        return { ...o, amount };
      });
      return res.json({
        orders: enriched,
        total: running,
        count: rows.length,
        completedCount: rows.filter((o) => o.status === "completed").length
      });
    } catch (e) {
      console.error("GET /statement", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  const PRODUCT_CATEGORIES = ["Vegetables", "Fruits", "Grains", "Dairy", "Herbs", "Spices", "Pulses", "Others"];
  const PRODUCT_UNITS = ["kg", "ton", "sack", "crate", "dozen", "liter"];
  const PRODUCT_AVAILABILITY = ["Available", "Limited Stock", "Sold Out"];
  const MAX_IMAGES = 5;
  const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
  const ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/webp"];
  const STORAGE_BUCKET = "product-images";
  function validateProduct(body) {
    if (!body.product_name || !String(body.product_name).trim()) return "missing_name";
    if (!body.category || !PRODUCT_CATEGORIES.includes(body.category)) return "invalid_category";
    if (body.price == null || Number(body.price) <= 0) return "invalid_price";
    if (body.quantity == null || Number(body.quantity) < 0) return "invalid_quantity";
    if (!body.unit || !PRODUCT_UNITS.includes(body.unit)) return "invalid_unit";
    if (!body.district || !String(body.district).trim()) return "missing_district";
    if (body.availability && !PRODUCT_AVAILABILITY.includes(body.availability)) return "invalid_availability";
    return null;
  }
  api.get("/products", async (req, res) => {
    try {
      const mine = req.query.mine === "true";
      const farmerId = req.query.farmer_id;
      let q = db.from("products").select("*, images:product_images(*)").order("created_at", { ascending: false });
      if (mine) {
        const me = await currentUser(req);
        if (!me) return res.status(401).json({ error: "unauthorized" });
        q = q.eq("farmer_id", me.id);
      } else if (farmerId) {
        q = q.eq("farmer_id", farmerId);
      }
      const { data, error } = await q;
      if (error) return res.status(500).json({ error: "server_error" });
      const rows = data ?? [];
      return res.json({ products: rows.map((p) => ({ ...p, images: (p.images || []).sort((a, b) => a.sort_order - b.sort_order) })) });
    } catch (e) {
      console.error("GET /products", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.get("/products/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { data, error } = await db.from("products").select("*, images:product_images(*)").eq("id", id).maybeSingle();
      if (error) return res.status(500).json({ error: "server_error" });
      if (!data) return res.status(404).json({ error: "not_found" });
      const p = data;
      p.images = (p.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ product: p });
    } catch (e) {
      console.error("GET /products/:id", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.post("/products", requireRole("farmer"), uploadMiddleware.any(), async (req, res) => {
    try {
      const me = req.user;
      const body = req.body || {};
      const files = req.files ?? [];
      const validationError = validateProduct(body);
      if (validationError) return res.status(400).json({ error: validationError });
      if (files.length > MAX_IMAGES) return res.status(400).json({ error: "too_many_images" });
      for (const f of files) {
        if (!ALLOWED_IMAGE_TYPES.includes(f.mimetype)) return res.status(400).json({ error: "invalid_image_type" });
        if (f.size > MAX_IMAGE_SIZE) return res.status(400).json({ error: "image_too_large" });
      }
      const { data: product, error } = await db.from("products").insert({
        farmer_id: me.id,
        product_name: String(body.product_name).trim(),
        category: body.category,
        description: body.description ? String(body.description).trim() : null,
        price: Number(body.price),
        quantity: Number(body.quantity),
        unit: body.unit,
        district: String(body.district).trim(),
        municipality: body.municipality ? String(body.municipality).trim() : null,
        harvest_date: body.harvest_date || null,
        availability: body.availability || "Available"
      }).select("*").single();
      if (error) return res.status(500).json({ error: "server_error" });
      const imageRows = await uploadProductImages(product.id, files);
      const { data: fullProduct } = await db.from("products").select("*, images:product_images(*)").eq("id", product.id).single();
      const result = fullProduct;
      result.images = (result.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ product: result });
    } catch (e) {
      console.error("POST /products", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.patch("/products/:id", requireRole("farmer"), uploadMiddleware.any(), async (req, res) => {
    try {
      const me = req.user;
      const { id } = req.params;
      const body = req.body || {};
      const files = req.files ?? [];
      const { data: product } = await db.from("products").select("*").eq("id", id).maybeSingle();
      if (!product) return res.status(404).json({ error: "not_found" });
      if (product.farmer_id !== me.id) return res.status(403).json({ error: "forbidden" });
      const { data: existingImages } = await db.from("product_images").select("id").eq("product_id", id);
      const existingCount = existingImages?.length ?? 0;
      let removeIds = [];
      if (body.remove_images) {
        try {
          removeIds = JSON.parse(body.remove_images);
        } catch {
          removeIds = [];
        }
      }
      const remainingAfterRemove = existingCount - removeIds.length;
      if (remainingAfterRemove + files.length > MAX_IMAGES) {
        return res.status(400).json({ error: "too_many_images" });
      }
      for (const f of files) {
        if (!ALLOWED_IMAGE_TYPES.includes(f.mimetype)) return res.status(400).json({ error: "invalid_image_type" });
        if (f.size > MAX_IMAGE_SIZE) return res.status(400).json({ error: "image_too_large" });
      }
      const patch = { updated_at: (/* @__PURE__ */ new Date()).toISOString() };
      if (body.product_name !== void 0) patch.product_name = String(body.product_name).trim();
      if (body.category !== void 0) {
        if (!PRODUCT_CATEGORIES.includes(body.category)) return res.status(400).json({ error: "invalid_category" });
        patch.category = body.category;
      }
      if (body.description !== void 0) patch.description = body.description ? String(body.description).trim() : null;
      if (body.price !== void 0) {
        if (Number(body.price) <= 0) return res.status(400).json({ error: "invalid_price" });
        patch.price = Number(body.price);
      }
      if (body.quantity !== void 0) {
        if (Number(body.quantity) < 0) return res.status(400).json({ error: "invalid_quantity" });
        patch.quantity = Number(body.quantity);
      }
      if (body.unit !== void 0) {
        if (!PRODUCT_UNITS.includes(body.unit)) return res.status(400).json({ error: "invalid_unit" });
        patch.unit = body.unit;
      }
      if (body.district !== void 0) patch.district = String(body.district).trim();
      if (body.municipality !== void 0) patch.municipality = body.municipality ? String(body.municipality).trim() : null;
      if (body.harvest_date !== void 0) patch.harvest_date = body.harvest_date || null;
      if (body.availability !== void 0) {
        if (!PRODUCT_AVAILABILITY.includes(body.availability)) return res.status(400).json({ error: "invalid_availability" });
        patch.availability = body.availability;
      }
      const { error: updateError } = await db.from("products").update(patch).eq("id", id);
      if (updateError) return res.status(500).json({ error: "server_error" });
      if (removeIds.length > 0) {
        const { data: imgsToRemove } = await db.from("product_images").select("image_url").in("id", removeIds).eq("product_id", id);
        if (imgsToRemove && imgsToRemove.length) {
          await Promise.all(imgsToRemove.map((img) => deleteStorageFile(img.image_url)));
          await db.from("product_images").delete().in("id", removeIds).eq("product_id", id);
        }
      }
      await uploadProductImages(id, files);
      const { data: fullProduct } = await db.from("products").select("*, images:product_images(*)").eq("id", id).single();
      const result = fullProduct;
      result.images = (result.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ product: result });
    } catch (e) {
      console.error("PATCH /products/:id", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  api.delete("/products/:id", requireRole("farmer"), async (req, res) => {
    try {
      const me = req.user;
      const { id } = req.params;
      const { data: product } = await db.from("products").select("*").eq("id", id).maybeSingle();
      if (!product) return res.status(404).json({ error: "not_found" });
      if (product.farmer_id !== me.id) return res.status(403).json({ error: "forbidden" });
      const { data: images } = await db.from("product_images").select("image_url").eq("product_id", id);
      if (images && images.length) {
        await Promise.all(images.map((img) => deleteStorageFile(img.image_url)));
      }
      const { error } = await db.from("products").delete().eq("id", id);
      if (error) return res.status(500).json({ error: "server_error" });
      return res.json({ ok: true });
    } catch (e) {
      console.error("DELETE /products/:id", e);
      return res.status(500).json({ error: "server_error" });
    }
  });
  async function uploadProductImages(productId, files) {
    if (!files.length) return [];
    const rows = [];
    const { data: existing } = await db.from("product_images").select("sort_order").eq("product_id", productId);
    let nextOrder = existing && existing.length ? Math.max(...existing.map((i) => i.sort_order)) + 1 : 0;
    for (const file of files) {
      const ext = file.originalname.split(".").pop()?.toLowerCase() || "jpg";
      const filePath = `${productId}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
      const { error: uploadError } = await db.storage.from(STORAGE_BUCKET).upload(filePath, file.buffer, {
        contentType: file.mimetype,
        upsert: false
      });
      if (uploadError) {
        console.error("Storage upload error", uploadError);
        continue;
      }
      const { data: pubUrl } = db.storage.from(STORAGE_BUCKET).getPublicUrl(filePath);
      const { data: imgRow } = await db.from("product_images").insert({ product_id: productId, image_url: pubUrl.publicUrl, sort_order: nextOrder }).select("*").single();
      if (imgRow) rows.push(imgRow);
      nextOrder++;
    }
    return rows;
  }
  async function deleteStorageFile(publicUrl) {
    try {
      const url = new URL(publicUrl);
      const parts = url.pathname.split(`/storage/v1/object/public/${STORAGE_BUCKET}/`);
      if (parts.length < 2) return;
      const filePath = decodeURIComponent(parts[1]);
      await db.storage.from(STORAGE_BUCKET).remove([filePath]);
    } catch (e) {
      console.error("deleteStorageFile error", e);
    }
  }
  return api;
}
function sanitize(u) {
  const { pin_hash, ...rest } = u;
  return rest;
}
function sanitizeCrop(c) {
  return { ...c, farmer: c.farmer ? sanitize(c.farmer) : void 0 };
}
function sanitizeReview(r) {
  return {
    ...r,
    reviewer: r.reviewer ? sanitize(r.reviewer) : void 0,
    order: r.order ? { ...r.order } : void 0
  };
}

// vite.config.ts
import express2 from "file:///home/project/node_modules/express/index.js";
import fs from "node:fs";
import path from "node:path";
var PAGES = {
  "/": "index.html",
  "/products": "src/pages/products.html",
  "/market-prices": "src/pages/market-prices.html",
  "/about": "src/pages/about.html",
  "/contact": "src/pages/contact.html",
  "/login": "src/pages/login.html",
  "/register": "src/pages/register.html",
  "/admin/login": "src/pages/admin-login.html",
  "/admin": "src/pages/admin.html",
  "/farmer": "src/pages/farmer.html",
  "/wholesaler": "src/pages/wholesaler.html"
};
function resolvePage(urlPath) {
  const p = urlPath.split("?")[0];
  return PAGES[p] ?? null;
}
function serveHtml(server) {
  return (req, res, next) => {
    const file = resolvePage(req.url || "");
    if (!file) return next();
    const abs = path.resolve(process.cwd(), file);
    if (!fs.existsSync(abs)) return next();
    fs.readFile(abs, "utf-8", async (err, data) => {
      if (err) return next(err);
      try {
        const transformed = await server.transformIndexHtml(req.url || "/", data);
        res.setHeader("Content-Type", "text/html");
        res.end(transformed);
      } catch (e) {
        next(e);
      }
    });
  };
}
var vite_config_default = defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  for (const [k, v] of Object.entries(env)) {
    if (!process.env[k]) process.env[k] = v;
  }
  return {
    server: {
      port: 5173,
      host: true
    },
    plugins: [
      {
        name: "kc-api-and-pages",
        configureServer(server) {
          const api = express2();
          api.use(express2.json({ limit: "1mb" }));
          api.use(createApiRouter());
          server.middlewares.use("/api", api);
          server.middlewares.use(serveHtml(server));
        },
        configurePreviewServer(server) {
          const api = express2();
          api.use(express2.json({ limit: "1mb" }));
          api.use(createApiRouter());
          server.middlewares.use("/api", api);
          server.middlewares.use(serveHtml(server));
        }
      }
    ],
    build: {
      outDir: "dist",
      emptyOutDir: true,
      rollupOptions: {
        input: {
          main: "index.html",
          products: "src/pages/products.html",
          marketPrices: "src/pages/market-prices.html",
          about: "src/pages/about.html",
          contact: "src/pages/contact.html",
          login: "src/pages/login.html",
          register: "src/pages/register.html",
          adminLogin: "src/pages/admin-login.html",
          admin: "src/pages/admin.html",
          farmer: "src/pages/farmer.html",
          wholesaler: "src/pages/wholesaler.html"
        }
      }
    }
  };
});
export {
  vite_config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL2FwaS9zZXJ2ZXIudHMiLCAic3JjL2FwaS9kYi50cyIsICJzcmMvYXBpL2F1dGgudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvaG9tZS9wcm9qZWN0XCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ZpbGVuYW1lID0gXCIvaG9tZS9wcm9qZWN0L3ZpdGUuY29uZmlnLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9ob21lL3Byb2plY3Qvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcsIHR5cGUgVml0ZURldlNlcnZlciwgbG9hZEVudiB9IGZyb20gJ3ZpdGUnO1xuaW1wb3J0IHR5cGUgeyBJbmNvbWluZ01lc3NhZ2UsIFNlcnZlclJlc3BvbnNlIH0gZnJvbSAnbm9kZTpodHRwJztcbmltcG9ydCB7IGNyZWF0ZUFwaVJvdXRlciB9IGZyb20gJy4vc3JjL2FwaS9zZXJ2ZXInO1xuaW1wb3J0IGV4cHJlc3MgZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgZnMgZnJvbSAnbm9kZTpmcyc7XG5pbXBvcnQgcGF0aCBmcm9tICdub2RlOnBhdGgnO1xuXG5jb25zdCBQQUdFUzogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHtcbiAgJy8nOiAnaW5kZXguaHRtbCcsXG4gICcvcHJvZHVjdHMnOiAnc3JjL3BhZ2VzL3Byb2R1Y3RzLmh0bWwnLFxuICAnL21hcmtldC1wcmljZXMnOiAnc3JjL3BhZ2VzL21hcmtldC1wcmljZXMuaHRtbCcsXG4gICcvYWJvdXQnOiAnc3JjL3BhZ2VzL2Fib3V0Lmh0bWwnLFxuICAnL2NvbnRhY3QnOiAnc3JjL3BhZ2VzL2NvbnRhY3QuaHRtbCcsXG4gICcvbG9naW4nOiAnc3JjL3BhZ2VzL2xvZ2luLmh0bWwnLFxuICAnL3JlZ2lzdGVyJzogJ3NyYy9wYWdlcy9yZWdpc3Rlci5odG1sJyxcbiAgJy9hZG1pbi9sb2dpbic6ICdzcmMvcGFnZXMvYWRtaW4tbG9naW4uaHRtbCcsXG4gICcvYWRtaW4nOiAnc3JjL3BhZ2VzL2FkbWluLmh0bWwnLFxuICAnL2Zhcm1lcic6ICdzcmMvcGFnZXMvZmFybWVyLmh0bWwnLFxuICAnL3dob2xlc2FsZXInOiAnc3JjL3BhZ2VzL3dob2xlc2FsZXIuaHRtbCcsXG59O1xuXG5mdW5jdGlvbiByZXNvbHZlUGFnZSh1cmxQYXRoOiBzdHJpbmcpOiBzdHJpbmcgfCBudWxsIHtcbiAgY29uc3QgcCA9IHVybFBhdGguc3BsaXQoJz8nKVswXTtcbiAgcmV0dXJuIFBBR0VTW3BdID8/IG51bGw7XG59XG5cbmZ1bmN0aW9uIHNlcnZlSHRtbChzZXJ2ZXI6IFZpdGVEZXZTZXJ2ZXIpIHtcbiAgcmV0dXJuIChyZXE6IEluY29taW5nTWVzc2FnZSwgcmVzOiBTZXJ2ZXJSZXNwb25zZSwgbmV4dDogKGVycj86IHVua25vd24pID0+IHZvaWQpID0+IHtcbiAgICBjb25zdCBmaWxlID0gcmVzb2x2ZVBhZ2UocmVxLnVybCB8fCAnJyk7XG4gICAgaWYgKCFmaWxlKSByZXR1cm4gbmV4dCgpO1xuICAgIGNvbnN0IGFicyA9IHBhdGgucmVzb2x2ZShwcm9jZXNzLmN3ZCgpLCBmaWxlKTtcbiAgICBpZiAoIWZzLmV4aXN0c1N5bmMoYWJzKSkgcmV0dXJuIG5leHQoKTtcbiAgICBmcy5yZWFkRmlsZShhYnMsICd1dGYtOCcsIGFzeW5jIChlcnIsIGRhdGEpID0+IHtcbiAgICAgIGlmIChlcnIpIHJldHVybiBuZXh0KGVycik7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCB0cmFuc2Zvcm1lZCA9IGF3YWl0IHNlcnZlci50cmFuc2Zvcm1JbmRleEh0bWwocmVxLnVybCB8fCAnLycsIGRhdGEpO1xuICAgICAgICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAndGV4dC9odG1sJyk7XG4gICAgICAgIHJlcy5lbmQodHJhbnNmb3JtZWQpO1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBuZXh0KGUpO1xuICAgICAgfVxuICAgIH0pO1xuICB9O1xufVxuXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiB7XG4gIC8vIExvYWQgLmVudiBpbnRvIHByb2Nlc3MuZW52IHNvIHRoZSBFeHByZXNzIEFQSSBjYW4gcmVhZCBTVVBBQkFTRV8qIHZhcnMuXG4gIGNvbnN0IGVudiA9IGxvYWRFbnYobW9kZSwgcHJvY2Vzcy5jd2QoKSwgJycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhlbnYpKSB7XG4gICAgaWYgKCFwcm9jZXNzLmVudltrXSkgcHJvY2Vzcy5lbnZba10gPSB2O1xuICB9XG4gIHJldHVybiB7XG4gICAgc2VydmVyOiB7XG4gICAgICBwb3J0OiA1MTczLFxuICAgICAgaG9zdDogdHJ1ZSxcbiAgICB9LFxuICAgIHBsdWdpbnM6IFtcbiAgICAgIHtcbiAgICAgICAgbmFtZTogJ2tjLWFwaS1hbmQtcGFnZXMnLFxuICAgICAgICBjb25maWd1cmVTZXJ2ZXIoc2VydmVyKSB7XG4gICAgICAgICAgY29uc3QgYXBpID0gZXhwcmVzcygpO1xuICAgICAgICAgIGFwaS51c2UoZXhwcmVzcy5qc29uKHsgbGltaXQ6ICcxbWInIH0pKTtcbiAgICAgICAgICBhcGkudXNlKGNyZWF0ZUFwaVJvdXRlcigpKTtcbiAgICAgICAgICBzZXJ2ZXIubWlkZGxld2FyZXMudXNlKCcvYXBpJywgYXBpKTtcbiAgICAgICAgICAvLyBNdWx0aS1wYWdlIEhUTUwgcm91dGluZyBcdTIwMTQgbXVzdCBydW4gYmVmb3JlIFZpdGUncyBkZWZhdWx0IGZhbGxiYWNrLlxuICAgICAgICAgIHNlcnZlci5taWRkbGV3YXJlcy51c2Uoc2VydmVIdG1sKHNlcnZlcikpO1xuICAgICAgICB9LFxuICAgICAgICBjb25maWd1cmVQcmV2aWV3U2VydmVyKHNlcnZlcikge1xuICAgICAgICAgIGNvbnN0IGFwaSA9IGV4cHJlc3MoKTtcbiAgICAgICAgICBhcGkudXNlKGV4cHJlc3MuanNvbih7IGxpbWl0OiAnMW1iJyB9KSk7XG4gICAgICAgICAgYXBpLnVzZShjcmVhdGVBcGlSb3V0ZXIoKSk7XG4gICAgICAgICAgc2VydmVyLm1pZGRsZXdhcmVzLnVzZSgnL2FwaScsIGFwaSk7XG4gICAgICAgICAgc2VydmVyLm1pZGRsZXdhcmVzLnVzZShzZXJ2ZUh0bWwoc2VydmVyIGFzIHVua25vd24gYXMgVml0ZURldlNlcnZlcikpO1xuICAgICAgICB9LFxuICAgICAgfSxcbiAgICBdLFxuICAgIGJ1aWxkOiB7XG4gICAgICBvdXREaXI6ICdkaXN0JyxcbiAgICAgIGVtcHR5T3V0RGlyOiB0cnVlLFxuICAgICAgcm9sbHVwT3B0aW9uczoge1xuICAgICAgICBpbnB1dDoge1xuICAgICAgICAgIG1haW46ICdpbmRleC5odG1sJyxcbiAgICAgICAgICBwcm9kdWN0czogJ3NyYy9wYWdlcy9wcm9kdWN0cy5odG1sJyxcbiAgICAgICAgICBtYXJrZXRQcmljZXM6ICdzcmMvcGFnZXMvbWFya2V0LXByaWNlcy5odG1sJyxcbiAgICAgICAgICBhYm91dDogJ3NyYy9wYWdlcy9hYm91dC5odG1sJyxcbiAgICAgICAgICBjb250YWN0OiAnc3JjL3BhZ2VzL2NvbnRhY3QuaHRtbCcsXG4gICAgICAgICAgbG9naW46ICdzcmMvcGFnZXMvbG9naW4uaHRtbCcsXG4gICAgICAgICAgcmVnaXN0ZXI6ICdzcmMvcGFnZXMvcmVnaXN0ZXIuaHRtbCcsXG4gICAgICAgICAgYWRtaW5Mb2dpbjogJ3NyYy9wYWdlcy9hZG1pbi1sb2dpbi5odG1sJyxcbiAgICAgICAgICBhZG1pbjogJ3NyYy9wYWdlcy9hZG1pbi5odG1sJyxcbiAgICAgICAgICBmYXJtZXI6ICdzcmMvcGFnZXMvZmFybWVyLmh0bWwnLFxuICAgICAgICAgIHdob2xlc2FsZXI6ICdzcmMvcGFnZXMvd2hvbGVzYWxlci5odG1sJyxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfTtcbn0pO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvaG9tZS9wcm9qZWN0L3NyYy9hcGlcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9ob21lL3Byb2plY3Qvc3JjL2FwaS9zZXJ2ZXIudHNcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfaW1wb3J0X21ldGFfdXJsID0gXCJmaWxlOi8vL2hvbWUvcHJvamVjdC9zcmMvYXBpL3NlcnZlci50c1wiO2ltcG9ydCBleHByZXNzIGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IGNvb2tpZVBhcnNlciBmcm9tICdjb29raWUtcGFyc2VyJztcbmltcG9ydCBtdWx0ZXIgZnJvbSAnbXVsdGVyJztcbmltcG9ydCBiY3J5cHQgZnJvbSAnYmNyeXB0anMnO1xuaW1wb3J0IHsgZGIsIFVzZXIsIENyb3AsIE9yZGVyLCBNYXJrZXRQcmljZSwgUmV2aWV3LCBQcm9kdWN0LCBQcm9kdWN0SW1hZ2UsIENyb3BJbWFnZSwgT3RwQ29kZSB9IGZyb20gJy4vZGInO1xuaW1wb3J0IHsgY3JlYXRlU2Vzc2lvbiwgZGVzdHJveVNlc3Npb24sIGN1cnJlbnRVc2VyLCByZXF1aXJlQXV0aCwgcmVxdWlyZVJvbGUsIHZlcmlmeVBpbiwgaGFzaFBpbiwgU0VTU0lPTl9DT09LSUUgfSBmcm9tICcuL2F1dGgnO1xuXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlQXBpUm91dGVyKCkge1xuICBjb25zdCBhcGkgPSBleHByZXNzLlJvdXRlcigpO1xuICBhcGkudXNlKGV4cHJlc3MuanNvbih7IGxpbWl0OiAnMW1iJyB9KSk7XG4gIGFwaS51c2UoY29va2llUGFyc2VyKCkpO1xuICBjb25zdCB1cGxvYWRNaWRkbGV3YXJlID0gbXVsdGVyKHsgc3RvcmFnZTogbXVsdGVyLm1lbW9yeVN0b3JhZ2UoKSwgbGltaXRzOiB7IGZpbGVTaXplOiA1ICogMTAyNCAqIDEwMjQgfSB9KTtcblxuICAvLyAtLS0tLS0tLS0tIEhlbHBlcnMgLS0tLS0tLS0tLVxuICBjb25zdCBPVFBfVFRMX01JTlVURVMgPSAxMDtcbiAgY29uc3QgT1RQX0NPT0xET1dOX1NFQyA9IDMwO1xuXG4gIGZ1bmN0aW9uIGdlbmVyYXRlT3RwKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFN0cmluZyhNYXRoLmZsb29yKDEwMDAgKyBNYXRoLnJhbmRvbSgpICogOTAwMCkpO1xuICB9XG5cbiAgZnVuY3Rpb24gaXNWYWxpZE5lcGFsUGhvbmUocGhvbmU6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgIGNvbnN0IHAgPSBwaG9uZS5yZXBsYWNlKC9bXFxzLV0vZywgJycpO1xuICAgIHJldHVybiAvXjlcXGR7OX0kLy50ZXN0KHApO1xuICB9XG5cbiAgYXN5bmMgZnVuY3Rpb24gc2VuZE90cChwaG9uZTogc3RyaW5nLCBwdXJwb3NlOiAncmVnaXN0ZXInIHwgJ3Jlc2V0X3BpbicpOiBQcm9taXNlPHsgY29kZTogc3RyaW5nOyBjb29sZG93bjogbnVtYmVyIH0+IHtcbiAgICAvLyBNYXJrIHByZXZpb3VzIHVudXNlZCBjb2RlcyBhcyB1c2VkXG4gICAgYXdhaXQgZGIuZnJvbSgnb3RwX2NvZGVzJykudXBkYXRlKHsgdXNlZDogdHJ1ZSB9KS5lcSgncGhvbmUnLCBwaG9uZSkuZXEoJ3B1cnBvc2UnLCBwdXJwb3NlKS5lcSgndXNlZCcsIGZhbHNlKTtcbiAgICBjb25zdCBjb2RlID0gZ2VuZXJhdGVPdHAoKTtcbiAgICBjb25zdCBleHBpcmVzQXQgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgT1RQX1RUTF9NSU5VVEVTICogNjBfMDAwKS50b0lTT1N0cmluZygpO1xuICAgIGNvbnN0IHsgZXJyb3IgfSA9IGF3YWl0IGRiLmZyb20oJ290cF9jb2RlcycpLmluc2VydCh7IHBob25lLCBjb2RlLCBwdXJwb3NlLCBleHBpcmVzX2F0OiBleHBpcmVzQXQgfSk7XG4gICAgaWYgKGVycm9yKSB0aHJvdyBlcnJvcjtcbiAgICAvLyBJbiBwcm9kdWN0aW9uOiBzZW5kIFNNUyBoZXJlLiBJbiB0aGlzIGVudmlyb25tZW50OiByZXR1cm4gdGhlIGNvZGUgc28gdGhlIFVJIGNhbiBkaXNwbGF5IGl0LlxuICAgIHJldHVybiB7IGNvZGUsIGNvb2xkb3duOiBPVFBfQ09PTERPV05fU0VDIH07XG4gIH1cblxuICBhc3luYyBmdW5jdGlvbiB2ZXJpZnlPdHAocGhvbmU6IHN0cmluZywgY29kZTogc3RyaW5nLCBwdXJwb3NlOiAncmVnaXN0ZXInIHwgJ3Jlc2V0X3BpbicpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBjb25zdCB7IGRhdGEgfSA9IGF3YWl0IGRiXG4gICAgICAuZnJvbSgnb3RwX2NvZGVzJylcbiAgICAgIC5zZWxlY3QoJyonKVxuICAgICAgLmVxKCdwaG9uZScsIHBob25lKVxuICAgICAgLmVxKCdwdXJwb3NlJywgcHVycG9zZSlcbiAgICAgIC5lcSgndXNlZCcsIGZhbHNlKVxuICAgICAgLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pXG4gICAgICAubGltaXQoMSlcbiAgICAgIC5tYXliZVNpbmdsZSgpIGFzIHsgZGF0YTogT3RwQ29kZSB8IG51bGwgfTtcbiAgICBpZiAoIWRhdGEpIHJldHVybiBmYWxzZTtcbiAgICBpZiAobmV3IERhdGUoZGF0YS5leHBpcmVzX2F0KS5nZXRUaW1lKCkgPCBEYXRlLm5vdygpKSByZXR1cm4gZmFsc2U7XG4gICAgaWYgKGRhdGEuY29kZSAhPT0gY29kZSkgcmV0dXJuIGZhbHNlO1xuICAgIGF3YWl0IGRiLmZyb20oJ290cF9jb2RlcycpLnVwZGF0ZSh7IHVzZWQ6IHRydWUgfSkuZXEoJ2lkJywgZGF0YS5pZCk7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuXG4gIC8vIC0tLS0tLS0tLS0gQXV0aCAtLS0tLS0tLS0tXG4gIC8vIC0tLS0tLS0tLS0gT1RQOiBzZW5kIC0tLS0tLS0tLS1cbiAgYXBpLnBvc3QoJy9hdXRoL3NlbmQtb3RwJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgcGhvbmUsIHB1cnBvc2UgfSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgaWYgKCFwaG9uZSB8fCAhcHVycG9zZSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdtaXNzaW5nX2ZpZWxkcycgfSk7XG4gICAgICBpZiAoIVsncmVnaXN0ZXInLCAncmVzZXRfcGluJ10uaW5jbHVkZXMocHVycG9zZSkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9wdXJwb3NlJyB9KTtcbiAgICAgIGlmICghaXNWYWxpZE5lcGFsUGhvbmUocGhvbmUpKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfcGhvbmUnIH0pO1xuXG4gICAgICAvLyBGb3IgcmVnaXN0ZXI6IGNoZWNrIHRoZSBwaG9uZSBpc24ndCBhbHJlYWR5IHJlZ2lzdGVyZWRcbiAgICAgIGlmIChwdXJwb3NlID09PSAncmVnaXN0ZXInKSB7XG4gICAgICAgIGNvbnN0IHsgZGF0YTogZXhpc3RpbmcgfSA9IGF3YWl0IGRiLmZyb20oJ3VzZXJzJykuc2VsZWN0KCdpZCcpLmVxKCdwaG9uZScsIHBob25lKS5tYXliZVNpbmdsZSgpO1xuICAgICAgICBpZiAoZXhpc3RpbmcpIHJldHVybiByZXMuc3RhdHVzKDQwOSkuanNvbih7IGVycm9yOiAnZXhpc3RzJyB9KTtcbiAgICAgIH1cbiAgICAgIC8vIEZvciByZXNldF9waW46IGNoZWNrIHRoZSBwaG9uZSBJUyByZWdpc3RlcmVkXG4gICAgICBpZiAocHVycG9zZSA9PT0gJ3Jlc2V0X3BpbicpIHtcbiAgICAgICAgY29uc3QgeyBkYXRhOiBleGlzdGluZyB9ID0gYXdhaXQgZGIuZnJvbSgndXNlcnMnKS5zZWxlY3QoJ2lkJykuZXEoJ3Bob25lJywgcGhvbmUpLm1heWJlU2luZ2xlKCk7XG4gICAgICAgIGlmICghZXhpc3RpbmcpIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIH1cblxuICAgICAgLy8gQ29vbGRvd246IGNoZWNrIGxhc3QgT1RQIHNlbnQgd2l0aGluIGNvb2xkb3duIHdpbmRvd1xuICAgICAgY29uc3QgeyBkYXRhOiByZWNlbnQgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCdvdHBfY29kZXMnKVxuICAgICAgICAuc2VsZWN0KCdjcmVhdGVkX2F0JylcbiAgICAgICAgLmVxKCdwaG9uZScsIHBob25lKVxuICAgICAgICAuZXEoJ3B1cnBvc2UnLCBwdXJwb3NlKVxuICAgICAgICAub3JkZXIoJ2NyZWF0ZWRfYXQnLCB7IGFzY2VuZGluZzogZmFsc2UgfSlcbiAgICAgICAgLmxpbWl0KDEpXG4gICAgICAgIC5tYXliZVNpbmdsZSgpIGFzIHsgZGF0YTogeyBjcmVhdGVkX2F0OiBzdHJpbmcgfSB8IG51bGwgfTtcbiAgICAgIGlmIChyZWNlbnQpIHtcbiAgICAgICAgY29uc3QgZWxhcHNlZCA9IChEYXRlLm5vdygpIC0gbmV3IERhdGUocmVjZW50LmNyZWF0ZWRfYXQpLmdldFRpbWUoKSkgLyAxMDAwO1xuICAgICAgICBpZiAoZWxhcHNlZCA8IE9UUF9DT09MRE9XTl9TRUMpIHtcbiAgICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MjkpLmpzb24oeyBlcnJvcjogJ2Nvb2xkb3duJywgcmV0cnlfYWZ0ZXI6IE1hdGguY2VpbChPVFBfQ09PTERPV05fU0VDIC0gZWxhcHNlZCkgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgY29uc3QgeyBjb2RlLCBjb29sZG93biB9ID0gYXdhaXQgc2VuZE90cChwaG9uZSwgcHVycG9zZSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBvazogdHJ1ZSwgY29vbGRvd24sIGRlbW9fY29kZTogY29kZSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdzZW5kLW90cCBlcnJvcicsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBPVFA6IHZlcmlmeSAtLS0tLS0tLS0tXG4gIGFwaS5wb3N0KCcvYXV0aC92ZXJpZnktb3RwJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgcGhvbmUsIGNvZGUsIHB1cnBvc2UgfSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgaWYgKCFwaG9uZSB8fCAhY29kZSB8fCAhcHVycG9zZSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdtaXNzaW5nX2ZpZWxkcycgfSk7XG4gICAgICBjb25zdCBvayA9IGF3YWl0IHZlcmlmeU90cChwaG9uZSwgU3RyaW5nKGNvZGUpLCBwdXJwb3NlKTtcbiAgICAgIGlmICghb2spIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9vdHAnIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgb2s6IHRydWUsIHZlcmlmaWVkOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ3ZlcmlmeS1vdHAgZXJyb3InLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIC0tLS0tLS0tLS0gUmVnaXN0ZXIgKHJlcXVpcmVzIHZlcmlmaWVkIHBob25lKSAtLS0tLS0tLS0tXG4gIGFwaS5wb3N0KCcvYXV0aC9yZWdpc3RlcicsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IGZ1bGxfbmFtZSwgcGhvbmUsIHBpbiwgY29uZmlybV9waW4sIHJvbGUsIGJ1c2luZXNzX25hbWUsIG90cF9jb2RlIH0gPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGlmICghZnVsbF9uYW1lIHx8ICFwaG9uZSB8fCAhcGluIHx8ICFyb2xlKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbWlzc2luZ19maWVsZHMnIH0pO1xuICAgICAgfVxuICAgICAgaWYgKCFpc1ZhbGlkTmVwYWxQaG9uZShwaG9uZSkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9waG9uZScgfSk7XG4gICAgICBpZiAoIVsnZmFybWVyJywgJ3dob2xlc2FsZXInXS5pbmNsdWRlcyhyb2xlKSkge1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfcm9sZScgfSk7XG4gICAgICB9XG4gICAgICBpZiAoIS9eXFxkezR9JC8udGVzdChTdHJpbmcocGluKSkpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX3BpbicgfSk7XG4gICAgICB9XG4gICAgICBpZiAoY29uZmlybV9waW4gIT09IHVuZGVmaW5lZCAmJiBTdHJpbmcoY29uZmlybV9waW4pICE9PSBTdHJpbmcocGluKSkge1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ3Bpbl9taXNtYXRjaCcgfSk7XG4gICAgICB9XG4gICAgICBpZiAocm9sZSA9PT0gJ3dob2xlc2FsZXInICYmICFidXNpbmVzc19uYW1lKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbWlzc2luZ19idXNpbmVzc19uYW1lJyB9KTtcbiAgICAgIH1cbiAgICAgIC8vIFJlcXVpcmUgT1RQIHZlcmlmaWNhdGlvblxuICAgICAgaWYgKCFvdHBfY29kZSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdvdHBfcmVxdWlyZWQnIH0pO1xuICAgICAgY29uc3Qgb3RwT2sgPSBhd2FpdCB2ZXJpZnlPdHAocGhvbmUsIFN0cmluZyhvdHBfY29kZSksICdyZWdpc3RlcicpO1xuICAgICAgaWYgKCFvdHBPaykgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX290cCcgfSk7XG5cbiAgICAgIGNvbnN0IHsgZGF0YTogZXhpc3RpbmcgfSA9IGF3YWl0IGRiLmZyb20oJ3VzZXJzJykuc2VsZWN0KCdpZCcpLmVxKCdwaG9uZScsIHBob25lKS5tYXliZVNpbmdsZSgpO1xuICAgICAgaWYgKGV4aXN0aW5nKSByZXR1cm4gcmVzLnN0YXR1cyg0MDkpLmpzb24oeyBlcnJvcjogJ2V4aXN0cycgfSk7XG5cbiAgICAgIGNvbnN0IHBpbl9oYXNoID0gYXdhaXQgaGFzaFBpbihTdHJpbmcocGluKSk7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgndXNlcnMnKVxuICAgICAgICAuaW5zZXJ0KHtcbiAgICAgICAgICBmdWxsX25hbWUsXG4gICAgICAgICAgcGhvbmUsXG4gICAgICAgICAgcGluX2hhc2gsXG4gICAgICAgICAgcm9sZSxcbiAgICAgICAgICBwaG9uZV92ZXJpZmllZDogdHJ1ZSxcbiAgICAgICAgICBidXNpbmVzc19uYW1lOiByb2xlID09PSAnd2hvbGVzYWxlcicgPyBidXNpbmVzc19uYW1lIDogbnVsbCxcbiAgICAgICAgICBzdGF0dXM6ICdhY3RpdmUnLFxuICAgICAgICB9KVxuICAgICAgICAuc2VsZWN0KCcqJylcbiAgICAgICAgLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICBhd2FpdCBjcmVhdGVTZXNzaW9uKHJlcywgKGRhdGEgYXMgVXNlcikuaWQpO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgdXNlcjogc2FuaXRpemUoZGF0YSkgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcigncmVnaXN0ZXIgZXJyb3InLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIC0tLS0tLS0tLS0gTG9naW4gKHBob25lICsgUElOLCBtdXN0IGJlIHZlcmlmaWVkKSAtLS0tLS0tLS0tXG4gIGFwaS5wb3N0KCcvYXV0aC9sb2dpbicsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IHBob25lLCBwaW4gfSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgaWYgKCFwaG9uZSB8fCAhcGluKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmdfZmllbGRzJyB9KTtcbiAgICAgIGNvbnN0IHsgZGF0YTogdXNlciB9ID0gKGF3YWl0IGRiLmZyb20oJ3VzZXJzJykuc2VsZWN0KCcqJykuZXEoJ3Bob25lJywgcGhvbmUpLm1heWJlU2luZ2xlKCkpIGFzIHsgZGF0YTogVXNlciB8IG51bGwgfTtcbiAgICAgIC8vIEdlbmVyaWMgZXJyb3IgZm9yIGFsbCBmYWlsdXJlcyAod3JvbmcgcGhvbmUsIHdyb25nIFBJTiwgdW52ZXJpZmllZClcbiAgICAgIGlmICghdXNlcikgcmV0dXJuIHJlcy5zdGF0dXMoNDAxKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX2NyZWRzJyB9KTtcbiAgICAgIGNvbnN0IG9rID0gYXdhaXQgdmVyaWZ5UGluKHVzZXIsIFN0cmluZyhwaW4pKTtcbiAgICAgIGlmICghb2spIHJldHVybiByZXMuc3RhdHVzKDQwMSkuanNvbih7IGVycm9yOiAnaW52YWxpZF9jcmVkcycgfSk7XG4gICAgICBpZiAodXNlci5zdGF0dXMgIT09ICdhY3RpdmUnKSByZXR1cm4gcmVzLnN0YXR1cyg0MDMpLmpzb24oeyBlcnJvcjogJ3N1c3BlbmRlZCcgfSk7XG4gICAgICBpZiAoIXVzZXIucGhvbmVfdmVyaWZpZWQpIHJldHVybiByZXMuc3RhdHVzKDQwMSkuanNvbih7IGVycm9yOiAnaW52YWxpZF9jcmVkcycgfSk7XG4gICAgICBhd2FpdCBjcmVhdGVTZXNzaW9uKHJlcywgdXNlci5pZCk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyB1c2VyOiBzYW5pdGl6ZSh1c2VyKSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdsb2dpbiBlcnJvcicsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBGb3Jnb3QgUElOOiByZXNldCB3aXRoIE9UUCAtLS0tLS0tLS0tXG4gIGFwaS5wb3N0KCcvYXV0aC9yZXNldC1waW4nLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgeyBwaG9uZSwgb3RwX2NvZGUsIG5ld19waW4sIGNvbmZpcm1fcGluIH0gPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGlmICghcGhvbmUgfHwgIW90cF9jb2RlIHx8ICFuZXdfcGluKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmdfZmllbGRzJyB9KTtcbiAgICAgIGlmICghL15cXGR7NH0kLy50ZXN0KFN0cmluZyhuZXdfcGluKSkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9waW4nIH0pO1xuICAgICAgaWYgKGNvbmZpcm1fcGluICE9PSB1bmRlZmluZWQgJiYgU3RyaW5nKGNvbmZpcm1fcGluKSAhPT0gU3RyaW5nKG5ld19waW4pKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAncGluX21pc21hdGNoJyB9KTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IG90cE9rID0gYXdhaXQgdmVyaWZ5T3RwKHBob25lLCBTdHJpbmcob3RwX2NvZGUpLCAncmVzZXRfcGluJyk7XG4gICAgICBpZiAoIW90cE9rKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfb3RwJyB9KTtcbiAgICAgIGNvbnN0IHsgZGF0YTogdXNlciB9ID0gKGF3YWl0IGRiLmZyb20oJ3VzZXJzJykuc2VsZWN0KCdpZCcpLmVxKCdwaG9uZScsIHBob25lKS5tYXliZVNpbmdsZSgpKSBhcyB7IGRhdGE6IFVzZXIgfCBudWxsIH07XG4gICAgICBpZiAoIXVzZXIpIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIGNvbnN0IHBpbl9oYXNoID0gYXdhaXQgaGFzaFBpbihTdHJpbmcobmV3X3BpbikpO1xuICAgICAgY29uc3QgeyBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgndXNlcnMnKS51cGRhdGUoeyBwaW5faGFzaCwgcGhvbmVfdmVyaWZpZWQ6IHRydWUgfSkuZXEoJ2lkJywgdXNlci5pZCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IG9rOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ3Jlc2V0LXBpbiBlcnJvcicsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLnBvc3QoJy9hdXRoL2xvZ291dCcsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBhd2FpdCBkZXN0cm95U2Vzc2lvbihyZXEsIHJlcyk7XG4gICAgICByZXMuanNvbih7IG9rOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2gge1xuICAgICAgcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkuZ2V0KCcvYXV0aC9tZScsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCBjdXJyZW50VXNlcihyZXEpO1xuICAgIGlmICghdXNlcikgcmV0dXJuIHJlcy5zdGF0dXMoMjAwKS5qc29uKHsgdXNlcjogbnVsbCB9KTtcbiAgICByZXR1cm4gcmVzLmpzb24oeyB1c2VyOiBzYW5pdGl6ZSh1c2VyKSB9KTtcbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBDcm9wcyAocHVibGljICsgZmFybWVyKSAtLS0tLS0tLS0tXG4gIGFwaS5nZXQoJy9jcm9wcycsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBzdGF0dXMgPSAocmVxLnF1ZXJ5LnN0YXR1cyBhcyBzdHJpbmcpIHx8ICdhcHByb3ZlZCc7XG4gICAgICBsZXQgcSA9IGRiLmZyb20oJ2Nyb3BzJykuc2VsZWN0KCcqLCBmYXJtZXI6dXNlcnMhY3JvcHNfZmFybWVyX2lkX2ZrZXkoKiksIGltYWdlczpjcm9wX2ltYWdlcygqKScpLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgICAgaWYgKHN0YXR1cyA9PT0gJ2FwcHJvdmVkJykgcSA9IHEuZXEoJ3N0YXR1cycsICdhcHByb3ZlZCcpO1xuICAgICAgZWxzZSBpZiAoc3RhdHVzID09PSAnbWluZScpIHtcbiAgICAgICAgLy8gY2FsbGVyIG11c3QgYmUgYXV0aGVkOyBmaWx0ZXJlZCBpbiBKUyBiZWxvd1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcSA9IHEuZXEoJ3N0YXR1cycsIHN0YXR1cyk7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBxO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICBsZXQgcm93cyA9IChkYXRhIGFzIChDcm9wICYgeyBpbWFnZXM6IENyb3BJbWFnZVtdIH0pW10pID8/IFtdO1xuICAgICAgaWYgKHN0YXR1cyA9PT0gJ21pbmUnKSB7XG4gICAgICAgIGNvbnN0IG1lID0gYXdhaXQgY3VycmVudFVzZXIocmVxKTtcbiAgICAgICAgaWYgKCFtZSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAxKS5qc29uKHsgZXJyb3I6ICd1bmF1dGhvcml6ZWQnIH0pO1xuICAgICAgICByb3dzID0gcm93cy5maWx0ZXIoKGMpID0+IGMuZmFybWVyX2lkID09PSBtZS5pZCk7XG4gICAgICB9XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBjcm9wczogcm93cy5tYXAoKGMpID0+ICh7IC4uLnNhbml0aXplQ3JvcChjKSwgaW1hZ2VzOiAoYy5pbWFnZXMgfHwgW10pLnNvcnQoKGEsIGIpID0+IGEuc29ydF9vcmRlciAtIGIuc29ydF9vcmRlcikgfSkpIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0dFVCAvY3JvcHMnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIGNvbnN0IENST1BfTUFYX0lNQUdFUyA9IDU7XG4gIGNvbnN0IENST1BfTUFYX0lNQUdFX1NJWkUgPSA1ICogMTAyNCAqIDEwMjQ7XG4gIGNvbnN0IENST1BfQUxMT1dFRF9UWVBFUyA9IFsnaW1hZ2UvanBlZycsICdpbWFnZS9wbmcnLCAnaW1hZ2Uvd2VicCddO1xuICBjb25zdCBDUk9QX0JVQ0tFVCA9ICdjcm9wLWltYWdlcyc7XG5cbiAgYXN5bmMgZnVuY3Rpb24gdXBsb2FkQ3JvcEltYWdlcyhjcm9wSWQ6IHN0cmluZywgZmlsZXM6IEV4cHJlc3MuTXVsdGVyLkZpbGVbXSk6IFByb21pc2U8Q3JvcEltYWdlW10+IHtcbiAgICBpZiAoIWZpbGVzLmxlbmd0aCkgcmV0dXJuIFtdO1xuICAgIGNvbnN0IHJvd3M6IENyb3BJbWFnZVtdID0gW107XG4gICAgY29uc3QgeyBkYXRhOiBleGlzdGluZyB9ID0gYXdhaXQgZGIuZnJvbSgnY3JvcF9pbWFnZXMnKS5zZWxlY3QoJ3NvcnRfb3JkZXInKS5lcSgnY3JvcF9pZCcsIGNyb3BJZCk7XG4gICAgbGV0IG5leHRPcmRlciA9IGV4aXN0aW5nICYmIGV4aXN0aW5nLmxlbmd0aCA/IE1hdGgubWF4KC4uLmV4aXN0aW5nLm1hcCgoaTogYW55KSA9PiBpLnNvcnRfb3JkZXIpKSArIDEgOiAwO1xuICAgIGZvciAoY29uc3QgZmlsZSBvZiBmaWxlcykge1xuICAgICAgY29uc3QgZXh0ID0gZmlsZS5vcmlnaW5hbG5hbWUuc3BsaXQoJy4nKS5wb3AoKT8udG9Mb3dlckNhc2UoKSB8fCAnanBnJztcbiAgICAgIGNvbnN0IGZpbGVQYXRoID0gYCR7Y3JvcElkfS8ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgOCl9LiR7ZXh0fWA7XG4gICAgICBjb25zdCB7IGVycm9yOiB1cEVyciB9ID0gYXdhaXQgZGIuc3RvcmFnZS5mcm9tKENST1BfQlVDS0VUKS51cGxvYWQoZmlsZVBhdGgsIGZpbGUuYnVmZmVyLCB7IGNvbnRlbnRUeXBlOiBmaWxlLm1pbWV0eXBlLCB1cHNlcnQ6IGZhbHNlIH0pO1xuICAgICAgaWYgKHVwRXJyKSB7IGNvbnNvbGUuZXJyb3IoJ2Nyb3AgaW1hZ2UgdXBsb2FkJywgdXBFcnIpOyBjb250aW51ZTsgfVxuICAgICAgY29uc3QgeyBkYXRhOiBwdWIgfSA9IGRiLnN0b3JhZ2UuZnJvbShDUk9QX0JVQ0tFVCkuZ2V0UHVibGljVXJsKGZpbGVQYXRoKTtcbiAgICAgIGNvbnN0IHsgZGF0YTogaW1nUm93IH0gPSBhd2FpdCBkYi5mcm9tKCdjcm9wX2ltYWdlcycpLmluc2VydCh7IGNyb3BfaWQ6IGNyb3BJZCwgaW1hZ2VfdXJsOiBwdWIucHVibGljVXJsLCBzb3J0X29yZGVyOiBuZXh0T3JkZXIgfSkuc2VsZWN0KCcqJykuc2luZ2xlKCk7XG4gICAgICBpZiAoaW1nUm93KSByb3dzLnB1c2goaW1nUm93IGFzIENyb3BJbWFnZSk7XG4gICAgICBuZXh0T3JkZXIrKztcbiAgICB9XG4gICAgcmV0dXJuIHJvd3M7XG4gIH1cblxuICBhc3luYyBmdW5jdGlvbiBkZWxldGVDcm9wU3RvcmFnZUZpbGUocHVibGljVXJsOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgdXJsID0gbmV3IFVSTChwdWJsaWNVcmwpO1xuICAgICAgY29uc3QgcGFydHMgPSB1cmwucGF0aG5hbWUuc3BsaXQoYC9zdG9yYWdlL3YxL29iamVjdC9wdWJsaWMvJHtDUk9QX0JVQ0tFVH0vYCk7XG4gICAgICBpZiAocGFydHMubGVuZ3RoIDwgMikgcmV0dXJuO1xuICAgICAgYXdhaXQgZGIuc3RvcmFnZS5mcm9tKENST1BfQlVDS0VUKS5yZW1vdmUoW2RlY29kZVVSSUNvbXBvbmVudChwYXJ0c1sxXSldKTtcbiAgICB9IGNhdGNoIChlKSB7IGNvbnNvbGUuZXJyb3IoJ2RlbGV0ZUNyb3BTdG9yYWdlRmlsZScsIGUpOyB9XG4gIH1cblxuICBhcGkuZ2V0KCcvY3JvcHMvOmlkJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgaWQgfSA9IHJlcS5wYXJhbXM7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgnY3JvcHMnKVxuICAgICAgICAuc2VsZWN0KCcqLCBmYXJtZXI6dXNlcnMhY3JvcHNfZmFybWVyX2lkX2ZrZXkoKiksIGltYWdlczpjcm9wX2ltYWdlcygqKScpXG4gICAgICAgIC5lcSgnaWQnLCBpZClcbiAgICAgICAgLm1heWJlU2luZ2xlKCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIGlmICghZGF0YSkgcmV0dXJuIHJlcy5zdGF0dXMoNDA0KS5qc29uKHsgZXJyb3I6ICdub3RfZm91bmQnIH0pO1xuICAgICAgY29uc3QgYyA9IGRhdGEgYXMgQ3JvcCAmIHsgaW1hZ2VzOiBDcm9wSW1hZ2VbXSB9O1xuICAgICAgYy5pbWFnZXMgPSAoYy5pbWFnZXMgfHwgW10pLnNvcnQoKGEsIGIpID0+IGEuc29ydF9vcmRlciAtIGIuc29ydF9vcmRlcik7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBjcm9wOiB7IC4uLnNhbml0aXplQ3JvcChjKSwgaW1hZ2VzOiBjLmltYWdlcyB9IH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0dFVCAvY3JvcHMvOmlkJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkucG9zdCgnL2Nyb3BzJywgcmVxdWlyZVJvbGUoJ2Zhcm1lcicpLCB1cGxvYWRNaWRkbGV3YXJlLmFueSgpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgYm9keSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgY29uc3QgZmlsZXMgPSAocmVxLmZpbGVzIGFzIEV4cHJlc3MuTXVsdGVyLkZpbGVbXSB8IHVuZGVmaW5lZCkgPz8gW107XG4gICAgICBjb25zdCB7IG5hbWUsIGNhdGVnb3J5LCBwcmljZSwgcXVhbnRpdHlfYXZhaWxhYmxlLCB1bml0LCBsb2NhdGlvbiwgaGFydmVzdF9kYXRlLCBkZXNjcmlwdGlvbiB9ID0gYm9keTtcbiAgICAgIGlmICghbmFtZSB8fCBwcmljZSA9PSBudWxsIHx8IHF1YW50aXR5X2F2YWlsYWJsZSA9PSBudWxsKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbWlzc2luZ19maWVsZHMnIH0pO1xuICAgICAgfVxuICAgICAgaWYgKGZpbGVzLmxlbmd0aCA+IENST1BfTUFYX0lNQUdFUykgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICd0b29fbWFueV9pbWFnZXMnIH0pO1xuICAgICAgZm9yIChjb25zdCBmIG9mIGZpbGVzKSB7XG4gICAgICAgIGlmICghQ1JPUF9BTExPV0VEX1RZUEVTLmluY2x1ZGVzKGYubWltZXR5cGUpKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfaW1hZ2VfdHlwZScgfSk7XG4gICAgICAgIGlmIChmLnNpemUgPiBDUk9QX01BWF9JTUFHRV9TSVpFKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ltYWdlX3Rvb19sYXJnZScgfSk7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgnY3JvcHMnKVxuICAgICAgICAuaW5zZXJ0KHtcbiAgICAgICAgICBmYXJtZXJfaWQ6IG1lLmlkLFxuICAgICAgICAgIG5hbWUsXG4gICAgICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5IHx8IG51bGwsXG4gICAgICAgICAgcHJpY2U6IE51bWJlcihwcmljZSksXG4gICAgICAgICAgcXVhbnRpdHlfYXZhaWxhYmxlOiBOdW1iZXIocXVhbnRpdHlfYXZhaWxhYmxlKSxcbiAgICAgICAgICB1bml0OiB1bml0IHx8ICdrZycsXG4gICAgICAgICAgbG9jYXRpb246IGxvY2F0aW9uIHx8IG51bGwsXG4gICAgICAgICAgaGFydmVzdF9kYXRlOiBoYXJ2ZXN0X2RhdGUgfHwgbnVsbCxcbiAgICAgICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb24gfHwgbnVsbCxcbiAgICAgICAgICBzdGF0dXM6ICdwZW5kaW5nJyxcbiAgICAgICAgfSlcbiAgICAgICAgLnNlbGVjdCgnKicpXG4gICAgICAgIC5zaW5nbGUoKTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgY29uc3QgY3JvcCA9IGRhdGEgYXMgQ3JvcDtcbiAgICAgIGF3YWl0IHVwbG9hZENyb3BJbWFnZXMoY3JvcC5pZCwgZmlsZXMpO1xuICAgICAgY29uc3QgeyBkYXRhOiBmdWxsIH0gPSBhd2FpdCBkYi5mcm9tKCdjcm9wcycpLnNlbGVjdCgnKiwgaW1hZ2VzOmNyb3BfaW1hZ2VzKCopJykuZXEoJ2lkJywgY3JvcC5pZCkuc2luZ2xlKCk7XG4gICAgICBjb25zdCByZXN1bHQgPSBmdWxsIGFzIENyb3AgJiB7IGltYWdlczogQ3JvcEltYWdlW10gfTtcbiAgICAgIHJlc3VsdC5pbWFnZXMgPSAocmVzdWx0LmltYWdlcyB8fCBbXSkuc29ydCgoYSwgYikgPT4gYS5zb3J0X29yZGVyIC0gYi5zb3J0X29yZGVyKTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IGNyb3A6IHsgLi4uc2FuaXRpemVDcm9wKHJlc3VsdCksIGltYWdlczogcmVzdWx0LmltYWdlcyB9IH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1BPU1QgL2Nyb3BzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkucGF0Y2goJy9jcm9wcy86aWQnLCByZXF1aXJlUm9sZSgnZmFybWVyJywgJ2FkbWluJyksIHVwbG9hZE1pZGRsZXdhcmUuYW55KCksIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBtZSA9IChyZXEgYXMgYW55KS51c2VyIGFzIFVzZXI7XG4gICAgICBjb25zdCB7IGlkIH0gPSByZXEucGFyYW1zO1xuICAgICAgY29uc3QgYm9keSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgY29uc3QgZmlsZXMgPSAocmVxLmZpbGVzIGFzIEV4cHJlc3MuTXVsdGVyLkZpbGVbXSB8IHVuZGVmaW5lZCkgPz8gW107XG4gICAgICBjb25zdCB7IGRhdGE6IGNyb3AgfSA9IChhd2FpdCBkYi5mcm9tKCdjcm9wcycpLnNlbGVjdCgnKicpLmVxKCdpZCcsIGlkKS5tYXliZVNpbmdsZSgpKSBhcyB7IGRhdGE6IENyb3AgfCBudWxsIH07XG4gICAgICBpZiAoIWNyb3ApIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIGlmIChtZS5yb2xlID09PSAnZmFybWVyJyAmJiBjcm9wLmZhcm1lcl9pZCAhPT0gbWUuaWQpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAzKS5qc29uKHsgZXJyb3I6ICdmb3JiaWRkZW4nIH0pO1xuICAgICAgfVxuICAgICAgbGV0IHJlbW92ZUlkczogc3RyaW5nW10gPSBbXTtcbiAgICAgIGlmIChib2R5LnJlbW92ZV9pbWFnZXMpIHtcbiAgICAgICAgdHJ5IHsgcmVtb3ZlSWRzID0gSlNPTi5wYXJzZShib2R5LnJlbW92ZV9pbWFnZXMpOyB9IGNhdGNoIHsgcmVtb3ZlSWRzID0gW107IH1cbiAgICAgIH1cbiAgICAgIGNvbnN0IHsgZGF0YTogZXhpc3RpbmdJbWdzIH0gPSBhd2FpdCBkYi5mcm9tKCdjcm9wX2ltYWdlcycpLnNlbGVjdCgnaWQnKS5lcSgnY3JvcF9pZCcsIGlkKTtcbiAgICAgIGNvbnN0IGV4aXN0aW5nQ291bnQgPSBleGlzdGluZ0ltZ3M/Lmxlbmd0aCA/PyAwO1xuICAgICAgY29uc3QgcmVtYWluaW5nQWZ0ZXJSZW1vdmUgPSBleGlzdGluZ0NvdW50IC0gcmVtb3ZlSWRzLmxlbmd0aDtcbiAgICAgIGlmIChyZW1haW5pbmdBZnRlclJlbW92ZSArIGZpbGVzLmxlbmd0aCA+IENST1BfTUFYX0lNQUdFUykge1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ3Rvb19tYW55X2ltYWdlcycgfSk7XG4gICAgICB9XG4gICAgICBmb3IgKGNvbnN0IGYgb2YgZmlsZXMpIHtcbiAgICAgICAgaWYgKCFDUk9QX0FMTE9XRURfVFlQRVMuaW5jbHVkZXMoZi5taW1ldHlwZSkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9pbWFnZV90eXBlJyB9KTtcbiAgICAgICAgaWYgKGYuc2l6ZSA+IENST1BfTUFYX0lNQUdFX1NJWkUpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW1hZ2VfdG9vX2xhcmdlJyB9KTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGFsbG93ZWQgPSBbJ25hbWUnLCAnY2F0ZWdvcnknLCAncHJpY2UnLCAncXVhbnRpdHlfYXZhaWxhYmxlJywgJ3VuaXQnLCAnbG9jYXRpb24nLCAnaGFydmVzdF9kYXRlJywgJ2Rlc2NyaXB0aW9uJywgJ3N0YXR1cyddO1xuICAgICAgY29uc3QgcGF0Y2g6IFJlY29yZDxzdHJpbmcsIHVua25vd24+ID0ge307XG4gICAgICBmb3IgKGNvbnN0IGsgb2YgYWxsb3dlZCkge1xuICAgICAgICBpZiAoYm9keVtrXSAhPT0gdW5kZWZpbmVkKSBwYXRjaFtrXSA9IGJvZHlba107XG4gICAgICB9XG4gICAgICBpZiAobWUucm9sZSAhPT0gJ2FkbWluJyAmJiAnc3RhdHVzJyBpbiBwYXRjaCkgZGVsZXRlIHBhdGNoLnN0YXR1cztcbiAgICAgIGlmIChPYmplY3Qua2V5cyhwYXRjaCkubGVuZ3RoKSB7XG4gICAgICAgIGNvbnN0IHsgZXJyb3IgfSA9IGF3YWl0IGRiLmZyb20oJ2Nyb3BzJykudXBkYXRlKHBhdGNoKS5lcSgnaWQnLCBpZCk7XG4gICAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgfVxuICAgICAgaWYgKHJlbW92ZUlkcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIGNvbnN0IHsgZGF0YTogaW1nc1RvUmVtb3ZlIH0gPSBhd2FpdCBkYi5mcm9tKCdjcm9wX2ltYWdlcycpLnNlbGVjdCgnaW1hZ2VfdXJsJykuaW4oJ2lkJywgcmVtb3ZlSWRzKS5lcSgnY3JvcF9pZCcsIGlkKTtcbiAgICAgICAgaWYgKGltZ3NUb1JlbW92ZSAmJiBpbWdzVG9SZW1vdmUubGVuZ3RoKSB7XG4gICAgICAgICAgYXdhaXQgUHJvbWlzZS5hbGwoaW1nc1RvUmVtb3ZlLm1hcCgoaW1nKSA9PiBkZWxldGVDcm9wU3RvcmFnZUZpbGUoaW1nLmltYWdlX3VybCkpKTtcbiAgICAgICAgICBhd2FpdCBkYi5mcm9tKCdjcm9wX2ltYWdlcycpLmRlbGV0ZSgpLmluKCdpZCcsIHJlbW92ZUlkcykuZXEoJ2Nyb3BfaWQnLCBpZCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGF3YWl0IHVwbG9hZENyb3BJbWFnZXMoaWQsIGZpbGVzKTtcbiAgICAgIGNvbnN0IHsgZGF0YTogZnVsbCB9ID0gYXdhaXQgZGIuZnJvbSgnY3JvcHMnKS5zZWxlY3QoJyosIGltYWdlczpjcm9wX2ltYWdlcygqKScpLmVxKCdpZCcsIGlkKS5zaW5nbGUoKTtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGZ1bGwgYXMgQ3JvcCAmIHsgaW1hZ2VzOiBDcm9wSW1hZ2VbXSB9O1xuICAgICAgcmVzdWx0LmltYWdlcyA9IChyZXN1bHQuaW1hZ2VzIHx8IFtdKS5zb3J0KChhLCBiKSA9PiBhLnNvcnRfb3JkZXIgLSBiLnNvcnRfb3JkZXIpO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgY3JvcDogeyAuLi5zYW5pdGl6ZUNyb3AocmVzdWx0KSwgaW1hZ2VzOiByZXN1bHQuaW1hZ2VzIH0gfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignUEFUQ0ggL2Nyb3BzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkuZGVsZXRlKCcvY3JvcHMvOmlkJywgcmVxdWlyZVJvbGUoJ2Zhcm1lcicpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgeyBpZCB9ID0gcmVxLnBhcmFtcztcbiAgICAgIGNvbnN0IHsgZGF0YTogY3JvcCB9ID0gKGF3YWl0IGRiLmZyb20oJ2Nyb3BzJykuc2VsZWN0KCcqJykuZXEoJ2lkJywgaWQpLm1heWJlU2luZ2xlKCkpIGFzIHsgZGF0YTogQ3JvcCB8IG51bGwgfTtcbiAgICAgIGlmICghY3JvcCkgcmV0dXJuIHJlcy5zdGF0dXMoNDA0KS5qc29uKHsgZXJyb3I6ICdub3RfZm91bmQnIH0pO1xuICAgICAgaWYgKGNyb3AuZmFybWVyX2lkICE9PSBtZS5pZCkgcmV0dXJuIHJlcy5zdGF0dXMoNDAzKS5qc29uKHsgZXJyb3I6ICdmb3JiaWRkZW4nIH0pO1xuICAgICAgY29uc3QgeyBkYXRhOiBpbWFnZXMgfSA9IGF3YWl0IGRiLmZyb20oJ2Nyb3BfaW1hZ2VzJykuc2VsZWN0KCdpbWFnZV91cmwnKS5lcSgnY3JvcF9pZCcsIGlkKTtcbiAgICAgIGlmIChpbWFnZXMgJiYgaW1hZ2VzLmxlbmd0aCkge1xuICAgICAgICBhd2FpdCBQcm9taXNlLmFsbChpbWFnZXMubWFwKChpbWcpID0+IGRlbGV0ZUNyb3BTdG9yYWdlRmlsZShpbWcuaW1hZ2VfdXJsKSkpO1xuICAgICAgfVxuICAgICAgY29uc3QgeyBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgnY3JvcHMnKS5kZWxldGUoKS5lcSgnaWQnLCBpZCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IG9rOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0RFTEVURSAvY3JvcHMvOmlkJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyAtLS0tLS0tLS0tIE9yZGVycyAtLS0tLS0tLS0tXG4gIGFwaS5nZXQoJy9vcmRlcnMnLCByZXF1aXJlQXV0aCwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIGxldCBxID0gZGJcbiAgICAgICAgLmZyb20oJ29yZGVycycpXG4gICAgICAgIC5zZWxlY3QoJyosIGNyb3A6Y3JvcHMoKiksIGZhcm1lcjp1c2VycyFvcmRlcnNfZmFybWVyX2lkX2ZrZXkoKiksIHdob2xlc2FsZXI6dXNlcnMhb3JkZXJzX3dob2xlc2FsZXJfaWRfZmtleSgqKScpXG4gICAgICAgIC5vcmRlcignY3JlYXRlZF9hdCcsIHsgYXNjZW5kaW5nOiBmYWxzZSB9KTtcbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IHE7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIGxldCByb3dzID0gKGRhdGEgYXMgT3JkZXJbXSkgPz8gW107XG4gICAgICBpZiAobWUucm9sZSA9PT0gJ2Zhcm1lcicpIHJvd3MgPSByb3dzLmZpbHRlcigobykgPT4gby5mYXJtZXJfaWQgPT09IG1lLmlkKTtcbiAgICAgIGVsc2UgaWYgKG1lLnJvbGUgPT09ICd3aG9sZXNhbGVyJykgcm93cyA9IHJvd3MuZmlsdGVyKChvKSA9PiBvLndob2xlc2FsZXJfaWQgPT09IG1lLmlkKTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IG9yZGVyczogcm93cyB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdHRVQgL29yZGVycycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLnBvc3QoJy9vcmRlcnMnLCByZXF1aXJlUm9sZSgnd2hvbGVzYWxlcicpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgeyBjcm9wX2lkLCBxdWFudGl0eSB9ID0gcmVxLmJvZHkgfHwge307XG4gICAgICBpZiAoIWNyb3BfaWQgfHwgIXF1YW50aXR5KSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmdfZmllbGRzJyB9KTtcbiAgICAgIGNvbnN0IHsgZGF0YTogY3JvcCB9ID0gKGF3YWl0IGRiLmZyb20oJ2Nyb3BzJykuc2VsZWN0KCcqJykuZXEoJ2lkJywgY3JvcF9pZCkubWF5YmVTaW5nbGUoKSkgYXMgeyBkYXRhOiBDcm9wIHwgbnVsbCB9O1xuICAgICAgaWYgKCFjcm9wKSByZXR1cm4gcmVzLnN0YXR1cyg0MDQpLmpzb24oeyBlcnJvcjogJ25vdF9mb3VuZCcgfSk7XG4gICAgICBpZiAoY3JvcC5zdGF0dXMgIT09ICdhcHByb3ZlZCcpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbm90X2FwcHJvdmVkJyB9KTtcbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCdvcmRlcnMnKVxuICAgICAgICAuaW5zZXJ0KHtcbiAgICAgICAgICB3aG9sZXNhbGVyX2lkOiBtZS5pZCxcbiAgICAgICAgICBmYXJtZXJfaWQ6IGNyb3AuZmFybWVyX2lkLFxuICAgICAgICAgIGNyb3BfaWQ6IGNyb3AuaWQsXG4gICAgICAgICAgcXVhbnRpdHk6IE51bWJlcihxdWFudGl0eSksXG4gICAgICAgICAgc3RhdHVzOiAncGVuZGluZycsXG4gICAgICAgIH0pXG4gICAgICAgIC5zZWxlY3QoJyosIGNyb3A6Y3JvcHMoKiksIGZhcm1lcjp1c2VycyFvcmRlcnNfZmFybWVyX2lkX2ZrZXkoKiknKVxuICAgICAgICAuc2luZ2xlKCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IG9yZGVyOiBkYXRhIGFzIE9yZGVyIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1BPU1QgL29yZGVycycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLnBhdGNoKCcvb3JkZXJzLzppZCcsIHJlcXVpcmVBdXRoLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgeyBpZCB9ID0gcmVxLnBhcmFtcztcbiAgICAgIGNvbnN0IHsgc3RhdHVzIH0gPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGlmICghWydwZW5kaW5nJywgJ2NvbXBsZXRlZCcsICdjYW5jZWxsZWQnXS5pbmNsdWRlcyhzdGF0dXMpKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9zdGF0dXMnIH0pO1xuICAgICAgfVxuICAgICAgY29uc3QgeyBkYXRhOiBvcmRlciB9ID0gKGF3YWl0IGRiLmZyb20oJ29yZGVycycpLnNlbGVjdCgnKicpLmVxKCdpZCcsIGlkKS5tYXliZVNpbmdsZSgpKSBhcyB7IGRhdGE6IE9yZGVyIHwgbnVsbCB9O1xuICAgICAgaWYgKCFvcmRlcikgcmV0dXJuIHJlcy5zdGF0dXMoNDA0KS5qc29uKHsgZXJyb3I6ICdub3RfZm91bmQnIH0pO1xuICAgICAgaWYgKG1lLnJvbGUgIT09ICdhZG1pbicgJiYgb3JkZXIuZmFybWVyX2lkICE9PSBtZS5pZCAmJiBvcmRlci53aG9sZXNhbGVyX2lkICE9PSBtZS5pZCkge1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MDMpLmpzb24oeyBlcnJvcjogJ2ZvcmJpZGRlbicgfSk7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYi5mcm9tKCdvcmRlcnMnKS51cGRhdGUoeyBzdGF0dXMgfSkuZXEoJ2lkJywgaWQpLnNlbGVjdCgnKicpLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBvcmRlcjogZGF0YSBhcyBPcmRlciB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdQQVRDSCAvb3JkZXJzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyAtLS0tLS0tLS0tIE1hcmtldCBwcmljZXMgLS0tLS0tLS0tLVxuICBhcGkuZ2V0KCcvcHJpY2VzJywgYXN5bmMgKF9yZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYi5mcm9tKCdtYXJrZXRfcHJpY2VzJykuc2VsZWN0KCcqJykub3JkZXIoJ3Byb2R1Y3QnKTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgcHJpY2VzOiBkYXRhIGFzIE1hcmtldFByaWNlW10gfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignR0VUIC9wcmljZXMnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIGFwaS5wb3N0KCcvcHJpY2VzJywgcmVxdWlyZVJvbGUoJ2FkbWluJyksIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IHByb2R1Y3QsIHVuaXQsIG1pbl9wcmljZSwgbWF4X3ByaWNlLCBhdmdfcHJpY2UsIHRyZW5kIH0gPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGlmICghcHJvZHVjdCB8fCBtaW5fcHJpY2UgPT0gbnVsbCB8fCBtYXhfcHJpY2UgPT0gbnVsbCB8fCBhdmdfcHJpY2UgPT0gbnVsbCkge1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmdfZmllbGRzJyB9KTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCdtYXJrZXRfcHJpY2VzJylcbiAgICAgICAgLmluc2VydCh7XG4gICAgICAgICAgcHJvZHVjdCxcbiAgICAgICAgICB1bml0OiB1bml0IHx8ICdrZycsXG4gICAgICAgICAgbWluX3ByaWNlOiBOdW1iZXIobWluX3ByaWNlKSxcbiAgICAgICAgICBtYXhfcHJpY2U6IE51bWJlcihtYXhfcHJpY2UpLFxuICAgICAgICAgIGF2Z19wcmljZTogTnVtYmVyKGF2Z19wcmljZSksXG4gICAgICAgICAgdHJlbmQ6IHRyZW5kIHx8ICdzdGFibGUnLFxuICAgICAgICAgIHVwZGF0ZWRfYXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcbiAgICAgICAgfSlcbiAgICAgICAgLnNlbGVjdCgnKicpXG4gICAgICAgIC5zaW5nbGUoKTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgcHJpY2U6IGRhdGEgYXMgTWFya2V0UHJpY2UgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignUE9TVCAvcHJpY2VzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkucGF0Y2goJy9wcmljZXMvOmlkJywgcmVxdWlyZVJvbGUoJ2FkbWluJyksIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IGlkIH0gPSByZXEucGFyYW1zO1xuICAgICAgY29uc3QgeyBwcm9kdWN0LCB1bml0LCBtaW5fcHJpY2UsIG1heF9wcmljZSwgYXZnX3ByaWNlLCB0cmVuZCB9ID0gcmVxLmJvZHkgfHwge307XG4gICAgICBjb25zdCBwYXRjaDogUmVjb3JkPHN0cmluZywgdW5rbm93bj4gPSB7IHVwZGF0ZWRfYXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSB9O1xuICAgICAgaWYgKHByb2R1Y3QgIT09IHVuZGVmaW5lZCkgcGF0Y2gucHJvZHVjdCA9IHByb2R1Y3Q7XG4gICAgICBpZiAodW5pdCAhPT0gdW5kZWZpbmVkKSBwYXRjaC51bml0ID0gdW5pdDtcbiAgICAgIGlmIChtaW5fcHJpY2UgIT09IHVuZGVmaW5lZCkgcGF0Y2gubWluX3ByaWNlID0gTnVtYmVyKG1pbl9wcmljZSk7XG4gICAgICBpZiAobWF4X3ByaWNlICE9PSB1bmRlZmluZWQpIHBhdGNoLm1heF9wcmljZSA9IE51bWJlcihtYXhfcHJpY2UpO1xuICAgICAgaWYgKGF2Z19wcmljZSAhPT0gdW5kZWZpbmVkKSBwYXRjaC5hdmdfcHJpY2UgPSBOdW1iZXIoYXZnX3ByaWNlKTtcbiAgICAgIGlmICh0cmVuZCAhPT0gdW5kZWZpbmVkKSBwYXRjaC50cmVuZCA9IHRyZW5kO1xuICAgICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgnbWFya2V0X3ByaWNlcycpLnVwZGF0ZShwYXRjaCkuZXEoJ2lkJywgaWQpLnNlbGVjdCgnKicpLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBwcmljZTogZGF0YSBhcyBNYXJrZXRQcmljZSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdQQVRDSCAvcHJpY2VzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkuZGVsZXRlKCcvcHJpY2VzLzppZCcsIHJlcXVpcmVSb2xlKCdhZG1pbicpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgeyBpZCB9ID0gcmVxLnBhcmFtcztcbiAgICAgIGNvbnN0IHsgZXJyb3IgfSA9IGF3YWl0IGRiLmZyb20oJ21hcmtldF9wcmljZXMnKS5kZWxldGUoKS5lcSgnaWQnLCBpZCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IG9rOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0RFTEVURSAvcHJpY2VzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyAtLS0tLS0tLS0tIENvbnRhY3RzIC0tLS0tLS0tLS1cbiAgYXBpLnBvc3QoJy9jb250YWN0cycsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IG5hbWUsIGVtYWlsLCBtZXNzYWdlIH0gPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGlmICghbmFtZSB8fCAhZW1haWwgfHwgIW1lc3NhZ2UpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbWlzc2luZ19maWVsZHMnIH0pO1xuICAgICAgY29uc3QgeyBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgnY29udGFjdHMnKS5pbnNlcnQoeyBuYW1lLCBlbWFpbCwgbWVzc2FnZSB9KTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgb2s6IHRydWUgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignUE9TVCAvY29udGFjdHMnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIC0tLS0tLS0tLS0gQWRtaW46IHVzZXJzIC0tLS0tLS0tLS1cbiAgYXBpLmdldCgnL2FkbWluL3VzZXJzJywgcmVxdWlyZVJvbGUoJ2FkbWluJyksIGFzeW5jIChfcmVxLCByZXMpID0+IHtcbiAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYi5mcm9tKCd1c2VycycpLnNlbGVjdCgnKicpLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIHJldHVybiByZXMuanNvbih7IHVzZXJzOiAoZGF0YSBhcyBVc2VyW10pLm1hcChzYW5pdGl6ZSkgfSk7XG4gIH0pO1xuXG4gIGFwaS5wYXRjaCgnL2FkbWluL3VzZXJzLzppZCcsIHJlcXVpcmVSb2xlKCdhZG1pbicpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgeyBpZCB9ID0gcmVxLnBhcmFtcztcbiAgICAgIGNvbnN0IHsgc3RhdHVzIH0gPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGlmICghWydhY3RpdmUnLCAnc3VzcGVuZGVkJywgJ2Jhbm5lZCddLmluY2x1ZGVzKHN0YXR1cykpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX3N0YXR1cycgfSk7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYi5mcm9tKCd1c2VycycpLnVwZGF0ZSh7IHN0YXR1cyB9KS5lcSgnaWQnLCBpZCkuc2VsZWN0KCcqJykuc2luZ2xlKCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IHVzZXI6IHNhbml0aXplKGRhdGEgYXMgVXNlcikgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignUEFUQ0ggL2FkbWluL3VzZXJzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyAtLS0tLS0tLS0tIEFkbWluOiBwZW5kaW5nIGNyb3BzIC0tLS0tLS0tLS1cbiAgYXBpLmdldCgnL2FkbWluL2Nyb3BzL3BlbmRpbmcnLCByZXF1aXJlUm9sZSgnYWRtaW4nKSwgYXN5bmMgKF9yZXEsIHJlcykgPT4ge1xuICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IGRiXG4gICAgICAuZnJvbSgnY3JvcHMnKVxuICAgICAgLnNlbGVjdCgnKiwgZmFybWVyOnVzZXJzIWNyb3BzX2Zhcm1lcl9pZF9ma2V5KCopJylcbiAgICAgIC5lcSgnc3RhdHVzJywgJ3BlbmRpbmcnKVxuICAgICAgLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIHJldHVybiByZXMuanNvbih7IGNyb3BzOiAoZGF0YSBhcyBDcm9wW10pLm1hcChzYW5pdGl6ZUNyb3ApIH0pO1xuICB9KTtcblxuICBhcGkuZ2V0KCcvYWRtaW4vb3JkZXJzJywgcmVxdWlyZVJvbGUoJ2FkbWluJyksIGFzeW5jIChfcmVxLCByZXMpID0+IHtcbiAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgLmZyb20oJ29yZGVycycpXG4gICAgICAuc2VsZWN0KCcqLCBjcm9wOmNyb3BzKCopLCBmYXJtZXI6dXNlcnMhb3JkZXJzX2Zhcm1lcl9pZF9ma2V5KCopLCB3aG9sZXNhbGVyOnVzZXJzIW9yZGVyc193aG9sZXNhbGVyX2lkX2ZrZXkoKiknKVxuICAgICAgLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIHJldHVybiByZXMuanNvbih7IG9yZGVyczogZGF0YSBhcyBPcmRlcltdIH0pO1xuICB9KTtcblxuICAvLyAtLS0tLS0tLS0tIFByb2ZpbGUgLS0tLS0tLS0tLVxuICBjb25zdCBQUk9GSUxFX0JVQ0tFVCA9ICdwcm9maWxlLWltYWdlcyc7XG4gIGNvbnN0IFBST0ZJTEVfTUFYX1NJWkUgPSA1ICogMTAyNCAqIDEwMjQ7XG4gIGNvbnN0IFBST0ZJTEVfQUxMT1dFRF9UWVBFUyA9IFsnaW1hZ2UvanBlZycsICdpbWFnZS9wbmcnLCAnaW1hZ2Uvd2VicCddO1xuXG4gIC8vIFBPU1QgL21lL2F2YXRhciBcdTIwMTQgdXBsb2FkIHByb2ZpbGUgcGljdHVyZSAobXVsdGlwYXJ0OiBmaWVsZCBcImF2YXRhclwiKVxuICBhcGkucG9zdCgnL21lL2F2YXRhcicsIHJlcXVpcmVBdXRoLCB1cGxvYWRNaWRkbGV3YXJlLnNpbmdsZSgnYXZhdGFyJyksIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBtZSA9IChyZXEgYXMgYW55KS51c2VyIGFzIFVzZXI7XG4gICAgICBjb25zdCBmaWxlID0gcmVxLmZpbGUgYXMgRXhwcmVzcy5NdWx0ZXIuRmlsZSB8IHVuZGVmaW5lZDtcbiAgICAgIGlmICghZmlsZSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdtaXNzaW5nX2ZpbGUnIH0pO1xuICAgICAgaWYgKCFQUk9GSUxFX0FMTE9XRURfVFlQRVMuaW5jbHVkZXMoZmlsZS5taW1ldHlwZSkpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX2ltYWdlX3R5cGUnIH0pO1xuICAgICAgfVxuICAgICAgaWYgKGZpbGUuc2l6ZSA+IFBST0ZJTEVfTUFYX1NJWkUpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbWFnZV90b29fbGFyZ2UnIH0pO1xuICAgICAgfVxuXG4gICAgICBjb25zdCBleHQgPSBmaWxlLm9yaWdpbmFsbmFtZS5zcGxpdCgnLicpLnBvcCgpPy50b0xvd2VyQ2FzZSgpIHx8ICdqcGcnO1xuICAgICAgY29uc3QgZmlsZVBhdGggPSBgcHJvZmlsZXMvJHttZS5pZH0vJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDgpfS4ke2V4dH1gO1xuXG4gICAgICBjb25zdCB7IGVycm9yOiB1cEVyciB9ID0gYXdhaXQgZGIuc3RvcmFnZVxuICAgICAgICAuZnJvbShQUk9GSUxFX0JVQ0tFVClcbiAgICAgICAgLnVwbG9hZChmaWxlUGF0aCwgZmlsZS5idWZmZXIsIHsgY29udGVudFR5cGU6IGZpbGUubWltZXR5cGUsIHVwc2VydDogZmFsc2UgfSk7XG4gICAgICBpZiAodXBFcnIpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignYXZhdGFyIHVwbG9hZCcsIHVwRXJyKTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgfVxuXG4gICAgICBjb25zdCB7IGRhdGE6IHB1YiB9ID0gZGIuc3RvcmFnZS5mcm9tKFBST0ZJTEVfQlVDS0VUKS5nZXRQdWJsaWNVcmwoZmlsZVBhdGgpO1xuICAgICAgY29uc3QgbmV3QXZhdGFyVXJsID0gcHViLnB1YmxpY1VybDtcblxuICAgICAgLy8gR2V0IG9sZCBhdmF0YXIgVVJMIHRvIGRlbGV0ZSBhZnRlciB1cGRhdGVcbiAgICAgIGNvbnN0IG9sZEF2YXRhclVybCA9IG1lLmF2YXRhcl91cmw7XG5cbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCd1c2VycycpXG4gICAgICAgIC51cGRhdGUoeyBhdmF0YXJfdXJsOiBuZXdBdmF0YXJVcmwgfSlcbiAgICAgICAgLmVxKCdpZCcsIG1lLmlkKVxuICAgICAgICAuc2VsZWN0KCcqJylcbiAgICAgICAgLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG5cbiAgICAgIC8vIERlbGV0ZSBvbGQgYXZhdGFyIGZyb20gc3RvcmFnZSAoYmVzdC1lZmZvcnQpXG4gICAgICBpZiAob2xkQXZhdGFyVXJsKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgY29uc3QgdXJsID0gbmV3IFVSTChvbGRBdmF0YXJVcmwpO1xuICAgICAgICAgIGNvbnN0IHBhcnRzID0gdXJsLnBhdGhuYW1lLnNwbGl0KGAvc3RvcmFnZS92MS9vYmplY3QvcHVibGljLyR7UFJPRklMRV9CVUNLRVR9L2ApO1xuICAgICAgICAgIGlmIChwYXJ0cy5sZW5ndGggPT09IDIgJiYgcGFydHNbMV0pIHtcbiAgICAgICAgICAgIGF3YWl0IGRiLnN0b3JhZ2UuZnJvbShQUk9GSUxFX0JVQ0tFVCkucmVtb3ZlKFtkZWNvZGVVUklDb21wb25lbnQocGFydHNbMV0pXSk7XG4gICAgICAgICAgfVxuICAgICAgICB9IGNhdGNoIChlKSB7IC8qIGlnbm9yZSAqLyB9XG4gICAgICB9XG5cbiAgICAgIHJldHVybiByZXMuanNvbih7IHVzZXI6IHNhbml0aXplKGRhdGEgYXMgVXNlcikgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignUE9TVCAvbWUvYXZhdGFyJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkucGF0Y2goJy9tZScsIHJlcXVpcmVBdXRoLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgYWxsb3dlZCA9IFtcbiAgICAgICAgJ2Z1bGxfbmFtZScsXG4gICAgICAgICdwaG9uZScsXG4gICAgICAgICdidXNpbmVzc19uYW1lJyxcbiAgICAgICAgJ2Zhcm1fbG9jYXRpb24nLFxuICAgICAgICAneWVhcnNfZXhwZXJpZW5jZScsXG4gICAgICAgICdhYm91dF9mYXJtJyxcbiAgICAgICAgJ2J1c2luZXNzX2xvY2F0aW9uJyxcbiAgICAgICAgJ3llYXJzX2luX2J1c2luZXNzJyxcbiAgICAgICAgJ3N0b3JhZ2VfY2FwYWNpdHlfdG9ucycsXG4gICAgICAgICdhdmF0YXJfdXJsJyxcbiAgICAgIF07XG4gICAgICBjb25zdCBwYXRjaDogUmVjb3JkPHN0cmluZywgdW5rbm93bj4gPSB7fTtcbiAgICAgIGZvciAoY29uc3QgayBvZiBhbGxvd2VkKSB7XG4gICAgICAgIGlmIChyZXEuYm9keVtrXSAhPT0gdW5kZWZpbmVkKSBwYXRjaFtrXSA9IHJlcS5ib2R5W2tdO1xuICAgICAgfVxuICAgICAgaWYgKHBhdGNoLnllYXJzX2V4cGVyaWVuY2UgIT09IHVuZGVmaW5lZCkgcGF0Y2gueWVhcnNfZXhwZXJpZW5jZSA9IHBhdGNoLnllYXJzX2V4cGVyaWVuY2UgPT09ICcnID8gbnVsbCA6IE51bWJlcihwYXRjaC55ZWFyc19leHBlcmllbmNlKTtcbiAgICAgIGlmIChwYXRjaC55ZWFyc19pbl9idXNpbmVzcyAhPT0gdW5kZWZpbmVkKSBwYXRjaC55ZWFyc19pbl9idXNpbmVzcyA9IHBhdGNoLnllYXJzX2luX2J1c2luZXNzID09PSAnJyA/IG51bGwgOiBOdW1iZXIocGF0Y2gueWVhcnNfaW5fYnVzaW5lc3MpO1xuICAgICAgaWYgKHBhdGNoLnN0b3JhZ2VfY2FwYWNpdHlfdG9ucyAhPT0gdW5kZWZpbmVkKSBwYXRjaC5zdG9yYWdlX2NhcGFjaXR5X3RvbnMgPSBwYXRjaC5zdG9yYWdlX2NhcGFjaXR5X3RvbnMgPT09ICcnID8gbnVsbCA6IE51bWJlcihwYXRjaC5zdG9yYWdlX2NhcGFjaXR5X3RvbnMpO1xuICAgICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgndXNlcnMnKS51cGRhdGUocGF0Y2gpLmVxKCdpZCcsIG1lLmlkKS5zZWxlY3QoJyonKS5zaW5nbGUoKTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgdXNlcjogc2FuaXRpemUoZGF0YSBhcyBVc2VyKSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdQQVRDSCAvbWUnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIC0tLS0tLS0tLS0gUmV2aWV3cyAodmVyaWZpZWQgXHUyMDE0IG9ubHkgYWZ0ZXIgYSBjb21wbGV0ZWQgb3JkZXIpIC0tLS0tLS0tLS1cbiAgLy8gR0VUIC9yZXZpZXdzP3VzZXJfaWQ9PGlkPiAgXHUyMDE0IGxpc3QgcmV2aWV3cyByZWNlaXZlZCBieSBhIHVzZXIgKG5ld2VzdCBmaXJzdCksXG4gIC8vICAgd2l0aCB0aGUgcmV2aWV3ZXIgKyB0aGUgdW5kZXJseWluZyBvcmRlciAoY3JvcCwgY291bnRlcnBhcnQsIGFtb3VudCwgZGF0ZSkuXG4gIC8vIEdFVCAvcmV2aWV3cy9taW5lICAgICAgICAgIFx1MjAxNCByZXZpZXdzIEkgaGF2ZSB3cml0dGVuLlxuICAvLyBHRVQgL3Jldmlld3MvZWxpZ2libGUgICAgICBcdTIwMTQgY29tcGxldGVkIG9yZGVycyBvZiBtaW5lIHRoYXQgSSBoYXZlbid0IHJldmlld2VkXG4gIC8vICAgeWV0IChmcm9tIG15IHNpZGUpLCB1c2VkIHRvIHBvcHVsYXRlIHRoZSBcImxlYXZlIGEgcmV2aWV3XCIgcGlja2VyLlxuICAvLyBQT1NUIC9yZXZpZXdzICAgICAgICAgICAgICBcdTIwMTQgbGVhdmUgYSByZXZpZXcgZm9yIG9uZSBvZiBteSBjb21wbGV0ZWQgb3JkZXJzLlxuICBhcGkuZ2V0KCcvcmV2aWV3cycsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB1c2VySWQgPSByZXEucXVlcnkudXNlcl9pZCBhcyBzdHJpbmcgfCB1bmRlZmluZWQ7XG4gICAgICBpZiAoIXVzZXJJZCkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdtaXNzaW5nX3VzZXInIH0pO1xuICAgICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGJcbiAgICAgICAgLmZyb20oJ3Jldmlld3MnKVxuICAgICAgICAuc2VsZWN0KCcqLCByZXZpZXdlcjp1c2VycyFyZXZpZXdzX3Jldmlld2VyX2lkX2ZrZXkoKiksIG9yZGVyOm9yZGVycygqKScpXG4gICAgICAgIC5lcSgncmV2aWV3ZWVfaWQnLCB1c2VySWQpXG4gICAgICAgIC5vcmRlcignY3JlYXRlZF9hdCcsIHsgYXNjZW5kaW5nOiBmYWxzZSB9KTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgY29uc3Qgcm93cyA9IChkYXRhIGFzIFJldmlld1tdKSA/PyBbXTtcbiAgICAgIC8vIEFnZ3JlZ2F0ZSByYXRpbmcuXG4gICAgICBjb25zdCBhdmcgPSByb3dzLmxlbmd0aCA/IHJvd3MucmVkdWNlKChzLCByKSA9PiBzICsgTnVtYmVyKHIucmF0aW5nKSwgMCkgLyByb3dzLmxlbmd0aCA6IDA7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyByZXZpZXdzOiByb3dzLm1hcChzYW5pdGl6ZVJldmlldyksIGF2ZXJhZ2U6IE1hdGgucm91bmQoYXZnICogMTApIC8gMTAsIGNvdW50OiByb3dzLmxlbmd0aCB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdHRVQgL3Jldmlld3MnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIGFwaS5nZXQoJy9yZXZpZXdzL21pbmUnLCByZXF1aXJlQXV0aCwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCdyZXZpZXdzJylcbiAgICAgICAgLnNlbGVjdCgnKiwgcmV2aWV3ZWU6dXNlcnMhcmV2aWV3c19yZXZpZXdlZV9pZF9ma2V5KCopLCBvcmRlcjpvcmRlcnMoKiknKVxuICAgICAgICAuZXEoJ3Jldmlld2VyX2lkJywgbWUuaWQpXG4gICAgICAgIC5vcmRlcignY3JlYXRlZF9hdCcsIHsgYXNjZW5kaW5nOiBmYWxzZSB9KTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgcmV2aWV3czogKGRhdGEgYXMgUmV2aWV3W10pLm1hcChzYW5pdGl6ZVJldmlldykgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignR0VUIC9yZXZpZXdzL21pbmUnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIGFwaS5nZXQoJy9yZXZpZXdzL2VsaWdpYmxlJywgcmVxdWlyZUF1dGgsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBtZSA9IChyZXEgYXMgYW55KS51c2VyIGFzIFVzZXI7XG4gICAgICAvLyBBbGwgY29tcGxldGVkIG9yZGVycyB3aGVyZSBJJ20gYSBwYXJ0aWNpcGFudC5cbiAgICAgIGNvbnN0IHsgZGF0YTogb3JkZXJzLCBlcnJvciB9ID0gYXdhaXQgZGJcbiAgICAgICAgLmZyb20oJ29yZGVycycpXG4gICAgICAgIC5zZWxlY3QoJyosIGNyb3A6Y3JvcHMoKiksIGZhcm1lcjp1c2VycyFvcmRlcnNfZmFybWVyX2lkX2ZrZXkoKiksIHdob2xlc2FsZXI6dXNlcnMhb3JkZXJzX3dob2xlc2FsZXJfaWRfZmtleSgqKScpXG4gICAgICAgIC5lcSgnc3RhdHVzJywgJ2NvbXBsZXRlZCcpXG4gICAgICAgIC5vcmRlcignY3JlYXRlZF9hdCcsIHsgYXNjZW5kaW5nOiBmYWxzZSB9KTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgY29uc3QgbWluZSA9IChvcmRlcnMgYXMgT3JkZXJbXSB8IG51bGwpID8/IFtdO1xuICAgICAgY29uc3QgcGFydGljaXBhdGVkID0gbWluZS5maWx0ZXIoKG8pID0+IG8uZmFybWVyX2lkID09PSBtZS5pZCB8fCBvLndob2xlc2FsZXJfaWQgPT09IG1lLmlkKTtcbiAgICAgIC8vIEV4aXN0aW5nIHJldmlld3MgSSd2ZSBhbHJlYWR5IHdyaXR0ZW4uXG4gICAgICBjb25zdCB7IGRhdGE6IG1pbmVSZXZpZXdzIH0gPSBhd2FpdCBkYi5mcm9tKCdyZXZpZXdzJykuc2VsZWN0KCdvcmRlcl9pZCwgcmV2aWV3ZXJfaWQnKS5lcSgncmV2aWV3ZXJfaWQnLCBtZS5pZCk7XG4gICAgICBjb25zdCByZXZpZXdlZCA9IG5ldyBTZXQoKChtaW5lUmV2aWV3cyBhcyBSZXZpZXdbXSB8IG51bGwpID8/IFtdKS5tYXAoKHIpID0+IHIub3JkZXJfaWQpKTtcbiAgICAgIGNvbnN0IGVsaWdpYmxlID0gcGFydGljaXBhdGVkLmZpbHRlcigobykgPT4gIXJldmlld2VkLmhhcyhvLmlkKSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBvcmRlcnM6IGVsaWdpYmxlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0dFVCAvcmV2aWV3cy9lbGlnaWJsZScsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLnBvc3QoJy9yZXZpZXdzJywgcmVxdWlyZUF1dGgsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBtZSA9IChyZXEgYXMgYW55KS51c2VyIGFzIFVzZXI7XG4gICAgICBjb25zdCB7IG9yZGVyX2lkLCByYXRpbmcsIGNvbW1lbnQgfSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgaWYgKCFvcmRlcl9pZCB8fCAhcmF0aW5nKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmdfZmllbGRzJyB9KTtcbiAgICAgIGNvbnN0IHIgPSBOdW1iZXIocmF0aW5nKTtcbiAgICAgIGlmICghTnVtYmVyLmlzSW50ZWdlcihyKSB8fCByIDwgMSB8fCByID4gNSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX3JhdGluZycgfSk7XG4gICAgICBjb25zdCB0cmltbWVkQ29tbWVudCA9IGNvbW1lbnQgPyBTdHJpbmcoY29tbWVudCkuc2xpY2UoMCwgNTAwKSA6IG51bGw7XG5cbiAgICAgIGNvbnN0IHsgZGF0YTogb3JkZXIgfSA9IChhd2FpdCBkYi5mcm9tKCdvcmRlcnMnKS5zZWxlY3QoJyonKS5lcSgnaWQnLCBvcmRlcl9pZCkubWF5YmVTaW5nbGUoKSkgYXMgeyBkYXRhOiBPcmRlciB8IG51bGwgfTtcbiAgICAgIGlmICghb3JkZXIpIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnb3JkZXJfbm90X2ZvdW5kJyB9KTtcbiAgICAgIGlmIChvcmRlci5zdGF0dXMgIT09ICdjb21wbGV0ZWQnKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ29yZGVyX25vdF9jb21wbGV0ZWQnIH0pO1xuXG4gICAgICBsZXQgcmV2aWV3ZXJSb2xlOiAnZmFybWVyJyB8ICd3aG9sZXNhbGVyJyB8IG51bGwgPSBudWxsO1xuICAgICAgbGV0IHJldmlld2VlSWQ6IHN0cmluZyB8IG51bGwgPSBudWxsO1xuICAgICAgaWYgKG9yZGVyLmZhcm1lcl9pZCA9PT0gbWUuaWQgJiYgbWUucm9sZSA9PT0gJ2Zhcm1lcicpIHtcbiAgICAgICAgcmV2aWV3ZXJSb2xlID0gJ2Zhcm1lcic7XG4gICAgICAgIHJldmlld2VlSWQgPSBvcmRlci53aG9sZXNhbGVyX2lkO1xuICAgICAgfSBlbHNlIGlmIChvcmRlci53aG9sZXNhbGVyX2lkID09PSBtZS5pZCAmJiBtZS5yb2xlID09PSAnd2hvbGVzYWxlcicpIHtcbiAgICAgICAgcmV2aWV3ZXJSb2xlID0gJ3dob2xlc2FsZXInO1xuICAgICAgICByZXZpZXdlZUlkID0gb3JkZXIuZmFybWVyX2lkO1xuICAgICAgfVxuICAgICAgaWYgKCFyZXZpZXdlclJvbGUgfHwgIXJldmlld2VlSWQpIHJldHVybiByZXMuc3RhdHVzKDQwMykuanNvbih7IGVycm9yOiAnZm9yYmlkZGVuJyB9KTtcblxuICAgICAgLy8gRW5mb3JjZSBvbmUtcGVyLWRpcmVjdGlvbiB2aWEgdXBzZXJ0LWxpa2UgaW5zZXJ0IHdpdGggY29uZmxpY3QgaGFuZGxpbmcuXG4gICAgICBjb25zdCB7IGRhdGE6IGV4aXN0aW5nIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgncmV2aWV3cycpXG4gICAgICAgIC5zZWxlY3QoJ2lkJylcbiAgICAgICAgLmVxKCdvcmRlcl9pZCcsIG9yZGVyX2lkKVxuICAgICAgICAuZXEoJ3Jldmlld2VyX3JvbGUnLCByZXZpZXdlclJvbGUpXG4gICAgICAgIC5tYXliZVNpbmdsZSgpO1xuICAgICAgaWYgKGV4aXN0aW5nKSByZXR1cm4gcmVzLnN0YXR1cyg0MDkpLmpzb24oeyBlcnJvcjogJ2FscmVhZHlfcmV2aWV3ZWQnIH0pO1xuXG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgncmV2aWV3cycpXG4gICAgICAgIC5pbnNlcnQoe1xuICAgICAgICAgIG9yZGVyX2lkLFxuICAgICAgICAgIHJldmlld2VyX2lkOiBtZS5pZCxcbiAgICAgICAgICByZXZpZXdlZV9pZDogcmV2aWV3ZWVJZCxcbiAgICAgICAgICByZXZpZXdlcl9yb2xlOiByZXZpZXdlclJvbGUsXG4gICAgICAgICAgcmF0aW5nOiByLFxuICAgICAgICAgIGNvbW1lbnQ6IHRyaW1tZWRDb21tZW50LFxuICAgICAgICB9KVxuICAgICAgICAuc2VsZWN0KCcqJylcbiAgICAgICAgLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyByZXZpZXc6IHNhbml0aXplUmV2aWV3KGRhdGEgYXMgUmV2aWV3KSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdQT1NUIC9yZXZpZXdzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyAtLS0tLS0tLS0tIFN0YXRlbWVudCAodHJhbnNhY3Rpb24gaGlzdG9yeSkgLS0tLS0tLS0tLVxuICAvLyBHRVQgL3N0YXRlbWVudD9mcm9tPVlZWVktTU0tREQmdG89WVlZWS1NTS1ERCZzdGF0dXM9Li4uXG4gIC8vIFJldHVybnMgdGhlIGNhbGxlcidzIG9yZGVycyAoYXMgZmFybWVyIG9yIHdob2xlc2FsZXIgZGVwZW5kaW5nIG9uIHJvbGUpLFxuICAvLyBlYWNoIHdpdGggY3JvcCArIGNvdW50ZXJwYXJ0LCBwbHVzIGEgcnVubmluZyBncmFuZCB0b3RhbCBvZiBjb21wbGV0ZWRcbiAgLy8gdHJhbnNhY3Rpb25zLiBGaWx0ZXJzIG9wdGlvbmFsLlxuICBhcGkuZ2V0KCcvc3RhdGVtZW50JywgcmVxdWlyZUF1dGgsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBtZSA9IChyZXEgYXMgYW55KS51c2VyIGFzIFVzZXI7XG4gICAgICBjb25zdCBmcm9tID0gcmVxLnF1ZXJ5LmZyb20gYXMgc3RyaW5nIHwgdW5kZWZpbmVkO1xuICAgICAgY29uc3QgdG8gPSByZXEucXVlcnkudG8gYXMgc3RyaW5nIHwgdW5kZWZpbmVkO1xuICAgICAgY29uc3Qgc3RhdHVzID0gcmVxLnF1ZXJ5LnN0YXR1cyBhcyBzdHJpbmcgfCB1bmRlZmluZWQ7XG5cbiAgICAgIGxldCBxID0gZGJcbiAgICAgICAgLmZyb20oJ29yZGVycycpXG4gICAgICAgIC5zZWxlY3QoJyosIGNyb3A6Y3JvcHMoKiksIGZhcm1lcjp1c2VycyFvcmRlcnNfZmFybWVyX2lkX2ZrZXkoKiksIHdob2xlc2FsZXI6dXNlcnMhb3JkZXJzX3dob2xlc2FsZXJfaWRfZmtleSgqKScpXG4gICAgICAgIC5vcmRlcignY3JlYXRlZF9hdCcsIHsgYXNjZW5kaW5nOiBmYWxzZSB9KTtcbiAgICAgIGlmIChzdGF0dXMgJiYgWydwZW5kaW5nJywgJ2NvbXBsZXRlZCcsICdjYW5jZWxsZWQnXS5pbmNsdWRlcyhzdGF0dXMpKSB7XG4gICAgICAgIHEgPSBxLmVxKCdzdGF0dXMnLCBzdGF0dXMpO1xuICAgICAgfVxuICAgICAgaWYgKGZyb20pIHEgPSBxLmd0ZSgnY3JlYXRlZF9hdCcsIG5ldyBEYXRlKGZyb20pLnRvSVNPU3RyaW5nKCkpO1xuICAgICAgaWYgKHRvKSB7XG4gICAgICAgIGNvbnN0IHRvRGF0ZSA9IG5ldyBEYXRlKHRvKTtcbiAgICAgICAgdG9EYXRlLnNldEhvdXJzKDIzLCA1OSwgNTksIDk5OSk7XG4gICAgICAgIHEgPSBxLmx0ZSgnY3JlYXRlZF9hdCcsIHRvRGF0ZS50b0lTT1N0cmluZygpKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IHE7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIGxldCByb3dzID0gKGRhdGEgYXMgT3JkZXJbXSkgPz8gW107XG4gICAgICBpZiAobWUucm9sZSA9PT0gJ2Zhcm1lcicpIHJvd3MgPSByb3dzLmZpbHRlcigobykgPT4gby5mYXJtZXJfaWQgPT09IG1lLmlkKTtcbiAgICAgIGVsc2UgaWYgKG1lLnJvbGUgPT09ICd3aG9sZXNhbGVyJykgcm93cyA9IHJvd3MuZmlsdGVyKChvKSA9PiBvLndob2xlc2FsZXJfaWQgPT09IG1lLmlkKTtcbiAgICAgIC8vIEFkbWluIHNlZXMgYWxsIChubyBmaWx0ZXIpLlxuXG4gICAgICAvLyBSdW5uaW5nIHRvdGFsIG9mIGNvbXBsZXRlZCBvcmRlcnMgb25seS5cbiAgICAgIGxldCBydW5uaW5nID0gMDtcbiAgICAgIGNvbnN0IGVucmljaGVkID0gcm93cy5tYXAoKG8pID0+IHtcbiAgICAgICAgY29uc3QgYW1vdW50ID0gby5jcm9wID8gTnVtYmVyKG8uY3JvcC5wcmljZSkgKiBOdW1iZXIoby5xdWFudGl0eSkgOiAwO1xuICAgICAgICBpZiAoby5zdGF0dXMgPT09ICdjb21wbGV0ZWQnKSBydW5uaW5nICs9IGFtb3VudDtcbiAgICAgICAgcmV0dXJuIHsgLi4ubywgYW1vdW50IH07XG4gICAgICB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7XG4gICAgICAgIG9yZGVyczogZW5yaWNoZWQsXG4gICAgICAgIHRvdGFsOiBydW5uaW5nLFxuICAgICAgICBjb3VudDogcm93cy5sZW5ndGgsXG4gICAgICAgIGNvbXBsZXRlZENvdW50OiByb3dzLmZpbHRlcigobykgPT4gby5zdGF0dXMgPT09ICdjb21wbGV0ZWQnKS5sZW5ndGgsXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdHRVQgL3N0YXRlbWVudCcsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBQcm9kdWN0cyAoZmFybWVyIHByb2R1Y3QgbWFuYWdlbWVudCkgLS0tLS0tLS0tLVxuICBjb25zdCBQUk9EVUNUX0NBVEVHT1JJRVMgPSBbJ1ZlZ2V0YWJsZXMnLCAnRnJ1aXRzJywgJ0dyYWlucycsICdEYWlyeScsICdIZXJicycsICdTcGljZXMnLCAnUHVsc2VzJywgJ090aGVycyddIGFzIGNvbnN0O1xuICBjb25zdCBQUk9EVUNUX1VOSVRTID0gWydrZycsICd0b24nLCAnc2FjaycsICdjcmF0ZScsICdkb3plbicsICdsaXRlciddIGFzIGNvbnN0O1xuICBjb25zdCBQUk9EVUNUX0FWQUlMQUJJTElUWSA9IFsnQXZhaWxhYmxlJywgJ0xpbWl0ZWQgU3RvY2snLCAnU29sZCBPdXQnXSBhcyBjb25zdDtcbiAgY29uc3QgTUFYX0lNQUdFUyA9IDU7XG4gIGNvbnN0IE1BWF9JTUFHRV9TSVpFID0gNSAqIDEwMjQgKiAxMDI0OyAvLyA1IE1CXG4gIGNvbnN0IEFMTE9XRURfSU1BR0VfVFlQRVMgPSBbJ2ltYWdlL2pwZWcnLCAnaW1hZ2UvcG5nJywgJ2ltYWdlL3dlYnAnXTtcbiAgY29uc3QgU1RPUkFHRV9CVUNLRVQgPSAncHJvZHVjdC1pbWFnZXMnO1xuXG4gIGZ1bmN0aW9uIHZhbGlkYXRlUHJvZHVjdChib2R5OiBhbnkpOiBzdHJpbmcgfCBudWxsIHtcbiAgICBpZiAoIWJvZHkucHJvZHVjdF9uYW1lIHx8ICFTdHJpbmcoYm9keS5wcm9kdWN0X25hbWUpLnRyaW0oKSkgcmV0dXJuICdtaXNzaW5nX25hbWUnO1xuICAgIGlmICghYm9keS5jYXRlZ29yeSB8fCAhUFJPRFVDVF9DQVRFR09SSUVTLmluY2x1ZGVzKGJvZHkuY2F0ZWdvcnkpKSByZXR1cm4gJ2ludmFsaWRfY2F0ZWdvcnknO1xuICAgIGlmIChib2R5LnByaWNlID09IG51bGwgfHwgTnVtYmVyKGJvZHkucHJpY2UpIDw9IDApIHJldHVybiAnaW52YWxpZF9wcmljZSc7XG4gICAgaWYgKGJvZHkucXVhbnRpdHkgPT0gbnVsbCB8fCBOdW1iZXIoYm9keS5xdWFudGl0eSkgPCAwKSByZXR1cm4gJ2ludmFsaWRfcXVhbnRpdHknO1xuICAgIGlmICghYm9keS51bml0IHx8ICFQUk9EVUNUX1VOSVRTLmluY2x1ZGVzKGJvZHkudW5pdCkpIHJldHVybiAnaW52YWxpZF91bml0JztcbiAgICBpZiAoIWJvZHkuZGlzdHJpY3QgfHwgIVN0cmluZyhib2R5LmRpc3RyaWN0KS50cmltKCkpIHJldHVybiAnbWlzc2luZ19kaXN0cmljdCc7XG4gICAgaWYgKGJvZHkuYXZhaWxhYmlsaXR5ICYmICFQUk9EVUNUX0FWQUlMQUJJTElUWS5pbmNsdWRlcyhib2R5LmF2YWlsYWJpbGl0eSkpIHJldHVybiAnaW52YWxpZF9hdmFpbGFiaWxpdHknO1xuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgLy8gR0VUIC9wcm9kdWN0cz9mYXJtZXJfaWQ9PGlkPiAgXHUyMDE0IGxpc3QgcHJvZHVjdHMgZm9yIGEgZmFybWVyIChvciBhbGwgaWYgbm8gZmlsdGVyKVxuICAvLyBHRVQgL3Byb2R1Y3RzP21pbmU9dHJ1ZSAgICAgICBcdTIwMTQgbGlzdCB0aGUgbG9nZ2VkLWluIGZhcm1lcidzIHByb2R1Y3RzXG4gIGFwaS5nZXQoJy9wcm9kdWN0cycsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBtaW5lID0gcmVxLnF1ZXJ5Lm1pbmUgPT09ICd0cnVlJztcbiAgICAgIGNvbnN0IGZhcm1lcklkID0gcmVxLnF1ZXJ5LmZhcm1lcl9pZCBhcyBzdHJpbmcgfCB1bmRlZmluZWQ7XG5cbiAgICAgIGxldCBxID0gZGIuZnJvbSgncHJvZHVjdHMnKS5zZWxlY3QoJyosIGltYWdlczpwcm9kdWN0X2ltYWdlcygqKScpLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgICAgaWYgKG1pbmUpIHtcbiAgICAgICAgY29uc3QgbWUgPSBhd2FpdCBjdXJyZW50VXNlcihyZXEpO1xuICAgICAgICBpZiAoIW1lKSByZXR1cm4gcmVzLnN0YXR1cyg0MDEpLmpzb24oeyBlcnJvcjogJ3VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgIHEgPSBxLmVxKCdmYXJtZXJfaWQnLCBtZS5pZCk7XG4gICAgICB9IGVsc2UgaWYgKGZhcm1lcklkKSB7XG4gICAgICAgIHEgPSBxLmVxKCdmYXJtZXJfaWQnLCBmYXJtZXJJZCk7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBxO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICBjb25zdCByb3dzID0gKGRhdGEgYXMgKFByb2R1Y3QgJiB7IGltYWdlczogUHJvZHVjdEltYWdlW10gfSlbXSkgPz8gW107XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBwcm9kdWN0czogcm93cy5tYXAoKHApID0+ICh7IC4uLnAsIGltYWdlczogKHAuaW1hZ2VzIHx8IFtdKS5zb3J0KChhLCBiKSA9PiBhLnNvcnRfb3JkZXIgLSBiLnNvcnRfb3JkZXIpIH0pKSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdHRVQgL3Byb2R1Y3RzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyBHRVQgL3Byb2R1Y3RzLzppZCBcdTIwMTQgc2luZ2xlIHByb2R1Y3Qgd2l0aCBpbWFnZXNcbiAgYXBpLmdldCgnL3Byb2R1Y3RzLzppZCcsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IGlkIH0gPSByZXEucGFyYW1zO1xuICAgICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGJcbiAgICAgICAgLmZyb20oJ3Byb2R1Y3RzJylcbiAgICAgICAgLnNlbGVjdCgnKiwgaW1hZ2VzOnByb2R1Y3RfaW1hZ2VzKCopJylcbiAgICAgICAgLmVxKCdpZCcsIGlkKVxuICAgICAgICAubWF5YmVTaW5nbGUoKTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgaWYgKCFkYXRhKSByZXR1cm4gcmVzLnN0YXR1cyg0MDQpLmpzb24oeyBlcnJvcjogJ25vdF9mb3VuZCcgfSk7XG4gICAgICBjb25zdCBwID0gZGF0YSBhcyBQcm9kdWN0ICYgeyBpbWFnZXM6IFByb2R1Y3RJbWFnZVtdIH07XG4gICAgICBwLmltYWdlcyA9IChwLmltYWdlcyB8fCBbXSkuc29ydCgoYSwgYikgPT4gYS5zb3J0X29yZGVyIC0gYi5zb3J0X29yZGVyKTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IHByb2R1Y3Q6IHAgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignR0VUIC9wcm9kdWN0cy86aWQnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIFBPU1QgL3Byb2R1Y3RzIFx1MjAxNCBjcmVhdGUgYSBuZXcgcHJvZHVjdCAobXVsdGlwYXJ0OiBmaWVsZHMgKyBpbWFnZXNbXSlcbiAgYXBpLnBvc3QoJy9wcm9kdWN0cycsIHJlcXVpcmVSb2xlKCdmYXJtZXInKSwgdXBsb2FkTWlkZGxld2FyZS5hbnkoKSwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIGNvbnN0IGJvZHkgPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGNvbnN0IGZpbGVzID0gKHJlcS5maWxlcyBhcyBFeHByZXNzLk11bHRlci5GaWxlW10gfCB1bmRlZmluZWQpID8/IFtdO1xuXG4gICAgICBjb25zdCB2YWxpZGF0aW9uRXJyb3IgPSB2YWxpZGF0ZVByb2R1Y3QoYm9keSk7XG4gICAgICBpZiAodmFsaWRhdGlvbkVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogdmFsaWRhdGlvbkVycm9yIH0pO1xuXG4gICAgICBpZiAoZmlsZXMubGVuZ3RoID4gTUFYX0lNQUdFUykgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICd0b29fbWFueV9pbWFnZXMnIH0pO1xuICAgICAgZm9yIChjb25zdCBmIG9mIGZpbGVzKSB7XG4gICAgICAgIGlmICghQUxMT1dFRF9JTUFHRV9UWVBFUy5pbmNsdWRlcyhmLm1pbWV0eXBlKSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX2ltYWdlX3R5cGUnIH0pO1xuICAgICAgICBpZiAoZi5zaXplID4gTUFYX0lNQUdFX1NJWkUpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW1hZ2VfdG9vX2xhcmdlJyB9KTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgeyBkYXRhOiBwcm9kdWN0LCBlcnJvciB9ID0gYXdhaXQgZGJcbiAgICAgICAgLmZyb20oJ3Byb2R1Y3RzJylcbiAgICAgICAgLmluc2VydCh7XG4gICAgICAgICAgZmFybWVyX2lkOiBtZS5pZCxcbiAgICAgICAgICBwcm9kdWN0X25hbWU6IFN0cmluZyhib2R5LnByb2R1Y3RfbmFtZSkudHJpbSgpLFxuICAgICAgICAgIGNhdGVnb3J5OiBib2R5LmNhdGVnb3J5LFxuICAgICAgICAgIGRlc2NyaXB0aW9uOiBib2R5LmRlc2NyaXB0aW9uID8gU3RyaW5nKGJvZHkuZGVzY3JpcHRpb24pLnRyaW0oKSA6IG51bGwsXG4gICAgICAgICAgcHJpY2U6IE51bWJlcihib2R5LnByaWNlKSxcbiAgICAgICAgICBxdWFudGl0eTogTnVtYmVyKGJvZHkucXVhbnRpdHkpLFxuICAgICAgICAgIHVuaXQ6IGJvZHkudW5pdCxcbiAgICAgICAgICBkaXN0cmljdDogU3RyaW5nKGJvZHkuZGlzdHJpY3QpLnRyaW0oKSxcbiAgICAgICAgICBtdW5pY2lwYWxpdHk6IGJvZHkubXVuaWNpcGFsaXR5ID8gU3RyaW5nKGJvZHkubXVuaWNpcGFsaXR5KS50cmltKCkgOiBudWxsLFxuICAgICAgICAgIGhhcnZlc3RfZGF0ZTogYm9keS5oYXJ2ZXN0X2RhdGUgfHwgbnVsbCxcbiAgICAgICAgICBhdmFpbGFiaWxpdHk6IGJvZHkuYXZhaWxhYmlsaXR5IHx8ICdBdmFpbGFibGUnLFxuICAgICAgICB9KVxuICAgICAgICAuc2VsZWN0KCcqJylcbiAgICAgICAgLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG5cbiAgICAgIC8vIFVwbG9hZCBpbWFnZXMgdG8gU3VwYWJhc2UgU3RvcmFnZSBhbmQgY3JlYXRlIHByb2R1Y3RfaW1hZ2VzIHJvd3NcbiAgICAgIGNvbnN0IGltYWdlUm93cyA9IGF3YWl0IHVwbG9hZFByb2R1Y3RJbWFnZXMocHJvZHVjdC5pZCwgZmlsZXMpO1xuICAgICAgY29uc3QgeyBkYXRhOiBmdWxsUHJvZHVjdCB9ID0gYXdhaXQgZGJcbiAgICAgICAgLmZyb20oJ3Byb2R1Y3RzJylcbiAgICAgICAgLnNlbGVjdCgnKiwgaW1hZ2VzOnByb2R1Y3RfaW1hZ2VzKCopJylcbiAgICAgICAgLmVxKCdpZCcsIHByb2R1Y3QuaWQpXG4gICAgICAgIC5zaW5nbGUoKTtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGZ1bGxQcm9kdWN0IGFzIFByb2R1Y3QgJiB7IGltYWdlczogUHJvZHVjdEltYWdlW10gfTtcbiAgICAgIHJlc3VsdC5pbWFnZXMgPSAocmVzdWx0LmltYWdlcyB8fCBbXSkuc29ydCgoYSwgYikgPT4gYS5zb3J0X29yZGVyIC0gYi5zb3J0X29yZGVyKTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IHByb2R1Y3Q6IHJlc3VsdCB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdQT1NUIC9wcm9kdWN0cycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gUEFUQ0ggL3Byb2R1Y3RzLzppZCBcdTIwMTQgdXBkYXRlIHByb2R1Y3QgZmllbGRzIChtdWx0aXBhcnQ6IGZpZWxkcyArIG5ldyBpbWFnZXNbXSlcbiAgYXBpLnBhdGNoKCcvcHJvZHVjdHMvOmlkJywgcmVxdWlyZVJvbGUoJ2Zhcm1lcicpLCB1cGxvYWRNaWRkbGV3YXJlLmFueSgpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgeyBpZCB9ID0gcmVxLnBhcmFtcztcbiAgICAgIGNvbnN0IGJvZHkgPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGNvbnN0IGZpbGVzID0gKHJlcS5maWxlcyBhcyBFeHByZXNzLk11bHRlci5GaWxlW10gfCB1bmRlZmluZWQpID8/IFtdO1xuXG4gICAgICBjb25zdCB7IGRhdGE6IHByb2R1Y3QgfSA9IChhd2FpdCBkYi5mcm9tKCdwcm9kdWN0cycpLnNlbGVjdCgnKicpLmVxKCdpZCcsIGlkKS5tYXliZVNpbmdsZSgpKSBhcyB7IGRhdGE6IFByb2R1Y3QgfCBudWxsIH07XG4gICAgICBpZiAoIXByb2R1Y3QpIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIGlmIChwcm9kdWN0LmZhcm1lcl9pZCAhPT0gbWUuaWQpIHJldHVybiByZXMuc3RhdHVzKDQwMykuanNvbih7IGVycm9yOiAnZm9yYmlkZGVuJyB9KTtcblxuICAgICAgLy8gQ291bnQgZXhpc3RpbmcgaW1hZ2VzICsgbmV3IHVwbG9hZHNcbiAgICAgIGNvbnN0IHsgZGF0YTogZXhpc3RpbmdJbWFnZXMgfSA9IGF3YWl0IGRiLmZyb20oJ3Byb2R1Y3RfaW1hZ2VzJykuc2VsZWN0KCdpZCcpLmVxKCdwcm9kdWN0X2lkJywgaWQpO1xuICAgICAgY29uc3QgZXhpc3RpbmdDb3VudCA9IGV4aXN0aW5nSW1hZ2VzPy5sZW5ndGggPz8gMDtcbiAgICAgIC8vIGltYWdlc190b19yZW1vdmUgaXMgYSBKU09OIHN0cmluZyBvZiBpbWFnZSBJRHMgdG8gZGVsZXRlXG4gICAgICBsZXQgcmVtb3ZlSWRzOiBzdHJpbmdbXSA9IFtdO1xuICAgICAgaWYgKGJvZHkucmVtb3ZlX2ltYWdlcykge1xuICAgICAgICB0cnkgeyByZW1vdmVJZHMgPSBKU09OLnBhcnNlKGJvZHkucmVtb3ZlX2ltYWdlcyk7IH0gY2F0Y2ggeyByZW1vdmVJZHMgPSBbXTsgfVxuICAgICAgfVxuICAgICAgY29uc3QgcmVtYWluaW5nQWZ0ZXJSZW1vdmUgPSBleGlzdGluZ0NvdW50IC0gcmVtb3ZlSWRzLmxlbmd0aDtcbiAgICAgIGlmIChyZW1haW5pbmdBZnRlclJlbW92ZSArIGZpbGVzLmxlbmd0aCA+IE1BWF9JTUFHRVMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICd0b29fbWFueV9pbWFnZXMnIH0pO1xuICAgICAgfVxuICAgICAgZm9yIChjb25zdCBmIG9mIGZpbGVzKSB7XG4gICAgICAgIGlmICghQUxMT1dFRF9JTUFHRV9UWVBFUy5pbmNsdWRlcyhmLm1pbWV0eXBlKSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX2ltYWdlX3R5cGUnIH0pO1xuICAgICAgICBpZiAoZi5zaXplID4gTUFYX0lNQUdFX1NJWkUpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW1hZ2VfdG9vX2xhcmdlJyB9KTtcbiAgICAgIH1cblxuICAgICAgLy8gVXBkYXRlIGZpZWxkc1xuICAgICAgY29uc3QgcGF0Y2g6IFJlY29yZDxzdHJpbmcsIHVua25vd24+ID0geyB1cGRhdGVkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfTtcbiAgICAgIGlmIChib2R5LnByb2R1Y3RfbmFtZSAhPT0gdW5kZWZpbmVkKSBwYXRjaC5wcm9kdWN0X25hbWUgPSBTdHJpbmcoYm9keS5wcm9kdWN0X25hbWUpLnRyaW0oKTtcbiAgICAgIGlmIChib2R5LmNhdGVnb3J5ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgaWYgKCFQUk9EVUNUX0NBVEVHT1JJRVMuaW5jbHVkZXMoYm9keS5jYXRlZ29yeSkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9jYXRlZ29yeScgfSk7XG4gICAgICAgIHBhdGNoLmNhdGVnb3J5ID0gYm9keS5jYXRlZ29yeTtcbiAgICAgIH1cbiAgICAgIGlmIChib2R5LmRlc2NyaXB0aW9uICE9PSB1bmRlZmluZWQpIHBhdGNoLmRlc2NyaXB0aW9uID0gYm9keS5kZXNjcmlwdGlvbiA/IFN0cmluZyhib2R5LmRlc2NyaXB0aW9uKS50cmltKCkgOiBudWxsO1xuICAgICAgaWYgKGJvZHkucHJpY2UgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICBpZiAoTnVtYmVyKGJvZHkucHJpY2UpIDw9IDApIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9wcmljZScgfSk7XG4gICAgICAgIHBhdGNoLnByaWNlID0gTnVtYmVyKGJvZHkucHJpY2UpO1xuICAgICAgfVxuICAgICAgaWYgKGJvZHkucXVhbnRpdHkgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICBpZiAoTnVtYmVyKGJvZHkucXVhbnRpdHkpIDwgMCkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX3F1YW50aXR5JyB9KTtcbiAgICAgICAgcGF0Y2gucXVhbnRpdHkgPSBOdW1iZXIoYm9keS5xdWFudGl0eSk7XG4gICAgICB9XG4gICAgICBpZiAoYm9keS51bml0ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgaWYgKCFQUk9EVUNUX1VOSVRTLmluY2x1ZGVzKGJvZHkudW5pdCkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF91bml0JyB9KTtcbiAgICAgICAgcGF0Y2gudW5pdCA9IGJvZHkudW5pdDtcbiAgICAgIH1cbiAgICAgIGlmIChib2R5LmRpc3RyaWN0ICE9PSB1bmRlZmluZWQpIHBhdGNoLmRpc3RyaWN0ID0gU3RyaW5nKGJvZHkuZGlzdHJpY3QpLnRyaW0oKTtcbiAgICAgIGlmIChib2R5Lm11bmljaXBhbGl0eSAhPT0gdW5kZWZpbmVkKSBwYXRjaC5tdW5pY2lwYWxpdHkgPSBib2R5Lm11bmljaXBhbGl0eSA/IFN0cmluZyhib2R5Lm11bmljaXBhbGl0eSkudHJpbSgpIDogbnVsbDtcbiAgICAgIGlmIChib2R5LmhhcnZlc3RfZGF0ZSAhPT0gdW5kZWZpbmVkKSBwYXRjaC5oYXJ2ZXN0X2RhdGUgPSBib2R5LmhhcnZlc3RfZGF0ZSB8fCBudWxsO1xuICAgICAgaWYgKGJvZHkuYXZhaWxhYmlsaXR5ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgaWYgKCFQUk9EVUNUX0FWQUlMQUJJTElUWS5pbmNsdWRlcyhib2R5LmF2YWlsYWJpbGl0eSkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9hdmFpbGFiaWxpdHknIH0pO1xuICAgICAgICBwYXRjaC5hdmFpbGFiaWxpdHkgPSBib2R5LmF2YWlsYWJpbGl0eTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgeyBlcnJvcjogdXBkYXRlRXJyb3IgfSA9IGF3YWl0IGRiLmZyb20oJ3Byb2R1Y3RzJykudXBkYXRlKHBhdGNoKS5lcSgnaWQnLCBpZCk7XG4gICAgICBpZiAodXBkYXRlRXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcblxuICAgICAgLy8gUmVtb3ZlIHNwZWNpZmllZCBpbWFnZXNcbiAgICAgIGlmIChyZW1vdmVJZHMubGVuZ3RoID4gMCkge1xuICAgICAgICBjb25zdCB7IGRhdGE6IGltZ3NUb1JlbW92ZSB9ID0gYXdhaXQgZGIuZnJvbSgncHJvZHVjdF9pbWFnZXMnKS5zZWxlY3QoJ2ltYWdlX3VybCcpLmluKCdpZCcsIHJlbW92ZUlkcykuZXEoJ3Byb2R1Y3RfaWQnLCBpZCk7XG4gICAgICAgIGlmIChpbWdzVG9SZW1vdmUgJiYgaW1nc1RvUmVtb3ZlLmxlbmd0aCkge1xuICAgICAgICAgIGF3YWl0IFByb21pc2UuYWxsKGltZ3NUb1JlbW92ZS5tYXAoKGltZykgPT4gZGVsZXRlU3RvcmFnZUZpbGUoaW1nLmltYWdlX3VybCkpKTtcbiAgICAgICAgICBhd2FpdCBkYi5mcm9tKCdwcm9kdWN0X2ltYWdlcycpLmRlbGV0ZSgpLmluKCdpZCcsIHJlbW92ZUlkcykuZXEoJ3Byb2R1Y3RfaWQnLCBpZCk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgLy8gVXBsb2FkIG5ldyBpbWFnZXNcbiAgICAgIGF3YWl0IHVwbG9hZFByb2R1Y3RJbWFnZXMoaWQsIGZpbGVzKTtcblxuICAgICAgY29uc3QgeyBkYXRhOiBmdWxsUHJvZHVjdCB9ID0gYXdhaXQgZGJcbiAgICAgICAgLmZyb20oJ3Byb2R1Y3RzJylcbiAgICAgICAgLnNlbGVjdCgnKiwgaW1hZ2VzOnByb2R1Y3RfaW1hZ2VzKCopJylcbiAgICAgICAgLmVxKCdpZCcsIGlkKVxuICAgICAgICAuc2luZ2xlKCk7XG4gICAgICBjb25zdCByZXN1bHQgPSBmdWxsUHJvZHVjdCBhcyBQcm9kdWN0ICYgeyBpbWFnZXM6IFByb2R1Y3RJbWFnZVtdIH07XG4gICAgICByZXN1bHQuaW1hZ2VzID0gKHJlc3VsdC5pbWFnZXMgfHwgW10pLnNvcnQoKGEsIGIpID0+IGEuc29ydF9vcmRlciAtIGIuc29ydF9vcmRlcik7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBwcm9kdWN0OiByZXN1bHQgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignUEFUQ0ggL3Byb2R1Y3RzLzppZCcsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gREVMRVRFIC9wcm9kdWN0cy86aWQgXHUyMDE0IGRlbGV0ZSBhIHByb2R1Y3QgYW5kIGl0cyBpbWFnZXNcbiAgYXBpLmRlbGV0ZSgnL3Byb2R1Y3RzLzppZCcsIHJlcXVpcmVSb2xlKCdmYXJtZXInKSwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIGNvbnN0IHsgaWQgfSA9IHJlcS5wYXJhbXM7XG4gICAgICBjb25zdCB7IGRhdGE6IHByb2R1Y3QgfSA9IChhd2FpdCBkYi5mcm9tKCdwcm9kdWN0cycpLnNlbGVjdCgnKicpLmVxKCdpZCcsIGlkKS5tYXliZVNpbmdsZSgpKSBhcyB7IGRhdGE6IFByb2R1Y3QgfCBudWxsIH07XG4gICAgICBpZiAoIXByb2R1Y3QpIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIGlmIChwcm9kdWN0LmZhcm1lcl9pZCAhPT0gbWUuaWQpIHJldHVybiByZXMuc3RhdHVzKDQwMykuanNvbih7IGVycm9yOiAnZm9yYmlkZGVuJyB9KTtcblxuICAgICAgLy8gRGVsZXRlIGltYWdlcyBmcm9tIHN0b3JhZ2VcbiAgICAgIGNvbnN0IHsgZGF0YTogaW1hZ2VzIH0gPSBhd2FpdCBkYi5mcm9tKCdwcm9kdWN0X2ltYWdlcycpLnNlbGVjdCgnaW1hZ2VfdXJsJykuZXEoJ3Byb2R1Y3RfaWQnLCBpZCk7XG4gICAgICBpZiAoaW1hZ2VzICYmIGltYWdlcy5sZW5ndGgpIHtcbiAgICAgICAgYXdhaXQgUHJvbWlzZS5hbGwoaW1hZ2VzLm1hcCgoaW1nKSA9PiBkZWxldGVTdG9yYWdlRmlsZShpbWcuaW1hZ2VfdXJsKSkpO1xuICAgICAgfVxuICAgICAgLy8gRGVsZXRlIHByb2R1Y3QgKGNhc2NhZGVzIHRvIHByb2R1Y3RfaW1hZ2VzKVxuICAgICAgY29uc3QgeyBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgncHJvZHVjdHMnKS5kZWxldGUoKS5lcSgnaWQnLCBpZCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IG9rOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0RFTEVURSAvcHJvZHVjdHMvOmlkJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyBIZWxwZXI6IHVwbG9hZCBmaWxlcyB0byBTdXBhYmFzZSBTdG9yYWdlIGFuZCBjcmVhdGUgcHJvZHVjdF9pbWFnZXMgcm93c1xuICBhc3luYyBmdW5jdGlvbiB1cGxvYWRQcm9kdWN0SW1hZ2VzKHByb2R1Y3RJZDogc3RyaW5nLCBmaWxlczogRXhwcmVzcy5NdWx0ZXIuRmlsZVtdKTogUHJvbWlzZTxQcm9kdWN0SW1hZ2VbXT4ge1xuICAgIGlmICghZmlsZXMubGVuZ3RoKSByZXR1cm4gW107XG4gICAgY29uc3Qgcm93czogUHJvZHVjdEltYWdlW10gPSBbXTtcbiAgICAvLyBHZXQgY3VycmVudCBtYXggc29ydF9vcmRlciBmb3IgdGhpcyBwcm9kdWN0XG4gICAgY29uc3QgeyBkYXRhOiBleGlzdGluZyB9ID0gYXdhaXQgZGIuZnJvbSgncHJvZHVjdF9pbWFnZXMnKS5zZWxlY3QoJ3NvcnRfb3JkZXInKS5lcSgncHJvZHVjdF9pZCcsIHByb2R1Y3RJZCk7XG4gICAgbGV0IG5leHRPcmRlciA9IGV4aXN0aW5nICYmIGV4aXN0aW5nLmxlbmd0aCA/IE1hdGgubWF4KC4uLmV4aXN0aW5nLm1hcCgoaTogYW55KSA9PiBpLnNvcnRfb3JkZXIpKSArIDEgOiAwO1xuXG4gICAgZm9yIChjb25zdCBmaWxlIG9mIGZpbGVzKSB7XG4gICAgICBjb25zdCBleHQgPSBmaWxlLm9yaWdpbmFsbmFtZS5zcGxpdCgnLicpLnBvcCgpPy50b0xvd2VyQ2FzZSgpIHx8ICdqcGcnO1xuICAgICAgY29uc3QgZmlsZVBhdGggPSBgJHtwcm9kdWN0SWR9LyR7RGF0ZS5ub3coKX0tJHtNYXRoLnJhbmRvbSgpLnRvU3RyaW5nKDM2KS5zbGljZSgyLCA4KX0uJHtleHR9YDtcbiAgICAgIGNvbnN0IHsgZXJyb3I6IHVwbG9hZEVycm9yIH0gPSBhd2FpdCBkYi5zdG9yYWdlLmZyb20oU1RPUkFHRV9CVUNLRVQpLnVwbG9hZChmaWxlUGF0aCwgZmlsZS5idWZmZXIsIHtcbiAgICAgICAgY29udGVudFR5cGU6IGZpbGUubWltZXR5cGUsXG4gICAgICAgIHVwc2VydDogZmFsc2UsXG4gICAgICB9KTtcbiAgICAgIGlmICh1cGxvYWRFcnJvcikge1xuICAgICAgICBjb25zb2xlLmVycm9yKCdTdG9yYWdlIHVwbG9hZCBlcnJvcicsIHVwbG9hZEVycm9yKTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGE6IHB1YlVybCB9ID0gZGIuc3RvcmFnZS5mcm9tKFNUT1JBR0VfQlVDS0VUKS5nZXRQdWJsaWNVcmwoZmlsZVBhdGgpO1xuICAgICAgY29uc3QgeyBkYXRhOiBpbWdSb3cgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCdwcm9kdWN0X2ltYWdlcycpXG4gICAgICAgIC5pbnNlcnQoeyBwcm9kdWN0X2lkOiBwcm9kdWN0SWQsIGltYWdlX3VybDogcHViVXJsLnB1YmxpY1VybCwgc29ydF9vcmRlcjogbmV4dE9yZGVyIH0pXG4gICAgICAgIC5zZWxlY3QoJyonKVxuICAgICAgICAuc2luZ2xlKCk7XG4gICAgICBpZiAoaW1nUm93KSByb3dzLnB1c2goaW1nUm93IGFzIFByb2R1Y3RJbWFnZSk7XG4gICAgICBuZXh0T3JkZXIrKztcbiAgICB9XG4gICAgcmV0dXJuIHJvd3M7XG4gIH1cblxuICAvLyBIZWxwZXI6IGRlbGV0ZSBhIGZpbGUgZnJvbSBTdXBhYmFzZSBTdG9yYWdlIGJ5IGl0cyBwdWJsaWMgVVJMXG4gIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVN0b3JhZ2VGaWxlKHB1YmxpY1VybDogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHVybCA9IG5ldyBVUkwocHVibGljVXJsKTtcbiAgICAgIGNvbnN0IHBhcnRzID0gdXJsLnBhdGhuYW1lLnNwbGl0KGAvc3RvcmFnZS92MS9vYmplY3QvcHVibGljLyR7U1RPUkFHRV9CVUNLRVR9L2ApO1xuICAgICAgaWYgKHBhcnRzLmxlbmd0aCA8IDIpIHJldHVybjtcbiAgICAgIGNvbnN0IGZpbGVQYXRoID0gZGVjb2RlVVJJQ29tcG9uZW50KHBhcnRzWzFdKTtcbiAgICAgIGF3YWl0IGRiLnN0b3JhZ2UuZnJvbShTVE9SQUdFX0JVQ0tFVCkucmVtb3ZlKFtmaWxlUGF0aF0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ2RlbGV0ZVN0b3JhZ2VGaWxlIGVycm9yJywgZSk7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGFwaTtcbn1cblxuZnVuY3Rpb24gc2FuaXRpemUodTogVXNlcikge1xuICBjb25zdCB7IHBpbl9oYXNoLCAuLi5yZXN0IH0gPSB1O1xuICB2b2lkIHBpbl9oYXNoO1xuICByZXR1cm4gcmVzdDtcbn1cbmZ1bmN0aW9uIHNhbml0aXplQ3JvcChjOiBDcm9wKSB7XG4gIHJldHVybiB7IC4uLmMsIGZhcm1lcjogYy5mYXJtZXIgPyBzYW5pdGl6ZShjLmZhcm1lcikgOiB1bmRlZmluZWQgfTtcbn1cbmZ1bmN0aW9uIHNhbml0aXplUmV2aWV3KHI6IFJldmlldykge1xuICByZXR1cm4ge1xuICAgIC4uLnIsXG4gICAgcmV2aWV3ZXI6IHIucmV2aWV3ZXIgPyBzYW5pdGl6ZShyLnJldmlld2VyKSA6IHVuZGVmaW5lZCxcbiAgICBvcmRlcjogci5vcmRlciA/IHsgLi4uci5vcmRlciB9IDogdW5kZWZpbmVkLFxuICB9O1xufVxuXG5leHBvcnQgeyBTRVNTSU9OX0NPT0tJRSB9O1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvaG9tZS9wcm9qZWN0L3NyYy9hcGlcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9ob21lL3Byb2plY3Qvc3JjL2FwaS9kYi50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vaG9tZS9wcm9qZWN0L3NyYy9hcGkvZGIudHNcIjtpbXBvcnQgeyBjcmVhdGVDbGllbnQsIHR5cGUgU3VwYWJhc2VDbGllbnQgfSBmcm9tICdAc3VwYWJhc2Uvc3VwYWJhc2UtanMnO1xuXG5mdW5jdGlvbiByZWFkRW52KCkge1xuICBjb25zdCB1cmwgPSBwcm9jZXNzLmVudi5TVVBBQkFTRV9VUkwgfHwgcHJvY2Vzcy5lbnYuVklURV9TVVBBQkFTRV9VUkw7XG4gIGNvbnN0IGFub25LZXkgPSBwcm9jZXNzLmVudi5TVVBBQkFTRV9BTk9OX0tFWSB8fCBwcm9jZXNzLmVudi5WSVRFX1NVUEFCQVNFX0FOT05fS0VZO1xuICByZXR1cm4geyB1cmwsIGFub25LZXkgfTtcbn1cblxubGV0IF9jbGllbnQ6IFN1cGFiYXNlQ2xpZW50IHwgbnVsbCA9IG51bGw7XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXREYigpOiBTdXBhYmFzZUNsaWVudCB7XG4gIGlmIChfY2xpZW50KSByZXR1cm4gX2NsaWVudDtcbiAgY29uc3QgeyB1cmwsIGFub25LZXkgfSA9IHJlYWRFbnYoKTtcbiAgaWYgKCF1cmwgfHwgIWFub25LZXkpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ1N1cGFiYXNlIGVudiB2YXJzIG1pc3NpbmcgXHUyMDE0IHNldCBTVVBBQkFTRV9VUkwgLyBTVVBBQkFTRV9BTk9OX0tFWScpO1xuICB9XG4gIF9jbGllbnQgPSBjcmVhdGVDbGllbnQodXJsLCBhbm9uS2V5LCB7XG4gICAgYXV0aDogeyBwZXJzaXN0U2Vzc2lvbjogZmFsc2UsIGF1dG9SZWZyZXNoVG9rZW46IGZhbHNlIH0sXG4gIH0pO1xuICByZXR1cm4gX2NsaWVudDtcbn1cblxuLy8gQmFja3dhcmRzLWNvbXBhdGlibGUgYGRiYCBleHBvcnQgdGhhdCBsYXppbHkgcHJveGllcyB0byBnZXREYigpLlxuZXhwb3J0IGNvbnN0IGRiID0gbmV3IFByb3h5KHt9IGFzIFN1cGFiYXNlQ2xpZW50LCB7XG4gIGdldChfdCwgcHJvcCkge1xuICAgIGNvbnN0IGNsaWVudCA9IGdldERiKCk7XG4gICAgY29uc3QgdmFsdWUgPSAoY2xpZW50IGFzIHVua25vd24gYXMgUmVjb3JkPHN0cmluZyB8IHN5bWJvbCwgdW5rbm93bj4pW3Byb3BdO1xuICAgIHJldHVybiB0eXBlb2YgdmFsdWUgPT09ICdmdW5jdGlvbicgPyB2YWx1ZS5iaW5kKGNsaWVudCkgOiB2YWx1ZTtcbiAgfSxcbn0pO1xuXG5leHBvcnQgaW50ZXJmYWNlIFVzZXIge1xuICBpZDogc3RyaW5nO1xuICBmdWxsX25hbWU6IHN0cmluZztcbiAgYnVzaW5lc3NfbmFtZTogc3RyaW5nIHwgbnVsbDtcbiAgcGhvbmU6IHN0cmluZztcbiAgcGluX2hhc2g6IHN0cmluZztcbiAgcGhvbmVfdmVyaWZpZWQ6IGJvb2xlYW47XG4gIHJvbGU6ICdmYXJtZXInIHwgJ3dob2xlc2FsZXInIHwgJ2FkbWluJztcbiAgc3RhdHVzOiAnYWN0aXZlJyB8ICdzdXNwZW5kZWQnIHwgJ2Jhbm5lZCc7XG4gIGZhcm1fbG9jYXRpb246IHN0cmluZyB8IG51bGw7XG4gIHllYXJzX2V4cGVyaWVuY2U6IG51bWJlciB8IG51bGw7XG4gIGFib3V0X2Zhcm06IHN0cmluZyB8IG51bGw7XG4gIGJ1c2luZXNzX2xvY2F0aW9uOiBzdHJpbmcgfCBudWxsO1xuICB5ZWFyc19pbl9idXNpbmVzczogbnVtYmVyIHwgbnVsbDtcbiAgc3RvcmFnZV9jYXBhY2l0eV90b25zOiBudW1iZXIgfCBudWxsO1xuICBhdmF0YXJfdXJsOiBzdHJpbmcgfCBudWxsO1xuICBjcmVhdGVkX2F0OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ3JvcCB7XG4gIGlkOiBzdHJpbmc7XG4gIGZhcm1lcl9pZDogc3RyaW5nO1xuICBuYW1lOiBzdHJpbmc7XG4gIGNhdGVnb3J5OiBzdHJpbmcgfCBudWxsO1xuICBwcmljZTogbnVtYmVyO1xuICBxdWFudGl0eV9hdmFpbGFibGU6IG51bWJlcjtcbiAgdW5pdDogc3RyaW5nO1xuICBsb2NhdGlvbjogc3RyaW5nIHwgbnVsbDtcbiAgaGFydmVzdF9kYXRlOiBzdHJpbmcgfCBudWxsO1xuICBpbWFnZV91cmw6IHN0cmluZyB8IG51bGw7XG4gIGRlc2NyaXB0aW9uOiBzdHJpbmcgfCBudWxsO1xuICBzdGF0dXM6ICdwZW5kaW5nJyB8ICdhcHByb3ZlZCcgfCAncmVqZWN0ZWQnIHwgJ3NvbGRfb3V0JztcbiAgY3JlYXRlZF9hdDogc3RyaW5nO1xuICBmYXJtZXI/OiBVc2VyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIE9yZGVyIHtcbiAgaWQ6IHN0cmluZztcbiAgd2hvbGVzYWxlcl9pZDogc3RyaW5nO1xuICBmYXJtZXJfaWQ6IHN0cmluZztcbiAgY3JvcF9pZDogc3RyaW5nO1xuICBxdWFudGl0eTogbnVtYmVyO1xuICBzdGF0dXM6ICdwZW5kaW5nJyB8ICdjb21wbGV0ZWQnIHwgJ2NhbmNlbGxlZCc7XG4gIGNyZWF0ZWRfYXQ6IHN0cmluZztcbiAgY3JvcD86IENyb3A7XG4gIGZhcm1lcj86IFVzZXI7XG4gIHdob2xlc2FsZXI/OiBVc2VyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIE1hcmtldFByaWNlIHtcbiAgaWQ6IHN0cmluZztcbiAgcHJvZHVjdDogc3RyaW5nO1xuICB1bml0OiBzdHJpbmc7XG4gIG1pbl9wcmljZTogbnVtYmVyO1xuICBtYXhfcHJpY2U6IG51bWJlcjtcbiAgYXZnX3ByaWNlOiBudW1iZXI7XG4gIHRyZW5kOiAndXAnIHwgJ2Rvd24nIHwgJ3N0YWJsZSc7XG4gIHVwZGF0ZWRfYXQ6IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBSZXZpZXcge1xuICBpZDogc3RyaW5nO1xuICBvcmRlcl9pZDogc3RyaW5nO1xuICByZXZpZXdlcl9pZDogc3RyaW5nO1xuICByZXZpZXdlZV9pZDogc3RyaW5nO1xuICByZXZpZXdlcl9yb2xlOiAnZmFybWVyJyB8ICd3aG9sZXNhbGVyJztcbiAgcmF0aW5nOiBudW1iZXI7XG4gIGNvbW1lbnQ6IHN0cmluZyB8IG51bGw7XG4gIGNyZWF0ZWRfYXQ6IHN0cmluZztcbiAgcmV2aWV3ZXI/OiBVc2VyO1xuICBvcmRlcj86IE9yZGVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFByb2R1Y3Qge1xuICBpZDogc3RyaW5nO1xuICBmYXJtZXJfaWQ6IHN0cmluZztcbiAgcHJvZHVjdF9uYW1lOiBzdHJpbmc7XG4gIGNhdGVnb3J5OiBzdHJpbmc7XG4gIGRlc2NyaXB0aW9uOiBzdHJpbmcgfCBudWxsO1xuICBwcmljZTogbnVtYmVyO1xuICBxdWFudGl0eTogbnVtYmVyO1xuICB1bml0OiBzdHJpbmc7XG4gIGRpc3RyaWN0OiBzdHJpbmc7XG4gIG11bmljaXBhbGl0eTogc3RyaW5nIHwgbnVsbDtcbiAgaGFydmVzdF9kYXRlOiBzdHJpbmcgfCBudWxsO1xuICBhdmFpbGFiaWxpdHk6ICdBdmFpbGFibGUnIHwgJ0xpbWl0ZWQgU3RvY2snIHwgJ1NvbGQgT3V0JztcbiAgY3JlYXRlZF9hdDogc3RyaW5nO1xuICB1cGRhdGVkX2F0OiBzdHJpbmc7XG4gIGltYWdlcz86IFByb2R1Y3RJbWFnZVtdO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFByb2R1Y3RJbWFnZSB7XG4gIGlkOiBzdHJpbmc7XG4gIHByb2R1Y3RfaWQ6IHN0cmluZztcbiAgaW1hZ2VfdXJsOiBzdHJpbmc7XG4gIHNvcnRfb3JkZXI6IG51bWJlcjtcbiAgY3JlYXRlZF9hdDogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyb3BJbWFnZSB7XG4gIGlkOiBzdHJpbmc7XG4gIGNyb3BfaWQ6IHN0cmluZztcbiAgaW1hZ2VfdXJsOiBzdHJpbmc7XG4gIHNvcnRfb3JkZXI6IG51bWJlcjtcbiAgY3JlYXRlZF9hdDogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIE90cENvZGUge1xuICBpZDogc3RyaW5nO1xuICBwaG9uZTogc3RyaW5nO1xuICBjb2RlOiBzdHJpbmc7XG4gIHB1cnBvc2U6ICdyZWdpc3RlcicgfCAncmVzZXRfcGluJztcbiAgZXhwaXJlc19hdDogc3RyaW5nO1xuICB1c2VkOiBib29sZWFuO1xuICBjcmVhdGVkX2F0OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ29udGFjdFJvdyB7XG4gIGlkOiBzdHJpbmc7XG4gIG5hbWU6IHN0cmluZztcbiAgZW1haWw6IHN0cmluZztcbiAgbWVzc2FnZTogc3RyaW5nO1xuICBjcmVhdGVkX2F0OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgU2Vzc2lvblJvdyB7XG4gIGlkOiBzdHJpbmc7XG4gIHRva2VuOiBzdHJpbmc7XG4gIHVzZXJfaWQ6IHN0cmluZztcbiAgY3JlYXRlZF9hdDogc3RyaW5nO1xuICBleHBpcmVzX2F0OiBzdHJpbmc7XG59XG4iLCAiY29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2Rpcm5hbWUgPSBcIi9ob21lL3Byb2plY3Qvc3JjL2FwaVwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2hvbWUvcHJvamVjdC9zcmMvYXBpL2F1dGgudHNcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfaW1wb3J0X21ldGFfdXJsID0gXCJmaWxlOi8vL2hvbWUvcHJvamVjdC9zcmMvYXBpL2F1dGgudHNcIjtpbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSwgTmV4dEZ1bmN0aW9uIH0gZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgYmNyeXB0IGZyb20gJ2JjcnlwdGpzJztcbmltcG9ydCB7IGRiLCBVc2VyLCBTZXNzaW9uUm93IH0gZnJvbSAnLi9kYic7XG5cbmNvbnN0IENPT0tJRSA9ICdrY19zZXNzaW9uJztcbmNvbnN0IFNFU1NJT05fREFZUyA9IDc7XG5cbmV4cG9ydCBjb25zdCBTRVNTSU9OX0NPT0tJRSA9IENPT0tJRTtcblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNyZWF0ZVNlc3Npb24ocmVzOiBSZXNwb25zZSwgdXNlcklkOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgY29uc3QgdG9rZW4gPSBhd2FpdCBiY3J5cHQuZ2VuU2FsdCgzMikudGhlbigocykgPT4gcy5yZXBsYWNlKC9cXC8vZywgJ3gnKSk7XG4gIGNvbnN0IGV4cGlyZXNBdCA9IG5ldyBEYXRlKERhdGUubm93KCkgKyBTRVNTSU9OX0RBWVMgKiA4NjQwMF8wMDApLnRvSVNPU3RyaW5nKCk7XG4gIGNvbnN0IHsgZXJyb3IgfSA9IGF3YWl0IGRiLmZyb20oJ3Nlc3Npb25zJykuaW5zZXJ0KHsgdG9rZW4sIHVzZXJfaWQ6IHVzZXJJZCwgZXhwaXJlc19hdDogZXhwaXJlc0F0IH0pO1xuICBpZiAoZXJyb3IpIHRocm93IGVycm9yO1xuICByZXMuY29va2llKENPT0tJRSwgdG9rZW4sIHtcbiAgICBodHRwT25seTogdHJ1ZSxcbiAgICBzYW1lU2l0ZTogJ2xheCcsXG4gICAgbWF4QWdlOiBTRVNTSU9OX0RBWVMgKiA4NjQwMF8wMDAsXG4gICAgcGF0aDogJy8nLFxuICB9KTtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlc3Ryb3lTZXNzaW9uKHJlcTogUmVxdWVzdCwgcmVzOiBSZXNwb25zZSk6IFByb21pc2U8dm9pZD4ge1xuICBjb25zdCB0b2tlbiA9IHJlcS5jb29raWVzPy5bQ09PS0lFXTtcbiAgaWYgKHRva2VuKSB7XG4gICAgYXdhaXQgZGIuZnJvbSgnc2Vzc2lvbnMnKS5kZWxldGUoKS5lcSgndG9rZW4nLCB0b2tlbik7XG4gIH1cbiAgcmVzLmNsZWFyQ29va2llKENPT0tJRSwgeyBwYXRoOiAnLycgfSk7XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjdXJyZW50VXNlcihyZXE6IFJlcXVlc3QpOiBQcm9taXNlPFVzZXIgfCBudWxsPiB7XG4gIGNvbnN0IHRva2VuID0gcmVxLmNvb2tpZXM/LltDT09LSUVdO1xuICBpZiAoIXRva2VuKSByZXR1cm4gbnVsbDtcbiAgY29uc3QgeyBkYXRhIH0gPSBhd2FpdCBkYlxuICAgIC5mcm9tKCdzZXNzaW9ucycpXG4gICAgLnNlbGVjdCgnKiwgdXNlcjp1c2VycygqKScpXG4gICAgLmVxKCd0b2tlbicsIHRva2VuKVxuICAgIC5tYXliZVNpbmdsZSgpIGFzIHsgZGF0YTogKFNlc3Npb25Sb3cgJiB7IHVzZXI6IFVzZXIgfSkgfCBudWxsIH07XG4gIGlmICghZGF0YSkgcmV0dXJuIG51bGw7XG4gIGlmIChuZXcgRGF0ZShkYXRhLmV4cGlyZXNfYXQpLmdldFRpbWUoKSA8IERhdGUubm93KCkpIHtcbiAgICBhd2FpdCBkYi5mcm9tKCdzZXNzaW9ucycpLmRlbGV0ZSgpLmVxKCd0b2tlbicsIHRva2VuKTtcbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuICByZXR1cm4gZGF0YS51c2VyID8/IG51bGw7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZXF1aXJlQXV0aChyZXE6IFJlcXVlc3QsIHJlczogUmVzcG9uc2UsIG5leHQ6IE5leHRGdW5jdGlvbikge1xuICAoYXN5bmMgKCkgPT4ge1xuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCBjdXJyZW50VXNlcihyZXEpO1xuICAgIGlmICghdXNlcikge1xuICAgICAgcmVzLnN0YXR1cyg0MDEpLmpzb24oeyBlcnJvcjogJ3VuYXV0aG9yaXplZCcgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIChyZXEgYXMgYW55KS51c2VyID0gdXNlcjtcbiAgICBuZXh0KCk7XG4gIH0pKCkuY2F0Y2goKGUpID0+IHtcbiAgICBjb25zb2xlLmVycm9yKCdyZXF1aXJlQXV0aCBlcnJvcicsIGUpO1xuICAgIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICB9KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHJlcXVpcmVSb2xlKC4uLnJvbGVzOiBBcnJheTwnZmFybWVyJyB8ICd3aG9sZXNhbGVyJyB8ICdhZG1pbic+KSB7XG4gIHJldHVybiAocmVxOiBSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pID0+IHtcbiAgICAoYXN5bmMgKCkgPT4ge1xuICAgICAgY29uc3QgdXNlciA9IGF3YWl0IGN1cnJlbnRVc2VyKHJlcSk7XG4gICAgICBpZiAoIXVzZXIpIHtcbiAgICAgICAgcmVzLnN0YXR1cyg0MDEpLmpzb24oeyBlcnJvcjogJ3VuYXV0aG9yaXplZCcgfSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIGlmICghcm9sZXMuaW5jbHVkZXModXNlci5yb2xlKSkge1xuICAgICAgICByZXMuc3RhdHVzKDQwMykuanNvbih7IGVycm9yOiAnZm9yYmlkZGVuJyB9KTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgKHJlcSBhcyBhbnkpLnVzZXIgPSB1c2VyO1xuICAgICAgbmV4dCgpO1xuICAgIH0pKCkuY2F0Y2goKGUpID0+IHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ3JlcXVpcmVSb2xlIGVycm9yJywgZSk7XG4gICAgICByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9KTtcbiAgfTtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHZlcmlmeVBpbih1c2VyOiBVc2VyLCBwaW46IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICB0cnkge1xuICAgIHJldHVybiBhd2FpdCBiY3J5cHQuY29tcGFyZShwaW4sIHVzZXIucGluX2hhc2gpO1xuICB9IGNhdGNoIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGhhc2hQaW4ocGluOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICByZXR1cm4gYmNyeXB0Lmhhc2gocGluLCAxMCk7XG59XG4iXSwKICAibWFwcGluZ3MiOiAiO0FBQXlOLFNBQVMsY0FBa0MsZUFBZTs7O0FDQTVDLE9BQU8sYUFBYTtB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
