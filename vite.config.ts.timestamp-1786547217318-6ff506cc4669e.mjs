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
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY;
  return { url, key };
}
var _client = null;
function getDb() {
  if (_client) return _client;
  const { url, key } = readEnv();
  if (!url || !key) {
    throw new Error("Supabase env vars missing \u2014 set SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY");
  }
  _client = createClient(url, key, {
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
        status: "approved"
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
  const PROFILE_ALLOWED_TYPES = ["image/jpeg", "image/jpg", "image/png", "image/webp"];
  function uploadAvatar(req, res, next) {
    uploadMiddleware.single("avatar")(req, res, (error) => {
      if (!error) {
        next();
        return;
      }
      if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
        res.status(413).json({ error: "image_too_large", message: "Image must be 5 MB or smaller." });
        return;
      }
      console.error("avatar multipart upload", error);
      res.status(400).json({ error: "upload_failed", message: "The image could not be read. Please choose a JPG, PNG, or WEBP image." });
    });
  }
  api.post("/me/avatar", requireAuth, uploadAvatar, async (req, res) => {
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
      const ext = file.mimetype === "image/png" ? "png" : file.mimetype === "image/webp" ? "webp" : "jpg";
      const filePath = `profiles/${me.id}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
      const { error: upErr } = await db.storage.from(PROFILE_BUCKET).upload(filePath, file.buffer, { contentType: file.mimetype, upsert: false });
      if (upErr) {
        console.error("avatar upload", upErr);
        return res.status(502).json({ error: "storage_upload_failed", message: upErr.message || "Storage rejected the image." });
      }
      const { data: pub } = db.storage.from(PROFILE_BUCKET).getPublicUrl(filePath);
      const newAvatarUrl = pub.publicUrl;
      const oldAvatarUrl = me.avatar_url;
      const { data, error } = await db.from("users").update({ avatar_url: newAvatarUrl }).eq("id", me.id).select("*").single();
      if (error) {
        await db.storage.from(PROFILE_BUCKET).remove([filePath]);
        console.error("avatar profile update", error);
        return res.status(500).json({ error: "profile_update_failed", message: error.message || "The profile could not be updated." });
      }
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
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAic3JjL2FwaS9zZXJ2ZXIudHMiLCAic3JjL2FwaS9kYi50cyIsICJzcmMvYXBpL2F1dGgudHMiXSwKICAic291cmNlc0NvbnRlbnQiOiBbImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvaG9tZS9wcm9qZWN0XCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ZpbGVuYW1lID0gXCIvaG9tZS9wcm9qZWN0L3ZpdGUuY29uZmlnLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9ob21lL3Byb2plY3Qvdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcsIHR5cGUgVml0ZURldlNlcnZlciwgbG9hZEVudiB9IGZyb20gJ3ZpdGUnO1xuaW1wb3J0IHR5cGUgeyBJbmNvbWluZ01lc3NhZ2UsIFNlcnZlclJlc3BvbnNlIH0gZnJvbSAnbm9kZTpodHRwJztcbmltcG9ydCB7IGNyZWF0ZUFwaVJvdXRlciB9IGZyb20gJy4vc3JjL2FwaS9zZXJ2ZXInO1xuaW1wb3J0IGV4cHJlc3MgZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgZnMgZnJvbSAnbm9kZTpmcyc7XG5pbXBvcnQgcGF0aCBmcm9tICdub2RlOnBhdGgnO1xuXG5jb25zdCBQQUdFUzogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHtcbiAgJy8nOiAnaW5kZXguaHRtbCcsXG4gICcvcHJvZHVjdHMnOiAnc3JjL3BhZ2VzL3Byb2R1Y3RzLmh0bWwnLFxuICAnL21hcmtldC1wcmljZXMnOiAnc3JjL3BhZ2VzL21hcmtldC1wcmljZXMuaHRtbCcsXG4gICcvYWJvdXQnOiAnc3JjL3BhZ2VzL2Fib3V0Lmh0bWwnLFxuICAnL2NvbnRhY3QnOiAnc3JjL3BhZ2VzL2NvbnRhY3QuaHRtbCcsXG4gICcvbG9naW4nOiAnc3JjL3BhZ2VzL2xvZ2luLmh0bWwnLFxuICAnL3JlZ2lzdGVyJzogJ3NyYy9wYWdlcy9yZWdpc3Rlci5odG1sJyxcbiAgJy9hZG1pbi9sb2dpbic6ICdzcmMvcGFnZXMvYWRtaW4tbG9naW4uaHRtbCcsXG4gICcvYWRtaW4nOiAnc3JjL3BhZ2VzL2FkbWluLmh0bWwnLFxuICAnL2Zhcm1lcic6ICdzcmMvcGFnZXMvZmFybWVyLmh0bWwnLFxuICAnL3dob2xlc2FsZXInOiAnc3JjL3BhZ2VzL3dob2xlc2FsZXIuaHRtbCcsXG59O1xuXG5mdW5jdGlvbiByZXNvbHZlUGFnZSh1cmxQYXRoOiBzdHJpbmcpOiBzdHJpbmcgfCBudWxsIHtcbiAgY29uc3QgcCA9IHVybFBhdGguc3BsaXQoJz8nKVswXTtcbiAgcmV0dXJuIFBBR0VTW3BdID8/IG51bGw7XG59XG5cbmZ1bmN0aW9uIHNlcnZlSHRtbChzZXJ2ZXI6IFZpdGVEZXZTZXJ2ZXIpIHtcbiAgcmV0dXJuIChyZXE6IEluY29taW5nTWVzc2FnZSwgcmVzOiBTZXJ2ZXJSZXNwb25zZSwgbmV4dDogKGVycj86IHVua25vd24pID0+IHZvaWQpID0+IHtcbiAgICBjb25zdCBmaWxlID0gcmVzb2x2ZVBhZ2UocmVxLnVybCB8fCAnJyk7XG4gICAgaWYgKCFmaWxlKSByZXR1cm4gbmV4dCgpO1xuICAgIGNvbnN0IGFicyA9IHBhdGgucmVzb2x2ZShwcm9jZXNzLmN3ZCgpLCBmaWxlKTtcbiAgICBpZiAoIWZzLmV4aXN0c1N5bmMoYWJzKSkgcmV0dXJuIG5leHQoKTtcbiAgICBmcy5yZWFkRmlsZShhYnMsICd1dGYtOCcsIGFzeW5jIChlcnIsIGRhdGEpID0+IHtcbiAgICAgIGlmIChlcnIpIHJldHVybiBuZXh0KGVycik7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCB0cmFuc2Zvcm1lZCA9IGF3YWl0IHNlcnZlci50cmFuc2Zvcm1JbmRleEh0bWwocmVxLnVybCB8fCAnLycsIGRhdGEpO1xuICAgICAgICByZXMuc2V0SGVhZGVyKCdDb250ZW50LVR5cGUnLCAndGV4dC9odG1sJyk7XG4gICAgICAgIHJlcy5lbmQodHJhbnNmb3JtZWQpO1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBuZXh0KGUpO1xuICAgICAgfVxuICAgIH0pO1xuICB9O1xufVxuXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoKHsgbW9kZSB9KSA9PiB7XG4gIC8vIExvYWQgLmVudiBpbnRvIHByb2Nlc3MuZW52IHNvIHRoZSBFeHByZXNzIEFQSSBjYW4gcmVhZCBTVVBBQkFTRV8qIHZhcnMuXG4gIGNvbnN0IGVudiA9IGxvYWRFbnYobW9kZSwgcHJvY2Vzcy5jd2QoKSwgJycpO1xuICBmb3IgKGNvbnN0IFtrLCB2XSBvZiBPYmplY3QuZW50cmllcyhlbnYpKSB7XG4gICAgaWYgKCFwcm9jZXNzLmVudltrXSkgcHJvY2Vzcy5lbnZba10gPSB2O1xuICB9XG4gIHJldHVybiB7XG4gICAgc2VydmVyOiB7XG4gICAgICBwb3J0OiA1MTczLFxuICAgICAgaG9zdDogdHJ1ZSxcbiAgICB9LFxuICAgIHBsdWdpbnM6IFtcbiAgICAgIHtcbiAgICAgICAgbmFtZTogJ2tjLWFwaS1hbmQtcGFnZXMnLFxuICAgICAgICBjb25maWd1cmVTZXJ2ZXIoc2VydmVyKSB7XG4gICAgICAgICAgY29uc3QgYXBpID0gZXhwcmVzcygpO1xuICAgICAgICAgIGFwaS51c2UoZXhwcmVzcy5qc29uKHsgbGltaXQ6ICcxbWInIH0pKTtcbiAgICAgICAgICBhcGkudXNlKGNyZWF0ZUFwaVJvdXRlcigpKTtcbiAgICAgICAgICBzZXJ2ZXIubWlkZGxld2FyZXMudXNlKCcvYXBpJywgYXBpKTtcbiAgICAgICAgICAvLyBNdWx0aS1wYWdlIEhUTUwgcm91dGluZyBcdTIwMTQgbXVzdCBydW4gYmVmb3JlIFZpdGUncyBkZWZhdWx0IGZhbGxiYWNrLlxuICAgICAgICAgIHNlcnZlci5taWRkbGV3YXJlcy51c2Uoc2VydmVIdG1sKHNlcnZlcikpO1xuICAgICAgICB9LFxuICAgICAgICBjb25maWd1cmVQcmV2aWV3U2VydmVyKHNlcnZlcikge1xuICAgICAgICAgIGNvbnN0IGFwaSA9IGV4cHJlc3MoKTtcbiAgICAgICAgICBhcGkudXNlKGV4cHJlc3MuanNvbih7IGxpbWl0OiAnMW1iJyB9KSk7XG4gICAgICAgICAgYXBpLnVzZShjcmVhdGVBcGlSb3V0ZXIoKSk7XG4gICAgICAgICAgc2VydmVyLm1pZGRsZXdhcmVzLnVzZSgnL2FwaScsIGFwaSk7XG4gICAgICAgICAgc2VydmVyLm1pZGRsZXdhcmVzLnVzZShzZXJ2ZUh0bWwoc2VydmVyIGFzIHVua25vd24gYXMgVml0ZURldlNlcnZlcikpO1xuICAgICAgICB9LFxuICAgICAgfSxcbiAgICBdLFxuICAgIGJ1aWxkOiB7XG4gICAgICBvdXREaXI6ICdkaXN0JyxcbiAgICAgIGVtcHR5T3V0RGlyOiB0cnVlLFxuICAgICAgcm9sbHVwT3B0aW9uczoge1xuICAgICAgICBpbnB1dDoge1xuICAgICAgICAgIG1haW46ICdpbmRleC5odG1sJyxcbiAgICAgICAgICBwcm9kdWN0czogJ3NyYy9wYWdlcy9wcm9kdWN0cy5odG1sJyxcbiAgICAgICAgICBtYXJrZXRQcmljZXM6ICdzcmMvcGFnZXMvbWFya2V0LXByaWNlcy5odG1sJyxcbiAgICAgICAgICBhYm91dDogJ3NyYy9wYWdlcy9hYm91dC5odG1sJyxcbiAgICAgICAgICBjb250YWN0OiAnc3JjL3BhZ2VzL2NvbnRhY3QuaHRtbCcsXG4gICAgICAgICAgbG9naW46ICdzcmMvcGFnZXMvbG9naW4uaHRtbCcsXG4gICAgICAgICAgcmVnaXN0ZXI6ICdzcmMvcGFnZXMvcmVnaXN0ZXIuaHRtbCcsXG4gICAgICAgICAgYWRtaW5Mb2dpbjogJ3NyYy9wYWdlcy9hZG1pbi1sb2dpbi5odG1sJyxcbiAgICAgICAgICBhZG1pbjogJ3NyYy9wYWdlcy9hZG1pbi5odG1sJyxcbiAgICAgICAgICBmYXJtZXI6ICdzcmMvcGFnZXMvZmFybWVyLmh0bWwnLFxuICAgICAgICAgIHdob2xlc2FsZXI6ICdzcmMvcGFnZXMvd2hvbGVzYWxlci5odG1sJyxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfTtcbn0pO1xuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvaG9tZS9wcm9qZWN0L3NyYy9hcGlcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9ob21lL3Byb2plY3Qvc3JjL2FwaS9zZXJ2ZXIudHNcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfaW1wb3J0X21ldGFfdXJsID0gXCJmaWxlOi8vL2hvbWUvcHJvamVjdC9zcmMvYXBpL3NlcnZlci50c1wiO2ltcG9ydCBleHByZXNzIGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IGNvb2tpZVBhcnNlciBmcm9tICdjb29raWUtcGFyc2VyJztcbmltcG9ydCBtdWx0ZXIgZnJvbSAnbXVsdGVyJztcbmltcG9ydCBiY3J5cHQgZnJvbSAnYmNyeXB0anMnO1xuaW1wb3J0IHsgZGIsIFVzZXIsIENyb3AsIE9yZGVyLCBNYXJrZXRQcmljZSwgUmV2aWV3LCBQcm9kdWN0LCBQcm9kdWN0SW1hZ2UsIENyb3BJbWFnZSwgT3RwQ29kZSB9IGZyb20gJy4vZGInO1xuaW1wb3J0IHsgY3JlYXRlU2Vzc2lvbiwgZGVzdHJveVNlc3Npb24sIGN1cnJlbnRVc2VyLCByZXF1aXJlQXV0aCwgcmVxdWlyZVJvbGUsIHZlcmlmeVBpbiwgaGFzaFBpbiwgU0VTU0lPTl9DT09LSUUgfSBmcm9tICcuL2F1dGgnO1xuXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlQXBpUm91dGVyKCkge1xuICBjb25zdCBhcGkgPSBleHByZXNzLlJvdXRlcigpO1xuICBhcGkudXNlKGV4cHJlc3MuanNvbih7IGxpbWl0OiAnMW1iJyB9KSk7XG4gIGFwaS51c2UoY29va2llUGFyc2VyKCkpO1xuICBjb25zdCB1cGxvYWRNaWRkbGV3YXJlID0gbXVsdGVyKHsgc3RvcmFnZTogbXVsdGVyLm1lbW9yeVN0b3JhZ2UoKSwgbGltaXRzOiB7IGZpbGVTaXplOiA1ICogMTAyNCAqIDEwMjQgfSB9KTtcblxuICAvLyAtLS0tLS0tLS0tIEhlbHBlcnMgLS0tLS0tLS0tLVxuICBjb25zdCBPVFBfVFRMX01JTlVURVMgPSAxMDtcbiAgY29uc3QgT1RQX0NPT0xET1dOX1NFQyA9IDMwO1xuXG4gIGZ1bmN0aW9uIGdlbmVyYXRlT3RwKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIFN0cmluZyhNYXRoLmZsb29yKDEwMDAgKyBNYXRoLnJhbmRvbSgpICogOTAwMCkpO1xuICB9XG5cbiAgZnVuY3Rpb24gaXNWYWxpZE5lcGFsUGhvbmUocGhvbmU6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgIGNvbnN0IHAgPSBwaG9uZS5yZXBsYWNlKC9bXFxzLV0vZywgJycpO1xuICAgIHJldHVybiAvXjlcXGR7OX0kLy50ZXN0KHApO1xuICB9XG5cbiAgYXN5bmMgZnVuY3Rpb24gc2VuZE90cChwaG9uZTogc3RyaW5nLCBwdXJwb3NlOiAncmVnaXN0ZXInIHwgJ3Jlc2V0X3BpbicpOiBQcm9taXNlPHsgY29kZTogc3RyaW5nOyBjb29sZG93bjogbnVtYmVyIH0+IHtcbiAgICAvLyBNYXJrIHByZXZpb3VzIHVudXNlZCBjb2RlcyBhcyB1c2VkXG4gICAgYXdhaXQgZGIuZnJvbSgnb3RwX2NvZGVzJykudXBkYXRlKHsgdXNlZDogdHJ1ZSB9KS5lcSgncGhvbmUnLCBwaG9uZSkuZXEoJ3B1cnBvc2UnLCBwdXJwb3NlKS5lcSgndXNlZCcsIGZhbHNlKTtcbiAgICBjb25zdCBjb2RlID0gZ2VuZXJhdGVPdHAoKTtcbiAgICBjb25zdCBleHBpcmVzQXQgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgT1RQX1RUTF9NSU5VVEVTICogNjBfMDAwKS50b0lTT1N0cmluZygpO1xuICAgIGNvbnN0IHsgZXJyb3IgfSA9IGF3YWl0IGRiLmZyb20oJ290cF9jb2RlcycpLmluc2VydCh7IHBob25lLCBjb2RlLCBwdXJwb3NlLCBleHBpcmVzX2F0OiBleHBpcmVzQXQgfSk7XG4gICAgaWYgKGVycm9yKSB0aHJvdyBlcnJvcjtcbiAgICAvLyBJbiBwcm9kdWN0aW9uOiBzZW5kIFNNUyBoZXJlLiBJbiB0aGlzIGVudmlyb25tZW50OiByZXR1cm4gdGhlIGNvZGUgc28gdGhlIFVJIGNhbiBkaXNwbGF5IGl0LlxuICAgIHJldHVybiB7IGNvZGUsIGNvb2xkb3duOiBPVFBfQ09PTERPV05fU0VDIH07XG4gIH1cblxuICBhc3luYyBmdW5jdGlvbiB2ZXJpZnlPdHAocGhvbmU6IHN0cmluZywgY29kZTogc3RyaW5nLCBwdXJwb3NlOiAncmVnaXN0ZXInIHwgJ3Jlc2V0X3BpbicpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBjb25zdCB7IGRhdGEgfSA9IGF3YWl0IGRiXG4gICAgICAuZnJvbSgnb3RwX2NvZGVzJylcbiAgICAgIC5zZWxlY3QoJyonKVxuICAgICAgLmVxKCdwaG9uZScsIHBob25lKVxuICAgICAgLmVxKCdwdXJwb3NlJywgcHVycG9zZSlcbiAgICAgIC5lcSgndXNlZCcsIGZhbHNlKVxuICAgICAgLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pXG4gICAgICAubGltaXQoMSlcbiAgICAgIC5tYXliZVNpbmdsZSgpIGFzIHsgZGF0YTogT3RwQ29kZSB8IG51bGwgfTtcbiAgICBpZiAoIWRhdGEpIHJldHVybiBmYWxzZTtcbiAgICBpZiAobmV3IERhdGUoZGF0YS5leHBpcmVzX2F0KS5nZXRUaW1lKCkgPCBEYXRlLm5vdygpKSByZXR1cm4gZmFsc2U7XG4gICAgaWYgKGRhdGEuY29kZSAhPT0gY29kZSkgcmV0dXJuIGZhbHNlO1xuICAgIGF3YWl0IGRiLmZyb20oJ290cF9jb2RlcycpLnVwZGF0ZSh7IHVzZWQ6IHRydWUgfSkuZXEoJ2lkJywgZGF0YS5pZCk7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuXG4gIC8vIC0tLS0tLS0tLS0gQXV0aCAtLS0tLS0tLS0tXG4gIC8vIC0tLS0tLS0tLS0gT1RQOiBzZW5kIC0tLS0tLS0tLS1cbiAgYXBpLnBvc3QoJy9hdXRoL3NlbmQtb3RwJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgcGhvbmUsIHB1cnBvc2UgfSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgaWYgKCFwaG9uZSB8fCAhcHVycG9zZSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdtaXNzaW5nX2ZpZWxkcycgfSk7XG4gICAgICBpZiAoIVsncmVnaXN0ZXInLCAncmVzZXRfcGluJ10uaW5jbHVkZXMocHVycG9zZSkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9wdXJwb3NlJyB9KTtcbiAgICAgIGlmICghaXNWYWxpZE5lcGFsUGhvbmUocGhvbmUpKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfcGhvbmUnIH0pO1xuXG4gICAgICAvLyBGb3IgcmVnaXN0ZXI6IGNoZWNrIHRoZSBwaG9uZSBpc24ndCBhbHJlYWR5IHJlZ2lzdGVyZWRcbiAgICAgIGlmIChwdXJwb3NlID09PSAncmVnaXN0ZXInKSB7XG4gICAgICAgIGNvbnN0IHsgZGF0YTogZXhpc3RpbmcgfSA9IGF3YWl0IGRiLmZyb20oJ3VzZXJzJykuc2VsZWN0KCdpZCcpLmVxKCdwaG9uZScsIHBob25lKS5tYXliZVNpbmdsZSgpO1xuICAgICAgICBpZiAoZXhpc3RpbmcpIHJldHVybiByZXMuc3RhdHVzKDQwOSkuanNvbih7IGVycm9yOiAnZXhpc3RzJyB9KTtcbiAgICAgIH1cbiAgICAgIC8vIEZvciByZXNldF9waW46IGNoZWNrIHRoZSBwaG9uZSBJUyByZWdpc3RlcmVkXG4gICAgICBpZiAocHVycG9zZSA9PT0gJ3Jlc2V0X3BpbicpIHtcbiAgICAgICAgY29uc3QgeyBkYXRhOiBleGlzdGluZyB9ID0gYXdhaXQgZGIuZnJvbSgndXNlcnMnKS5zZWxlY3QoJ2lkJykuZXEoJ3Bob25lJywgcGhvbmUpLm1heWJlU2luZ2xlKCk7XG4gICAgICAgIGlmICghZXhpc3RpbmcpIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIH1cblxuICAgICAgLy8gQ29vbGRvd246IGNoZWNrIGxhc3QgT1RQIHNlbnQgd2l0aGluIGNvb2xkb3duIHdpbmRvd1xuICAgICAgY29uc3QgeyBkYXRhOiByZWNlbnQgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCdvdHBfY29kZXMnKVxuICAgICAgICAuc2VsZWN0KCdjcmVhdGVkX2F0JylcbiAgICAgICAgLmVxKCdwaG9uZScsIHBob25lKVxuICAgICAgICAuZXEoJ3B1cnBvc2UnLCBwdXJwb3NlKVxuICAgICAgICAub3JkZXIoJ2NyZWF0ZWRfYXQnLCB7IGFzY2VuZGluZzogZmFsc2UgfSlcbiAgICAgICAgLmxpbWl0KDEpXG4gICAgICAgIC5tYXliZVNpbmdsZSgpIGFzIHsgZGF0YTogeyBjcmVhdGVkX2F0OiBzdHJpbmcgfSB8IG51bGwgfTtcbiAgICAgIGlmIChyZWNlbnQpIHtcbiAgICAgICAgY29uc3QgZWxhcHNlZCA9IChEYXRlLm5vdygpIC0gbmV3IERhdGUocmVjZW50LmNyZWF0ZWRfYXQpLmdldFRpbWUoKSkgLyAxMDAwO1xuICAgICAgICBpZiAoZWxhcHNlZCA8IE9UUF9DT09MRE9XTl9TRUMpIHtcbiAgICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MjkpLmpzb24oeyBlcnJvcjogJ2Nvb2xkb3duJywgcmV0cnlfYWZ0ZXI6IE1hdGguY2VpbChPVFBfQ09PTERPV05fU0VDIC0gZWxhcHNlZCkgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgY29uc3QgeyBjb2RlLCBjb29sZG93biB9ID0gYXdhaXQgc2VuZE90cChwaG9uZSwgcHVycG9zZSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBvazogdHJ1ZSwgY29vbGRvd24sIGRlbW9fY29kZTogY29kZSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdzZW5kLW90cCBlcnJvcicsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBPVFA6IHZlcmlmeSAtLS0tLS0tLS0tXG4gIGFwaS5wb3N0KCcvYXV0aC92ZXJpZnktb3RwJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgcGhvbmUsIGNvZGUsIHB1cnBvc2UgfSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgaWYgKCFwaG9uZSB8fCAhY29kZSB8fCAhcHVycG9zZSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdtaXNzaW5nX2ZpZWxkcycgfSk7XG4gICAgICBjb25zdCBvayA9IGF3YWl0IHZlcmlmeU90cChwaG9uZSwgU3RyaW5nKGNvZGUpLCBwdXJwb3NlKTtcbiAgICAgIGlmICghb2spIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9vdHAnIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgb2s6IHRydWUsIHZlcmlmaWVkOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ3ZlcmlmeS1vdHAgZXJyb3InLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIC0tLS0tLS0tLS0gUmVnaXN0ZXIgKHJlcXVpcmVzIHZlcmlmaWVkIHBob25lKSAtLS0tLS0tLS0tXG4gIGFwaS5wb3N0KCcvYXV0aC9yZWdpc3RlcicsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IGZ1bGxfbmFtZSwgcGhvbmUsIHBpbiwgY29uZmlybV9waW4sIHJvbGUsIGJ1c2luZXNzX25hbWUsIG90cF9jb2RlIH0gPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGlmICghZnVsbF9uYW1lIHx8ICFwaG9uZSB8fCAhcGluIHx8ICFyb2xlKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbWlzc2luZ19maWVsZHMnIH0pO1xuICAgICAgfVxuICAgICAgaWYgKCFpc1ZhbGlkTmVwYWxQaG9uZShwaG9uZSkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9waG9uZScgfSk7XG4gICAgICBpZiAoIVsnZmFybWVyJywgJ3dob2xlc2FsZXInXS5pbmNsdWRlcyhyb2xlKSkge1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfcm9sZScgfSk7XG4gICAgICB9XG4gICAgICBpZiAoIS9eXFxkezR9JC8udGVzdChTdHJpbmcocGluKSkpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX3BpbicgfSk7XG4gICAgICB9XG4gICAgICBpZiAoY29uZmlybV9waW4gIT09IHVuZGVmaW5lZCAmJiBTdHJpbmcoY29uZmlybV9waW4pICE9PSBTdHJpbmcocGluKSkge1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ3Bpbl9taXNtYXRjaCcgfSk7XG4gICAgICB9XG4gICAgICBpZiAocm9sZSA9PT0gJ3dob2xlc2FsZXInICYmICFidXNpbmVzc19uYW1lKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbWlzc2luZ19idXNpbmVzc19uYW1lJyB9KTtcbiAgICAgIH1cbiAgICAgIC8vIFJlcXVpcmUgT1RQIHZlcmlmaWNhdGlvblxuICAgICAgaWYgKCFvdHBfY29kZSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdvdHBfcmVxdWlyZWQnIH0pO1xuICAgICAgY29uc3Qgb3RwT2sgPSBhd2FpdCB2ZXJpZnlPdHAocGhvbmUsIFN0cmluZyhvdHBfY29kZSksICdyZWdpc3RlcicpO1xuICAgICAgaWYgKCFvdHBPaykgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX290cCcgfSk7XG5cbiAgICAgIGNvbnN0IHsgZGF0YTogZXhpc3RpbmcgfSA9IGF3YWl0IGRiLmZyb20oJ3VzZXJzJykuc2VsZWN0KCdpZCcpLmVxKCdwaG9uZScsIHBob25lKS5tYXliZVNpbmdsZSgpO1xuICAgICAgaWYgKGV4aXN0aW5nKSByZXR1cm4gcmVzLnN0YXR1cyg0MDkpLmpzb24oeyBlcnJvcjogJ2V4aXN0cycgfSk7XG5cbiAgICAgIGNvbnN0IHBpbl9oYXNoID0gYXdhaXQgaGFzaFBpbihTdHJpbmcocGluKSk7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgndXNlcnMnKVxuICAgICAgICAuaW5zZXJ0KHtcbiAgICAgICAgICBmdWxsX25hbWUsXG4gICAgICAgICAgcGhvbmUsXG4gICAgICAgICAgcGluX2hhc2gsXG4gICAgICAgICAgcm9sZSxcbiAgICAgICAgICBwaG9uZV92ZXJpZmllZDogdHJ1ZSxcbiAgICAgICAgICBidXNpbmVzc19uYW1lOiByb2xlID09PSAnd2hvbGVzYWxlcicgPyBidXNpbmVzc19uYW1lIDogbnVsbCxcbiAgICAgICAgICBzdGF0dXM6ICdhY3RpdmUnLFxuICAgICAgICB9KVxuICAgICAgICAuc2VsZWN0KCcqJylcbiAgICAgICAgLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICBhd2FpdCBjcmVhdGVTZXNzaW9uKHJlcywgKGRhdGEgYXMgVXNlcikuaWQpO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgdXNlcjogc2FuaXRpemUoZGF0YSkgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcigncmVnaXN0ZXIgZXJyb3InLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIC0tLS0tLS0tLS0gTG9naW4gKHBob25lICsgUElOLCBtdXN0IGJlIHZlcmlmaWVkKSAtLS0tLS0tLS0tXG4gIGFwaS5wb3N0KCcvYXV0aC9sb2dpbicsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IHBob25lLCBwaW4gfSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgaWYgKCFwaG9uZSB8fCAhcGluKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmdfZmllbGRzJyB9KTtcbiAgICAgIGNvbnN0IHsgZGF0YTogdXNlciB9ID0gKGF3YWl0IGRiLmZyb20oJ3VzZXJzJykuc2VsZWN0KCcqJykuZXEoJ3Bob25lJywgcGhvbmUpLm1heWJlU2luZ2xlKCkpIGFzIHsgZGF0YTogVXNlciB8IG51bGwgfTtcbiAgICAgIC8vIEdlbmVyaWMgZXJyb3IgZm9yIGFsbCBmYWlsdXJlcyAod3JvbmcgcGhvbmUsIHdyb25nIFBJTiwgdW52ZXJpZmllZClcbiAgICAgIGlmICghdXNlcikgcmV0dXJuIHJlcy5zdGF0dXMoNDAxKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX2NyZWRzJyB9KTtcbiAgICAgIGNvbnN0IG9rID0gYXdhaXQgdmVyaWZ5UGluKHVzZXIsIFN0cmluZyhwaW4pKTtcbiAgICAgIGlmICghb2spIHJldHVybiByZXMuc3RhdHVzKDQwMSkuanNvbih7IGVycm9yOiAnaW52YWxpZF9jcmVkcycgfSk7XG4gICAgICBpZiAodXNlci5zdGF0dXMgIT09ICdhY3RpdmUnKSByZXR1cm4gcmVzLnN0YXR1cyg0MDMpLmpzb24oeyBlcnJvcjogJ3N1c3BlbmRlZCcgfSk7XG4gICAgICBpZiAoIXVzZXIucGhvbmVfdmVyaWZpZWQpIHJldHVybiByZXMuc3RhdHVzKDQwMSkuanNvbih7IGVycm9yOiAnaW52YWxpZF9jcmVkcycgfSk7XG4gICAgICBhd2FpdCBjcmVhdGVTZXNzaW9uKHJlcywgdXNlci5pZCk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyB1c2VyOiBzYW5pdGl6ZSh1c2VyKSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdsb2dpbiBlcnJvcicsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBGb3Jnb3QgUElOOiByZXNldCB3aXRoIE9UUCAtLS0tLS0tLS0tXG4gIGFwaS5wb3N0KCcvYXV0aC9yZXNldC1waW4nLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgeyBwaG9uZSwgb3RwX2NvZGUsIG5ld19waW4sIGNvbmZpcm1fcGluIH0gPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGlmICghcGhvbmUgfHwgIW90cF9jb2RlIHx8ICFuZXdfcGluKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmdfZmllbGRzJyB9KTtcbiAgICAgIGlmICghL15cXGR7NH0kLy50ZXN0KFN0cmluZyhuZXdfcGluKSkpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9waW4nIH0pO1xuICAgICAgaWYgKGNvbmZpcm1fcGluICE9PSB1bmRlZmluZWQgJiYgU3RyaW5nKGNvbmZpcm1fcGluKSAhPT0gU3RyaW5nKG5ld19waW4pKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAncGluX21pc21hdGNoJyB9KTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IG90cE9rID0gYXdhaXQgdmVyaWZ5T3RwKHBob25lLCBTdHJpbmcob3RwX2NvZGUpLCAncmVzZXRfcGluJyk7XG4gICAgICBpZiAoIW90cE9rKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfb3RwJyB9KTtcbiAgICAgIGNvbnN0IHsgZGF0YTogdXNlciB9ID0gKGF3YWl0IGRiLmZyb20oJ3VzZXJzJykuc2VsZWN0KCdpZCcpLmVxKCdwaG9uZScsIHBob25lKS5tYXliZVNpbmdsZSgpKSBhcyB7IGRhdGE6IFVzZXIgfCBudWxsIH07XG4gICAgICBpZiAoIXVzZXIpIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIGNvbnN0IHBpbl9oYXNoID0gYXdhaXQgaGFzaFBpbihTdHJpbmcobmV3X3BpbikpO1xuICAgICAgY29uc3QgeyBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgndXNlcnMnKS51cGRhdGUoeyBwaW5faGFzaCwgcGhvbmVfdmVyaWZpZWQ6IHRydWUgfSkuZXEoJ2lkJywgdXNlci5pZCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IG9rOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ3Jlc2V0LXBpbiBlcnJvcicsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLnBvc3QoJy9hdXRoL2xvZ291dCcsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBhd2FpdCBkZXN0cm95U2Vzc2lvbihyZXEsIHJlcyk7XG4gICAgICByZXMuanNvbih7IG9rOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2gge1xuICAgICAgcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkuZ2V0KCcvYXV0aC9tZScsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIGNvbnN0IHVzZXIgPSBhd2FpdCBjdXJyZW50VXNlcihyZXEpO1xuICAgIGlmICghdXNlcikgcmV0dXJuIHJlcy5zdGF0dXMoMjAwKS5qc29uKHsgdXNlcjogbnVsbCB9KTtcbiAgICByZXR1cm4gcmVzLmpzb24oeyB1c2VyOiBzYW5pdGl6ZSh1c2VyKSB9KTtcbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBDcm9wcyAocHVibGljICsgZmFybWVyKSAtLS0tLS0tLS0tXG4gIGFwaS5nZXQoJy9jcm9wcycsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBzdGF0dXMgPSAocmVxLnF1ZXJ5LnN0YXR1cyBhcyBzdHJpbmcpIHx8ICdhcHByb3ZlZCc7XG4gICAgICBsZXQgcSA9IGRiLmZyb20oJ2Nyb3BzJykuc2VsZWN0KCcqLCBmYXJtZXI6dXNlcnMhY3JvcHNfZmFybWVyX2lkX2ZrZXkoKiksIGltYWdlczpjcm9wX2ltYWdlcygqKScpLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgICAgaWYgKHN0YXR1cyA9PT0gJ2FwcHJvdmVkJykgcSA9IHEuZXEoJ3N0YXR1cycsICdhcHByb3ZlZCcpO1xuICAgICAgZWxzZSBpZiAoc3RhdHVzID09PSAnbWluZScpIHtcbiAgICAgICAgLy8gY2FsbGVyIG11c3QgYmUgYXV0aGVkOyBmaWx0ZXJlZCBpbiBKUyBiZWxvd1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcSA9IHEuZXEoJ3N0YXR1cycsIHN0YXR1cyk7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBxO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICBsZXQgcm93cyA9IChkYXRhIGFzIChDcm9wICYgeyBpbWFnZXM6IENyb3BJbWFnZVtdIH0pW10pID8/IFtdO1xuICAgICAgaWYgKHN0YXR1cyA9PT0gJ21pbmUnKSB7XG4gICAgICAgIGNvbnN0IG1lID0gYXdhaXQgY3VycmVudFVzZXIocmVxKTtcbiAgICAgICAgaWYgKCFtZSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAxKS5qc29uKHsgZXJyb3I6ICd1bmF1dGhvcml6ZWQnIH0pO1xuICAgICAgICByb3dzID0gcm93cy5maWx0ZXIoKGMpID0+IGMuZmFybWVyX2lkID09PSBtZS5pZCk7XG4gICAgICB9XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBjcm9wczogcm93cy5tYXAoKGMpID0+ICh7IC4uLnNhbml0aXplQ3JvcChjKSwgaW1hZ2VzOiAoYy5pbWFnZXMgfHwgW10pLnNvcnQoKGEsIGIpID0+IGEuc29ydF9vcmRlciAtIGIuc29ydF9vcmRlcikgfSkpIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0dFVCAvY3JvcHMnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIGNvbnN0IENST1BfTUFYX0lNQUdFUyA9IDU7XG4gIGNvbnN0IENST1BfTUFYX0lNQUdFX1NJWkUgPSA1ICogMTAyNCAqIDEwMjQ7XG4gIGNvbnN0IENST1BfQUxMT1dFRF9UWVBFUyA9IFsnaW1hZ2UvanBlZycsICdpbWFnZS9wbmcnLCAnaW1hZ2Uvd2VicCddO1xuICBjb25zdCBDUk9QX0JVQ0tFVCA9ICdjcm9wLWltYWdlcyc7XG5cbiAgYXN5bmMgZnVuY3Rpb24gdXBsb2FkQ3JvcEltYWdlcyhjcm9wSWQ6IHN0cmluZywgZmlsZXM6IEV4cHJlc3MuTXVsdGVyLkZpbGVbXSk6IFByb21pc2U8Q3JvcEltYWdlW10+IHtcbiAgICBpZiAoIWZpbGVzLmxlbmd0aCkgcmV0dXJuIFtdO1xuICAgIGNvbnN0IHJvd3M6IENyb3BJbWFnZVtdID0gW107XG4gICAgY29uc3QgeyBkYXRhOiBleGlzdGluZyB9ID0gYXdhaXQgZGIuZnJvbSgnY3JvcF9pbWFnZXMnKS5zZWxlY3QoJ3NvcnRfb3JkZXInKS5lcSgnY3JvcF9pZCcsIGNyb3BJZCk7XG4gICAgbGV0IG5leHRPcmRlciA9IGV4aXN0aW5nICYmIGV4aXN0aW5nLmxlbmd0aCA/IE1hdGgubWF4KC4uLmV4aXN0aW5nLm1hcCgoaTogYW55KSA9PiBpLnNvcnRfb3JkZXIpKSArIDEgOiAwO1xuICAgIGZvciAoY29uc3QgZmlsZSBvZiBmaWxlcykge1xuICAgICAgY29uc3QgZXh0ID0gZmlsZS5vcmlnaW5hbG5hbWUuc3BsaXQoJy4nKS5wb3AoKT8udG9Mb3dlckNhc2UoKSB8fCAnanBnJztcbiAgICAgIGNvbnN0IGZpbGVQYXRoID0gYCR7Y3JvcElkfS8ke0RhdGUubm93KCl9LSR7TWF0aC5yYW5kb20oKS50b1N0cmluZygzNikuc2xpY2UoMiwgOCl9LiR7ZXh0fWA7XG4gICAgICBjb25zdCB7IGVycm9yOiB1cEVyciB9ID0gYXdhaXQgZGIuc3RvcmFnZS5mcm9tKENST1BfQlVDS0VUKS51cGxvYWQoZmlsZVBhdGgsIGZpbGUuYnVmZmVyLCB7IGNvbnRlbnRUeXBlOiBmaWxlLm1pbWV0eXBlLCB1cHNlcnQ6IGZhbHNlIH0pO1xuICAgICAgaWYgKHVwRXJyKSB7IGNvbnNvbGUuZXJyb3IoJ2Nyb3AgaW1hZ2UgdXBsb2FkJywgdXBFcnIpOyBjb250aW51ZTsgfVxuICAgICAgY29uc3QgeyBkYXRhOiBwdWIgfSA9IGRiLnN0b3JhZ2UuZnJvbShDUk9QX0JVQ0tFVCkuZ2V0UHVibGljVXJsKGZpbGVQYXRoKTtcbiAgICAgIGNvbnN0IHsgZGF0YTogaW1nUm93IH0gPSBhd2FpdCBkYi5mcm9tKCdjcm9wX2ltYWdlcycpLmluc2VydCh7IGNyb3BfaWQ6IGNyb3BJZCwgaW1hZ2VfdXJsOiBwdWIucHVibGljVXJsLCBzb3J0X29yZGVyOiBuZXh0T3JkZXIgfSkuc2VsZWN0KCcqJykuc2luZ2xlKCk7XG4gICAgICBpZiAoaW1nUm93KSByb3dzLnB1c2goaW1nUm93IGFzIENyb3BJbWFnZSk7XG4gICAgICBuZXh0T3JkZXIrKztcbiAgICB9XG4gICAgcmV0dXJuIHJvd3M7XG4gIH1cblxuICBhc3luYyBmdW5jdGlvbiBkZWxldGVDcm9wU3RvcmFnZUZpbGUocHVibGljVXJsOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgdXJsID0gbmV3IFVSTChwdWJsaWNVcmwpO1xuICAgICAgY29uc3QgcGFydHMgPSB1cmwucGF0aG5hbWUuc3BsaXQoYC9zdG9yYWdlL3YxL29iamVjdC9wdWJsaWMvJHtDUk9QX0JVQ0tFVH0vYCk7XG4gICAgICBpZiAocGFydHMubGVuZ3RoIDwgMikgcmV0dXJuO1xuICAgICAgYXdhaXQgZGIuc3RvcmFnZS5mcm9tKENST1BfQlVDS0VUKS5yZW1vdmUoW2RlY29kZVVSSUNvbXBvbmVudChwYXJ0c1sxXSldKTtcbiAgICB9IGNhdGNoIChlKSB7IGNvbnNvbGUuZXJyb3IoJ2RlbGV0ZUNyb3BTdG9yYWdlRmlsZScsIGUpOyB9XG4gIH1cblxuICBhcGkuZ2V0KCcvY3JvcHMvOmlkJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgaWQgfSA9IHJlcS5wYXJhbXM7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgnY3JvcHMnKVxuICAgICAgICAuc2VsZWN0KCcqLCBmYXJtZXI6dXNlcnMhY3JvcHNfZmFybWVyX2lkX2ZrZXkoKiksIGltYWdlczpjcm9wX2ltYWdlcygqKScpXG4gICAgICAgIC5lcSgnaWQnLCBpZClcbiAgICAgICAgLm1heWJlU2luZ2xlKCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIGlmICghZGF0YSkgcmV0dXJuIHJlcy5zdGF0dXMoNDA0KS5qc29uKHsgZXJyb3I6ICdub3RfZm91bmQnIH0pO1xuICAgICAgY29uc3QgYyA9IGRhdGEgYXMgQ3JvcCAmIHsgaW1hZ2VzOiBDcm9wSW1hZ2VbXSB9O1xuICAgICAgYy5pbWFnZXMgPSAoYy5pbWFnZXMgfHwgW10pLnNvcnQoKGEsIGIpID0+IGEuc29ydF9vcmRlciAtIGIuc29ydF9vcmRlcik7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBjcm9wOiB7IC4uLnNhbml0aXplQ3JvcChjKSwgaW1hZ2VzOiBjLmltYWdlcyB9IH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0dFVCAvY3JvcHMvOmlkJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkucG9zdCgnL2Nyb3BzJywgcmVxdWlyZVJvbGUoJ2Zhcm1lcicpLCB1cGxvYWRNaWRkbGV3YXJlLmFueSgpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgYm9keSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgY29uc3QgZmlsZXMgPSAocmVxLmZpbGVzIGFzIEV4cHJlc3MuTXVsdGVyLkZpbGVbXSB8IHVuZGVmaW5lZCkgPz8gW107XG4gICAgICBjb25zdCB7IG5hbWUsIGNhdGVnb3J5LCBwcmljZSwgcXVhbnRpdHlfYXZhaWxhYmxlLCB1bml0LCBsb2NhdGlvbiwgaGFydmVzdF9kYXRlLCBkZXNjcmlwdGlvbiB9ID0gYm9keTtcbiAgICAgIGlmICghbmFtZSB8fCBwcmljZSA9PSBudWxsIHx8IHF1YW50aXR5X2F2YWlsYWJsZSA9PSBudWxsKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbWlzc2luZ19maWVsZHMnIH0pO1xuICAgICAgfVxuICAgICAgaWYgKGZpbGVzLmxlbmd0aCA+IENST1BfTUFYX0lNQUdFUykgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICd0b29fbWFueV9pbWFnZXMnIH0pO1xuICAgICAgZm9yIChjb25zdCBmIG9mIGZpbGVzKSB7XG4gICAgICAgIGlmICghQ1JPUF9BTExPV0VEX1RZUEVTLmluY2x1ZGVzKGYubWltZXR5cGUpKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfaW1hZ2VfdHlwZScgfSk7XG4gICAgICAgIGlmIChmLnNpemUgPiBDUk9QX01BWF9JTUFHRV9TSVpFKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ltYWdlX3Rvb19sYXJnZScgfSk7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgnY3JvcHMnKVxuICAgICAgICAuaW5zZXJ0KHtcbiAgICAgICAgICBmYXJtZXJfaWQ6IG1lLmlkLFxuICAgICAgICAgIG5hbWUsXG4gICAgICAgICAgY2F0ZWdvcnk6IGNhdGVnb3J5IHx8IG51bGwsXG4gICAgICAgICAgcHJpY2U6IE51bWJlcihwcmljZSksXG4gICAgICAgICAgcXVhbnRpdHlfYXZhaWxhYmxlOiBOdW1iZXIocXVhbnRpdHlfYXZhaWxhYmxlKSxcbiAgICAgICAgICB1bml0OiB1bml0IHx8ICdrZycsXG4gICAgICAgICAgbG9jYXRpb246IGxvY2F0aW9uIHx8IG51bGwsXG4gICAgICAgICAgaGFydmVzdF9kYXRlOiBoYXJ2ZXN0X2RhdGUgfHwgbnVsbCxcbiAgICAgICAgICBkZXNjcmlwdGlvbjogZGVzY3JpcHRpb24gfHwgbnVsbCxcbiAgICAgICAgICBzdGF0dXM6ICdhcHByb3ZlZCcsXG4gICAgICAgIH0pXG4gICAgICAgIC5zZWxlY3QoJyonKVxuICAgICAgICAuc2luZ2xlKCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIGNvbnN0IGNyb3AgPSBkYXRhIGFzIENyb3A7XG4gICAgICBhd2FpdCB1cGxvYWRDcm9wSW1hZ2VzKGNyb3AuaWQsIGZpbGVzKTtcbiAgICAgIGNvbnN0IHsgZGF0YTogZnVsbCB9ID0gYXdhaXQgZGIuZnJvbSgnY3JvcHMnKS5zZWxlY3QoJyosIGltYWdlczpjcm9wX2ltYWdlcygqKScpLmVxKCdpZCcsIGNyb3AuaWQpLnNpbmdsZSgpO1xuICAgICAgY29uc3QgcmVzdWx0ID0gZnVsbCBhcyBDcm9wICYgeyBpbWFnZXM6IENyb3BJbWFnZVtdIH07XG4gICAgICByZXN1bHQuaW1hZ2VzID0gKHJlc3VsdC5pbWFnZXMgfHwgW10pLnNvcnQoKGEsIGIpID0+IGEuc29ydF9vcmRlciAtIGIuc29ydF9vcmRlcik7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBjcm9wOiB7IC4uLnNhbml0aXplQ3JvcChyZXN1bHQpLCBpbWFnZXM6IHJlc3VsdC5pbWFnZXMgfSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdQT1NUIC9jcm9wcycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLnBhdGNoKCcvY3JvcHMvOmlkJywgcmVxdWlyZVJvbGUoJ2Zhcm1lcicsICdhZG1pbicpLCB1cGxvYWRNaWRkbGV3YXJlLmFueSgpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgeyBpZCB9ID0gcmVxLnBhcmFtcztcbiAgICAgIGNvbnN0IGJvZHkgPSByZXEuYm9keSB8fCB7fTtcbiAgICAgIGNvbnN0IGZpbGVzID0gKHJlcS5maWxlcyBhcyBFeHByZXNzLk11bHRlci5GaWxlW10gfCB1bmRlZmluZWQpID8/IFtdO1xuICAgICAgY29uc3QgeyBkYXRhOiBjcm9wIH0gPSAoYXdhaXQgZGIuZnJvbSgnY3JvcHMnKS5zZWxlY3QoJyonKS5lcSgnaWQnLCBpZCkubWF5YmVTaW5nbGUoKSkgYXMgeyBkYXRhOiBDcm9wIHwgbnVsbCB9O1xuICAgICAgaWYgKCFjcm9wKSByZXR1cm4gcmVzLnN0YXR1cyg0MDQpLmpzb24oeyBlcnJvcjogJ25vdF9mb3VuZCcgfSk7XG4gICAgICBpZiAobWUucm9sZSA9PT0gJ2Zhcm1lcicgJiYgY3JvcC5mYXJtZXJfaWQgIT09IG1lLmlkKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMykuanNvbih7IGVycm9yOiAnZm9yYmlkZGVuJyB9KTtcbiAgICAgIH1cbiAgICAgIGxldCByZW1vdmVJZHM6IHN0cmluZ1tdID0gW107XG4gICAgICBpZiAoYm9keS5yZW1vdmVfaW1hZ2VzKSB7XG4gICAgICAgIHRyeSB7IHJlbW92ZUlkcyA9IEpTT04ucGFyc2UoYm9keS5yZW1vdmVfaW1hZ2VzKTsgfSBjYXRjaCB7IHJlbW92ZUlkcyA9IFtdOyB9XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGE6IGV4aXN0aW5nSW1ncyB9ID0gYXdhaXQgZGIuZnJvbSgnY3JvcF9pbWFnZXMnKS5zZWxlY3QoJ2lkJykuZXEoJ2Nyb3BfaWQnLCBpZCk7XG4gICAgICBjb25zdCBleGlzdGluZ0NvdW50ID0gZXhpc3RpbmdJbWdzPy5sZW5ndGggPz8gMDtcbiAgICAgIGNvbnN0IHJlbWFpbmluZ0FmdGVyUmVtb3ZlID0gZXhpc3RpbmdDb3VudCAtIHJlbW92ZUlkcy5sZW5ndGg7XG4gICAgICBpZiAocmVtYWluaW5nQWZ0ZXJSZW1vdmUgKyBmaWxlcy5sZW5ndGggPiBDUk9QX01BWF9JTUFHRVMpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICd0b29fbWFueV9pbWFnZXMnIH0pO1xuICAgICAgfVxuICAgICAgZm9yIChjb25zdCBmIG9mIGZpbGVzKSB7XG4gICAgICAgIGlmICghQ1JPUF9BTExPV0VEX1RZUEVTLmluY2x1ZGVzKGYubWltZXR5cGUpKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfaW1hZ2VfdHlwZScgfSk7XG4gICAgICAgIGlmIChmLnNpemUgPiBDUk9QX01BWF9JTUFHRV9TSVpFKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ltYWdlX3Rvb19sYXJnZScgfSk7XG4gICAgICB9XG4gICAgICBjb25zdCBhbGxvd2VkID0gWyduYW1lJywgJ2NhdGVnb3J5JywgJ3ByaWNlJywgJ3F1YW50aXR5X2F2YWlsYWJsZScsICd1bml0JywgJ2xvY2F0aW9uJywgJ2hhcnZlc3RfZGF0ZScsICdkZXNjcmlwdGlvbicsICdzdGF0dXMnXTtcbiAgICAgIGNvbnN0IHBhdGNoOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiA9IHt9O1xuICAgICAgZm9yIChjb25zdCBrIG9mIGFsbG93ZWQpIHtcbiAgICAgICAgaWYgKGJvZHlba10gIT09IHVuZGVmaW5lZCkgcGF0Y2hba10gPSBib2R5W2tdO1xuICAgICAgfVxuICAgICAgaWYgKG1lLnJvbGUgIT09ICdhZG1pbicgJiYgJ3N0YXR1cycgaW4gcGF0Y2gpIGRlbGV0ZSBwYXRjaC5zdGF0dXM7XG4gICAgICBpZiAoT2JqZWN0LmtleXMocGF0Y2gpLmxlbmd0aCkge1xuICAgICAgICBjb25zdCB7IGVycm9yIH0gPSBhd2FpdCBkYi5mcm9tKCdjcm9wcycpLnVwZGF0ZShwYXRjaCkuZXEoJ2lkJywgaWQpO1xuICAgICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIH1cbiAgICAgIGlmIChyZW1vdmVJZHMubGVuZ3RoID4gMCkge1xuICAgICAgICBjb25zdCB7IGRhdGE6IGltZ3NUb1JlbW92ZSB9ID0gYXdhaXQgZGIuZnJvbSgnY3JvcF9pbWFnZXMnKS5zZWxlY3QoJ2ltYWdlX3VybCcpLmluKCdpZCcsIHJlbW92ZUlkcykuZXEoJ2Nyb3BfaWQnLCBpZCk7XG4gICAgICAgIGlmIChpbWdzVG9SZW1vdmUgJiYgaW1nc1RvUmVtb3ZlLmxlbmd0aCkge1xuICAgICAgICAgIGF3YWl0IFByb21pc2UuYWxsKGltZ3NUb1JlbW92ZS5tYXAoKGltZykgPT4gZGVsZXRlQ3JvcFN0b3JhZ2VGaWxlKGltZy5pbWFnZV91cmwpKSk7XG4gICAgICAgICAgYXdhaXQgZGIuZnJvbSgnY3JvcF9pbWFnZXMnKS5kZWxldGUoKS5pbignaWQnLCByZW1vdmVJZHMpLmVxKCdjcm9wX2lkJywgaWQpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICBhd2FpdCB1cGxvYWRDcm9wSW1hZ2VzKGlkLCBmaWxlcyk7XG4gICAgICBjb25zdCB7IGRhdGE6IGZ1bGwgfSA9IGF3YWl0IGRiLmZyb20oJ2Nyb3BzJykuc2VsZWN0KCcqLCBpbWFnZXM6Y3JvcF9pbWFnZXMoKiknKS5lcSgnaWQnLCBpZCkuc2luZ2xlKCk7XG4gICAgICBjb25zdCByZXN1bHQgPSBmdWxsIGFzIENyb3AgJiB7IGltYWdlczogQ3JvcEltYWdlW10gfTtcbiAgICAgIHJlc3VsdC5pbWFnZXMgPSAocmVzdWx0LmltYWdlcyB8fCBbXSkuc29ydCgoYSwgYikgPT4gYS5zb3J0X29yZGVyIC0gYi5zb3J0X29yZGVyKTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IGNyb3A6IHsgLi4uc2FuaXRpemVDcm9wKHJlc3VsdCksIGltYWdlczogcmVzdWx0LmltYWdlcyB9IH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1BBVENIIC9jcm9wcycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLmRlbGV0ZSgnL2Nyb3BzLzppZCcsIHJlcXVpcmVSb2xlKCdmYXJtZXInKSwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIGNvbnN0IHsgaWQgfSA9IHJlcS5wYXJhbXM7XG4gICAgICBjb25zdCB7IGRhdGE6IGNyb3AgfSA9IChhd2FpdCBkYi5mcm9tKCdjcm9wcycpLnNlbGVjdCgnKicpLmVxKCdpZCcsIGlkKS5tYXliZVNpbmdsZSgpKSBhcyB7IGRhdGE6IENyb3AgfCBudWxsIH07XG4gICAgICBpZiAoIWNyb3ApIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIGlmIChjcm9wLmZhcm1lcl9pZCAhPT0gbWUuaWQpIHJldHVybiByZXMuc3RhdHVzKDQwMykuanNvbih7IGVycm9yOiAnZm9yYmlkZGVuJyB9KTtcbiAgICAgIGNvbnN0IHsgZGF0YTogaW1hZ2VzIH0gPSBhd2FpdCBkYi5mcm9tKCdjcm9wX2ltYWdlcycpLnNlbGVjdCgnaW1hZ2VfdXJsJykuZXEoJ2Nyb3BfaWQnLCBpZCk7XG4gICAgICBpZiAoaW1hZ2VzICYmIGltYWdlcy5sZW5ndGgpIHtcbiAgICAgICAgYXdhaXQgUHJvbWlzZS5hbGwoaW1hZ2VzLm1hcCgoaW1nKSA9PiBkZWxldGVDcm9wU3RvcmFnZUZpbGUoaW1nLmltYWdlX3VybCkpKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHsgZXJyb3IgfSA9IGF3YWl0IGRiLmZyb20oJ2Nyb3BzJykuZGVsZXRlKCkuZXEoJ2lkJywgaWQpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBvazogdHJ1ZSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdERUxFVEUgL2Nyb3BzLzppZCcsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBPcmRlcnMgLS0tLS0tLS0tLVxuICBhcGkuZ2V0KCcvb3JkZXJzJywgcmVxdWlyZUF1dGgsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBtZSA9IChyZXEgYXMgYW55KS51c2VyIGFzIFVzZXI7XG4gICAgICBsZXQgcSA9IGRiXG4gICAgICAgIC5mcm9tKCdvcmRlcnMnKVxuICAgICAgICAuc2VsZWN0KCcqLCBjcm9wOmNyb3BzKCopLCBmYXJtZXI6dXNlcnMhb3JkZXJzX2Zhcm1lcl9pZF9ma2V5KCopLCB3aG9sZXNhbGVyOnVzZXJzIW9yZGVyc193aG9sZXNhbGVyX2lkX2ZrZXkoKiknKVxuICAgICAgICAub3JkZXIoJ2NyZWF0ZWRfYXQnLCB7IGFzY2VuZGluZzogZmFsc2UgfSk7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBxO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICBsZXQgcm93cyA9IChkYXRhIGFzIE9yZGVyW10pID8/IFtdO1xuICAgICAgaWYgKG1lLnJvbGUgPT09ICdmYXJtZXInKSByb3dzID0gcm93cy5maWx0ZXIoKG8pID0+IG8uZmFybWVyX2lkID09PSBtZS5pZCk7XG4gICAgICBlbHNlIGlmIChtZS5yb2xlID09PSAnd2hvbGVzYWxlcicpIHJvd3MgPSByb3dzLmZpbHRlcigobykgPT4gby53aG9sZXNhbGVyX2lkID09PSBtZS5pZCk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBvcmRlcnM6IHJvd3MgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignR0VUIC9vcmRlcnMnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIGFwaS5wb3N0KCcvb3JkZXJzJywgcmVxdWlyZVJvbGUoJ3dob2xlc2FsZXInKSwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIGNvbnN0IHsgY3JvcF9pZCwgcXVhbnRpdHkgfSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgaWYgKCFjcm9wX2lkIHx8ICFxdWFudGl0eSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdtaXNzaW5nX2ZpZWxkcycgfSk7XG4gICAgICBjb25zdCB7IGRhdGE6IGNyb3AgfSA9IChhd2FpdCBkYi5mcm9tKCdjcm9wcycpLnNlbGVjdCgnKicpLmVxKCdpZCcsIGNyb3BfaWQpLm1heWJlU2luZ2xlKCkpIGFzIHsgZGF0YTogQ3JvcCB8IG51bGwgfTtcbiAgICAgIGlmICghY3JvcCkgcmV0dXJuIHJlcy5zdGF0dXMoNDA0KS5qc29uKHsgZXJyb3I6ICdub3RfZm91bmQnIH0pO1xuICAgICAgaWYgKGNyb3Auc3RhdHVzICE9PSAnYXBwcm92ZWQnKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ25vdF9hcHByb3ZlZCcgfSk7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgnb3JkZXJzJylcbiAgICAgICAgLmluc2VydCh7XG4gICAgICAgICAgd2hvbGVzYWxlcl9pZDogbWUuaWQsXG4gICAgICAgICAgZmFybWVyX2lkOiBjcm9wLmZhcm1lcl9pZCxcbiAgICAgICAgICBjcm9wX2lkOiBjcm9wLmlkLFxuICAgICAgICAgIHF1YW50aXR5OiBOdW1iZXIocXVhbnRpdHkpLFxuICAgICAgICAgIHN0YXR1czogJ3BlbmRpbmcnLFxuICAgICAgICB9KVxuICAgICAgICAuc2VsZWN0KCcqLCBjcm9wOmNyb3BzKCopLCBmYXJtZXI6dXNlcnMhb3JkZXJzX2Zhcm1lcl9pZF9ma2V5KCopJylcbiAgICAgICAgLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBvcmRlcjogZGF0YSBhcyBPcmRlciB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdQT1NUIC9vcmRlcnMnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIGFwaS5wYXRjaCgnL29yZGVycy86aWQnLCByZXF1aXJlQXV0aCwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIGNvbnN0IHsgaWQgfSA9IHJlcS5wYXJhbXM7XG4gICAgICBjb25zdCB7IHN0YXR1cyB9ID0gcmVxLmJvZHkgfHwge307XG4gICAgICBpZiAoIVsncGVuZGluZycsICdjb21wbGV0ZWQnLCAnY2FuY2VsbGVkJ10uaW5jbHVkZXMoc3RhdHVzKSkge1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfc3RhdHVzJyB9KTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHsgZGF0YTogb3JkZXIgfSA9IChhd2FpdCBkYi5mcm9tKCdvcmRlcnMnKS5zZWxlY3QoJyonKS5lcSgnaWQnLCBpZCkubWF5YmVTaW5nbGUoKSkgYXMgeyBkYXRhOiBPcmRlciB8IG51bGwgfTtcbiAgICAgIGlmICghb3JkZXIpIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIGlmIChtZS5yb2xlICE9PSAnYWRtaW4nICYmIG9yZGVyLmZhcm1lcl9pZCAhPT0gbWUuaWQgJiYgb3JkZXIud2hvbGVzYWxlcl9pZCAhPT0gbWUuaWQpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAzKS5qc29uKHsgZXJyb3I6ICdmb3JiaWRkZW4nIH0pO1xuICAgICAgfVxuICAgICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgnb3JkZXJzJykudXBkYXRlKHsgc3RhdHVzIH0pLmVxKCdpZCcsIGlkKS5zZWxlY3QoJyonKS5zaW5nbGUoKTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgb3JkZXI6IGRhdGEgYXMgT3JkZXIgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignUEFUQ0ggL29yZGVycycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBNYXJrZXQgcHJpY2VzIC0tLS0tLS0tLS1cbiAgYXBpLmdldCgnL3ByaWNlcycsIGFzeW5jIChfcmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgnbWFya2V0X3ByaWNlcycpLnNlbGVjdCgnKicpLm9yZGVyKCdwcm9kdWN0Jyk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IHByaWNlczogZGF0YSBhcyBNYXJrZXRQcmljZVtdIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0dFVCAvcHJpY2VzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkucG9zdCgnL3ByaWNlcycsIHJlcXVpcmVSb2xlKCdhZG1pbicpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgeyBwcm9kdWN0LCB1bml0LCBtaW5fcHJpY2UsIG1heF9wcmljZSwgYXZnX3ByaWNlLCB0cmVuZCB9ID0gcmVxLmJvZHkgfHwge307XG4gICAgICBpZiAoIXByb2R1Y3QgfHwgbWluX3ByaWNlID09IG51bGwgfHwgbWF4X3ByaWNlID09IG51bGwgfHwgYXZnX3ByaWNlID09IG51bGwpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdtaXNzaW5nX2ZpZWxkcycgfSk7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgnbWFya2V0X3ByaWNlcycpXG4gICAgICAgIC5pbnNlcnQoe1xuICAgICAgICAgIHByb2R1Y3QsXG4gICAgICAgICAgdW5pdDogdW5pdCB8fCAna2cnLFxuICAgICAgICAgIG1pbl9wcmljZTogTnVtYmVyKG1pbl9wcmljZSksXG4gICAgICAgICAgbWF4X3ByaWNlOiBOdW1iZXIobWF4X3ByaWNlKSxcbiAgICAgICAgICBhdmdfcHJpY2U6IE51bWJlcihhdmdfcHJpY2UpLFxuICAgICAgICAgIHRyZW5kOiB0cmVuZCB8fCAnc3RhYmxlJyxcbiAgICAgICAgICB1cGRhdGVkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG4gICAgICAgIH0pXG4gICAgICAgIC5zZWxlY3QoJyonKVxuICAgICAgICAuc2luZ2xlKCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IHByaWNlOiBkYXRhIGFzIE1hcmtldFByaWNlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1BPU1QgL3ByaWNlcycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLnBhdGNoKCcvcHJpY2VzLzppZCcsIHJlcXVpcmVSb2xlKCdhZG1pbicpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgeyBpZCB9ID0gcmVxLnBhcmFtcztcbiAgICAgIGNvbnN0IHsgcHJvZHVjdCwgdW5pdCwgbWluX3ByaWNlLCBtYXhfcHJpY2UsIGF2Z19wcmljZSwgdHJlbmQgfSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgY29uc3QgcGF0Y2g6IFJlY29yZDxzdHJpbmcsIHVua25vd24+ID0geyB1cGRhdGVkX2F0OiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkgfTtcbiAgICAgIGlmIChwcm9kdWN0ICE9PSB1bmRlZmluZWQpIHBhdGNoLnByb2R1Y3QgPSBwcm9kdWN0O1xuICAgICAgaWYgKHVuaXQgIT09IHVuZGVmaW5lZCkgcGF0Y2gudW5pdCA9IHVuaXQ7XG4gICAgICBpZiAobWluX3ByaWNlICE9PSB1bmRlZmluZWQpIHBhdGNoLm1pbl9wcmljZSA9IE51bWJlcihtaW5fcHJpY2UpO1xuICAgICAgaWYgKG1heF9wcmljZSAhPT0gdW5kZWZpbmVkKSBwYXRjaC5tYXhfcHJpY2UgPSBOdW1iZXIobWF4X3ByaWNlKTtcbiAgICAgIGlmIChhdmdfcHJpY2UgIT09IHVuZGVmaW5lZCkgcGF0Y2guYXZnX3ByaWNlID0gTnVtYmVyKGF2Z19wcmljZSk7XG4gICAgICBpZiAodHJlbmQgIT09IHVuZGVmaW5lZCkgcGF0Y2gudHJlbmQgPSB0cmVuZDtcbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IGRiLmZyb20oJ21hcmtldF9wcmljZXMnKS51cGRhdGUocGF0Y2gpLmVxKCdpZCcsIGlkKS5zZWxlY3QoJyonKS5zaW5nbGUoKTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgcHJpY2U6IGRhdGEgYXMgTWFya2V0UHJpY2UgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignUEFUQ0ggL3ByaWNlcycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLmRlbGV0ZSgnL3ByaWNlcy86aWQnLCByZXF1aXJlUm9sZSgnYWRtaW4nKSwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgaWQgfSA9IHJlcS5wYXJhbXM7XG4gICAgICBjb25zdCB7IGVycm9yIH0gPSBhd2FpdCBkYi5mcm9tKCdtYXJrZXRfcHJpY2VzJykuZGVsZXRlKCkuZXEoJ2lkJywgaWQpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyBvazogdHJ1ZSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdERUxFVEUgL3ByaWNlcycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBDb250YWN0cyAtLS0tLS0tLS0tXG4gIGFwaS5wb3N0KCcvY29udGFjdHMnLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgeyBuYW1lLCBlbWFpbCwgbWVzc2FnZSB9ID0gcmVxLmJvZHkgfHwge307XG4gICAgICBpZiAoIW5hbWUgfHwgIWVtYWlsIHx8ICFtZXNzYWdlKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmdfZmllbGRzJyB9KTtcbiAgICAgIGNvbnN0IHsgZXJyb3IgfSA9IGF3YWl0IGRiLmZyb20oJ2NvbnRhY3RzJykuaW5zZXJ0KHsgbmFtZSwgZW1haWwsIG1lc3NhZ2UgfSk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IG9rOiB0cnVlIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1BPU1QgL2NvbnRhY3RzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyAtLS0tLS0tLS0tIEFkbWluOiB1c2VycyAtLS0tLS0tLS0tXG4gIGFwaS5nZXQoJy9hZG1pbi91c2VycycsIHJlcXVpcmVSb2xlKCdhZG1pbicpLCBhc3luYyAoX3JlcSwgcmVzKSA9PiB7XG4gICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgndXNlcnMnKS5zZWxlY3QoJyonKS5vcmRlcignY3JlYXRlZF9hdCcsIHsgYXNjZW5kaW5nOiBmYWxzZSB9KTtcbiAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICByZXR1cm4gcmVzLmpzb24oeyB1c2VyczogKGRhdGEgYXMgVXNlcltdKS5tYXAoc2FuaXRpemUpIH0pO1xuICB9KTtcblxuICBhcGkucGF0Y2goJy9hZG1pbi91c2Vycy86aWQnLCByZXF1aXJlUm9sZSgnYWRtaW4nKSwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgaWQgfSA9IHJlcS5wYXJhbXM7XG4gICAgICBjb25zdCB7IHN0YXR1cyB9ID0gcmVxLmJvZHkgfHwge307XG4gICAgICBpZiAoIVsnYWN0aXZlJywgJ3N1c3BlbmRlZCcsICdiYW5uZWQnXS5pbmNsdWRlcyhzdGF0dXMpKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9zdGF0dXMnIH0pO1xuICAgICAgfVxuICAgICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgndXNlcnMnKS51cGRhdGUoeyBzdGF0dXMgfSkuZXEoJ2lkJywgaWQpLnNlbGVjdCgnKicpLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyB1c2VyOiBzYW5pdGl6ZShkYXRhIGFzIFVzZXIpIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1BBVENIIC9hZG1pbi91c2VycycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBBZG1pbjogcGVuZGluZyBjcm9wcyAtLS0tLS0tLS0tXG4gIGFwaS5nZXQoJy9hZG1pbi9jcm9wcy9wZW5kaW5nJywgcmVxdWlyZVJvbGUoJ2FkbWluJyksIGFzeW5jIChfcmVxLCByZXMpID0+IHtcbiAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgLmZyb20oJ2Nyb3BzJylcbiAgICAgIC5zZWxlY3QoJyosIGZhcm1lcjp1c2VycyFjcm9wc19mYXJtZXJfaWRfZmtleSgqKScpXG4gICAgICAuZXEoJ3N0YXR1cycsICdwZW5kaW5nJylcbiAgICAgIC5vcmRlcignY3JlYXRlZF9hdCcsIHsgYXNjZW5kaW5nOiBmYWxzZSB9KTtcbiAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICByZXR1cm4gcmVzLmpzb24oeyBjcm9wczogKGRhdGEgYXMgQ3JvcFtdKS5tYXAoc2FuaXRpemVDcm9wKSB9KTtcbiAgfSk7XG5cbiAgYXBpLmdldCgnL2FkbWluL29yZGVycycsIHJlcXVpcmVSb2xlKCdhZG1pbicpLCBhc3luYyAoX3JlcSwgcmVzKSA9PiB7XG4gICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGJcbiAgICAgIC5mcm9tKCdvcmRlcnMnKVxuICAgICAgLnNlbGVjdCgnKiwgY3JvcDpjcm9wcygqKSwgZmFybWVyOnVzZXJzIW9yZGVyc19mYXJtZXJfaWRfZmtleSgqKSwgd2hvbGVzYWxlcjp1c2VycyFvcmRlcnNfd2hvbGVzYWxlcl9pZF9ma2V5KCopJylcbiAgICAgIC5vcmRlcignY3JlYXRlZF9hdCcsIHsgYXNjZW5kaW5nOiBmYWxzZSB9KTtcbiAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICByZXR1cm4gcmVzLmpzb24oeyBvcmRlcnM6IGRhdGEgYXMgT3JkZXJbXSB9KTtcbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBQcm9maWxlIC0tLS0tLS0tLS1cbiAgY29uc3QgUFJPRklMRV9CVUNLRVQgPSAncHJvZmlsZS1pbWFnZXMnO1xuICBjb25zdCBQUk9GSUxFX01BWF9TSVpFID0gNSAqIDEwMjQgKiAxMDI0O1xuICBjb25zdCBQUk9GSUxFX0FMTE9XRURfVFlQRVMgPSBbJ2ltYWdlL2pwZWcnLCAnaW1hZ2UvanBnJywgJ2ltYWdlL3BuZycsICdpbWFnZS93ZWJwJ107XG5cbiAgZnVuY3Rpb24gdXBsb2FkQXZhdGFyKHJlcTogZXhwcmVzcy5SZXF1ZXN0LCByZXM6IGV4cHJlc3MuUmVzcG9uc2UsIG5leHQ6IGV4cHJlc3MuTmV4dEZ1bmN0aW9uKSB7XG4gICAgdXBsb2FkTWlkZGxld2FyZS5zaW5nbGUoJ2F2YXRhcicpKHJlcSwgcmVzLCAoZXJyb3I6IHVua25vd24pID0+IHtcbiAgICAgIGlmICghZXJyb3IpIHtcbiAgICAgICAgbmV4dCgpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBpZiAoZXJyb3IgaW5zdGFuY2VvZiBtdWx0ZXIuTXVsdGVyRXJyb3IgJiYgZXJyb3IuY29kZSA9PT0gJ0xJTUlUX0ZJTEVfU0laRScpIHtcbiAgICAgICAgcmVzLnN0YXR1cyg0MTMpLmpzb24oeyBlcnJvcjogJ2ltYWdlX3Rvb19sYXJnZScsIG1lc3NhZ2U6ICdJbWFnZSBtdXN0IGJlIDUgTUIgb3Igc21hbGxlci4nIH0pO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjb25zb2xlLmVycm9yKCdhdmF0YXIgbXVsdGlwYXJ0IHVwbG9hZCcsIGVycm9yKTtcbiAgICAgIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICd1cGxvYWRfZmFpbGVkJywgbWVzc2FnZTogJ1RoZSBpbWFnZSBjb3VsZCBub3QgYmUgcmVhZC4gUGxlYXNlIGNob29zZSBhIEpQRywgUE5HLCBvciBXRUJQIGltYWdlLicgfSk7XG4gICAgfSk7XG4gIH1cblxuICAvLyBQT1NUIC9tZS9hdmF0YXIgXHUyMDE0IHVwbG9hZCBwcm9maWxlIHBpY3R1cmUgKG11bHRpcGFydDogZmllbGQgXCJhdmF0YXJcIilcbiAgYXBpLnBvc3QoJy9tZS9hdmF0YXInLCByZXF1aXJlQXV0aCwgdXBsb2FkQXZhdGFyLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgZmlsZSA9IHJlcS5maWxlIGFzIEV4cHJlc3MuTXVsdGVyLkZpbGUgfCB1bmRlZmluZWQ7XG4gICAgICBpZiAoIWZpbGUpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbWlzc2luZ19maWxlJyB9KTtcbiAgICAgIGlmICghUFJPRklMRV9BTExPV0VEX1RZUEVTLmluY2x1ZGVzKGZpbGUubWltZXR5cGUpKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW52YWxpZF9pbWFnZV90eXBlJyB9KTtcbiAgICAgIH1cbiAgICAgIGlmIChmaWxlLnNpemUgPiBQUk9GSUxFX01BWF9TSVpFKSB7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnaW1hZ2VfdG9vX2xhcmdlJyB9KTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgZXh0ID0gZmlsZS5taW1ldHlwZSA9PT0gJ2ltYWdlL3BuZycgPyAncG5nJyA6IGZpbGUubWltZXR5cGUgPT09ICdpbWFnZS93ZWJwJyA/ICd3ZWJwJyA6ICdqcGcnO1xuICAgICAgY29uc3QgZmlsZVBhdGggPSBgcHJvZmlsZXMvJHttZS5pZH0vJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDgpfS4ke2V4dH1gO1xuXG4gICAgICBjb25zdCB7IGVycm9yOiB1cEVyciB9ID0gYXdhaXQgZGIuc3RvcmFnZVxuICAgICAgICAuZnJvbShQUk9GSUxFX0JVQ0tFVClcbiAgICAgICAgLnVwbG9hZChmaWxlUGF0aCwgZmlsZS5idWZmZXIsIHsgY29udGVudFR5cGU6IGZpbGUubWltZXR5cGUsIHVwc2VydDogZmFsc2UgfSk7XG4gICAgICBpZiAodXBFcnIpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcignYXZhdGFyIHVwbG9hZCcsIHVwRXJyKTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAyKS5qc29uKHsgZXJyb3I6ICdzdG9yYWdlX3VwbG9hZF9mYWlsZWQnLCBtZXNzYWdlOiB1cEVyci5tZXNzYWdlIHx8ICdTdG9yYWdlIHJlamVjdGVkIHRoZSBpbWFnZS4nIH0pO1xuICAgICAgfVxuXG4gICAgICBjb25zdCB7IGRhdGE6IHB1YiB9ID0gZGIuc3RvcmFnZS5mcm9tKFBST0ZJTEVfQlVDS0VUKS5nZXRQdWJsaWNVcmwoZmlsZVBhdGgpO1xuICAgICAgY29uc3QgbmV3QXZhdGFyVXJsID0gcHViLnB1YmxpY1VybDtcblxuICAgICAgLy8gR2V0IG9sZCBhdmF0YXIgVVJMIHRvIGRlbGV0ZSBhZnRlciB1cGRhdGVcbiAgICAgIGNvbnN0IG9sZEF2YXRhclVybCA9IG1lLmF2YXRhcl91cmw7XG5cbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCd1c2VycycpXG4gICAgICAgIC51cGRhdGUoeyBhdmF0YXJfdXJsOiBuZXdBdmF0YXJVcmwgfSlcbiAgICAgICAgLmVxKCdpZCcsIG1lLmlkKVxuICAgICAgICAuc2VsZWN0KCcqJylcbiAgICAgICAgLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSB7XG4gICAgICAgIGF3YWl0IGRiLnN0b3JhZ2UuZnJvbShQUk9GSUxFX0JVQ0tFVCkucmVtb3ZlKFtmaWxlUGF0aF0pO1xuICAgICAgICBjb25zb2xlLmVycm9yKCdhdmF0YXIgcHJvZmlsZSB1cGRhdGUnLCBlcnJvcik7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAncHJvZmlsZV91cGRhdGVfZmFpbGVkJywgbWVzc2FnZTogZXJyb3IubWVzc2FnZSB8fCAnVGhlIHByb2ZpbGUgY291bGQgbm90IGJlIHVwZGF0ZWQuJyB9KTtcbiAgICAgIH1cblxuICAgICAgLy8gRGVsZXRlIG9sZCBhdmF0YXIgZnJvbSBzdG9yYWdlIChiZXN0LWVmZm9ydClcbiAgICAgIGlmIChvbGRBdmF0YXJVcmwpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBjb25zdCB1cmwgPSBuZXcgVVJMKG9sZEF2YXRhclVybCk7XG4gICAgICAgICAgY29uc3QgcGFydHMgPSB1cmwucGF0aG5hbWUuc3BsaXQoYC9zdG9yYWdlL3YxL29iamVjdC9wdWJsaWMvJHtQUk9GSUxFX0JVQ0tFVH0vYCk7XG4gICAgICAgICAgaWYgKHBhcnRzLmxlbmd0aCA9PT0gMiAmJiBwYXJ0c1sxXSkge1xuICAgICAgICAgICAgYXdhaXQgZGIuc3RvcmFnZS5mcm9tKFBST0ZJTEVfQlVDS0VUKS5yZW1vdmUoW2RlY29kZVVSSUNvbXBvbmVudChwYXJ0c1sxXSldKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0gY2F0Y2ggKGUpIHsgLyogaWdub3JlICovIH1cbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgdXNlcjogc2FuaXRpemUoZGF0YSBhcyBVc2VyKSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdQT1NUIC9tZS9hdmF0YXInLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIGFwaS5wYXRjaCgnL21lJywgcmVxdWlyZUF1dGgsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBtZSA9IChyZXEgYXMgYW55KS51c2VyIGFzIFVzZXI7XG4gICAgICBjb25zdCBhbGxvd2VkID0gW1xuICAgICAgICAnZnVsbF9uYW1lJyxcbiAgICAgICAgJ3Bob25lJyxcbiAgICAgICAgJ2J1c2luZXNzX25hbWUnLFxuICAgICAgICAnZmFybV9sb2NhdGlvbicsXG4gICAgICAgICd5ZWFyc19leHBlcmllbmNlJyxcbiAgICAgICAgJ2Fib3V0X2Zhcm0nLFxuICAgICAgICAnYnVzaW5lc3NfbG9jYXRpb24nLFxuICAgICAgICAneWVhcnNfaW5fYnVzaW5lc3MnLFxuICAgICAgICAnc3RvcmFnZV9jYXBhY2l0eV90b25zJyxcbiAgICAgICAgJ2F2YXRhcl91cmwnLFxuICAgICAgXTtcbiAgICAgIGNvbnN0IHBhdGNoOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiA9IHt9O1xuICAgICAgZm9yIChjb25zdCBrIG9mIGFsbG93ZWQpIHtcbiAgICAgICAgaWYgKHJlcS5ib2R5W2tdICE9PSB1bmRlZmluZWQpIHBhdGNoW2tdID0gcmVxLmJvZHlba107XG4gICAgICB9XG4gICAgICBpZiAocGF0Y2gueWVhcnNfZXhwZXJpZW5jZSAhPT0gdW5kZWZpbmVkKSBwYXRjaC55ZWFyc19leHBlcmllbmNlID0gcGF0Y2gueWVhcnNfZXhwZXJpZW5jZSA9PT0gJycgPyBudWxsIDogTnVtYmVyKHBhdGNoLnllYXJzX2V4cGVyaWVuY2UpO1xuICAgICAgaWYgKHBhdGNoLnllYXJzX2luX2J1c2luZXNzICE9PSB1bmRlZmluZWQpIHBhdGNoLnllYXJzX2luX2J1c2luZXNzID0gcGF0Y2gueWVhcnNfaW5fYnVzaW5lc3MgPT09ICcnID8gbnVsbCA6IE51bWJlcihwYXRjaC55ZWFyc19pbl9idXNpbmVzcyk7XG4gICAgICBpZiAocGF0Y2guc3RvcmFnZV9jYXBhY2l0eV90b25zICE9PSB1bmRlZmluZWQpIHBhdGNoLnN0b3JhZ2VfY2FwYWNpdHlfdG9ucyA9IHBhdGNoLnN0b3JhZ2VfY2FwYWNpdHlfdG9ucyA9PT0gJycgPyBudWxsIDogTnVtYmVyKHBhdGNoLnN0b3JhZ2VfY2FwYWNpdHlfdG9ucyk7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYi5mcm9tKCd1c2VycycpLnVwZGF0ZShwYXRjaCkuZXEoJ2lkJywgbWUuaWQpLnNlbGVjdCgnKicpLnNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyB1c2VyOiBzYW5pdGl6ZShkYXRhIGFzIFVzZXIpIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1BBVENIIC9tZScsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gLS0tLS0tLS0tLSBSZXZpZXdzICh2ZXJpZmllZCBcdTIwMTQgb25seSBhZnRlciBhIGNvbXBsZXRlZCBvcmRlcikgLS0tLS0tLS0tLVxuICAvLyBHRVQgL3Jldmlld3M/dXNlcl9pZD08aWQ+ICBcdTIwMTQgbGlzdCByZXZpZXdzIHJlY2VpdmVkIGJ5IGEgdXNlciAobmV3ZXN0IGZpcnN0KSxcbiAgLy8gICB3aXRoIHRoZSByZXZpZXdlciArIHRoZSB1bmRlcmx5aW5nIG9yZGVyIChjcm9wLCBjb3VudGVycGFydCwgYW1vdW50LCBkYXRlKS5cbiAgLy8gR0VUIC9yZXZpZXdzL21pbmUgICAgICAgICAgXHUyMDE0IHJldmlld3MgSSBoYXZlIHdyaXR0ZW4uXG4gIC8vIEdFVCAvcmV2aWV3cy9lbGlnaWJsZSAgICAgIFx1MjAxNCBjb21wbGV0ZWQgb3JkZXJzIG9mIG1pbmUgdGhhdCBJIGhhdmVuJ3QgcmV2aWV3ZWRcbiAgLy8gICB5ZXQgKGZyb20gbXkgc2lkZSksIHVzZWQgdG8gcG9wdWxhdGUgdGhlIFwibGVhdmUgYSByZXZpZXdcIiBwaWNrZXIuXG4gIC8vIFBPU1QgL3Jldmlld3MgICAgICAgICAgICAgIFx1MjAxNCBsZWF2ZSBhIHJldmlldyBmb3Igb25lIG9mIG15IGNvbXBsZXRlZCBvcmRlcnMuXG4gIGFwaS5nZXQoJy9yZXZpZXdzJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHVzZXJJZCA9IHJlcS5xdWVyeS51c2VyX2lkIGFzIHN0cmluZyB8IHVuZGVmaW5lZDtcbiAgICAgIGlmICghdXNlcklkKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmdfdXNlcicgfSk7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgncmV2aWV3cycpXG4gICAgICAgIC5zZWxlY3QoJyosIHJldmlld2VyOnVzZXJzIXJldmlld3NfcmV2aWV3ZXJfaWRfZmtleSgqKSwgb3JkZXI6b3JkZXJzKCopJylcbiAgICAgICAgLmVxKCdyZXZpZXdlZV9pZCcsIHVzZXJJZClcbiAgICAgICAgLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICBjb25zdCByb3dzID0gKGRhdGEgYXMgUmV2aWV3W10pID8/IFtdO1xuICAgICAgLy8gQWdncmVnYXRlIHJhdGluZy5cbiAgICAgIGNvbnN0IGF2ZyA9IHJvd3MubGVuZ3RoID8gcm93cy5yZWR1Y2UoKHMsIHIpID0+IHMgKyBOdW1iZXIoci5yYXRpbmcpLCAwKSAvIHJvd3MubGVuZ3RoIDogMDtcbiAgICAgIHJldHVybiByZXMuanNvbih7IHJldmlld3M6IHJvd3MubWFwKHNhbml0aXplUmV2aWV3KSwgYXZlcmFnZTogTWF0aC5yb3VuZChhdmcgKiAxMCkgLyAxMCwgY291bnQ6IHJvd3MubGVuZ3RoIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0dFVCAvcmV2aWV3cycsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLmdldCgnL3Jldmlld3MvbWluZScsIHJlcXVpcmVBdXRoLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgZGJcbiAgICAgICAgLmZyb20oJ3Jldmlld3MnKVxuICAgICAgICAuc2VsZWN0KCcqLCByZXZpZXdlZTp1c2VycyFyZXZpZXdzX3Jldmlld2VlX2lkX2ZrZXkoKiksIG9yZGVyOm9yZGVycygqKScpXG4gICAgICAgIC5lcSgncmV2aWV3ZXJfaWQnLCBtZS5pZClcbiAgICAgICAgLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICByZXR1cm4gcmVzLmpzb24oeyByZXZpZXdzOiAoZGF0YSBhcyBSZXZpZXdbXSkubWFwKHNhbml0aXplUmV2aWV3KSB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdHRVQgL3Jldmlld3MvbWluZScsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgYXBpLmdldCgnL3Jldmlld3MvZWxpZ2libGUnLCByZXF1aXJlQXV0aCwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIC8vIEFsbCBjb21wbGV0ZWQgb3JkZXJzIHdoZXJlIEknbSBhIHBhcnRpY2lwYW50LlxuICAgICAgY29uc3QgeyBkYXRhOiBvcmRlcnMsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgnb3JkZXJzJylcbiAgICAgICAgLnNlbGVjdCgnKiwgY3JvcDpjcm9wcygqKSwgZmFybWVyOnVzZXJzIW9yZGVyc19mYXJtZXJfaWRfZmtleSgqKSwgd2hvbGVzYWxlcjp1c2VycyFvcmRlcnNfd2hvbGVzYWxlcl9pZF9ma2V5KCopJylcbiAgICAgICAgLmVxKCdzdGF0dXMnLCAnY29tcGxldGVkJylcbiAgICAgICAgLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICBjb25zdCBtaW5lID0gKG9yZGVycyBhcyBPcmRlcltdIHwgbnVsbCkgPz8gW107XG4gICAgICBjb25zdCBwYXJ0aWNpcGF0ZWQgPSBtaW5lLmZpbHRlcigobykgPT4gby5mYXJtZXJfaWQgPT09IG1lLmlkIHx8IG8ud2hvbGVzYWxlcl9pZCA9PT0gbWUuaWQpO1xuICAgICAgLy8gRXhpc3RpbmcgcmV2aWV3cyBJJ3ZlIGFscmVhZHkgd3JpdHRlbi5cbiAgICAgIGNvbnN0IHsgZGF0YTogbWluZVJldmlld3MgfSA9IGF3YWl0IGRiLmZyb20oJ3Jldmlld3MnKS5zZWxlY3QoJ29yZGVyX2lkLCByZXZpZXdlcl9pZCcpLmVxKCdyZXZpZXdlcl9pZCcsIG1lLmlkKTtcbiAgICAgIGNvbnN0IHJldmlld2VkID0gbmV3IFNldCgoKG1pbmVSZXZpZXdzIGFzIFJldmlld1tdIHwgbnVsbCkgPz8gW10pLm1hcCgocikgPT4gci5vcmRlcl9pZCkpO1xuICAgICAgY29uc3QgZWxpZ2libGUgPSBwYXJ0aWNpcGF0ZWQuZmlsdGVyKChvKSA9PiAhcmV2aWV3ZWQuaGFzKG8uaWQpKTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IG9yZGVyczogZWxpZ2libGUgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignR0VUIC9yZXZpZXdzL2VsaWdpYmxlJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICBhcGkucG9zdCgnL3Jldmlld3MnLCByZXF1aXJlQXV0aCwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIGNvbnN0IHsgb3JkZXJfaWQsIHJhdGluZywgY29tbWVudCB9ID0gcmVxLmJvZHkgfHwge307XG4gICAgICBpZiAoIW9yZGVyX2lkIHx8ICFyYXRpbmcpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnbWlzc2luZ19maWVsZHMnIH0pO1xuICAgICAgY29uc3QgciA9IE51bWJlcihyYXRpbmcpO1xuICAgICAgaWYgKCFOdW1iZXIuaXNJbnRlZ2VyKHIpIHx8IHIgPCAxIHx8IHIgPiA1KSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfcmF0aW5nJyB9KTtcbiAgICAgIGNvbnN0IHRyaW1tZWRDb21tZW50ID0gY29tbWVudCA/IFN0cmluZyhjb21tZW50KS5zbGljZSgwLCA1MDApIDogbnVsbDtcblxuICAgICAgY29uc3QgeyBkYXRhOiBvcmRlciB9ID0gKGF3YWl0IGRiLmZyb20oJ29yZGVycycpLnNlbGVjdCgnKicpLmVxKCdpZCcsIG9yZGVyX2lkKS5tYXliZVNpbmdsZSgpKSBhcyB7IGRhdGE6IE9yZGVyIHwgbnVsbCB9O1xuICAgICAgaWYgKCFvcmRlcikgcmV0dXJuIHJlcy5zdGF0dXMoNDA0KS5qc29uKHsgZXJyb3I6ICdvcmRlcl9ub3RfZm91bmQnIH0pO1xuICAgICAgaWYgKG9yZGVyLnN0YXR1cyAhPT0gJ2NvbXBsZXRlZCcpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiAnb3JkZXJfbm90X2NvbXBsZXRlZCcgfSk7XG5cbiAgICAgIGxldCByZXZpZXdlclJvbGU6ICdmYXJtZXInIHwgJ3dob2xlc2FsZXInIHwgbnVsbCA9IG51bGw7XG4gICAgICBsZXQgcmV2aWV3ZWVJZDogc3RyaW5nIHwgbnVsbCA9IG51bGw7XG4gICAgICBpZiAob3JkZXIuZmFybWVyX2lkID09PSBtZS5pZCAmJiBtZS5yb2xlID09PSAnZmFybWVyJykge1xuICAgICAgICByZXZpZXdlclJvbGUgPSAnZmFybWVyJztcbiAgICAgICAgcmV2aWV3ZWVJZCA9IG9yZGVyLndob2xlc2FsZXJfaWQ7XG4gICAgICB9IGVsc2UgaWYgKG9yZGVyLndob2xlc2FsZXJfaWQgPT09IG1lLmlkICYmIG1lLnJvbGUgPT09ICd3aG9sZXNhbGVyJykge1xuICAgICAgICByZXZpZXdlclJvbGUgPSAnd2hvbGVzYWxlcic7XG4gICAgICAgIHJldmlld2VlSWQgPSBvcmRlci5mYXJtZXJfaWQ7XG4gICAgICB9XG4gICAgICBpZiAoIXJldmlld2VyUm9sZSB8fCAhcmV2aWV3ZWVJZCkgcmV0dXJuIHJlcy5zdGF0dXMoNDAzKS5qc29uKHsgZXJyb3I6ICdmb3JiaWRkZW4nIH0pO1xuXG4gICAgICAvLyBFbmZvcmNlIG9uZS1wZXItZGlyZWN0aW9uIHZpYSB1cHNlcnQtbGlrZSBpbnNlcnQgd2l0aCBjb25mbGljdCBoYW5kbGluZy5cbiAgICAgIGNvbnN0IHsgZGF0YTogZXhpc3RpbmcgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCdyZXZpZXdzJylcbiAgICAgICAgLnNlbGVjdCgnaWQnKVxuICAgICAgICAuZXEoJ29yZGVyX2lkJywgb3JkZXJfaWQpXG4gICAgICAgIC5lcSgncmV2aWV3ZXJfcm9sZScsIHJldmlld2VyUm9sZSlcbiAgICAgICAgLm1heWJlU2luZ2xlKCk7XG4gICAgICBpZiAoZXhpc3RpbmcpIHJldHVybiByZXMuc3RhdHVzKDQwOSkuanNvbih7IGVycm9yOiAnYWxyZWFkeV9yZXZpZXdlZCcgfSk7XG5cbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IGRiXG4gICAgICAgIC5mcm9tKCdyZXZpZXdzJylcbiAgICAgICAgLmluc2VydCh7XG4gICAgICAgICAgb3JkZXJfaWQsXG4gICAgICAgICAgcmV2aWV3ZXJfaWQ6IG1lLmlkLFxuICAgICAgICAgIHJldmlld2VlX2lkOiByZXZpZXdlZUlkLFxuICAgICAgICAgIHJldmlld2VyX3JvbGU6IHJldmlld2VyUm9sZSxcbiAgICAgICAgICByYXRpbmc6IHIsXG4gICAgICAgICAgY29tbWVudDogdHJpbW1lZENvbW1lbnQsXG4gICAgICAgIH0pXG4gICAgICAgIC5zZWxlY3QoJyonKVxuICAgICAgICAuc2luZ2xlKCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IHJldmlldzogc2FuaXRpemVSZXZpZXcoZGF0YSBhcyBSZXZpZXcpIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1BPU1QgL3Jldmlld3MnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIC0tLS0tLS0tLS0gU3RhdGVtZW50ICh0cmFuc2FjdGlvbiBoaXN0b3J5KSAtLS0tLS0tLS0tXG4gIC8vIEdFVCAvc3RhdGVtZW50P2Zyb209WVlZWS1NTS1ERCZ0bz1ZWVlZLU1NLUREJnN0YXR1cz0uLi5cbiAgLy8gUmV0dXJucyB0aGUgY2FsbGVyJ3Mgb3JkZXJzIChhcyBmYXJtZXIgb3Igd2hvbGVzYWxlciBkZXBlbmRpbmcgb24gcm9sZSksXG4gIC8vIGVhY2ggd2l0aCBjcm9wICsgY291bnRlcnBhcnQsIHBsdXMgYSBydW5uaW5nIGdyYW5kIHRvdGFsIG9mIGNvbXBsZXRlZFxuICAvLyB0cmFuc2FjdGlvbnMuIEZpbHRlcnMgb3B0aW9uYWwuXG4gIGFwaS5nZXQoJy9zdGF0ZW1lbnQnLCByZXF1aXJlQXV0aCwgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1lID0gKHJlcSBhcyBhbnkpLnVzZXIgYXMgVXNlcjtcbiAgICAgIGNvbnN0IGZyb20gPSByZXEucXVlcnkuZnJvbSBhcyBzdHJpbmcgfCB1bmRlZmluZWQ7XG4gICAgICBjb25zdCB0byA9IHJlcS5xdWVyeS50byBhcyBzdHJpbmcgfCB1bmRlZmluZWQ7XG4gICAgICBjb25zdCBzdGF0dXMgPSByZXEucXVlcnkuc3RhdHVzIGFzIHN0cmluZyB8IHVuZGVmaW5lZDtcblxuICAgICAgbGV0IHEgPSBkYlxuICAgICAgICAuZnJvbSgnb3JkZXJzJylcbiAgICAgICAgLnNlbGVjdCgnKiwgY3JvcDpjcm9wcygqKSwgZmFybWVyOnVzZXJzIW9yZGVyc19mYXJtZXJfaWRfZmtleSgqKSwgd2hvbGVzYWxlcjp1c2VycyFvcmRlcnNfd2hvbGVzYWxlcl9pZF9ma2V5KCopJylcbiAgICAgICAgLm9yZGVyKCdjcmVhdGVkX2F0JywgeyBhc2NlbmRpbmc6IGZhbHNlIH0pO1xuICAgICAgaWYgKHN0YXR1cyAmJiBbJ3BlbmRpbmcnLCAnY29tcGxldGVkJywgJ2NhbmNlbGxlZCddLmluY2x1ZGVzKHN0YXR1cykpIHtcbiAgICAgICAgcSA9IHEuZXEoJ3N0YXR1cycsIHN0YXR1cyk7XG4gICAgICB9XG4gICAgICBpZiAoZnJvbSkgcSA9IHEuZ3RlKCdjcmVhdGVkX2F0JywgbmV3IERhdGUoZnJvbSkudG9JU09TdHJpbmcoKSk7XG4gICAgICBpZiAodG8pIHtcbiAgICAgICAgY29uc3QgdG9EYXRlID0gbmV3IERhdGUodG8pO1xuICAgICAgICB0b0RhdGUuc2V0SG91cnMoMjMsIDU5LCA1OSwgOTk5KTtcbiAgICAgICAgcSA9IHEubHRlKCdjcmVhdGVkX2F0JywgdG9EYXRlLnRvSVNPU3RyaW5nKCkpO1xuICAgICAgfVxuICAgICAgY29uc3QgeyBkYXRhLCBlcnJvciB9ID0gYXdhaXQgcTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgbGV0IHJvd3MgPSAoZGF0YSBhcyBPcmRlcltdKSA/PyBbXTtcbiAgICAgIGlmIChtZS5yb2xlID09PSAnZmFybWVyJykgcm93cyA9IHJvd3MuZmlsdGVyKChvKSA9PiBvLmZhcm1lcl9pZCA9PT0gbWUuaWQpO1xuICAgICAgZWxzZSBpZiAobWUucm9sZSA9PT0gJ3dob2xlc2FsZXInKSByb3dzID0gcm93cy5maWx0ZXIoKG8pID0+IG8ud2hvbGVzYWxlcl9pZCA9PT0gbWUuaWQpO1xuICAgICAgLy8gQWRtaW4gc2VlcyBhbGwgKG5vIGZpbHRlcikuXG5cbiAgICAgIC8vIFJ1bm5pbmcgdG90YWwgb2YgY29tcGxldGVkIG9yZGVycyBvbmx5LlxuICAgICAgbGV0IHJ1bm5pbmcgPSAwO1xuICAgICAgY29uc3QgZW5yaWNoZWQgPSByb3dzLm1hcCgobykgPT4ge1xuICAgICAgICBjb25zdCBhbW91bnQgPSBvLmNyb3AgPyBOdW1iZXIoby5jcm9wLnByaWNlKSAqIE51bWJlcihvLnF1YW50aXR5KSA6IDA7XG4gICAgICAgIGlmIChvLnN0YXR1cyA9PT0gJ2NvbXBsZXRlZCcpIHJ1bm5pbmcgKz0gYW1vdW50O1xuICAgICAgICByZXR1cm4geyAuLi5vLCBhbW91bnQgfTtcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHtcbiAgICAgICAgb3JkZXJzOiBlbnJpY2hlZCxcbiAgICAgICAgdG90YWw6IHJ1bm5pbmcsXG4gICAgICAgIGNvdW50OiByb3dzLmxlbmd0aCxcbiAgICAgICAgY29tcGxldGVkQ291bnQ6IHJvd3MuZmlsdGVyKChvKSA9PiBvLnN0YXR1cyA9PT0gJ2NvbXBsZXRlZCcpLmxlbmd0aCxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0dFVCAvc3RhdGVtZW50JywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyAtLS0tLS0tLS0tIFByb2R1Y3RzIChmYXJtZXIgcHJvZHVjdCBtYW5hZ2VtZW50KSAtLS0tLS0tLS0tXG4gIGNvbnN0IFBST0RVQ1RfQ0FURUdPUklFUyA9IFsnVmVnZXRhYmxlcycsICdGcnVpdHMnLCAnR3JhaW5zJywgJ0RhaXJ5JywgJ0hlcmJzJywgJ1NwaWNlcycsICdQdWxzZXMnLCAnT3RoZXJzJ10gYXMgY29uc3Q7XG4gIGNvbnN0IFBST0RVQ1RfVU5JVFMgPSBbJ2tnJywgJ3RvbicsICdzYWNrJywgJ2NyYXRlJywgJ2RvemVuJywgJ2xpdGVyJ10gYXMgY29uc3Q7XG4gIGNvbnN0IFBST0RVQ1RfQVZBSUxBQklMSVRZID0gWydBdmFpbGFibGUnLCAnTGltaXRlZCBTdG9jaycsICdTb2xkIE91dCddIGFzIGNvbnN0O1xuICBjb25zdCBNQVhfSU1BR0VTID0gNTtcbiAgY29uc3QgTUFYX0lNQUdFX1NJWkUgPSA1ICogMTAyNCAqIDEwMjQ7IC8vIDUgTUJcbiAgY29uc3QgQUxMT1dFRF9JTUFHRV9UWVBFUyA9IFsnaW1hZ2UvanBlZycsICdpbWFnZS9wbmcnLCAnaW1hZ2Uvd2VicCddO1xuICBjb25zdCBTVE9SQUdFX0JVQ0tFVCA9ICdwcm9kdWN0LWltYWdlcyc7XG5cbiAgZnVuY3Rpb24gdmFsaWRhdGVQcm9kdWN0KGJvZHk6IGFueSk6IHN0cmluZyB8IG51bGwge1xuICAgIGlmICghYm9keS5wcm9kdWN0X25hbWUgfHwgIVN0cmluZyhib2R5LnByb2R1Y3RfbmFtZSkudHJpbSgpKSByZXR1cm4gJ21pc3NpbmdfbmFtZSc7XG4gICAgaWYgKCFib2R5LmNhdGVnb3J5IHx8ICFQUk9EVUNUX0NBVEVHT1JJRVMuaW5jbHVkZXMoYm9keS5jYXRlZ29yeSkpIHJldHVybiAnaW52YWxpZF9jYXRlZ29yeSc7XG4gICAgaWYgKGJvZHkucHJpY2UgPT0gbnVsbCB8fCBOdW1iZXIoYm9keS5wcmljZSkgPD0gMCkgcmV0dXJuICdpbnZhbGlkX3ByaWNlJztcbiAgICBpZiAoYm9keS5xdWFudGl0eSA9PSBudWxsIHx8IE51bWJlcihib2R5LnF1YW50aXR5KSA8IDApIHJldHVybiAnaW52YWxpZF9xdWFudGl0eSc7XG4gICAgaWYgKCFib2R5LnVuaXQgfHwgIVBST0RVQ1RfVU5JVFMuaW5jbHVkZXMoYm9keS51bml0KSkgcmV0dXJuICdpbnZhbGlkX3VuaXQnO1xuICAgIGlmICghYm9keS5kaXN0cmljdCB8fCAhU3RyaW5nKGJvZHkuZGlzdHJpY3QpLnRyaW0oKSkgcmV0dXJuICdtaXNzaW5nX2Rpc3RyaWN0JztcbiAgICBpZiAoYm9keS5hdmFpbGFiaWxpdHkgJiYgIVBST0RVQ1RfQVZBSUxBQklMSVRZLmluY2x1ZGVzKGJvZHkuYXZhaWxhYmlsaXR5KSkgcmV0dXJuICdpbnZhbGlkX2F2YWlsYWJpbGl0eSc7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICAvLyBHRVQgL3Byb2R1Y3RzP2Zhcm1lcl9pZD08aWQ+ICBcdTIwMTQgbGlzdCBwcm9kdWN0cyBmb3IgYSBmYXJtZXIgKG9yIGFsbCBpZiBubyBmaWx0ZXIpXG4gIC8vIEdFVCAvcHJvZHVjdHM/bWluZT10cnVlICAgICAgIFx1MjAxNCBsaXN0IHRoZSBsb2dnZWQtaW4gZmFybWVyJ3MgcHJvZHVjdHNcbiAgYXBpLmdldCgnL3Byb2R1Y3RzJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IG1pbmUgPSByZXEucXVlcnkubWluZSA9PT0gJ3RydWUnO1xuICAgICAgY29uc3QgZmFybWVySWQgPSByZXEucXVlcnkuZmFybWVyX2lkIGFzIHN0cmluZyB8IHVuZGVmaW5lZDtcblxuICAgICAgbGV0IHEgPSBkYi5mcm9tKCdwcm9kdWN0cycpLnNlbGVjdCgnKiwgaW1hZ2VzOnByb2R1Y3RfaW1hZ2VzKCopJykub3JkZXIoJ2NyZWF0ZWRfYXQnLCB7IGFzY2VuZGluZzogZmFsc2UgfSk7XG4gICAgICBpZiAobWluZSkge1xuICAgICAgICBjb25zdCBtZSA9IGF3YWl0IGN1cnJlbnRVc2VyKHJlcSk7XG4gICAgICAgIGlmICghbWUpIHJldHVybiByZXMuc3RhdHVzKDQwMSkuanNvbih7IGVycm9yOiAndW5hdXRob3JpemVkJyB9KTtcbiAgICAgICAgcSA9IHEuZXEoJ2Zhcm1lcl9pZCcsIG1lLmlkKTtcbiAgICAgIH0gZWxzZSBpZiAoZmFybWVySWQpIHtcbiAgICAgICAgcSA9IHEuZXEoJ2Zhcm1lcl9pZCcsIGZhcm1lcklkKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHsgZGF0YSwgZXJyb3IgfSA9IGF3YWl0IHE7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICAgIGNvbnN0IHJvd3MgPSAoZGF0YSBhcyAoUHJvZHVjdCAmIHsgaW1hZ2VzOiBQcm9kdWN0SW1hZ2VbXSB9KVtdKSA/PyBbXTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IHByb2R1Y3RzOiByb3dzLm1hcCgocCkgPT4gKHsgLi4ucCwgaW1hZ2VzOiAocC5pbWFnZXMgfHwgW10pLnNvcnQoKGEsIGIpID0+IGEuc29ydF9vcmRlciAtIGIuc29ydF9vcmRlcikgfSkpIH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ0dFVCAvcHJvZHVjdHMnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIEdFVCAvcHJvZHVjdHMvOmlkIFx1MjAxNCBzaW5nbGUgcHJvZHVjdCB3aXRoIGltYWdlc1xuICBhcGkuZ2V0KCcvcHJvZHVjdHMvOmlkJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgaWQgfSA9IHJlcS5wYXJhbXM7XG4gICAgICBjb25zdCB7IGRhdGEsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgncHJvZHVjdHMnKVxuICAgICAgICAuc2VsZWN0KCcqLCBpbWFnZXM6cHJvZHVjdF9pbWFnZXMoKiknKVxuICAgICAgICAuZXEoJ2lkJywgaWQpXG4gICAgICAgIC5tYXliZVNpbmdsZSgpO1xuICAgICAgaWYgKGVycm9yKSByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgICBpZiAoIWRhdGEpIHJldHVybiByZXMuc3RhdHVzKDQwNCkuanNvbih7IGVycm9yOiAnbm90X2ZvdW5kJyB9KTtcbiAgICAgIGNvbnN0IHAgPSBkYXRhIGFzIFByb2R1Y3QgJiB7IGltYWdlczogUHJvZHVjdEltYWdlW10gfTtcbiAgICAgIHAuaW1hZ2VzID0gKHAuaW1hZ2VzIHx8IFtdKS5zb3J0KChhLCBiKSA9PiBhLnNvcnRfb3JkZXIgLSBiLnNvcnRfb3JkZXIpO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgcHJvZHVjdDogcCB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdHRVQgL3Byb2R1Y3RzLzppZCcsIGUpO1xuICAgICAgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgLy8gUE9TVCAvcHJvZHVjdHMgXHUyMDE0IGNyZWF0ZSBhIG5ldyBwcm9kdWN0IChtdWx0aXBhcnQ6IGZpZWxkcyArIGltYWdlc1tdKVxuICBhcGkucG9zdCgnL3Byb2R1Y3RzJywgcmVxdWlyZVJvbGUoJ2Zhcm1lcicpLCB1cGxvYWRNaWRkbGV3YXJlLmFueSgpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgYm9keSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgY29uc3QgZmlsZXMgPSAocmVxLmZpbGVzIGFzIEV4cHJlc3MuTXVsdGVyLkZpbGVbXSB8IHVuZGVmaW5lZCkgPz8gW107XG5cbiAgICAgIGNvbnN0IHZhbGlkYXRpb25FcnJvciA9IHZhbGlkYXRlUHJvZHVjdChib2R5KTtcbiAgICAgIGlmICh2YWxpZGF0aW9uRXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDQwMCkuanNvbih7IGVycm9yOiB2YWxpZGF0aW9uRXJyb3IgfSk7XG5cbiAgICAgIGlmIChmaWxlcy5sZW5ndGggPiBNQVhfSU1BR0VTKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ3Rvb19tYW55X2ltYWdlcycgfSk7XG4gICAgICBmb3IgKGNvbnN0IGYgb2YgZmlsZXMpIHtcbiAgICAgICAgaWYgKCFBTExPV0VEX0lNQUdFX1RZUEVTLmluY2x1ZGVzKGYubWltZXR5cGUpKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfaW1hZ2VfdHlwZScgfSk7XG4gICAgICAgIGlmIChmLnNpemUgPiBNQVhfSU1BR0VfU0laRSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbWFnZV90b29fbGFyZ2UnIH0pO1xuICAgICAgfVxuXG4gICAgICBjb25zdCB7IGRhdGE6IHByb2R1Y3QsIGVycm9yIH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgncHJvZHVjdHMnKVxuICAgICAgICAuaW5zZXJ0KHtcbiAgICAgICAgICBmYXJtZXJfaWQ6IG1lLmlkLFxuICAgICAgICAgIHByb2R1Y3RfbmFtZTogU3RyaW5nKGJvZHkucHJvZHVjdF9uYW1lKS50cmltKCksXG4gICAgICAgICAgY2F0ZWdvcnk6IGJvZHkuY2F0ZWdvcnksXG4gICAgICAgICAgZGVzY3JpcHRpb246IGJvZHkuZGVzY3JpcHRpb24gPyBTdHJpbmcoYm9keS5kZXNjcmlwdGlvbikudHJpbSgpIDogbnVsbCxcbiAgICAgICAgICBwcmljZTogTnVtYmVyKGJvZHkucHJpY2UpLFxuICAgICAgICAgIHF1YW50aXR5OiBOdW1iZXIoYm9keS5xdWFudGl0eSksXG4gICAgICAgICAgdW5pdDogYm9keS51bml0LFxuICAgICAgICAgIGRpc3RyaWN0OiBTdHJpbmcoYm9keS5kaXN0cmljdCkudHJpbSgpLFxuICAgICAgICAgIG11bmljaXBhbGl0eTogYm9keS5tdW5pY2lwYWxpdHkgPyBTdHJpbmcoYm9keS5tdW5pY2lwYWxpdHkpLnRyaW0oKSA6IG51bGwsXG4gICAgICAgICAgaGFydmVzdF9kYXRlOiBib2R5LmhhcnZlc3RfZGF0ZSB8fCBudWxsLFxuICAgICAgICAgIGF2YWlsYWJpbGl0eTogYm9keS5hdmFpbGFiaWxpdHkgfHwgJ0F2YWlsYWJsZScsXG4gICAgICAgIH0pXG4gICAgICAgIC5zZWxlY3QoJyonKVxuICAgICAgICAuc2luZ2xlKCk7XG4gICAgICBpZiAoZXJyb3IpIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcblxuICAgICAgLy8gVXBsb2FkIGltYWdlcyB0byBTdXBhYmFzZSBTdG9yYWdlIGFuZCBjcmVhdGUgcHJvZHVjdF9pbWFnZXMgcm93c1xuICAgICAgY29uc3QgaW1hZ2VSb3dzID0gYXdhaXQgdXBsb2FkUHJvZHVjdEltYWdlcyhwcm9kdWN0LmlkLCBmaWxlcyk7XG4gICAgICBjb25zdCB7IGRhdGE6IGZ1bGxQcm9kdWN0IH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgncHJvZHVjdHMnKVxuICAgICAgICAuc2VsZWN0KCcqLCBpbWFnZXM6cHJvZHVjdF9pbWFnZXMoKiknKVxuICAgICAgICAuZXEoJ2lkJywgcHJvZHVjdC5pZClcbiAgICAgICAgLnNpbmdsZSgpO1xuICAgICAgY29uc3QgcmVzdWx0ID0gZnVsbFByb2R1Y3QgYXMgUHJvZHVjdCAmIHsgaW1hZ2VzOiBQcm9kdWN0SW1hZ2VbXSB9O1xuICAgICAgcmVzdWx0LmltYWdlcyA9IChyZXN1bHQuaW1hZ2VzIHx8IFtdKS5zb3J0KChhLCBiKSA9PiBhLnNvcnRfb3JkZXIgLSBiLnNvcnRfb3JkZXIpO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgcHJvZHVjdDogcmVzdWx0IH0pO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ1BPU1QgL3Byb2R1Y3RzJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyBQQVRDSCAvcHJvZHVjdHMvOmlkIFx1MjAxNCB1cGRhdGUgcHJvZHVjdCBmaWVsZHMgKG11bHRpcGFydDogZmllbGRzICsgbmV3IGltYWdlc1tdKVxuICBhcGkucGF0Y2goJy9wcm9kdWN0cy86aWQnLCByZXF1aXJlUm9sZSgnZmFybWVyJyksIHVwbG9hZE1pZGRsZXdhcmUuYW55KCksIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBtZSA9IChyZXEgYXMgYW55KS51c2VyIGFzIFVzZXI7XG4gICAgICBjb25zdCB7IGlkIH0gPSByZXEucGFyYW1zO1xuICAgICAgY29uc3QgYm9keSA9IHJlcS5ib2R5IHx8IHt9O1xuICAgICAgY29uc3QgZmlsZXMgPSAocmVxLmZpbGVzIGFzIEV4cHJlc3MuTXVsdGVyLkZpbGVbXSB8IHVuZGVmaW5lZCkgPz8gW107XG5cbiAgICAgIGNvbnN0IHsgZGF0YTogcHJvZHVjdCB9ID0gKGF3YWl0IGRiLmZyb20oJ3Byb2R1Y3RzJykuc2VsZWN0KCcqJykuZXEoJ2lkJywgaWQpLm1heWJlU2luZ2xlKCkpIGFzIHsgZGF0YTogUHJvZHVjdCB8IG51bGwgfTtcbiAgICAgIGlmICghcHJvZHVjdCkgcmV0dXJuIHJlcy5zdGF0dXMoNDA0KS5qc29uKHsgZXJyb3I6ICdub3RfZm91bmQnIH0pO1xuICAgICAgaWYgKHByb2R1Y3QuZmFybWVyX2lkICE9PSBtZS5pZCkgcmV0dXJuIHJlcy5zdGF0dXMoNDAzKS5qc29uKHsgZXJyb3I6ICdmb3JiaWRkZW4nIH0pO1xuXG4gICAgICAvLyBDb3VudCBleGlzdGluZyBpbWFnZXMgKyBuZXcgdXBsb2Fkc1xuICAgICAgY29uc3QgeyBkYXRhOiBleGlzdGluZ0ltYWdlcyB9ID0gYXdhaXQgZGIuZnJvbSgncHJvZHVjdF9pbWFnZXMnKS5zZWxlY3QoJ2lkJykuZXEoJ3Byb2R1Y3RfaWQnLCBpZCk7XG4gICAgICBjb25zdCBleGlzdGluZ0NvdW50ID0gZXhpc3RpbmdJbWFnZXM/Lmxlbmd0aCA/PyAwO1xuICAgICAgLy8gaW1hZ2VzX3RvX3JlbW92ZSBpcyBhIEpTT04gc3RyaW5nIG9mIGltYWdlIElEcyB0byBkZWxldGVcbiAgICAgIGxldCByZW1vdmVJZHM6IHN0cmluZ1tdID0gW107XG4gICAgICBpZiAoYm9keS5yZW1vdmVfaW1hZ2VzKSB7XG4gICAgICAgIHRyeSB7IHJlbW92ZUlkcyA9IEpTT04ucGFyc2UoYm9keS5yZW1vdmVfaW1hZ2VzKTsgfSBjYXRjaCB7IHJlbW92ZUlkcyA9IFtdOyB9XG4gICAgICB9XG4gICAgICBjb25zdCByZW1haW5pbmdBZnRlclJlbW92ZSA9IGV4aXN0aW5nQ291bnQgLSByZW1vdmVJZHMubGVuZ3RoO1xuICAgICAgaWYgKHJlbWFpbmluZ0FmdGVyUmVtb3ZlICsgZmlsZXMubGVuZ3RoID4gTUFYX0lNQUdFUykge1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ3Rvb19tYW55X2ltYWdlcycgfSk7XG4gICAgICB9XG4gICAgICBmb3IgKGNvbnN0IGYgb2YgZmlsZXMpIHtcbiAgICAgICAgaWYgKCFBTExPV0VEX0lNQUdFX1RZUEVTLmluY2x1ZGVzKGYubWltZXR5cGUpKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfaW1hZ2VfdHlwZScgfSk7XG4gICAgICAgIGlmIChmLnNpemUgPiBNQVhfSU1BR0VfU0laRSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbWFnZV90b29fbGFyZ2UnIH0pO1xuICAgICAgfVxuXG4gICAgICAvLyBVcGRhdGUgZmllbGRzXG4gICAgICBjb25zdCBwYXRjaDogUmVjb3JkPHN0cmluZywgdW5rbm93bj4gPSB7IHVwZGF0ZWRfYXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSB9O1xuICAgICAgaWYgKGJvZHkucHJvZHVjdF9uYW1lICE9PSB1bmRlZmluZWQpIHBhdGNoLnByb2R1Y3RfbmFtZSA9IFN0cmluZyhib2R5LnByb2R1Y3RfbmFtZSkudHJpbSgpO1xuICAgICAgaWYgKGJvZHkuY2F0ZWdvcnkgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICBpZiAoIVBST0RVQ1RfQ0FURUdPUklFUy5pbmNsdWRlcyhib2R5LmNhdGVnb3J5KSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX2NhdGVnb3J5JyB9KTtcbiAgICAgICAgcGF0Y2guY2F0ZWdvcnkgPSBib2R5LmNhdGVnb3J5O1xuICAgICAgfVxuICAgICAgaWYgKGJvZHkuZGVzY3JpcHRpb24gIT09IHVuZGVmaW5lZCkgcGF0Y2guZGVzY3JpcHRpb24gPSBib2R5LmRlc2NyaXB0aW9uID8gU3RyaW5nKGJvZHkuZGVzY3JpcHRpb24pLnRyaW0oKSA6IG51bGw7XG4gICAgICBpZiAoYm9keS5wcmljZSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIGlmIChOdW1iZXIoYm9keS5wcmljZSkgPD0gMCkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX3ByaWNlJyB9KTtcbiAgICAgICAgcGF0Y2gucHJpY2UgPSBOdW1iZXIoYm9keS5wcmljZSk7XG4gICAgICB9XG4gICAgICBpZiAoYm9keS5xdWFudGl0eSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIGlmIChOdW1iZXIoYm9keS5xdWFudGl0eSkgPCAwKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ2ludmFsaWRfcXVhbnRpdHknIH0pO1xuICAgICAgICBwYXRjaC5xdWFudGl0eSA9IE51bWJlcihib2R5LnF1YW50aXR5KTtcbiAgICAgIH1cbiAgICAgIGlmIChib2R5LnVuaXQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICBpZiAoIVBST0RVQ1RfVU5JVFMuaW5jbHVkZXMoYm9keS51bml0KSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX3VuaXQnIH0pO1xuICAgICAgICBwYXRjaC51bml0ID0gYm9keS51bml0O1xuICAgICAgfVxuICAgICAgaWYgKGJvZHkuZGlzdHJpY3QgIT09IHVuZGVmaW5lZCkgcGF0Y2guZGlzdHJpY3QgPSBTdHJpbmcoYm9keS5kaXN0cmljdCkudHJpbSgpO1xuICAgICAgaWYgKGJvZHkubXVuaWNpcGFsaXR5ICE9PSB1bmRlZmluZWQpIHBhdGNoLm11bmljaXBhbGl0eSA9IGJvZHkubXVuaWNpcGFsaXR5ID8gU3RyaW5nKGJvZHkubXVuaWNpcGFsaXR5KS50cmltKCkgOiBudWxsO1xuICAgICAgaWYgKGJvZHkuaGFydmVzdF9kYXRlICE9PSB1bmRlZmluZWQpIHBhdGNoLmhhcnZlc3RfZGF0ZSA9IGJvZHkuaGFydmVzdF9kYXRlIHx8IG51bGw7XG4gICAgICBpZiAoYm9keS5hdmFpbGFiaWxpdHkgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICBpZiAoIVBST0RVQ1RfQVZBSUxBQklMSVRZLmluY2x1ZGVzKGJvZHkuYXZhaWxhYmlsaXR5KSkgcmV0dXJuIHJlcy5zdGF0dXMoNDAwKS5qc29uKHsgZXJyb3I6ICdpbnZhbGlkX2F2YWlsYWJpbGl0eScgfSk7XG4gICAgICAgIHBhdGNoLmF2YWlsYWJpbGl0eSA9IGJvZHkuYXZhaWxhYmlsaXR5O1xuICAgICAgfVxuXG4gICAgICBjb25zdCB7IGVycm9yOiB1cGRhdGVFcnJvciB9ID0gYXdhaXQgZGIuZnJvbSgncHJvZHVjdHMnKS51cGRhdGUocGF0Y2gpLmVxKCdpZCcsIGlkKTtcbiAgICAgIGlmICh1cGRhdGVFcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuXG4gICAgICAvLyBSZW1vdmUgc3BlY2lmaWVkIGltYWdlc1xuICAgICAgaWYgKHJlbW92ZUlkcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIGNvbnN0IHsgZGF0YTogaW1nc1RvUmVtb3ZlIH0gPSBhd2FpdCBkYi5mcm9tKCdwcm9kdWN0X2ltYWdlcycpLnNlbGVjdCgnaW1hZ2VfdXJsJykuaW4oJ2lkJywgcmVtb3ZlSWRzKS5lcSgncHJvZHVjdF9pZCcsIGlkKTtcbiAgICAgICAgaWYgKGltZ3NUb1JlbW92ZSAmJiBpbWdzVG9SZW1vdmUubGVuZ3RoKSB7XG4gICAgICAgICAgYXdhaXQgUHJvbWlzZS5hbGwoaW1nc1RvUmVtb3ZlLm1hcCgoaW1nKSA9PiBkZWxldGVTdG9yYWdlRmlsZShpbWcuaW1hZ2VfdXJsKSkpO1xuICAgICAgICAgIGF3YWl0IGRiLmZyb20oJ3Byb2R1Y3RfaW1hZ2VzJykuZGVsZXRlKCkuaW4oJ2lkJywgcmVtb3ZlSWRzKS5lcSgncHJvZHVjdF9pZCcsIGlkKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICAvLyBVcGxvYWQgbmV3IGltYWdlc1xuICAgICAgYXdhaXQgdXBsb2FkUHJvZHVjdEltYWdlcyhpZCwgZmlsZXMpO1xuXG4gICAgICBjb25zdCB7IGRhdGE6IGZ1bGxQcm9kdWN0IH0gPSBhd2FpdCBkYlxuICAgICAgICAuZnJvbSgncHJvZHVjdHMnKVxuICAgICAgICAuc2VsZWN0KCcqLCBpbWFnZXM6cHJvZHVjdF9pbWFnZXMoKiknKVxuICAgICAgICAuZXEoJ2lkJywgaWQpXG4gICAgICAgIC5zaW5nbGUoKTtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGZ1bGxQcm9kdWN0IGFzIFByb2R1Y3QgJiB7IGltYWdlczogUHJvZHVjdEltYWdlW10gfTtcbiAgICAgIHJlc3VsdC5pbWFnZXMgPSAocmVzdWx0LmltYWdlcyB8fCBbXSkuc29ydCgoYSwgYikgPT4gYS5zb3J0X29yZGVyIC0gYi5zb3J0X29yZGVyKTtcbiAgICAgIHJldHVybiByZXMuanNvbih7IHByb2R1Y3Q6IHJlc3VsdCB9KTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdQQVRDSCAvcHJvZHVjdHMvOmlkJywgZSk7XG4gICAgICByZXR1cm4gcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfVxuICB9KTtcblxuICAvLyBERUxFVEUgL3Byb2R1Y3RzLzppZCBcdTIwMTQgZGVsZXRlIGEgcHJvZHVjdCBhbmQgaXRzIGltYWdlc1xuICBhcGkuZGVsZXRlKCcvcHJvZHVjdHMvOmlkJywgcmVxdWlyZVJvbGUoJ2Zhcm1lcicpLCBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbWUgPSAocmVxIGFzIGFueSkudXNlciBhcyBVc2VyO1xuICAgICAgY29uc3QgeyBpZCB9ID0gcmVxLnBhcmFtcztcbiAgICAgIGNvbnN0IHsgZGF0YTogcHJvZHVjdCB9ID0gKGF3YWl0IGRiLmZyb20oJ3Byb2R1Y3RzJykuc2VsZWN0KCcqJykuZXEoJ2lkJywgaWQpLm1heWJlU2luZ2xlKCkpIGFzIHsgZGF0YTogUHJvZHVjdCB8IG51bGwgfTtcbiAgICAgIGlmICghcHJvZHVjdCkgcmV0dXJuIHJlcy5zdGF0dXMoNDA0KS5qc29uKHsgZXJyb3I6ICdub3RfZm91bmQnIH0pO1xuICAgICAgaWYgKHByb2R1Y3QuZmFybWVyX2lkICE9PSBtZS5pZCkgcmV0dXJuIHJlcy5zdGF0dXMoNDAzKS5qc29uKHsgZXJyb3I6ICdmb3JiaWRkZW4nIH0pO1xuXG4gICAgICAvLyBEZWxldGUgaW1hZ2VzIGZyb20gc3RvcmFnZVxuICAgICAgY29uc3QgeyBkYXRhOiBpbWFnZXMgfSA9IGF3YWl0IGRiLmZyb20oJ3Byb2R1Y3RfaW1hZ2VzJykuc2VsZWN0KCdpbWFnZV91cmwnKS5lcSgncHJvZHVjdF9pZCcsIGlkKTtcbiAgICAgIGlmIChpbWFnZXMgJiYgaW1hZ2VzLmxlbmd0aCkge1xuICAgICAgICBhd2FpdCBQcm9taXNlLmFsbChpbWFnZXMubWFwKChpbWcpID0+IGRlbGV0ZVN0b3JhZ2VGaWxlKGltZy5pbWFnZV91cmwpKSk7XG4gICAgICB9XG4gICAgICAvLyBEZWxldGUgcHJvZHVjdCAoY2FzY2FkZXMgdG8gcHJvZHVjdF9pbWFnZXMpXG4gICAgICBjb25zdCB7IGVycm9yIH0gPSBhd2FpdCBkYi5mcm9tKCdwcm9kdWN0cycpLmRlbGV0ZSgpLmVxKCdpZCcsIGlkKTtcbiAgICAgIGlmIChlcnJvcikgcmV0dXJuIHJlcy5zdGF0dXMoNTAwKS5qc29uKHsgZXJyb3I6ICdzZXJ2ZXJfZXJyb3InIH0pO1xuICAgICAgcmV0dXJuIHJlcy5qc29uKHsgb2s6IHRydWUgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignREVMRVRFIC9wcm9kdWN0cy86aWQnLCBlKTtcbiAgICAgIHJldHVybiByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgICB9XG4gIH0pO1xuXG4gIC8vIEhlbHBlcjogdXBsb2FkIGZpbGVzIHRvIFN1cGFiYXNlIFN0b3JhZ2UgYW5kIGNyZWF0ZSBwcm9kdWN0X2ltYWdlcyByb3dzXG4gIGFzeW5jIGZ1bmN0aW9uIHVwbG9hZFByb2R1Y3RJbWFnZXMocHJvZHVjdElkOiBzdHJpbmcsIGZpbGVzOiBFeHByZXNzLk11bHRlci5GaWxlW10pOiBQcm9taXNlPFByb2R1Y3RJbWFnZVtdPiB7XG4gICAgaWYgKCFmaWxlcy5sZW5ndGgpIHJldHVybiBbXTtcbiAgICBjb25zdCByb3dzOiBQcm9kdWN0SW1hZ2VbXSA9IFtdO1xuICAgIC8vIEdldCBjdXJyZW50IG1heCBzb3J0X29yZGVyIGZvciB0aGlzIHByb2R1Y3RcbiAgICBjb25zdCB7IGRhdGE6IGV4aXN0aW5nIH0gPSBhd2FpdCBkYi5mcm9tKCdwcm9kdWN0X2ltYWdlcycpLnNlbGVjdCgnc29ydF9vcmRlcicpLmVxKCdwcm9kdWN0X2lkJywgcHJvZHVjdElkKTtcbiAgICBsZXQgbmV4dE9yZGVyID0gZXhpc3RpbmcgJiYgZXhpc3RpbmcubGVuZ3RoID8gTWF0aC5tYXgoLi4uZXhpc3RpbmcubWFwKChpOiBhbnkpID0+IGkuc29ydF9vcmRlcikpICsgMSA6IDA7XG5cbiAgICBmb3IgKGNvbnN0IGZpbGUgb2YgZmlsZXMpIHtcbiAgICAgIGNvbnN0IGV4dCA9IGZpbGUub3JpZ2luYWxuYW1lLnNwbGl0KCcuJykucG9wKCk/LnRvTG93ZXJDYXNlKCkgfHwgJ2pwZyc7XG4gICAgICBjb25zdCBmaWxlUGF0aCA9IGAke3Byb2R1Y3RJZH0vJHtEYXRlLm5vdygpfS0ke01hdGgucmFuZG9tKCkudG9TdHJpbmcoMzYpLnNsaWNlKDIsIDgpfS4ke2V4dH1gO1xuICAgICAgY29uc3QgeyBlcnJvcjogdXBsb2FkRXJyb3IgfSA9IGF3YWl0IGRiLnN0b3JhZ2UuZnJvbShTVE9SQUdFX0JVQ0tFVCkudXBsb2FkKGZpbGVQYXRoLCBmaWxlLmJ1ZmZlciwge1xuICAgICAgICBjb250ZW50VHlwZTogZmlsZS5taW1ldHlwZSxcbiAgICAgICAgdXBzZXJ0OiBmYWxzZSxcbiAgICAgIH0pO1xuICAgICAgaWYgKHVwbG9hZEVycm9yKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ1N0b3JhZ2UgdXBsb2FkIGVycm9yJywgdXBsb2FkRXJyb3IpO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHsgZGF0YTogcHViVXJsIH0gPSBkYi5zdG9yYWdlLmZyb20oU1RPUkFHRV9CVUNLRVQpLmdldFB1YmxpY1VybChmaWxlUGF0aCk7XG4gICAgICBjb25zdCB7IGRhdGE6IGltZ1JvdyB9ID0gYXdhaXQgZGJcbiAgICAgICAgLmZyb20oJ3Byb2R1Y3RfaW1hZ2VzJylcbiAgICAgICAgLmluc2VydCh7IHByb2R1Y3RfaWQ6IHByb2R1Y3RJZCwgaW1hZ2VfdXJsOiBwdWJVcmwucHVibGljVXJsLCBzb3J0X29yZGVyOiBuZXh0T3JkZXIgfSlcbiAgICAgICAgLnNlbGVjdCgnKicpXG4gICAgICAgIC5zaW5nbGUoKTtcbiAgICAgIGlmIChpbWdSb3cpIHJvd3MucHVzaChpbWdSb3cgYXMgUHJvZHVjdEltYWdlKTtcbiAgICAgIG5leHRPcmRlcisrO1xuICAgIH1cbiAgICByZXR1cm4gcm93cztcbiAgfVxuXG4gIC8vIEhlbHBlcjogZGVsZXRlIGEgZmlsZSBmcm9tIFN1cGFiYXNlIFN0b3JhZ2UgYnkgaXRzIHB1YmxpYyBVUkxcbiAgYXN5bmMgZnVuY3Rpb24gZGVsZXRlU3RvcmFnZUZpbGUocHVibGljVXJsOiBzdHJpbmcpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgdXJsID0gbmV3IFVSTChwdWJsaWNVcmwpO1xuICAgICAgY29uc3QgcGFydHMgPSB1cmwucGF0aG5hbWUuc3BsaXQoYC9zdG9yYWdlL3YxL29iamVjdC9wdWJsaWMvJHtTVE9SQUdFX0JVQ0tFVH0vYCk7XG4gICAgICBpZiAocGFydHMubGVuZ3RoIDwgMikgcmV0dXJuO1xuICAgICAgY29uc3QgZmlsZVBhdGggPSBkZWNvZGVVUklDb21wb25lbnQocGFydHNbMV0pO1xuICAgICAgYXdhaXQgZGIuc3RvcmFnZS5mcm9tKFNUT1JBR0VfQlVDS0VUKS5yZW1vdmUoW2ZpbGVQYXRoXSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcignZGVsZXRlU3RvcmFnZUZpbGUgZXJyb3InLCBlKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gYXBpO1xufVxuXG5mdW5jdGlvbiBzYW5pdGl6ZSh1OiBVc2VyKSB7XG4gIGNvbnN0IHsgcGluX2hhc2gsIC4uLnJlc3QgfSA9IHU7XG4gIHZvaWQgcGluX2hhc2g7XG4gIHJldHVybiByZXN0O1xufVxuZnVuY3Rpb24gc2FuaXRpemVDcm9wKGM6IENyb3ApIHtcbiAgcmV0dXJuIHsgLi4uYywgZmFybWVyOiBjLmZhcm1lciA/IHNhbml0aXplKGMuZmFybWVyKSA6IHVuZGVmaW5lZCB9O1xufVxuZnVuY3Rpb24gc2FuaXRpemVSZXZpZXcocjogUmV2aWV3KSB7XG4gIHJldHVybiB7XG4gICAgLi4ucixcbiAgICByZXZpZXdlcjogci5yZXZpZXdlciA/IHNhbml0aXplKHIucmV2aWV3ZXIpIDogdW5kZWZpbmVkLFxuICAgIG9yZGVyOiByLm9yZGVyID8geyAuLi5yLm9yZGVyIH0gOiB1bmRlZmluZWQsXG4gIH07XG59XG5cbmV4cG9ydCB7IFNFU1NJT05fQ09PS0lFIH07XG4iLCAiY29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2Rpcm5hbWUgPSBcIi9ob21lL3Byb2plY3Qvc3JjL2FwaVwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiL2hvbWUvcHJvamVjdC9zcmMvYXBpL2RiLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9ob21lL3Byb2plY3Qvc3JjL2FwaS9kYi50c1wiO2ltcG9ydCB7IGNyZWF0ZUNsaWVudCwgdHlwZSBTdXBhYmFzZUNsaWVudCB9IGZyb20gJ0BzdXBhYmFzZS9zdXBhYmFzZS1qcyc7XG5cbmZ1bmN0aW9uIHJlYWRFbnYoKSB7XG4gIGNvbnN0IHVybCA9IHByb2Nlc3MuZW52LlNVUEFCQVNFX1VSTCB8fCBwcm9jZXNzLmVudi5WSVRFX1NVUEFCQVNFX1VSTDtcbiAgY29uc3Qga2V5ID0gcHJvY2Vzcy5lbnYuU1VQQUJBU0VfU0VSVklDRV9ST0xFX0tFWSB8fCBwcm9jZXNzLmVudi5TVVBBQkFTRV9BTk9OX0tFWSB8fCBwcm9jZXNzLmVudi5WSVRFX1NVUEFCQVNFX0FOT05fS0VZO1xuICByZXR1cm4geyB1cmwsIGtleSB9O1xufVxuXG5sZXQgX2NsaWVudDogU3VwYWJhc2VDbGllbnQgfCBudWxsID0gbnVsbDtcblxuZXhwb3J0IGZ1bmN0aW9uIGdldERiKCk6IFN1cGFiYXNlQ2xpZW50IHtcbiAgaWYgKF9jbGllbnQpIHJldHVybiBfY2xpZW50O1xuICBjb25zdCB7IHVybCwga2V5IH0gPSByZWFkRW52KCk7XG4gIGlmICghdXJsIHx8ICFrZXkpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ1N1cGFiYXNlIGVudiB2YXJzIG1pc3NpbmcgXHUyMDE0IHNldCBTVVBBQkFTRV9VUkwgLyBTVVBBQkFTRV9TRVJWSUNFX1JPTEVfS0VZJyk7XG4gIH1cbiAgX2NsaWVudCA9IGNyZWF0ZUNsaWVudCh1cmwsIGtleSwge1xuICAgIGF1dGg6IHsgcGVyc2lzdFNlc3Npb246IGZhbHNlLCBhdXRvUmVmcmVzaFRva2VuOiBmYWxzZSB9LFxuICB9KTtcbiAgcmV0dXJuIF9jbGllbnQ7XG59XG5cbi8vIEJhY2t3YXJkcy1jb21wYXRpYmxlIGBkYmAgZXhwb3J0IHRoYXQgbGF6aWx5IHByb3hpZXMgdG8gZ2V0RGIoKS5cbmV4cG9ydCBjb25zdCBkYiA9IG5ldyBQcm94eSh7fSBhcyBTdXBhYmFzZUNsaWVudCwge1xuICBnZXQoX3QsIHByb3ApIHtcbiAgICBjb25zdCBjbGllbnQgPSBnZXREYigpO1xuICAgIGNvbnN0IHZhbHVlID0gKGNsaWVudCBhcyB1bmtub3duIGFzIFJlY29yZDxzdHJpbmcgfCBzeW1ib2wsIHVua25vd24+KVtwcm9wXTtcbiAgICByZXR1cm4gdHlwZW9mIHZhbHVlID09PSAnZnVuY3Rpb24nID8gdmFsdWUuYmluZChjbGllbnQpIDogdmFsdWU7XG4gIH0sXG59KTtcblxuZXhwb3J0IGludGVyZmFjZSBVc2VyIHtcbiAgaWQ6IHN0cmluZztcbiAgZnVsbF9uYW1lOiBzdHJpbmc7XG4gIGJ1c2luZXNzX25hbWU6IHN0cmluZyB8IG51bGw7XG4gIHBob25lOiBzdHJpbmc7XG4gIHBpbl9oYXNoOiBzdHJpbmc7XG4gIHBob25lX3ZlcmlmaWVkOiBib29sZWFuO1xuICByb2xlOiAnZmFybWVyJyB8ICd3aG9sZXNhbGVyJyB8ICdhZG1pbic7XG4gIHN0YXR1czogJ2FjdGl2ZScgfCAnc3VzcGVuZGVkJyB8ICdiYW5uZWQnO1xuICBmYXJtX2xvY2F0aW9uOiBzdHJpbmcgfCBudWxsO1xuICB5ZWFyc19leHBlcmllbmNlOiBudW1iZXIgfCBudWxsO1xuICBhYm91dF9mYXJtOiBzdHJpbmcgfCBudWxsO1xuICBidXNpbmVzc19sb2NhdGlvbjogc3RyaW5nIHwgbnVsbDtcbiAgeWVhcnNfaW5fYnVzaW5lc3M6IG51bWJlciB8IG51bGw7XG4gIHN0b3JhZ2VfY2FwYWNpdHlfdG9uczogbnVtYmVyIHwgbnVsbDtcbiAgYXZhdGFyX3VybDogc3RyaW5nIHwgbnVsbDtcbiAgY3JlYXRlZF9hdDogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENyb3Age1xuICBpZDogc3RyaW5nO1xuICBmYXJtZXJfaWQ6IHN0cmluZztcbiAgbmFtZTogc3RyaW5nO1xuICBjYXRlZ29yeTogc3RyaW5nIHwgbnVsbDtcbiAgcHJpY2U6IG51bWJlcjtcbiAgcXVhbnRpdHlfYXZhaWxhYmxlOiBudW1iZXI7XG4gIHVuaXQ6IHN0cmluZztcbiAgbG9jYXRpb246IHN0cmluZyB8IG51bGw7XG4gIGhhcnZlc3RfZGF0ZTogc3RyaW5nIHwgbnVsbDtcbiAgaW1hZ2VfdXJsOiBzdHJpbmcgfCBudWxsO1xuICBkZXNjcmlwdGlvbjogc3RyaW5nIHwgbnVsbDtcbiAgc3RhdHVzOiAncGVuZGluZycgfCAnYXBwcm92ZWQnIHwgJ3JlamVjdGVkJyB8ICdzb2xkX291dCc7XG4gIGNyZWF0ZWRfYXQ6IHN0cmluZztcbiAgZmFybWVyPzogVXNlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBPcmRlciB7XG4gIGlkOiBzdHJpbmc7XG4gIHdob2xlc2FsZXJfaWQ6IHN0cmluZztcbiAgZmFybWVyX2lkOiBzdHJpbmc7XG4gIGNyb3BfaWQ6IHN0cmluZztcbiAgcXVhbnRpdHk6IG51bWJlcjtcbiAgc3RhdHVzOiAncGVuZGluZycgfCAnY29tcGxldGVkJyB8ICdjYW5jZWxsZWQnO1xuICBjcmVhdGVkX2F0OiBzdHJpbmc7XG4gIGNyb3A/OiBDcm9wO1xuICBmYXJtZXI/OiBVc2VyO1xuICB3aG9sZXNhbGVyPzogVXNlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBNYXJrZXRQcmljZSB7XG4gIGlkOiBzdHJpbmc7XG4gIHByb2R1Y3Q6IHN0cmluZztcbiAgdW5pdDogc3RyaW5nO1xuICBtaW5fcHJpY2U6IG51bWJlcjtcbiAgbWF4X3ByaWNlOiBudW1iZXI7XG4gIGF2Z19wcmljZTogbnVtYmVyO1xuICB0cmVuZDogJ3VwJyB8ICdkb3duJyB8ICdzdGFibGUnO1xuICB1cGRhdGVkX2F0OiBzdHJpbmc7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUmV2aWV3IHtcbiAgaWQ6IHN0cmluZztcbiAgb3JkZXJfaWQ6IHN0cmluZztcbiAgcmV2aWV3ZXJfaWQ6IHN0cmluZztcbiAgcmV2aWV3ZWVfaWQ6IHN0cmluZztcbiAgcmV2aWV3ZXJfcm9sZTogJ2Zhcm1lcicgfCAnd2hvbGVzYWxlcic7XG4gIHJhdGluZzogbnVtYmVyO1xuICBjb21tZW50OiBzdHJpbmcgfCBudWxsO1xuICBjcmVhdGVkX2F0OiBzdHJpbmc7XG4gIHJldmlld2VyPzogVXNlcjtcbiAgb3JkZXI/OiBPcmRlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQcm9kdWN0IHtcbiAgaWQ6IHN0cmluZztcbiAgZmFybWVyX2lkOiBzdHJpbmc7XG4gIHByb2R1Y3RfbmFtZTogc3RyaW5nO1xuICBjYXRlZ29yeTogc3RyaW5nO1xuICBkZXNjcmlwdGlvbjogc3RyaW5nIHwgbnVsbDtcbiAgcHJpY2U6IG51bWJlcjtcbiAgcXVhbnRpdHk6IG51bWJlcjtcbiAgdW5pdDogc3RyaW5nO1xuICBkaXN0cmljdDogc3RyaW5nO1xuICBtdW5pY2lwYWxpdHk6IHN0cmluZyB8IG51bGw7XG4gIGhhcnZlc3RfZGF0ZTogc3RyaW5nIHwgbnVsbDtcbiAgYXZhaWxhYmlsaXR5OiAnQXZhaWxhYmxlJyB8ICdMaW1pdGVkIFN0b2NrJyB8ICdTb2xkIE91dCc7XG4gIGNyZWF0ZWRfYXQ6IHN0cmluZztcbiAgdXBkYXRlZF9hdDogc3RyaW5nO1xuICBpbWFnZXM/OiBQcm9kdWN0SW1hZ2VbXTtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBQcm9kdWN0SW1hZ2Uge1xuICBpZDogc3RyaW5nO1xuICBwcm9kdWN0X2lkOiBzdHJpbmc7XG4gIGltYWdlX3VybDogc3RyaW5nO1xuICBzb3J0X29yZGVyOiBudW1iZXI7XG4gIGNyZWF0ZWRfYXQ6IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBDcm9wSW1hZ2Uge1xuICBpZDogc3RyaW5nO1xuICBjcm9wX2lkOiBzdHJpbmc7XG4gIGltYWdlX3VybDogc3RyaW5nO1xuICBzb3J0X29yZGVyOiBudW1iZXI7XG4gIGNyZWF0ZWRfYXQ6IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBPdHBDb2RlIHtcbiAgaWQ6IHN0cmluZztcbiAgcGhvbmU6IHN0cmluZztcbiAgY29kZTogc3RyaW5nO1xuICBwdXJwb3NlOiAncmVnaXN0ZXInIHwgJ3Jlc2V0X3Bpbic7XG4gIGV4cGlyZXNfYXQ6IHN0cmluZztcbiAgdXNlZDogYm9vbGVhbjtcbiAgY3JlYXRlZF9hdDogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIENvbnRhY3RSb3cge1xuICBpZDogc3RyaW5nO1xuICBuYW1lOiBzdHJpbmc7XG4gIGVtYWlsOiBzdHJpbmc7XG4gIG1lc3NhZ2U6IHN0cmluZztcbiAgY3JlYXRlZF9hdDogc3RyaW5nO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFNlc3Npb25Sb3cge1xuICBpZDogc3RyaW5nO1xuICB0b2tlbjogc3RyaW5nO1xuICB1c2VyX2lkOiBzdHJpbmc7XG4gIGNyZWF0ZWRfYXQ6IHN0cmluZztcbiAgZXhwaXJlc19hdDogc3RyaW5nO1xufVxuIiwgImNvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9kaXJuYW1lID0gXCIvaG9tZS9wcm9qZWN0L3NyYy9hcGlcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZmlsZW5hbWUgPSBcIi9ob21lL3Byb2plY3Qvc3JjL2FwaS9hdXRoLnRzXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ltcG9ydF9tZXRhX3VybCA9IFwiZmlsZTovLy9ob21lL3Byb2plY3Qvc3JjL2FwaS9hdXRoLnRzXCI7aW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UsIE5leHRGdW5jdGlvbiB9IGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IGJjcnlwdCBmcm9tICdiY3J5cHRqcyc7XG5pbXBvcnQgeyBkYiwgVXNlciwgU2Vzc2lvblJvdyB9IGZyb20gJy4vZGInO1xuXG5jb25zdCBDT09LSUUgPSAna2Nfc2Vzc2lvbic7XG5jb25zdCBTRVNTSU9OX0RBWVMgPSA3O1xuXG5leHBvcnQgY29uc3QgU0VTU0lPTl9DT09LSUUgPSBDT09LSUU7XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjcmVhdGVTZXNzaW9uKHJlczogUmVzcG9uc2UsIHVzZXJJZDogc3RyaW5nKTogUHJvbWlzZTx2b2lkPiB7XG4gIGNvbnN0IHRva2VuID0gYXdhaXQgYmNyeXB0LmdlblNhbHQoMzIpLnRoZW4oKHMpID0+IHMucmVwbGFjZSgvXFwvL2csICd4JykpO1xuICBjb25zdCBleHBpcmVzQXQgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgU0VTU0lPTl9EQVlTICogODY0MDBfMDAwKS50b0lTT1N0cmluZygpO1xuICBjb25zdCB7IGVycm9yIH0gPSBhd2FpdCBkYi5mcm9tKCdzZXNzaW9ucycpLmluc2VydCh7IHRva2VuLCB1c2VyX2lkOiB1c2VySWQsIGV4cGlyZXNfYXQ6IGV4cGlyZXNBdCB9KTtcbiAgaWYgKGVycm9yKSB0aHJvdyBlcnJvcjtcbiAgcmVzLmNvb2tpZShDT09LSUUsIHRva2VuLCB7XG4gICAgaHR0cE9ubHk6IHRydWUsXG4gICAgc2FtZVNpdGU6ICdsYXgnLFxuICAgIG1heEFnZTogU0VTU0lPTl9EQVlTICogODY0MDBfMDAwLFxuICAgIHBhdGg6ICcvJyxcbiAgfSk7XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZXN0cm95U2Vzc2lvbihyZXE6IFJlcXVlc3QsIHJlczogUmVzcG9uc2UpOiBQcm9taXNlPHZvaWQ+IHtcbiAgY29uc3QgdG9rZW4gPSByZXEuY29va2llcz8uW0NPT0tJRV07XG4gIGlmICh0b2tlbikge1xuICAgIGF3YWl0IGRiLmZyb20oJ3Nlc3Npb25zJykuZGVsZXRlKCkuZXEoJ3Rva2VuJywgdG9rZW4pO1xuICB9XG4gIHJlcy5jbGVhckNvb2tpZShDT09LSUUsIHsgcGF0aDogJy8nIH0pO1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY3VycmVudFVzZXIocmVxOiBSZXF1ZXN0KTogUHJvbWlzZTxVc2VyIHwgbnVsbD4ge1xuICBjb25zdCB0b2tlbiA9IHJlcS5jb29raWVzPy5bQ09PS0lFXTtcbiAgaWYgKCF0b2tlbikgcmV0dXJuIG51bGw7XG4gIGNvbnN0IHsgZGF0YSB9ID0gYXdhaXQgZGJcbiAgICAuZnJvbSgnc2Vzc2lvbnMnKVxuICAgIC5zZWxlY3QoJyosIHVzZXI6dXNlcnMoKiknKVxuICAgIC5lcSgndG9rZW4nLCB0b2tlbilcbiAgICAubWF5YmVTaW5nbGUoKSBhcyB7IGRhdGE6IChTZXNzaW9uUm93ICYgeyB1c2VyOiBVc2VyIH0pIHwgbnVsbCB9O1xuICBpZiAoIWRhdGEpIHJldHVybiBudWxsO1xuICBpZiAobmV3IERhdGUoZGF0YS5leHBpcmVzX2F0KS5nZXRUaW1lKCkgPCBEYXRlLm5vdygpKSB7XG4gICAgYXdhaXQgZGIuZnJvbSgnc2Vzc2lvbnMnKS5kZWxldGUoKS5lcSgndG9rZW4nLCB0b2tlbik7XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cbiAgcmV0dXJuIGRhdGEudXNlciA/PyBudWxsO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gcmVxdWlyZUF1dGgocmVxOiBSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pIHtcbiAgKGFzeW5jICgpID0+IHtcbiAgICBjb25zdCB1c2VyID0gYXdhaXQgY3VycmVudFVzZXIocmVxKTtcbiAgICBpZiAoIXVzZXIpIHtcbiAgICAgIHJlcy5zdGF0dXMoNDAxKS5qc29uKHsgZXJyb3I6ICd1bmF1dGhvcml6ZWQnIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICAocmVxIGFzIGFueSkudXNlciA9IHVzZXI7XG4gICAgbmV4dCgpO1xuICB9KSgpLmNhdGNoKChlKSA9PiB7XG4gICAgY29uc29sZS5lcnJvcigncmVxdWlyZUF1dGggZXJyb3InLCBlKTtcbiAgICByZXMuc3RhdHVzKDUwMCkuanNvbih7IGVycm9yOiAnc2VydmVyX2Vycm9yJyB9KTtcbiAgfSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZXF1aXJlUm9sZSguLi5yb2xlczogQXJyYXk8J2Zhcm1lcicgfCAnd2hvbGVzYWxlcicgfCAnYWRtaW4nPikge1xuICByZXR1cm4gKHJlcTogUmVxdWVzdCwgcmVzOiBSZXNwb25zZSwgbmV4dDogTmV4dEZ1bmN0aW9uKSA9PiB7XG4gICAgKGFzeW5jICgpID0+IHtcbiAgICAgIGNvbnN0IHVzZXIgPSBhd2FpdCBjdXJyZW50VXNlcihyZXEpO1xuICAgICAgaWYgKCF1c2VyKSB7XG4gICAgICAgIHJlcy5zdGF0dXMoNDAxKS5qc29uKHsgZXJyb3I6ICd1bmF1dGhvcml6ZWQnIH0pO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBpZiAoIXJvbGVzLmluY2x1ZGVzKHVzZXIucm9sZSkpIHtcbiAgICAgICAgcmVzLnN0YXR1cyg0MDMpLmpzb24oeyBlcnJvcjogJ2ZvcmJpZGRlbicgfSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIChyZXEgYXMgYW55KS51c2VyID0gdXNlcjtcbiAgICAgIG5leHQoKTtcbiAgICB9KSgpLmNhdGNoKChlKSA9PiB7XG4gICAgICBjb25zb2xlLmVycm9yKCdyZXF1aXJlUm9sZSBlcnJvcicsIGUpO1xuICAgICAgcmVzLnN0YXR1cyg1MDApLmpzb24oeyBlcnJvcjogJ3NlcnZlcl9lcnJvcicgfSk7XG4gICAgfSk7XG4gIH07XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB2ZXJpZnlQaW4odXNlcjogVXNlciwgcGluOiBzdHJpbmcpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgdHJ5IHtcbiAgICByZXR1cm4gYXdhaXQgYmNyeXB0LmNvbXBhcmUocGluLCB1c2VyLnBpbl9oYXNoKTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBoYXNoUGluKHBpbjogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAg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QUFDeEIsVUFBSTtBQUNGLGNBQU0sY0FBYyxNQUFNLE9BQU8sbUJBQW1CLElBQUksT0FBTyxLQUFLLElBQUk7QUFDeEUsWUFBSSxVQUFVLGdCQUFnQixXQUFXO0FBQ3pDLFlBQUksSUFBSSxXQUFXO0FBQUEsTUFDckIsU0FBUyxHQUFHO0FBQ1YsYUFBSyxDQUFDO0FBQUEsTUFDUjtBQUFBLElBQ0YsQ0FBQztBQUFBLEVBQ0g7QUFDRjtBQUVBLElBQU8sc0JBQVEsYUFBYSxDQUFDLEVBQUUsS0FBSyxNQUFNO0FBRXhDLFFBQU0sTUFBTSxRQUFRLE1BQU0sUUFBUSxJQUFJLEdBQUcsRUFBRTtBQUMzQyxhQUFXLENBQUMsR0FBRyxDQUFDLEtBQUssT0FBTyxRQUFRLEdBQUcsR0FBRztBQUN4QyxRQUFJLENBQUMsUUFBUSxJQUFJLENBQUMsRUFBRyxTQUFRLElBQUksQ0FBQyxJQUFJO0FBQUEsRUFDeEM7QUFDQSxTQUFPO0FBQUEsSUFDTCxRQUFRO0FBQUEsTUFDTixNQUFNO0FBQUEsTUFDTixNQUFNO0FBQUEsSUFDUjtBQUFBLElBQ0EsU0FBUztBQUFBLE1BQ1A7QUFBQSxRQUNFLE1BQU07QUFBQSxRQUNOLGdCQUFnQixRQUFRO0FBQ3RCLGdCQUFNLE1BQU1DLFNBQVE7QUFDcEIsY0FBSSxJQUFJQSxTQUFRLEtBQUssRUFBRSxPQUFPLE1BQU0sQ0FBQyxDQUFDO0FBQ3RDLGNBQUksSUFBSSxnQkFBZ0IsQ0FBQztBQUN6QixpQkFBTyxZQUFZLElBQUksUUFBUSxHQUFHO0FBRWxDLGlCQUFPLFlBQVksSUFBSSxVQUFVLE1BQU0sQ0FBQztBQUFBLFFBQzFDO0FBQUEsUUFDQSx1QkFBdUIsUUFBUTtBQUM3QixnQkFBTSxNQUFNQSxTQUFRO0FBQ3BCLGNBQUksSUFBSUEsU0FBUSxLQUFLLEVBQUUsT0FBTyxNQUFNLENBQUMsQ0FBQztBQUN0QyxjQUFJLElBQUksZ0JBQWdCLENBQUM7QUFDekIsaUJBQU8sWUFBWSxJQUFJLFFBQVEsR0FBRztBQUNsQyxpQkFBTyxZQUFZLElBQUksVUFBVSxNQUFrQyxDQUFDO0FBQUEsUUFDdEU7QUFBQSxNQUNGO0FBQUEsSUFDRjtBQUFBLElBQ0EsT0FBTztBQUFBLE1BQ0wsUUFBUTtBQUFBLE1BQ1IsYUFBYTtBQUFBLE1BQ2IsZUFBZTtBQUFBLFFBQ2IsT0FBTztBQUFBLFVBQ0wsTUFBTTtBQUFBLFVBQ04sVUFBVTtBQUFBLFVBQ1YsY0FBYztBQUFBLFVBQ2QsT0FBTztBQUFBLFVBQ1AsU0FBUztBQUFBLFVBQ1QsT0FBTztBQUFBLFVBQ1AsVUFBVTtBQUFBLFVBQ1YsWUFBWTtBQUFBLFVBQ1osT0FBTztBQUFBLFVBQ1AsUUFBUTtBQUFBLFVBQ1IsWUFBWTtBQUFBLFFBQ2Q7QUFBQSxNQUNGO0FBQUEsSUFDRjtBQUFBLEVBQ0Y7QUFDRixDQUFDOyIsCiAgIm5hbWVzIjogWyJleHByZXNzIiwgImV4cHJlc3MiXQp9Cg==
