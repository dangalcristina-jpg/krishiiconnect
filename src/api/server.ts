import express from 'express';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import { db, User, Crop, Order, MarketPrice, Review, Product, ProductImage, CropImage, OtpCode } from './db';
import { createSession, destroySession, currentUser, requireAuth, requireRole, verifyPin, hashPin, SESSION_COOKIE } from './auth';

export function createApiRouter() {
  const api = express.Router();
  api.use(express.json({ limit: '1mb' }));
  api.use(cookieParser());
  const uploadMiddleware = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

  // ---------- Helpers ----------
  const OTP_TTL_MINUTES = 10;
  const OTP_COOLDOWN_SEC = 30;

  function generateOtp(): string {
    return String(Math.floor(1000 + Math.random() * 9000));
  }

  function isValidNepalPhone(phone: string): boolean {
    const p = phone.replace(/[\s-]/g, '');
    return /^9\d{9}$/.test(p);
  }

  async function sendOtp(phone: string, purpose: 'register' | 'reset_pin'): Promise<{ code: string; cooldown: number }> {
    // Mark previous unused codes as used
    await db.from('otp_codes').update({ used: true }).eq('phone', phone).eq('purpose', purpose).eq('used', false);
    const code = generateOtp();
    const expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60_000).toISOString();
    const { error } = await db.from('otp_codes').insert({ phone, code, purpose, expires_at: expiresAt });
    if (error) throw error;
    // In production: send SMS here. In this environment: return the code so the UI can display it.
    return { code, cooldown: OTP_COOLDOWN_SEC };
  }

  async function verifyOtp(phone: string, code: string, purpose: 'register' | 'reset_pin'): Promise<boolean> {
    const { data } = await db
      .from('otp_codes')
      .select('*')
      .eq('phone', phone)
      .eq('purpose', purpose)
      .eq('used', false)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle() as { data: OtpCode | null };
    if (!data) return false;
    if (new Date(data.expires_at).getTime() < Date.now()) return false;
    if (data.code !== code) return false;
    await db.from('otp_codes').update({ used: true }).eq('id', data.id);
    return true;
  }


  // ---------- Auth ----------
  // ---------- OTP: send ----------
  api.post('/auth/send-otp', async (req, res) => {
    try {
      const { phone, purpose } = req.body || {};
      if (!phone || !purpose) return res.status(400).json({ error: 'missing_fields' });
      if (!['register', 'reset_pin'].includes(purpose)) return res.status(400).json({ error: 'invalid_purpose' });
      if (!isValidNepalPhone(phone)) return res.status(400).json({ error: 'invalid_phone' });

      // For register: check the phone isn't already registered
      if (purpose === 'register') {
        const { data: existing } = await db.from('users').select('id').eq('phone', phone).maybeSingle();
        if (existing) return res.status(409).json({ error: 'exists' });
      }
      // For reset_pin: check the phone IS registered
      if (purpose === 'reset_pin') {
        const { data: existing } = await db.from('users').select('id').eq('phone', phone).maybeSingle();
        if (!existing) return res.status(404).json({ error: 'not_found' });
      }

      // Cooldown: check last OTP sent within cooldown window
      const { data: recent } = await db
        .from('otp_codes')
        .select('created_at')
        .eq('phone', phone)
        .eq('purpose', purpose)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle() as { data: { created_at: string } | null };
      if (recent) {
        const elapsed = (Date.now() - new Date(recent.created_at).getTime()) / 1000;
        if (elapsed < OTP_COOLDOWN_SEC) {
          return res.status(429).json({ error: 'cooldown', retry_after: Math.ceil(OTP_COOLDOWN_SEC - elapsed) });
        }
      }

      const { code, cooldown } = await sendOtp(phone, purpose);
      return res.json({ ok: true, cooldown, demo_code: code });
    } catch (e) {
      console.error('send-otp error', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- OTP: verify ----------
  api.post('/auth/verify-otp', async (req, res) => {
    try {
      const { phone, code, purpose } = req.body || {};
      if (!phone || !code || !purpose) return res.status(400).json({ error: 'missing_fields' });
      const ok = await verifyOtp(phone, String(code), purpose);
      if (!ok) return res.status(400).json({ error: 'invalid_otp' });
      return res.json({ ok: true, verified: true });
    } catch (e) {
      console.error('verify-otp error', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Register (requires verified phone) ----------
  api.post('/auth/register', async (req, res) => {
    try {
      const { full_name, phone, pin, confirm_pin, role, business_name, otp_code } = req.body || {};
      if (!full_name || !phone || !pin || !role) {
        return res.status(400).json({ error: 'missing_fields' });
      }
      if (!isValidNepalPhone(phone)) return res.status(400).json({ error: 'invalid_phone' });
      if (!['farmer', 'wholesaler'].includes(role)) {
        return res.status(400).json({ error: 'invalid_role' });
      }
      if (!/^\d{4}$/.test(String(pin))) {
        return res.status(400).json({ error: 'invalid_pin' });
      }
      if (confirm_pin !== undefined && String(confirm_pin) !== String(pin)) {
        return res.status(400).json({ error: 'pin_mismatch' });
      }
      if (role === 'wholesaler' && !business_name) {
        return res.status(400).json({ error: 'missing_business_name' });
      }
      // Require OTP verification
      if (!otp_code) return res.status(400).json({ error: 'otp_required' });
      const otpOk = await verifyOtp(phone, String(otp_code), 'register');
      if (!otpOk) return res.status(400).json({ error: 'invalid_otp' });

      const { data: existing } = await db.from('users').select('id').eq('phone', phone).maybeSingle();
      if (existing) return res.status(409).json({ error: 'exists' });

      const pin_hash = await hashPin(String(pin));
      const { data, error } = await db
        .from('users')
        .insert({
          full_name,
          phone,
          pin_hash,
          role,
          phone_verified: true,
          business_name: role === 'wholesaler' ? business_name : null,
          status: 'active',
        })
        .select('*')
        .single();
      if (error) return res.status(500).json({ error: 'server_error' });
      await createSession(res, (data as User).id);
      return res.json({ user: sanitize(data) });
    } catch (e) {
      console.error('register error', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Login (phone + PIN, must be verified) ----------
  api.post('/auth/login', async (req, res) => {
    try {
      const { phone, pin } = req.body || {};
      if (!phone || !pin) return res.status(400).json({ error: 'missing_fields' });
      const { data: user } = (await db.from('users').select('*').eq('phone', phone).maybeSingle()) as { data: User | null };
      // Generic error for all failures (wrong phone, wrong PIN, unverified)
      if (!user) return res.status(401).json({ error: 'invalid_creds' });
      const ok = await verifyPin(user, String(pin));
      if (!ok) return res.status(401).json({ error: 'invalid_creds' });
      if (user.status !== 'active') return res.status(403).json({ error: 'suspended' });
      if (!user.phone_verified) return res.status(401).json({ error: 'invalid_creds' });
      await createSession(res, user.id);
      return res.json({ user: sanitize(user) });
    } catch (e) {
      console.error('login error', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Forgot PIN: reset with OTP ----------
  api.post('/auth/reset-pin', async (req, res) => {
    try {
      const { phone, otp_code, new_pin, confirm_pin } = req.body || {};
      if (!phone || !otp_code || !new_pin) return res.status(400).json({ error: 'missing_fields' });
      if (!/^\d{4}$/.test(String(new_pin))) return res.status(400).json({ error: 'invalid_pin' });
      if (confirm_pin !== undefined && String(confirm_pin) !== String(new_pin)) {
        return res.status(400).json({ error: 'pin_mismatch' });
      }
      const otpOk = await verifyOtp(phone, String(otp_code), 'reset_pin');
      if (!otpOk) return res.status(400).json({ error: 'invalid_otp' });
      const { data: user } = (await db.from('users').select('id').eq('phone', phone).maybeSingle()) as { data: User | null };
      if (!user) return res.status(404).json({ error: 'not_found' });
      const pin_hash = await hashPin(String(new_pin));
      const { error } = await db.from('users').update({ pin_hash, phone_verified: true }).eq('id', user.id);
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ ok: true });
    } catch (e) {
      console.error('reset-pin error', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.post('/auth/logout', async (req, res) => {
    try {
      await destroySession(req, res);
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: 'server_error' });
    }
  });

  api.get('/auth/me', async (req, res) => {
    const user = await currentUser(req);
    if (!user) return res.status(200).json({ user: null });
    return res.json({ user: sanitize(user) });
  });

  // ---------- Crops (public + farmer) ----------
  api.get('/crops', async (req, res) => {
    try {
      const status = (req.query.status as string) || 'approved';
      let q = db.from('crops').select('*, farmer:users!crops_farmer_id_fkey(*), images:crop_images(*)').order('created_at', { ascending: false });
      if (status === 'approved') q = q.eq('status', 'approved');
      else if (status === 'mine') {
        // caller must be authed; filtered in JS below
      } else {
        q = q.eq('status', status);
      }
      const { data, error } = await q;
      if (error) return res.status(500).json({ error: 'server_error' });
      let rows = (data as (Crop & { images: CropImage[] })[]) ?? [];
      if (status === 'mine') {
        const me = await currentUser(req);
        if (!me) return res.status(401).json({ error: 'unauthorized' });
        rows = rows.filter((c) => c.farmer_id === me.id);
      }
      return res.json({ crops: rows.map((c) => ({ ...sanitizeCrop(c), images: (c.images || []).sort((a, b) => a.sort_order - b.sort_order) })) });
    } catch (e) {
      console.error('GET /crops', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  const CROP_MAX_IMAGES = 5;
  const CROP_MAX_IMAGE_SIZE = 5 * 1024 * 1024;
  const CROP_ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
  const CROP_BUCKET = 'crop-images';

  async function uploadCropImages(cropId: string, files: Express.Multer.File[]): Promise<CropImage[]> {
    if (!files.length) return [];
    const rows: CropImage[] = [];
    const { data: existing } = await db.from('crop_images').select('sort_order').eq('crop_id', cropId);
    let nextOrder = existing && existing.length ? Math.max(...existing.map((i: any) => i.sort_order)) + 1 : 0;
    for (const file of files) {
      const ext = file.originalname.split('.').pop()?.toLowerCase() || 'jpg';
      const filePath = `${cropId}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
      const { error: upErr } = await db.storage.from(CROP_BUCKET).upload(filePath, file.buffer, { contentType: file.mimetype, upsert: false });
      if (upErr) { console.error('crop image upload', upErr); continue; }
      const { data: pub } = db.storage.from(CROP_BUCKET).getPublicUrl(filePath);
      const { data: imgRow } = await db.from('crop_images').insert({ crop_id: cropId, image_url: pub.publicUrl, sort_order: nextOrder }).select('*').single();
      if (imgRow) rows.push(imgRow as CropImage);
      nextOrder++;
    }
    return rows;
  }

  async function deleteCropStorageFile(publicUrl: string): Promise<void> {
    try {
      const url = new URL(publicUrl);
      const parts = url.pathname.split(`/storage/v1/object/public/${CROP_BUCKET}/`);
      if (parts.length < 2) return;
      await db.storage.from(CROP_BUCKET).remove([decodeURIComponent(parts[1])]);
    } catch (e) { console.error('deleteCropStorageFile', e); }
  }

  api.get('/crops/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const { data, error } = await db
        .from('crops')
        .select('*, farmer:users!crops_farmer_id_fkey(*), images:crop_images(*)')
        .eq('id', id)
        .maybeSingle();
      if (error) return res.status(500).json({ error: 'server_error' });
      if (!data) return res.status(404).json({ error: 'not_found' });
      const c = data as Crop & { images: CropImage[] };
      c.images = (c.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ crop: { ...sanitizeCrop(c), images: c.images } });
    } catch (e) {
      console.error('GET /crops/:id', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.post('/crops', requireRole('farmer'), uploadMiddleware.any(), async (req, res) => {
    try {
      const me = (req as any).user as User;
      const body = req.body || {};
      const files = (req.files as Express.Multer.File[] | undefined) ?? [];
      const { name, category, price, quantity_available, unit, location, harvest_date, description } = body;
      if (!name || price == null || quantity_available == null) {
        return res.status(400).json({ error: 'missing_fields' });
      }
      if (files.length > CROP_MAX_IMAGES) return res.status(400).json({ error: 'too_many_images' });
      for (const f of files) {
        if (!CROP_ALLOWED_TYPES.includes(f.mimetype)) return res.status(400).json({ error: 'invalid_image_type' });
        if (f.size > CROP_MAX_IMAGE_SIZE) return res.status(400).json({ error: 'image_too_large' });
      }
      const { data, error } = await db
        .from('crops')
        .insert({
          farmer_id: me.id,
          name,
          category: category || null,
          price: Number(price),
          quantity_available: Number(quantity_available),
          unit: unit || 'kg',
          location: location || null,
          harvest_date: harvest_date || null,
          description: description || null,
          status: 'approved',
        })
        .select('*')
        .single();
      if (error) return res.status(500).json({ error: 'server_error' });
      const crop = data as Crop;
      await uploadCropImages(crop.id, files);
      const { data: full } = await db.from('crops').select('*, images:crop_images(*)').eq('id', crop.id).single();
      const result = full as Crop & { images: CropImage[] };
      result.images = (result.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ crop: { ...sanitizeCrop(result), images: result.images } });
    } catch (e) {
      console.error('POST /crops', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.patch('/crops/:id', requireRole('farmer', 'admin'), uploadMiddleware.any(), async (req, res) => {
    try {
      const me = (req as any).user as User;
      const { id } = req.params;
      const body = req.body || {};
      const files = (req.files as Express.Multer.File[] | undefined) ?? [];
      const { data: crop } = (await db.from('crops').select('*').eq('id', id).maybeSingle()) as { data: Crop | null };
      if (!crop) return res.status(404).json({ error: 'not_found' });
      if (me.role === 'farmer' && crop.farmer_id !== me.id) {
        return res.status(403).json({ error: 'forbidden' });
      }
      let removeIds: string[] = [];
      if (body.remove_images) {
        try { removeIds = JSON.parse(body.remove_images); } catch { removeIds = []; }
      }
      const { data: existingImgs } = await db.from('crop_images').select('id').eq('crop_id', id);
      const existingCount = existingImgs?.length ?? 0;
      const remainingAfterRemove = existingCount - removeIds.length;
      if (remainingAfterRemove + files.length > CROP_MAX_IMAGES) {
        return res.status(400).json({ error: 'too_many_images' });
      }
      for (const f of files) {
        if (!CROP_ALLOWED_TYPES.includes(f.mimetype)) return res.status(400).json({ error: 'invalid_image_type' });
        if (f.size > CROP_MAX_IMAGE_SIZE) return res.status(400).json({ error: 'image_too_large' });
      }
      const allowed = ['name', 'category', 'price', 'quantity_available', 'unit', 'location', 'harvest_date', 'description', 'status'];
      const patch: Record<string, unknown> = {};
      for (const k of allowed) {
        if (body[k] !== undefined) patch[k] = body[k];
      }
      if (me.role !== 'admin' && 'status' in patch) delete patch.status;
      if (Object.keys(patch).length) {
        const { error } = await db.from('crops').update(patch).eq('id', id);
        if (error) return res.status(500).json({ error: 'server_error' });
      }
      if (removeIds.length > 0) {
        const { data: imgsToRemove } = await db.from('crop_images').select('image_url').in('id', removeIds).eq('crop_id', id);
        if (imgsToRemove && imgsToRemove.length) {
          await Promise.all(imgsToRemove.map((img) => deleteCropStorageFile(img.image_url)));
          await db.from('crop_images').delete().in('id', removeIds).eq('crop_id', id);
        }
      }
      await uploadCropImages(id, files);
      const { data: full } = await db.from('crops').select('*, images:crop_images(*)').eq('id', id).single();
      const result = full as Crop & { images: CropImage[] };
      result.images = (result.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ crop: { ...sanitizeCrop(result), images: result.images } });
    } catch (e) {
      console.error('PATCH /crops', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.delete('/crops/:id', requireRole('farmer'), async (req, res) => {
    try {
      const me = (req as any).user as User;
      const { id } = req.params;
      const { data: crop } = (await db.from('crops').select('*').eq('id', id).maybeSingle()) as { data: Crop | null };
      if (!crop) return res.status(404).json({ error: 'not_found' });
      if (crop.farmer_id !== me.id) return res.status(403).json({ error: 'forbidden' });
      const { data: images } = await db.from('crop_images').select('image_url').eq('crop_id', id);
      if (images && images.length) {
        await Promise.all(images.map((img) => deleteCropStorageFile(img.image_url)));
      }
      const { error } = await db.from('crops').delete().eq('id', id);
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ ok: true });
    } catch (e) {
      console.error('DELETE /crops/:id', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Orders ----------
  api.get('/orders', requireAuth, async (req, res) => {
    try {
      const me = (req as any).user as User;
      let q = db
        .from('orders')
        .select('*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*), wholesaler:users!orders_wholesaler_id_fkey(*)')
        .order('created_at', { ascending: false });
      const { data, error } = await q;
      if (error) return res.status(500).json({ error: 'server_error' });
      let rows = (data as Order[]) ?? [];
      if (me.role === 'farmer') rows = rows.filter((o) => o.farmer_id === me.id);
      else if (me.role === 'wholesaler') rows = rows.filter((o) => o.wholesaler_id === me.id);
      return res.json({ orders: rows });
    } catch (e) {
      console.error('GET /orders', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.post('/orders', requireRole('wholesaler'), async (req, res) => {
    try {
      const me = (req as any).user as User;
      const { crop_id, quantity } = req.body || {};
      if (!crop_id || !quantity) return res.status(400).json({ error: 'missing_fields' });
      const { data: crop } = (await db.from('crops').select('*').eq('id', crop_id).maybeSingle()) as { data: Crop | null };
      if (!crop) return res.status(404).json({ error: 'not_found' });
      if (crop.status !== 'approved') return res.status(400).json({ error: 'not_approved' });
      const { data, error } = await db
        .from('orders')
        .insert({
          wholesaler_id: me.id,
          farmer_id: crop.farmer_id,
          crop_id: crop.id,
          quantity: Number(quantity),
          status: 'pending',
        })
        .select('*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*)')
        .single();
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ order: data as Order });
    } catch (e) {
      console.error('POST /orders', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.patch('/orders/:id', requireAuth, async (req, res) => {
    try {
      const me = (req as any).user as User;
      const { id } = req.params;
      const { status } = req.body || {};
      if (!['accepted', 'completed', 'cancelled'].includes(status)) {
        return res.status(400).json({ error: 'invalid_status' });
      }
      const { data: order } = (await db.from('orders').select('*').eq('id', id).maybeSingle()) as { data: Order | null };
      if (!order) return res.status(404).json({ error: 'not_found' });
      if (me.role !== 'admin' && order.farmer_id !== me.id && order.wholesaler_id !== me.id) {
        return res.status(403).json({ error: 'forbidden' });
      }
      // Enforce valid transitions: pending → accepted/cancelled, accepted → completed/cancelled
      const validTransitions: Record<string, string[]> = {
        pending: ['accepted', 'cancelled'],
        accepted: ['completed', 'cancelled'],
        completed: [],
        cancelled: [],
      };
      if (!validTransitions[order.status]?.includes(status)) {
        return res.status(400).json({ error: 'invalid_transition', current: order.status, attempted: status });
      }
      const { data, error } = await db.from('orders').update({ status }).eq('id', id).select('*').single();
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ order: data as Order });
    } catch (e) {
      console.error('PATCH /orders', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Market prices ----------
  api.get('/prices', async (_req, res) => {
    try {
      const { data, error } = await db.from('market_prices').select('*').order('product');
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ prices: data as MarketPrice[] });
    } catch (e) {
      console.error('GET /prices', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.post('/prices', requireRole('admin'), async (req, res) => {
    try {
      const { product, unit, min_price, max_price, avg_price, trend } = req.body || {};
      if (!product || min_price == null || max_price == null || avg_price == null) {
        return res.status(400).json({ error: 'missing_fields' });
      }
      const { data, error } = await db
        .from('market_prices')
        .insert({
          product,
          unit: unit || 'kg',
          min_price: Number(min_price),
          max_price: Number(max_price),
          avg_price: Number(avg_price),
          trend: trend || 'stable',
          updated_at: new Date().toISOString(),
        })
        .select('*')
        .single();
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ price: data as MarketPrice });
    } catch (e) {
      console.error('POST /prices', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.patch('/prices/:id', requireRole('admin'), async (req, res) => {
    try {
      const { id } = req.params;
      const { product, unit, min_price, max_price, avg_price, trend } = req.body || {};
      const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
      if (product !== undefined) patch.product = product;
      if (unit !== undefined) patch.unit = unit;
      if (min_price !== undefined) patch.min_price = Number(min_price);
      if (max_price !== undefined) patch.max_price = Number(max_price);
      if (avg_price !== undefined) patch.avg_price = Number(avg_price);
      if (trend !== undefined) patch.trend = trend;
      const { data, error } = await db.from('market_prices').update(patch).eq('id', id).select('*').single();
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ price: data as MarketPrice });
    } catch (e) {
      console.error('PATCH /prices', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.delete('/prices/:id', requireRole('admin'), async (req, res) => {
    try {
      const { id } = req.params;
      const { error } = await db.from('market_prices').delete().eq('id', id);
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ ok: true });
    } catch (e) {
      console.error('DELETE /prices', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Contacts ----------
  api.post('/contacts', async (req, res) => {
    try {
      const { name, email, message } = req.body || {};
      if (!name || !email || !message) return res.status(400).json({ error: 'missing_fields' });
      const { error } = await db.from('contacts').insert({ name, email, message });
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ ok: true });
    } catch (e) {
      console.error('POST /contacts', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Admin: users ----------
  api.get('/admin/users', requireRole('admin'), async (_req, res) => {
    const { data, error } = await db.from('users').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: 'server_error' });
    return res.json({ users: (data as User[]).map(sanitize) });
  });

  api.patch('/admin/users/:id', requireRole('admin'), async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body || {};
      if (!['active', 'suspended', 'banned'].includes(status)) {
        return res.status(400).json({ error: 'invalid_status' });
      }
      const { data, error } = await db.from('users').update({ status }).eq('id', id).select('*').single();
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ user: sanitize(data as User) });
    } catch (e) {
      console.error('PATCH /admin/users', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Admin: pending crops ----------
  api.get('/admin/crops/pending', requireRole('admin'), async (_req, res) => {
    const { data, error } = await db
      .from('crops')
      .select('*, farmer:users!crops_farmer_id_fkey(*)')
      .eq('status', 'pending')
      .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: 'server_error' });
    return res.json({ crops: (data as Crop[]).map(sanitizeCrop) });
  });

  api.get('/admin/orders', requireRole('admin'), async (_req, res) => {
    const { data, error } = await db
      .from('orders')
      .select('*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*), wholesaler:users!orders_wholesaler_id_fkey(*)')
      .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: 'server_error' });
    return res.json({ orders: data as Order[] });
  });

  // ---------- Profile ----------
  const PROFILE_BUCKET = 'profile-images';
  const PROFILE_MAX_SIZE = 5 * 1024 * 1024;
  const PROFILE_ALLOWED_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];

  function uploadAvatar(req: express.Request, res: express.Response, next: express.NextFunction) {
    uploadMiddleware.single('avatar')(req, res, (error: unknown) => {
      if (!error) {
        next();
        return;
      }
      if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
        res.status(413).json({ error: 'image_too_large', message: 'Image must be 5 MB or smaller.' });
        return;
      }
      console.error('avatar multipart upload', error);
      res.status(400).json({ error: 'upload_failed', message: 'The image could not be read. Please choose a JPG, PNG, or WEBP image.' });
    });
  }

  // POST /me/avatar — upload profile picture (multipart: field "avatar")
  api.post('/me/avatar', requireAuth, uploadAvatar, async (req, res) => {
    try {
      const me = (req as any).user as User;
      const file = req.file as Express.Multer.File | undefined;
      if (!file) return res.status(400).json({ error: 'missing_file' });
      if (!PROFILE_ALLOWED_TYPES.includes(file.mimetype)) {
        return res.status(400).json({ error: 'invalid_image_type' });
      }
      if (file.size > PROFILE_MAX_SIZE) {
        return res.status(400).json({ error: 'image_too_large' });
      }

      const ext = file.mimetype === 'image/png' ? 'png' : file.mimetype === 'image/webp' ? 'webp' : 'jpg';
      const filePath = `profiles/${me.id}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;

      const { error: upErr } = await db.storage
        .from(PROFILE_BUCKET)
        .upload(filePath, file.buffer, { contentType: file.mimetype, upsert: false });
      if (upErr) {
        console.error('avatar upload', upErr);
        return res.status(502).json({ error: 'storage_upload_failed', message: upErr.message || 'Storage rejected the image.' });
      }

      const { data: pub } = db.storage.from(PROFILE_BUCKET).getPublicUrl(filePath);
      const newAvatarUrl = pub.publicUrl;

      // Get old avatar URL to delete after update
      const oldAvatarUrl = me.avatar_url;

      const { data, error } = await db
        .from('users')
        .update({ avatar_url: newAvatarUrl })
        .eq('id', me.id)
        .select('*')
        .single();
      if (error) {
        await db.storage.from(PROFILE_BUCKET).remove([filePath]);
        console.error('avatar profile update', error);
        return res.status(500).json({ error: 'profile_update_failed', message: error.message || 'The profile could not be updated.' });
      }

      // Delete old avatar from storage (best-effort)
      if (oldAvatarUrl) {
        try {
          const url = new URL(oldAvatarUrl);
          const parts = url.pathname.split(`/storage/v1/object/public/${PROFILE_BUCKET}/`);
          if (parts.length === 2 && parts[1]) {
            await db.storage.from(PROFILE_BUCKET).remove([decodeURIComponent(parts[1])]);
          }
        } catch (e) { /* ignore */ }
      }

      return res.json({ user: sanitize(data as User) });
    } catch (e) {
      console.error('POST /me/avatar', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.patch('/me', requireAuth, async (req, res) => {
    try {
      const me = (req as any).user as User;
      const allowed = [
        'full_name',
        'phone',
        'business_name',
        'farm_location',
        'years_experience',
        'about_farm',
        'business_location',
        'years_in_business',
        'storage_capacity_tons',
        'avatar_url',
      ];
      const patch: Record<string, unknown> = {};
      for (const k of allowed) {
        if (req.body[k] !== undefined) patch[k] = req.body[k];
      }
      if (patch.years_experience !== undefined) patch.years_experience = patch.years_experience === '' ? null : Number(patch.years_experience);
      if (patch.years_in_business !== undefined) patch.years_in_business = patch.years_in_business === '' ? null : Number(patch.years_in_business);
      if (patch.storage_capacity_tons !== undefined) patch.storage_capacity_tons = patch.storage_capacity_tons === '' ? null : Number(patch.storage_capacity_tons);
      const { data, error } = await db.from('users').update(patch).eq('id', me.id).select('*').single();
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ user: sanitize(data as User) });
    } catch (e) {
      console.error('PATCH /me', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Reviews (verified — only after a completed order) ----------
  // GET /reviews?user_id=<id>  — list reviews received by a user (newest first),
  //   with the reviewer + the underlying order (crop, counterpart, amount, date).
  // GET /reviews/mine          — reviews I have written.
  // GET /reviews/eligible      — completed orders of mine that I haven't reviewed
  //   yet (from my side), used to populate the "leave a review" picker.
  // POST /reviews              — leave a review for one of my completed orders.
  api.get('/reviews', async (req, res) => {
    try {
      const userId = req.query.user_id as string | undefined;
      if (!userId) return res.status(400).json({ error: 'missing_user' });
      const { data, error } = await db
        .from('reviews')
        .select('*, reviewer:users!reviews_reviewer_id_fkey(*), order:orders(*)')
        .eq('reviewee_id', userId)
        .order('created_at', { ascending: false });
      if (error) return res.status(500).json({ error: 'server_error' });
      const rows = (data as Review[]) ?? [];
      // Aggregate rating.
      const avg = rows.length ? rows.reduce((s, r) => s + Number(r.rating), 0) / rows.length : 0;
      return res.json({ reviews: rows.map(sanitizeReview), average: Math.round(avg * 10) / 10, count: rows.length });
    } catch (e) {
      console.error('GET /reviews', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.get('/reviews/mine', requireAuth, async (req, res) => {
    try {
      const me = (req as any).user as User;
      const { data, error } = await db
        .from('reviews')
        .select('*, reviewee:users!reviews_reviewee_id_fkey(*), order:orders(*)')
        .eq('reviewer_id', me.id)
        .order('created_at', { ascending: false });
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ reviews: (data as Review[]).map(sanitizeReview) });
    } catch (e) {
      console.error('GET /reviews/mine', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.get('/reviews/eligible', requireAuth, async (req, res) => {
    try {
      const me = (req as any).user as User;
      // All completed orders where I'm a participant.
      const { data: orders, error } = await db
        .from('orders')
        .select('*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*), wholesaler:users!orders_wholesaler_id_fkey(*)')
        .eq('status', 'completed')
        .order('created_at', { ascending: false });
      if (error) return res.status(500).json({ error: 'server_error' });
      const mine = (orders as Order[] | null) ?? [];
      const participated = mine.filter((o) => o.farmer_id === me.id || o.wholesaler_id === me.id);
      // Existing reviews I've already written.
      const { data: mineReviews } = await db.from('reviews').select('order_id, reviewer_id').eq('reviewer_id', me.id);
      const reviewed = new Set(((mineReviews as Review[] | null) ?? []).map((r) => r.order_id));
      const eligible = participated.filter((o) => !reviewed.has(o.id));
      return res.json({ orders: eligible });
    } catch (e) {
      console.error('GET /reviews/eligible', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  api.post('/reviews', requireAuth, async (req, res) => {
    try {
      const me = (req as any).user as User;
      const { order_id, rating, comment } = req.body || {};
      if (!order_id || !rating) return res.status(400).json({ error: 'missing_fields' });
      const r = Number(rating);
      if (!Number.isInteger(r) || r < 1 || r > 5) return res.status(400).json({ error: 'invalid_rating' });
      const trimmedComment = comment ? String(comment).slice(0, 500) : null;

      const { data: order } = (await db.from('orders').select('*').eq('id', order_id).maybeSingle()) as { data: Order | null };
      if (!order) return res.status(404).json({ error: 'order_not_found' });
      if (order.status !== 'completed') return res.status(400).json({ error: 'order_not_completed' });

      let reviewerRole: 'farmer' | 'wholesaler' | null = null;
      let revieweeId: string | null = null;
      if (order.farmer_id === me.id && me.role === 'farmer') {
        reviewerRole = 'farmer';
        revieweeId = order.wholesaler_id;
      } else if (order.wholesaler_id === me.id && me.role === 'wholesaler') {
        reviewerRole = 'wholesaler';
        revieweeId = order.farmer_id;
      }
      if (!reviewerRole || !revieweeId) return res.status(403).json({ error: 'forbidden' });

      // Enforce one-per-direction via upsert-like insert with conflict handling.
      const { data: existing } = await db
        .from('reviews')
        .select('id')
        .eq('order_id', order_id)
        .eq('reviewer_role', reviewerRole)
        .maybeSingle();
      if (existing) return res.status(409).json({ error: 'already_reviewed' });

      const { data, error } = await db
        .from('reviews')
        .insert({
          order_id,
          reviewer_id: me.id,
          reviewee_id: revieweeId,
          reviewer_role: reviewerRole,
          rating: r,
          comment: trimmedComment,
        })
        .select('*')
        .single();
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ review: sanitizeReview(data as Review) });
    } catch (e) {
      console.error('POST /reviews', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Statement (transaction history) ----------
  // GET /statement?from=YYYY-MM-DD&to=YYYY-MM-DD&status=...
  // Returns the caller's orders (as farmer or wholesaler depending on role),
  // each with crop + counterpart, plus a running grand total of completed
  // transactions. Filters optional.
  api.get('/statement', requireAuth, async (req, res) => {
    try {
      const me = (req as any).user as User;
      const from = req.query.from as string | undefined;
      const to = req.query.to as string | undefined;
      const status = req.query.status as string | undefined;

      let q = db
        .from('orders')
        .select('*, crop:crops(*), farmer:users!orders_farmer_id_fkey(*), wholesaler:users!orders_wholesaler_id_fkey(*)')
        .order('created_at', { ascending: false });
      if (status && ['pending', 'accepted', 'completed', 'cancelled'].includes(status)) {
        q = q.eq('status', status);
      }
      if (from) q = q.gte('created_at', new Date(from).toISOString());
      if (to) {
        const toDate = new Date(to);
        toDate.setHours(23, 59, 59, 999);
        q = q.lte('created_at', toDate.toISOString());
      }
      const { data, error } = await q;
      if (error) return res.status(500).json({ error: 'server_error' });
      let rows = (data as Order[]) ?? [];
      if (me.role === 'farmer') rows = rows.filter((o) => o.farmer_id === me.id);
      else if (me.role === 'wholesaler') rows = rows.filter((o) => o.wholesaler_id === me.id);
      // Admin sees all (no filter).

      // Running total of completed orders only.
      let running = 0;
      const enriched = rows.map((o) => {
        const amount = o.crop ? Number(o.crop.price) * Number(o.quantity) : 0;
        if (o.status === 'completed') running += amount;
        return { ...o, amount };
      });
      return res.json({
        orders: enriched,
        total: running,
        count: rows.length,
        completedCount: rows.filter((o) => o.status === 'completed').length,
      });
    } catch (e) {
      console.error('GET /statement', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // ---------- Products (farmer product management) ----------
  const PRODUCT_CATEGORIES = ['Vegetables', 'Fruits', 'Grains', 'Dairy', 'Herbs', 'Spices', 'Pulses', 'Others'] as const;
  const PRODUCT_UNITS = ['kg', 'ton', 'sack', 'crate', 'dozen', 'liter'] as const;
  const PRODUCT_AVAILABILITY = ['Available', 'Limited Stock', 'Sold Out'] as const;
  const MAX_IMAGES = 5;
  const MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5 MB
  const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
  const STORAGE_BUCKET = 'product-images';

  function validateProduct(body: any): string | null {
    if (!body.product_name || !String(body.product_name).trim()) return 'missing_name';
    if (!body.category || !PRODUCT_CATEGORIES.includes(body.category)) return 'invalid_category';
    if (body.price == null || Number(body.price) <= 0) return 'invalid_price';
    if (body.quantity == null || Number(body.quantity) < 0) return 'invalid_quantity';
    if (!body.unit || !PRODUCT_UNITS.includes(body.unit)) return 'invalid_unit';
    if (!body.district || !String(body.district).trim()) return 'missing_district';
    if (body.availability && !PRODUCT_AVAILABILITY.includes(body.availability)) return 'invalid_availability';
    return null;
  }

  // GET /products?farmer_id=<id>  — list products for a farmer (or all if no filter)
  // GET /products?mine=true       — list the logged-in farmer's products
  api.get('/products', async (req, res) => {
    try {
      const mine = req.query.mine === 'true';
      const farmerId = req.query.farmer_id as string | undefined;

      let q = db.from('products').select('*, images:product_images(*)').order('created_at', { ascending: false });
      if (mine) {
        const me = await currentUser(req);
        if (!me) return res.status(401).json({ error: 'unauthorized' });
        q = q.eq('farmer_id', me.id);
      } else if (farmerId) {
        q = q.eq('farmer_id', farmerId);
      }
      const { data, error } = await q;
      if (error) return res.status(500).json({ error: 'server_error' });
      const rows = (data as (Product & { images: ProductImage[] })[]) ?? [];
      return res.json({ products: rows.map((p) => ({ ...p, images: (p.images || []).sort((a, b) => a.sort_order - b.sort_order) })) });
    } catch (e) {
      console.error('GET /products', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // GET /products/:id — single product with images
  api.get('/products/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const { data, error } = await db
        .from('products')
        .select('*, images:product_images(*)')
        .eq('id', id)
        .maybeSingle();
      if (error) return res.status(500).json({ error: 'server_error' });
      if (!data) return res.status(404).json({ error: 'not_found' });
      const p = data as Product & { images: ProductImage[] };
      p.images = (p.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ product: p });
    } catch (e) {
      console.error('GET /products/:id', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // POST /products — create a new product (multipart: fields + images[])
  api.post('/products', requireRole('farmer'), uploadMiddleware.any(), async (req, res) => {
    try {
      const me = (req as any).user as User;
      const body = req.body || {};
      const files = (req.files as Express.Multer.File[] | undefined) ?? [];

      const validationError = validateProduct(body);
      if (validationError) return res.status(400).json({ error: validationError });

      if (files.length > MAX_IMAGES) return res.status(400).json({ error: 'too_many_images' });
      for (const f of files) {
        if (!ALLOWED_IMAGE_TYPES.includes(f.mimetype)) return res.status(400).json({ error: 'invalid_image_type' });
        if (f.size > MAX_IMAGE_SIZE) return res.status(400).json({ error: 'image_too_large' });
      }

      const { data: product, error } = await db
        .from('products')
        .insert({
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
          availability: body.availability || 'Available',
        })
        .select('*')
        .single();
      if (error) return res.status(500).json({ error: 'server_error' });

      // Upload images to Supabase Storage and create product_images rows
      const imageRows = await uploadProductImages(product.id, files);
      const { data: fullProduct } = await db
        .from('products')
        .select('*, images:product_images(*)')
        .eq('id', product.id)
        .single();
      const result = fullProduct as Product & { images: ProductImage[] };
      result.images = (result.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ product: result });
    } catch (e) {
      console.error('POST /products', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // PATCH /products/:id — update product fields (multipart: fields + new images[])
  api.patch('/products/:id', requireRole('farmer'), uploadMiddleware.any(), async (req, res) => {
    try {
      const me = (req as any).user as User;
      const { id } = req.params;
      const body = req.body || {};
      const files = (req.files as Express.Multer.File[] | undefined) ?? [];

      const { data: product } = (await db.from('products').select('*').eq('id', id).maybeSingle()) as { data: Product | null };
      if (!product) return res.status(404).json({ error: 'not_found' });
      if (product.farmer_id !== me.id) return res.status(403).json({ error: 'forbidden' });

      // Count existing images + new uploads
      const { data: existingImages } = await db.from('product_images').select('id').eq('product_id', id);
      const existingCount = existingImages?.length ?? 0;
      // images_to_remove is a JSON string of image IDs to delete
      let removeIds: string[] = [];
      if (body.remove_images) {
        try { removeIds = JSON.parse(body.remove_images); } catch { removeIds = []; }
      }
      const remainingAfterRemove = existingCount - removeIds.length;
      if (remainingAfterRemove + files.length > MAX_IMAGES) {
        return res.status(400).json({ error: 'too_many_images' });
      }
      for (const f of files) {
        if (!ALLOWED_IMAGE_TYPES.includes(f.mimetype)) return res.status(400).json({ error: 'invalid_image_type' });
        if (f.size > MAX_IMAGE_SIZE) return res.status(400).json({ error: 'image_too_large' });
      }

      // Update fields
      const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
      if (body.product_name !== undefined) patch.product_name = String(body.product_name).trim();
      if (body.category !== undefined) {
        if (!PRODUCT_CATEGORIES.includes(body.category)) return res.status(400).json({ error: 'invalid_category' });
        patch.category = body.category;
      }
      if (body.description !== undefined) patch.description = body.description ? String(body.description).trim() : null;
      if (body.price !== undefined) {
        if (Number(body.price) <= 0) return res.status(400).json({ error: 'invalid_price' });
        patch.price = Number(body.price);
      }
      if (body.quantity !== undefined) {
        if (Number(body.quantity) < 0) return res.status(400).json({ error: 'invalid_quantity' });
        patch.quantity = Number(body.quantity);
      }
      if (body.unit !== undefined) {
        if (!PRODUCT_UNITS.includes(body.unit)) return res.status(400).json({ error: 'invalid_unit' });
        patch.unit = body.unit;
      }
      if (body.district !== undefined) patch.district = String(body.district).trim();
      if (body.municipality !== undefined) patch.municipality = body.municipality ? String(body.municipality).trim() : null;
      if (body.harvest_date !== undefined) patch.harvest_date = body.harvest_date || null;
      if (body.availability !== undefined) {
        if (!PRODUCT_AVAILABILITY.includes(body.availability)) return res.status(400).json({ error: 'invalid_availability' });
        patch.availability = body.availability;
      }

      const { error: updateError } = await db.from('products').update(patch).eq('id', id);
      if (updateError) return res.status(500).json({ error: 'server_error' });

      // Remove specified images
      if (removeIds.length > 0) {
        const { data: imgsToRemove } = await db.from('product_images').select('image_url').in('id', removeIds).eq('product_id', id);
        if (imgsToRemove && imgsToRemove.length) {
          await Promise.all(imgsToRemove.map((img) => deleteStorageFile(img.image_url)));
          await db.from('product_images').delete().in('id', removeIds).eq('product_id', id);
        }
      }

      // Upload new images
      await uploadProductImages(id, files);

      const { data: fullProduct } = await db
        .from('products')
        .select('*, images:product_images(*)')
        .eq('id', id)
        .single();
      const result = fullProduct as Product & { images: ProductImage[] };
      result.images = (result.images || []).sort((a, b) => a.sort_order - b.sort_order);
      return res.json({ product: result });
    } catch (e) {
      console.error('PATCH /products/:id', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // DELETE /products/:id — delete a product and its images
  api.delete('/products/:id', requireRole('farmer'), async (req, res) => {
    try {
      const me = (req as any).user as User;
      const { id } = req.params;
      const { data: product } = (await db.from('products').select('*').eq('id', id).maybeSingle()) as { data: Product | null };
      if (!product) return res.status(404).json({ error: 'not_found' });
      if (product.farmer_id !== me.id) return res.status(403).json({ error: 'forbidden' });

      // Delete images from storage
      const { data: images } = await db.from('product_images').select('image_url').eq('product_id', id);
      if (images && images.length) {
        await Promise.all(images.map((img) => deleteStorageFile(img.image_url)));
      }
      // Delete product (cascades to product_images)
      const { error } = await db.from('products').delete().eq('id', id);
      if (error) return res.status(500).json({ error: 'server_error' });
      return res.json({ ok: true });
    } catch (e) {
      console.error('DELETE /products/:id', e);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  // Helper: upload files to Supabase Storage and create product_images rows
  async function uploadProductImages(productId: string, files: Express.Multer.File[]): Promise<ProductImage[]> {
    if (!files.length) return [];
    const rows: ProductImage[] = [];
    // Get current max sort_order for this product
    const { data: existing } = await db.from('product_images').select('sort_order').eq('product_id', productId);
    let nextOrder = existing && existing.length ? Math.max(...existing.map((i: any) => i.sort_order)) + 1 : 0;

    for (const file of files) {
      const ext = file.originalname.split('.').pop()?.toLowerCase() || 'jpg';
      const filePath = `${productId}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
      const { error: uploadError } = await db.storage.from(STORAGE_BUCKET).upload(filePath, file.buffer, {
        contentType: file.mimetype,
        upsert: false,
      });
      if (uploadError) {
        console.error('Storage upload error', uploadError);
        continue;
      }
      const { data: pubUrl } = db.storage.from(STORAGE_BUCKET).getPublicUrl(filePath);
      const { data: imgRow } = await db
        .from('product_images')
        .insert({ product_id: productId, image_url: pubUrl.publicUrl, sort_order: nextOrder })
        .select('*')
        .single();
      if (imgRow) rows.push(imgRow as ProductImage);
      nextOrder++;
    }
    return rows;
  }

  // Helper: delete a file from Supabase Storage by its public URL
  async function deleteStorageFile(publicUrl: string): Promise<void> {
    try {
      const url = new URL(publicUrl);
      const parts = url.pathname.split(`/storage/v1/object/public/${STORAGE_BUCKET}/`);
      if (parts.length < 2) return;
      const filePath = decodeURIComponent(parts[1]);
      await db.storage.from(STORAGE_BUCKET).remove([filePath]);
    } catch (e) {
      console.error('deleteStorageFile error', e);
    }
  }

  return api;
}

function sanitize(u: User) {
  const { pin_hash, ...rest } = u;
  void pin_hash;
  return rest;
}
function sanitizeCrop(c: Crop) {
  return { ...c, farmer: c.farmer ? sanitize(c.farmer) : undefined };
}
function sanitizeReview(r: Review) {
  return {
    ...r,
    reviewer: r.reviewer ? sanitize(r.reviewer) : undefined,
    order: r.order ? { ...r.order } : undefined,
  };
}

export { SESSION_COOKIE };
