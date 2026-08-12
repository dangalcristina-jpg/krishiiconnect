/*
# Crop images table + Auth OTP verification

## Purpose
1. Add multi-image support for crops (crop_images table + storage bucket).
2. Add phone OTP verification to the auth system (phone_verified flag + otp_codes table).

## New Tables

### crop_images
Stores multiple image URLs per crop, ordered by sort_order.
- id (uuid PK)
- crop_id (uuid FK → crops.id, ON DELETE CASCADE)
- image_url (text) — public URL from Supabase Storage
- sort_order (int, default 0)
- created_at (timestamptz)

### otp_codes
Stores one-time passwords for phone verification and PIN reset.
- id (uuid PK)
- phone (text, not null) — the phone being verified
- code (text, not null) — 4-digit OTP code
- purpose (text, not null) — 'register' or 'reset_pin'
- expires_at (timestamptz, not null) — 10 min validity
- used (boolean, default false)
- created_at (timestamptz, default now())

## Modified Tables

### users
- ADD phone_verified (boolean, NOT NULL, default false) — whether phone was OTP-verified

## Security (RLS)
- crop_images: anon + authenticated full CRUD (Express enforces ownership via crops FK)
- otp_codes: anon + authenticated full CRUD (Express manages OTP lifecycle)

## Storage
- Create public bucket 'crop-images' (done via SQL below)
- Storage policies: anon + authenticated full CRUD on 'crop-images' bucket

## Indexes
- crop_images(crop_id)
- otp_codes(phone, used) — lookup during verification

## Notes
1. The Express backend enforces crop ownership before any image operation.
2. OTP codes are 4 digits, valid for 10 minutes, single-use.
3. phone_verified defaults to false; set to true after successful OTP verification.
4. No real SMS gateway in this environment — the API returns the OTP code in the
   response so the demo UI can display/auto-fill it. In production this would
   be sent via SMS and never returned to the client.
*/

-- ---------- crop_images table ----------
CREATE TABLE IF NOT EXISTS crop_images (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  crop_id uuid NOT NULL REFERENCES crops(id) ON DELETE CASCADE,
  image_url text NOT NULL,
  sort_order int NOT NULL DEFAULT 0,
  created_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_crop_images_crop ON crop_images(crop_id);

ALTER TABLE crop_images ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_crop_images_sel" ON crop_images;
CREATE POLICY "anon_crop_images_sel" ON crop_images FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_crop_images_ins" ON crop_images;
CREATE POLICY "anon_crop_images_ins" ON crop_images FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_crop_images_upd" ON crop_images;
CREATE POLICY "anon_crop_images_upd" ON crop_images FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_crop_images_del" ON crop_images;
CREATE POLICY "anon_crop_images_del" ON crop_images FOR DELETE
  TO anon, authenticated USING (true);

-- ---------- users.phone_verified column ----------
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'users' AND column_name = 'phone_verified'
  ) THEN
    ALTER TABLE users ADD COLUMN phone_verified boolean NOT NULL DEFAULT false;
  END IF;
END $$;

-- ---------- otp_codes table ----------
CREATE TABLE IF NOT EXISTS otp_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  phone text NOT NULL,
  code text NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('register', 'reset_pin')),
  expires_at timestamptz NOT NULL,
  used boolean NOT NULL DEFAULT false,
  created_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_otp_phone_used ON otp_codes(phone, used);

ALTER TABLE otp_codes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_otp_sel" ON otp_codes;
CREATE POLICY "anon_otp_sel" ON otp_codes FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_otp_ins" ON otp_codes;
CREATE POLICY "anon_otp_ins" ON otp_codes FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_otp_upd" ON otp_codes;
CREATE POLICY "anon_otp_upd" ON otp_codes FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_otp_del" ON otp_codes;
CREATE POLICY "anon_otp_del" ON otp_codes FOR DELETE
  TO anon, authenticated USING (true);

-- ---------- crop-images storage bucket ----------
INSERT INTO storage.buckets (id, name, public)
VALUES ('crop-images', 'crop-images', true)
ON CONFLICT (id) DO NOTHING;

DROP POLICY IF EXISTS "anon_crop_storage_sel" ON storage.objects;
CREATE POLICY "anon_crop_storage_sel" ON storage.objects
  FOR SELECT TO anon, authenticated USING (bucket_id = 'crop-images');

DROP POLICY IF EXISTS "anon_crop_storage_ins" ON storage.objects;
CREATE POLICY "anon_crop_storage_ins" ON storage.objects
  FOR INSERT TO anon, authenticated WITH CHECK (bucket_id = 'crop-images');

DROP POLICY IF EXISTS "anon_crop_storage_upd" ON storage.objects;
CREATE POLICY "anon_crop_storage_upd" ON storage.objects
  FOR UPDATE TO anon, authenticated
  USING (bucket_id = 'crop-images') WITH CHECK (bucket_id = 'crop-images');

DROP POLICY IF EXISTS "anon_crop_storage_del" ON storage.objects;
CREATE POLICY "anon_crop_storage_del" ON storage.objects
  FOR DELETE TO anon, authenticated USING (bucket_id = 'crop-images');
