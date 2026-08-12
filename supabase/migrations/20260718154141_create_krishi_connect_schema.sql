/*
# Krishi Connect — initial schema

Builds the database for a farmer↔wholesaler marketplace in Nepal.

1. New Tables
- `profiles`: app-level user row (one per auth.users). Fields:
  - id (uuid, PK, FK -> auth.users.id)
  - full_name (text, not null)
  - business_name (text, nullable — wholesalers only)
  - phone (text, unique, not null)
  - role (text, not null, in farmer/wholesaler/admin) — stored in raw_user_meta_data too for client reads
  - status (text, not null, default 'active' — active/suspended/banned)
  - farm_location (text, nullable)
  - years_experience (int, nullable)
  - about_farm (text, nullable)
  - business_location (text, nullable)
  - years_in_business (int, nullable)
  - storage_capacity_tons (numeric, nullable)
  - avatar_url (text, nullable)
  - created_at (timestamptz, default now())
- `crops`: farmer listings. Fields:
  - id (uuid, PK)
  - farmer_id (uuid, FK -> profiles.id)
  - name (text, not null)
  - category (text, nullable)
  - price (numeric, not null) — price per kg in NPR
  - quantity_available (numeric, not null)
  - unit (text, default 'kg')
  - location (text, nullable)
  - harvest_date (date, nullable)
  - image_url (text, nullable)
  - description (text, nullable)
  - status (text, default 'pending' — pending/approved/rejected/sold_out)
  - created_at (timestamptz, default now())
- `orders`: wholesaler→farmer requests. Fields:
  - id (uuid, PK)
  - wholesaler_id (uuid, FK -> profiles.id)
  - farmer_id (uuid, FK -> profiles.id)
  - crop_id (uuid, FK -> crops.id)
  - quantity (numeric, not null)
  - status (text, default 'pending' — pending/completed/cancelled)
  - created_at (timestamptz, default now())
- `market_prices`: live crop prices (admin-managed). Fields:
  - id (uuid, PK)
  - product (text, not null)
  - unit (text, default 'kg')
  - min_price (numeric, not null)
  - max_price (numeric, not null)
  - avg_price (numeric, not null)
  - trend (text, default 'stable' — up/down/stable)
  - updated_at (timestamptz, default now())
- `contacts`: contact form submissions. Fields:
  - id (uuid, PK)
  - name (text, not null)
  - email (text, not null)
  - message (text, not null)
  - created_at (timestamptz, default now())

2. Security (RLS)
- profiles: each authenticated user can read all profiles (needed for farmer names on listings) but only update their own. anon can read profiles (so public product cards can show farmer names without login).
- crops: anon+authenticated can SELECT approved crops; farmers can insert/update/delete their own; admins (role = 'admin') can update any (approve/reject).
- orders: wholesalers can insert their own; users can read their own (as buyer or seller); admins can read all and update status.
- market_prices: anon+authenticated can SELECT; only admins can INSERT/UPDATE/DELETE.
- contacts: anon+authenticated can INSERT; only admins can SELECT.

3. Important notes
- Owner columns default to auth.uid() so inserts that omit them still satisfy WITH CHECK.
- Admin status is enforced via a lookup of profiles.role = 'admin' for the auth.uid().
- Suspended/banned users are blocked at the application layer after sign-in.
*/

-- profiles
CREATE TABLE IF NOT EXISTS profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name text NOT NULL,
  business_name text,
  phone text UNIQUE NOT NULL,
  role text NOT NULL CHECK (role IN ('farmer','wholesaler','admin')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','banned')),
  farm_location text,
  years_experience int,
  about_farm text,
  business_location text,
  years_in_business int,
  storage_capacity_tons numeric,
  avatar_url text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "profiles_select_all" ON profiles;
CREATE POLICY "profiles_select_all" ON profiles FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "profiles_update_own" ON profiles;
CREATE POLICY "profiles_update_own" ON profiles FOR UPDATE
  TO authenticated USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

-- crops
CREATE TABLE IF NOT EXISTS crops (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  farmer_id uuid NOT NULL DEFAULT auth.uid() REFERENCES profiles(id) ON DELETE CASCADE,
  name text NOT NULL,
  category text,
  price numeric NOT NULL,
  quantity_available numeric NOT NULL,
  unit text NOT NULL DEFAULT 'kg',
  location text,
  harvest_date date,
  image_url text,
  description text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','sold_out')),
  created_at timestamptz DEFAULT now()
);

ALTER TABLE crops ENABLE ROW LEVEL SECURITY;

-- Public can read approved crops (and sold_out so the card still renders historically)
DROP POLICY IF EXISTS "crops_select_public" ON crops;
CREATE POLICY "crops_select_public" ON crops FOR SELECT
  TO anon, authenticated
  USING (status IN ('approved','sold_out'));

-- Farmers can read all their own crops (any status)
DROP POLICY IF EXISTS "crops_select_own" ON crops;
CREATE POLICY "crops_select_own" ON crops FOR SELECT
  TO authenticated
  USING (farmer_id = auth.uid());

-- Farmers insert their own (start as pending — enforced by app, but DB default handles it)
DROP POLICY IF EXISTS "crops_insert_own" ON crops;
CREATE POLICY "crops_insert_own" ON crops FOR INSERT
  TO authenticated WITH CHECK (farmer_id = auth.uid());

-- Farmers update their own; admins update any
DROP POLICY IF EXISTS "crops_update_own_or_admin" ON crops;
CREATE POLICY "crops_update_own_or_admin" ON crops FOR UPDATE
  TO authenticated
  USING (farmer_id = auth.uid() OR EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'))
  WITH CHECK (farmer_id = auth.uid() OR EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));

-- Farmers delete their own; admins delete any
DROP POLICY IF EXISTS "crops_delete_own_or_admin" ON crops;
CREATE POLICY "crops_delete_own_or_admin" ON crops FOR DELETE
  TO authenticated
  USING (farmer_id = auth.uid() OR EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));

-- orders
CREATE TABLE IF NOT EXISTS orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  wholesaler_id uuid NOT NULL DEFAULT auth.uid() REFERENCES profiles(id) ON DELETE CASCADE,
  farmer_id uuid NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  crop_id uuid NOT NULL REFERENCES crops(id) ON DELETE CASCADE,
  quantity numeric NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','cancelled')),
  created_at timestamptz DEFAULT now()
);

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

-- A user can read orders where they are the buyer OR the seller OR they are an admin
DROP POLICY IF EXISTS "orders_select_participants" ON orders;
CREATE POLICY "orders_select_participants" ON orders FOR SELECT
  TO authenticated
  USING (
    wholesaler_id = auth.uid()
    OR farmer_id = auth.uid()
    OR EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin')
  );

-- Wholesalers insert their own orders
DROP POLICY IF EXISTS "orders_insert_own" ON orders;
CREATE POLICY "orders_insert_own" ON orders FOR INSERT
  TO authenticated WITH CHECK (wholesaler_id = auth.uid());

-- Buyer, seller, or admin can update status
DROP POLICY IF EXISTS "orders_update_participants" ON orders;
CREATE POLICY "orders_update_participants" ON orders FOR UPDATE
  TO authenticated
  USING (
    wholesaler_id = auth.uid()
    OR farmer_id = auth.uid()
    OR EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin')
  )
  WITH CHECK (
    wholesaler_id = auth.uid()
    OR farmer_id = auth.uid()
    OR EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin')
  );

-- market_prices
CREATE TABLE IF NOT EXISTS market_prices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  product text NOT NULL,
  unit text NOT NULL DEFAULT 'kg',
  min_price numeric NOT NULL,
  max_price numeric NOT NULL,
  avg_price numeric NOT NULL,
  trend text NOT NULL DEFAULT 'stable' CHECK (trend IN ('up','down','stable')),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE market_prices ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "prices_select_public" ON market_prices;
CREATE POLICY "prices_select_public" ON market_prices FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "prices_write_admin" ON market_prices;
CREATE POLICY "prices_write_admin" ON market_prices FOR INSERT
  TO authenticated
  WITH CHECK (EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));

DROP POLICY IF EXISTS "prices_update_admin" ON market_prices;
CREATE POLICY "prices_update_admin" ON market_prices FOR UPDATE
  TO authenticated
  USING (EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'))
  WITH CHECK (EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));

DROP POLICY IF EXISTS "prices_delete_admin" ON market_prices;
CREATE POLICY "prices_delete_admin" ON market_prices FOR DELETE
  TO authenticated
  USING (EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));

-- contacts
CREATE TABLE IF NOT EXISTS contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  email text NOT NULL,
  message text NOT NULL,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "contacts_insert_public" ON contacts;
CREATE POLICY "contacts_insert_public" ON contacts FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "contacts_select_admin" ON contacts;
CREATE POLICY "contacts_select_admin" ON contacts FOR SELECT
  TO authenticated
  USING (EXISTS (SELECT 1 FROM profiles p WHERE p.id = auth.uid() AND p.role = 'admin'));

-- trigger: create a profile row whenever a new auth.users row is inserted.
-- We do NOT auto-create here because the app will insert the profile row explicitly
-- after signUp so it can pass role/business_name/phone. So no trigger needed.

-- indexes
CREATE INDEX IF NOT EXISTS crops_status_idx ON crops(status);
CREATE INDEX IF NOT EXISTS crops_farmer_idx ON crops(farmer_id);
CREATE INDEX IF NOT EXISTS orders_buyer_idx ON orders(wholesaler_id);
CREATE INDEX IF NOT EXISTS orders_seller_idx ON orders(farmer_id);

-- seed a few market price rows so the public page isn't empty
INSERT INTO market_prices (product, unit, min_price, max_price, avg_price, trend)
VALUES
  ('Rice', 'kg', 45, 60, 52, 'stable'),
  ('Tomato', 'kg', 30, 50, 40, 'up'),
  ('Potato', 'kg', 25, 35, 30, 'down'),
  ('Onion', 'kg', 40, 55, 47, 'stable'),
  ('Wheat', 'kg', 35, 45, 40, 'up'),
  ('Tea Leaves', 'kg', 80, 120, 100, 'stable')
ON CONFLICT DO NOTHING;
