/*
# Krishi Connect — rewrite for Express + PIN auth

Replaces the Supabase-Auth-based schema with a self-managed PIN-auth schema that
the Node/Express backend controls directly. Supabase Auth is no longer used.

1. Drop old tables (one-time rebuild; no production data exists).

2. New tables: users, sessions, crops, orders, market_prices, contacts.
- users: full_name, business_name (nullable), phone (unique), pin_hash (bcrypt),
  role (farmer/wholesaler/admin), status (active/suspended/banned), profile fields.
- sessions: token (unique), user_id, expires_at — for Express server-side sessions.
- crops: farmer_id FK, name, category, price, quantity_available, unit, location,
  harvest_date, image_url, description, status (pending/approved/rejected/sold_out).
- orders: wholesaler_id, farmer_id, crop_id, quantity, status, created_at.
- market_prices: product, unit, min/max/avg_price, trend, updated_at.
- contacts: name, email, message, created_at.

3. Security (RLS)
- The Express backend uses the anon-key client (no service role available in this
  environment), so RLS must allow the anon role to perform all CRUD. The Express
  server is the only caller and enforces auth + ownership in JavaScript before
  each write. The anon key is never exposed to the browser.

4. Notes
- PINs are bcrypt-hashed by the server before insert.
- Sessions are opaque tokens in HttpOnly cookies; looked up in the sessions table.
- Admin accounts are created by direct INSERT into users with role='admin'.
*/

DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS crops;
DROP TABLE IF EXISTS contacts;
DROP TABLE IF EXISTS market_prices;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS profiles;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name text NOT NULL,
  business_name text,
  phone text UNIQUE NOT NULL,
  pin_hash text NOT NULL,
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

CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token text UNIQUE NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE TABLE crops (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  farmer_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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

CREATE TABLE orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  wholesaler_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  farmer_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  crop_id uuid NOT NULL REFERENCES crops(id) ON DELETE CASCADE,
  quantity numeric NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','cancelled')),
  created_at timestamptz DEFAULT now()
);

CREATE TABLE market_prices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  product text NOT NULL,
  unit text NOT NULL DEFAULT 'kg',
  min_price numeric NOT NULL,
  max_price numeric NOT NULL,
  avg_price numeric NOT NULL,
  trend text NOT NULL DEFAULT 'stable' CHECK (trend IN ('up','down','stable')),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE contacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  email text NOT NULL,
  message text NOT NULL,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE crops ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE market_prices ENABLE ROW LEVEL SECURITY;
ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;

-- SELECT policies (USING only)
DROP POLICY IF EXISTS anon_users_sel ON users;
CREATE POLICY anon_users_sel ON users FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_sessions_sel ON sessions;
CREATE POLICY anon_sessions_sel ON sessions FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_crops_sel ON crops;
CREATE POLICY anon_crops_sel ON crops FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_orders_sel ON orders;
CREATE POLICY anon_orders_sel ON orders FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_prices_sel ON market_prices;
CREATE POLICY anon_prices_sel ON market_prices FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_contacts_sel ON contacts;
CREATE POLICY anon_contacts_sel ON contacts FOR SELECT TO anon, authenticated USING (true);

-- INSERT policies (WITH CHECK only)
DROP POLICY IF EXISTS anon_users_ins ON users;
CREATE POLICY anon_users_ins ON users FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS anon_sessions_ins ON sessions;
CREATE POLICY anon_sessions_ins ON sessions FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS anon_crops_ins ON crops;
CREATE POLICY anon_crops_ins ON crops FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS anon_orders_ins ON orders;
CREATE POLICY anon_orders_ins ON orders FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS anon_prices_ins ON market_prices;
CREATE POLICY anon_prices_ins ON market_prices FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS anon_contacts_ins ON contacts;
CREATE POLICY anon_contacts_ins ON contacts FOR INSERT TO anon, authenticated WITH CHECK (true);

-- UPDATE policies (USING + WITH CHECK)
DROP POLICY IF EXISTS anon_users_upd ON users;
CREATE POLICY anon_users_upd ON users FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS anon_sessions_upd ON sessions;
CREATE POLICY anon_sessions_upd ON sessions FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS anon_crops_upd ON crops;
CREATE POLICY anon_crops_upd ON crops FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS anon_orders_upd ON orders;
CREATE POLICY anon_orders_upd ON orders FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS anon_prices_upd ON market_prices;
CREATE POLICY anon_prices_upd ON market_prices FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS anon_contacts_upd ON contacts;
CREATE POLICY anon_contacts_upd ON contacts FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);

-- DELETE policies (USING only)
DROP POLICY IF EXISTS anon_users_del ON users;
CREATE POLICY anon_users_del ON users FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_sessions_del ON sessions;
CREATE POLICY anon_sessions_del ON sessions FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_crops_del ON crops;
CREATE POLICY anon_crops_del ON crops FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_orders_del ON orders;
CREATE POLICY anon_orders_del ON orders FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_prices_del ON market_prices;
CREATE POLICY anon_prices_del ON market_prices FOR DELETE TO anon, authenticated USING (true);
DROP POLICY IF EXISTS anon_contacts_del ON contacts;
CREATE POLICY anon_contacts_del ON contacts FOR DELETE TO anon, authenticated USING (true);

CREATE INDEX idx_crops_status ON crops(status);
CREATE INDEX idx_crops_farmer ON crops(farmer_id);
CREATE INDEX idx_orders_buyer ON orders(wholesaler_id);
CREATE INDEX idx_orders_seller ON orders(farmer_id);
CREATE INDEX idx_sessions_token ON sessions(token);

INSERT INTO market_prices (product, unit, min_price, max_price, avg_price, trend) VALUES
  ('Rice', 'kg', 45, 60, 52, 'stable'),
  ('Tomato', 'kg', 30, 50, 40, 'up'),
  ('Potato', 'kg', 25, 35, 30, 'down'),
  ('Onion', 'kg', 40, 55, 47, 'stable'),
  ('Wheat', 'kg', 35, 45, 40, 'up'),
  ('Tea Leaves', 'kg', 80, 120, 100, 'stable')
ON CONFLICT DO NOTHING;
