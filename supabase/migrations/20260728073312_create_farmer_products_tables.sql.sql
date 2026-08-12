/*
# Farmer Product Management — products + product_images tables

## Purpose
Gives farmers the ability to create, edit, and delete their own agricultural
products with multiple images. This is the data layer for the Farmer Product
Management module.

## New Tables

### products
Stores one row per product a farmer has listed.
- `id` (uuid PK)
- `farmer_id` (uuid FK → users.id, ON DELETE CASCADE) — owner of the product
- `product_name` (text, not null)
- `category` (text, not null) — one of: Vegetables, Fruits, Grains, Dairy, Herbs, Spices, Pulses, Others
- `description` (text, nullable)
- `price` (numeric, not null, CHECK > 0)
- `quantity` (numeric, not null, CHECK >= 0)
- `unit` (text, not null) — one of: kg, ton, sack, crate, dozen, liter
- `district` (text, not null)
- `municipality` (text, nullable)
- `harvest_date` (date, nullable)
- `availability` (text, not null, default 'Available') — one of: Available, Limited Stock, Sold Out
- `created_at` (timestamptz, default now())
- `updated_at` (timestamptz, default now())

### product_images
Stores multiple image URLs per product, ordered by `sort_order`.
- `id` (uuid PK)
- `product_id` (uuid FK → products.id, ON DELETE CASCADE)
- `image_url` (text, not null) — public URL from Supabase Storage
- `sort_order` (int, default 0)
- `created_at` (timestamptz, default now())

## Security (RLS)
This app uses Express-served sessions (not Supabase Auth). The Express backend
connects with the anon key and enforces ownership in JavaScript before every
write. Therefore RLS policies allow the anon role full CRUD, matching the
existing pattern used by users, crops, orders, etc.

- products: anon + authenticated SELECT/INSERT/UPDATE/DELETE (all true)
- product_images: anon + authenticated SELECT/INSERT/UPDATE/DELETE (all true)

## Indexes
- products(farmer_id) — farmer's own product list
- products(category) — marketplace filtering
- products(availability) — marketplace filtering
- product_images(product_id) — fetching images for a product

## Notes
1. The Express backend is the sole caller and enforces auth + ownership.
2. The anon key is never exposed to the browser; all DB access goes through /api.
3. Image files are stored in Supabase Storage; only the public URL is saved here.
4. `updated_at` is maintained by the Express backend on every PATCH.
*/

CREATE TABLE IF NOT EXISTS products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  farmer_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_name text NOT NULL,
  category text NOT NULL CHECK (category IN ('Vegetables','Fruits','Grains','Dairy','Herbs','Spices','Pulses','Others')),
  description text,
  price numeric NOT NULL CHECK (price > 0),
  quantity numeric NOT NULL CHECK (quantity >= 0),
  unit text NOT NULL CHECK (unit IN ('kg','ton','sack','crate','dozen','liter')),
  district text NOT NULL,
  municipality text,
  harvest_date date,
  availability text NOT NULL DEFAULT 'Available' CHECK (availability IN ('Available','Limited Stock','Sold Out')),
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS product_images (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id uuid NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  image_url text NOT NULL,
  sort_order int NOT NULL DEFAULT 0,
  created_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_products_farmer ON products(farmer_id);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
CREATE INDEX IF NOT EXISTS idx_products_availability ON products(availability);
CREATE INDEX IF NOT EXISTS idx_product_images_product ON product_images(product_id);

ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE product_images ENABLE ROW LEVEL SECURITY;

-- products: anon + authenticated full CRUD (Express enforces ownership)
DROP POLICY IF EXISTS "anon_products_sel" ON products;
CREATE POLICY "anon_products_sel" ON products FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_products_ins" ON products;
CREATE POLICY "anon_products_ins" ON products FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_products_upd" ON products;
CREATE POLICY "anon_products_upd" ON products FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_products_del" ON products;
CREATE POLICY "anon_products_del" ON products FOR DELETE
  TO anon, authenticated USING (true);

-- product_images: anon + authenticated full CRUD
DROP POLICY IF EXISTS "anon_pimages_sel" ON product_images;
CREATE POLICY "anon_pimages_sel" ON product_images FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_pimages_ins" ON product_images;
CREATE POLICY "anon_pimages_ins" ON product_images FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_pimages_upd" ON product_images;
CREATE POLICY "anon_pimages_upd" ON product_images FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_pimages_del" ON product_images;
CREATE POLICY "anon_pimages_del" ON product_images FOR DELETE
  TO anon, authenticated USING (true);

-- updated_at trigger
CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_updated_at_products ON products;
CREATE TRIGGER set_updated_at_products
  BEFORE UPDATE ON products
  FOR EACH ROW
  EXECUTE FUNCTION trigger_set_updated_at();
