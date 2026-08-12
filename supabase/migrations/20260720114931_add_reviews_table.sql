/*
# Krishi Connect — Verified reviews + statement support

1. Purpose
This migration adds a `reviews` table for verified, bidirectional reviews
between farmers and wholesalers. A review can only exist if tied to a
specific completed (status='completed') order. The same order can produce
up to two independent reviews: one from the wholesaler about the farmer,
and one from the farmer about the wholesaler. Each side can leave exactly
one review per order (enforced by a unique constraint on
(order_id, reviewer_role)).

2. New table: reviews
- id (uuid, primary key)
- order_id (uuid, FK to orders, ON DELETE CASCADE)
- reviewer_id (uuid, FK to users, the user writing the review)
- reviewee_id (uuid, FK to users, the user being reviewed)
- reviewer_role (text, 'farmer' or 'wholesaler') — distinguishes the
  two directions and is part of the unique key so the same order can
  have one farmer-review and one wholesaler-review.
- rating (int, 1..5, NOT NULL)
- comment (text, optional, max ~500 chars enforced in API)
- created_at (timestamptz default now())

3. Constraints & indexes
- UNIQUE (order_id, reviewer_role) — one review per direction per order.
- INDEX on reviewee_id for fast "show reviews of this user" queries.
- INDEX on order_id for fast "did this order already get a review from
  this side" lookups.
- CHECK (rating BETWEEN 1 AND 5).
- CHECK (reviewer_role IN ('farmer','wholesaler')).

4. Security (RLS)
- The Express backend uses the anon-key Supabase client (no service role
  available in this environment), so RLS must allow the anon role to
  perform all CRUD. The Express server is the only caller and enforces
  auth + ownership + "completed order only" rules in JavaScript before
  each write. The anon key is never exposed to the browser.
- 4 policies (SELECT/INSERT/UPDATE/DELETE) scoped to TO anon, authenticated.

5. Notes
- The existing orders table already has status IN ('pending','completed',
  'cancelled'). The API will only allow INSERT into reviews when the
  related order has status='completed' AND the reviewer is a participant
  (either farmer_id or wholesaler_id) AND reviewer_role matches their
  actual role on that order. This is enforced in server.ts, not the DB,
  because the rule depends on the requesting session.
- No data is dropped or modified. Existing orders/crops/users are
  untouched. The new table is purely additive.
*/

CREATE TABLE IF NOT EXISTS reviews (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  reviewer_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reviewee_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reviewer_role text NOT NULL CHECK (reviewer_role IN ('farmer','wholesaler')),
  rating int NOT NULL CHECK (rating BETWEEN 1 AND 5),
  comment text,
  created_at timestamptz DEFAULT now(),
  CONSTRAINT reviews_one_per_direction_per_order UNIQUE (order_id, reviewer_role)
);

ALTER TABLE reviews ENABLE ROW LEVEL SECURITY;

-- SELECT
DROP POLICY IF EXISTS anon_reviews_sel ON reviews;
CREATE POLICY anon_reviews_sel ON reviews FOR SELECT
  TO anon, authenticated USING (true);

-- INSERT
DROP POLICY IF EXISTS anon_reviews_ins ON reviews;
CREATE POLICY anon_reviews_ins ON reviews FOR INSERT
  TO anon, authenticated WITH CHECK (true);

-- UPDATE
DROP POLICY IF EXISTS anon_reviews_upd ON reviews;
CREATE POLICY anon_reviews_upd ON reviews FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

-- DELETE
DROP POLICY IF EXISTS anon_reviews_del ON reviews;
CREATE POLICY anon_reviews_del ON reviews FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_reviews_reviewee ON reviews(reviewee_id);
CREATE INDEX IF NOT EXISTS idx_reviews_order ON reviews(order_id);
CREATE INDEX IF NOT EXISTS idx_reviews_reviewer ON reviews(reviewer_id);
