-- Add 'accepted' to the orders status CHECK constraint
-- Enables the workflow: Pending → Accepted → Completed (or Cancelled)
ALTER TABLE orders DROP CONSTRAINT IF EXISTS orders_status_check;
ALTER TABLE orders ADD CONSTRAINT orders_status_check CHECK (status IN ('pending','accepted','completed','cancelled'));
