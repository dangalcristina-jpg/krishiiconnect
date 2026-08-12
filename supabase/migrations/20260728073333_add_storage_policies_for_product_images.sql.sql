/*
# Storage policies for product-images bucket

## Purpose
Allow the Express backend (using the anon key) to upload, read, and delete
product images in the `product-images` public storage bucket.

## Security
The Express backend is the sole caller and enforces auth + ownership in JS.
Storage policies allow the anon role to perform all CRUD on the bucket, matching
the pattern used by all other tables in this project.

## Policies
- SELECT (read): anon + authenticated, USING (true) — public bucket, anyone can read
- INSERT (upload): anon + authenticated, WITH CHECK (true)
- UPDATE: anon + authenticated, USING (true) WITH CHECK (true)
- DELETE: anon + authenticated, USING (true)
*/

DROP POLICY IF EXISTS "anon_product_images_sel" ON storage.objects;
CREATE POLICY "anon_product_images_sel" ON storage.objects
  FOR SELECT TO anon, authenticated USING (bucket_id = 'product-images');

DROP POLICY IF EXISTS "anon_product_images_ins" ON storage.objects;
CREATE POLICY "anon_product_images_ins" ON storage.objects
  FOR INSERT TO anon, authenticated WITH CHECK (bucket_id = 'product-images');

DROP POLICY IF EXISTS "anon_product_images_upd" ON storage.objects;
CREATE POLICY "anon_product_images_upd" ON storage.objects
  FOR UPDATE TO anon, authenticated
  USING (bucket_id = 'product-images') WITH CHECK (bucket_id = 'product-images');

DROP POLICY IF EXISTS "anon_product_images_del" ON storage.objects;
CREATE POLICY "anon_product_images_del" ON storage.objects
  FOR DELETE TO anon, authenticated USING (bucket_id = 'product-images');
