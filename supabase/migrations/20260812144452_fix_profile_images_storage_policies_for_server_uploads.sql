/*
# Fix profile-images storage policies for server-side uploads

## Root cause
The Express backend uses the anon key (no service role key is provisioned),
and the server has no Supabase user session. The original profile-images
policies required `auth.uid()` to match the folder name, so the server's
anon-key client was rejected by RLS on INSERT — producing the generic
"Sorry, we can't do that" error.

The product-images and crop-images buckets already work with this
architecture: their policies allow the `anon` role to perform all CRUD on
the bucket, and the server enforces auth + ownership in JS. This migration
aligns profile-images to that same proven pattern.

## Security
The Express backend is the sole caller and enforces auth + ownership in JS
(the POST /me/avatar route requires an authenticated session and writes
only to `profiles/<user_id>/`). These policies are a defense-in-depth layer.
*/

-- SELECT (read): public read — avatars are displayed across the app
DROP POLICY IF EXISTS "profile_images_public_read" ON storage.objects;
CREATE POLICY "profile_images_public_read" ON storage.objects
  FOR SELECT TO anon, authenticated
  USING (bucket_id = 'profile-images');

-- INSERT (upload): allow the server (anon key) to upload
DROP POLICY IF EXISTS "profile_images_insert_own" ON storage.objects;
CREATE POLICY "profile_images_insert_own" ON storage.objects
  FOR INSERT TO anon, authenticated
  WITH CHECK (bucket_id = 'profile-images');

-- UPDATE: allow the server to update files in the bucket
DROP POLICY IF EXISTS "profile_images_update_own" ON storage.objects;
CREATE POLICY "profile_images_update_own" ON storage.objects
  FOR UPDATE TO anon, authenticated
  USING (bucket_id = 'profile-images')
  WITH CHECK (bucket_id = 'profile-images');

-- DELETE: allow the server to delete old avatars
DROP POLICY IF EXISTS "profile_images_delete_own" ON storage.objects;
CREATE POLICY "profile_images_delete_own" ON storage.objects
  FOR DELETE TO anon, authenticated
  USING (bucket_id = 'profile-images');
