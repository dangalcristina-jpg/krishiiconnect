/*
# Create profile-images storage bucket

1. Purpose
- Store user profile avatar images in Supabase Storage under a dedicated `profile-images` bucket.
- Each user uploads their own avatar; old avatars are deleted when replaced.

2. Storage Bucket
- `profile-images` (public bucket so avatars can be displayed via public URL)

3. Storage Policies (RLS on storage.objects)
- SELECT: anyone can read (public avatars displayed across the app).
- INSERT: authenticated users can upload to their own folder `profiles/<user_id>/`.
- UPDATE: owners can update their own folder.
- DELETE: owners can delete files in their own folder.

4. Notes
- Files stored under path `profiles/<user_id>/<unique-name>.<ext>`.
- The server uses the service-role client to manage uploads/deletions, so these
  policies are a defense-in-depth layer for any direct client uploads.
*/

INSERT INTO storage.buckets (id, name, public)
VALUES ('profile-images', 'profile-images', true)
ON CONFLICT (id) DO NOTHING;

-- SELECT: public read (avatars visible to all users)
DROP POLICY IF EXISTS "profile_images_public_read" ON storage.objects;
CREATE POLICY "profile_images_public_read"
ON storage.objects FOR SELECT
TO anon, authenticated
USING (bucket_id = 'profile-images');

-- INSERT: authenticated users can upload into their own folder
DROP POLICY IF EXISTS "profile_images_insert_own" ON storage.objects;
CREATE POLICY "profile_images_insert_own"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'profile-images'
  AND (storage.foldername(name))[1] = 'profiles'
  AND (storage.foldername(name))[2] = auth.uid()::text
);

-- UPDATE: owners can update files in their own folder
DROP POLICY IF EXISTS "profile_images_update_own" ON storage.objects;
CREATE POLICY "profile_images_update_own"
ON storage.objects FOR UPDATE
TO authenticated
USING (
  bucket_id = 'profile-images'
  AND (storage.foldername(name))[1] = 'profiles'
  AND (storage.foldername(name))[2] = auth.uid()::text
)
WITH CHECK (
  bucket_id = 'profile-images'
  AND (storage.foldername(name))[1] = 'profiles'
  AND (storage.foldername(name))[2] = auth.uid()::text
);

-- DELETE: owners can delete files in their own folder
DROP POLICY IF EXISTS "profile_images_delete_own" ON storage.objects;
CREATE POLICY "profile_images_delete_own"
ON storage.objects FOR DELETE
TO authenticated
USING (
  bucket_id = 'profile-images'
  AND (storage.foldername(name))[1] = 'profiles'
  AND (storage.foldername(name))[2] = auth.uid()::text
);
