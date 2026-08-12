/**
 * Shared avatar upload component.
 * Renders a circular avatar with click-to-upload, drag & drop, compression,
 * square crop, progress indicator, and toast notifications.
 *
 * Usage:
 *   renderAvatarUploader(container, {
 *     avatarUrl, fullName, color,
 *     onUploaded: (newUrl) => { ... },
 *     onProgressChange: (uploading: boolean) => { ... },
 *   });
 */

const ALLOWED_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
const MAX_SIZE = 5 * 1024 * 1024;

let toastRoot;
function showToast(message, type = 'success') {
  if (!toastRoot) {
    toastRoot = document.createElement('div');
    toastRoot.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;';
    document.body.appendChild(toastRoot);
  }
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  toastRoot.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function validateFile(file) {
  const type = file.type.toLowerCase();
  if (!ALLOWED_TYPES.includes(type)) return 'invalid_image_type';
  if (file.size > MAX_SIZE) return 'image_too_large';
  return null;
}

/**
 * Compress + square-crop an image file via canvas.
 * Returns a File ready for upload.
 */
function processImage(file, maxSize = 512, quality = 0.85) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        const size = Math.min(img.width, img.height);
        const sx = (img.width - size) / 2;
        const sy = (img.height - size) / 2;
        const outSize = Math.min(size, maxSize);
        const canvas = document.createElement('canvas');
        canvas.width = outSize;
        canvas.height = outSize;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, sx, sy, size, size, 0, 0, outSize, outSize);
        const outType = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
        canvas.toBlob(
          (blob) => {
            if (blob) {
              const ext = outType === 'image/png' ? 'png' : 'jpg';
              resolve(new File([blob], `avatar.${ext}`, { type: outType }));
            } else {
              reject(new Error('canvas_failed'));
            }
          },
          outType,
          quality
        );
      };
      img.onerror = () => reject(new Error('image_load_failed'));
      img.src = e.target.result;
    };
    reader.onerror = () => reject(new Error('file_read_failed'));
    reader.readAsDataURL(file);
  });
}

/**
 * Render the avatar uploader into a container element.
 * Returns an object with `setAvatar(url)` to update the preview externally.
 */
export function renderAvatarUploader(container, opts) {
  const { avatarUrl, fullName, color = 'green', onUploaded, onProgressChange } = opts;
  const initial = (fullName || '?').slice(0, 1).toUpperCase();

  container.innerHTML = `
    <div class="avatar-uploader">
      <div class="avatar-upload-area" data-avatar-drop>
        <div class="avatar-preview" data-avatar-preview>
          ${avatarUrl
            ? `<img src="${avatarUrl}" alt="${fullName || ''}" />`
            : `<span class="avatar-initial">${initial}</span>`}
        </div>
        <div class="avatar-overlay">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
          <span class="avatar-overlay-text">Change</span>
        </div>
        <input type="file" accept="image/jpeg,image/jpg,image/png,image/webp" data-avatar-input hidden />
      </div>
      <button type="button" class="btn btn-outline btn-sm avatar-change-btn" data-avatar-btn>Change Picture</button>
      <div class="avatar-progress" data-avatar-progress>
        <div class="avatar-progress-bar" data-avatar-bar></div>
      </div>
      <p class="field-hint avatar-hint">JPG, PNG, or WEBP. Max 5 MB.</p>
    </div>
  `;

  const dropArea = container.querySelector('[data-avatar-drop]');
  const fileInput = container.querySelector('[data-avatar-input]');
  const changeBtn = container.querySelector('[data-avatar-btn]');
  const previewEl = container.querySelector('[data-avatar-preview]');
  const progressEl = container.querySelector('[data-avatar-progress]');
  const progressBar = container.querySelector('[data-avatar-bar]');

  function setAvatar(url, name) {
    previewEl.innerHTML = url
      ? `<img src="${url}" alt="${name || ''}" />`
      : `<span class="avatar-initial">${(name || '?').slice(0, 1).toUpperCase()}</span>`;
  }

  function openPicker() { fileInput.click(); }

  dropArea.addEventListener('click', openPicker);
  changeBtn.addEventListener('click', openPicker);

  dropArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropArea.classList.add('dragover');
  });
  dropArea.addEventListener('dragleave', () => dropArea.classList.remove('dragover'));
  dropArea.addEventListener('drop', (e) => {
    e.preventDefault();
    dropArea.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) handleFile(fileInput.files[0]);
    fileInput.value = '';
  });

  async function handleFile(file) {
    const err = validateFile(file);
    if (err) {
      showToast(
        err === 'invalid_image_type' ? 'Only JPG, PNG, and WEBP images are allowed' : 'Image must be under 5 MB',
        'error'
      );
      return;
    }

    let processed;
    try {
      processed = await processImage(file);
    } catch {
      showToast('Failed to process image. Please try another file.', 'error');
      return;
    }

    // Show local preview immediately
    const reader = new FileReader();
    reader.onload = (e) => {
      previewEl.innerHTML = `<img src="${e.target.result}" alt="preview" />`;
    };
    reader.readAsDataURL(processed);

    // Upload
    progressEl.classList.add('active');
    progressBar.style.width = '30%';
    if (onProgressChange) onProgressChange(true);

    try {
      const fd = new FormData();
      fd.append('avatar', processed);
      const res = await fetch('/api/me/avatar', {
        method: 'POST',
        credentials: 'same-origin',
        body: fd,
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw Object.assign(new Error(data.message || data.error || 'Upload failed.'), { code: data.error });
      }
      const data = await res.json();
      if (!data?.user || typeof data.user.avatar_url !== 'string' || !data.user.avatar_url) {
        throw Object.assign(new Error('The server did not return the updated profile picture.'), { code: 'invalid_response' });
      }
      progressBar.style.width = '100%';
      setTimeout(() => {
        progressEl.classList.remove('active');
        progressBar.style.width = '0';
      }, 500);
      setAvatar(data.user.avatar_url, data.user.full_name);
      showToast('Profile picture updated', 'success');
      if (onUploaded) onUploaded(data.user.avatar_url, data.user);
    } catch (err) {
      progressEl.classList.remove('active');
      progressBar.style.width = '0';
      const messages = {
        unauthorized: 'Your session has expired. Please log in again.',
        missing_file: 'Please choose an image first.',
        invalid_image_type: 'Only JPG, JPEG, PNG, and WEBP images are allowed.',
        image_too_large: 'Image must be 5 MB or smaller.',
        storage_upload_failed: err.message || 'Storage rejected the image.',
        profile_update_failed: err.message || 'The profile could not be updated.',
        upload_failed: err.message || 'The image could not be read.',
        invalid_response: err.message,
      };
      showToast(messages[err.code] || err.message || 'Upload failed.', 'error');
    } finally {
      if (onProgressChange) onProgressChange(false);
    }
  }

  return { setAvatar };
}
