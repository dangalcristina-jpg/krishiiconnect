import { t, formatNPR, timeAgo, imageOrPlaceholder, cropImageSrc } from '../scripts/i18n.js';
import { api, errCode } from '../scripts/api.js';
import { currentUser, resetCurrentUser, onLangChange } from '../scripts/shared.js';
import { renderDashboardShell, getDashBody, statCard, quickAction, emptyState, statusBadge } from '../scripts/dashboard.js';
import { renderStatement } from '../scripts/statement.js';
import { fetchReviewsFor, renderReviewList, ratingBadge, openLeaveReviewModal } from '../scripts/reviews.js';
import { renderMyProducts, renderProductForm } from '../scripts/products.js';
import { renderAvatarUploader } from '../scripts/avatar-upload.js';

let me = null;
let tab = 'dashboard';
let crops = [];
let prices = [];
let orders = [];

async function load() {
  const [c, p, o] = await Promise.all([
    api('/crops?status=mine'),
    api('/prices'),
    api('/orders'),
  ]);
  crops = c.crops || [];
  prices = p.prices || [];
  orders = o.orders || [];
}

function tabs() {
  return [
    { key: 'dashboard', label: t('farmer.dashboard'), icon: '📊' },
    { key: 'myProducts', label: 'My Products', icon: '🌾' },
    { key: 'myCrops', label: t('farmer.myCrops'), icon: '🌱' },
    { key: 'addCrop', label: t('farmer.addCrop'), icon: '➕' },
    { key: 'marketPrices', label: t('farmer.marketPrices'), icon: '📈' },
    { key: 'statement', label: t('farmer.statement'), icon: '🧾' },
    { key: 'reviews', label: t('reviews.title'), icon: '⭐' },
    { key: 'profile', label: t('farmer.profile'), icon: '👤' },
  ];
}

function renderDashboard() {
  const activeCrops = crops.filter((c) => c.status === 'approved' || c.status === 'pending').length;
  const completedOrders = orders.filter((o) => o.status === 'completed' && o.crop);
  const earnings = completedOrders
    .reduce((s, o) => s + Number(o.crop.price) * Number(o.quantity), 0);
  const pendingOrders = orders.filter((o) => o.status === 'pending').length;
  const acceptedOrders = orders.filter((o) => o.status === 'accepted').length;

  const body = getDashBody();
  body.innerHTML = `
    <div class="block">
      <div class="stats">
        ${statCard({ label: t('farmer.statActiveCrops'), value: activeCrops, icon: '🌾' })}
        ${statCard({ label: t('farmer.statEarnings'), value: formatNPR(earnings), icon: '💰', color: 'orange' })}
        ${statCard({ label: t('farmer.statPendingOrders'), value: pendingOrders, icon: '⏳' })}
        ${statCard({ label: t('farmer.statAcceptedOrders'), value: acceptedOrders, icon: '✅' })}
      </div>
    </div>
    <div class="block">
      <h3 class="block-title">${t('farmer.quickActions')}</h3>
      <div class="quick-actions" id="quick-actions"></div>
    </div>
    <div class="block">
      <h3 class="block-title">${t('farmer.recentOrders')}</h3>
      <div id="farmer-orders"></div>
    </div>
    <div class="block">
      <h3 class="block-title">${t('farmer.recentActivity')}</h3>
      <div class="activity" id="activity"></div>
    </div>
  `;

  const qa = document.getElementById('quick-actions');
  qa.appendChild(quickAction({ label: t('farmer.actionAddCrop'), icon: '➕', onClick: () => switchTab('addCrop') }));
  qa.appendChild(quickAction({ label: 'My Products', icon: '📦', onClick: () => switchTab('myProducts') }));
  qa.appendChild(quickAction({ label: t('farmer.actionViewCrops'), icon: '🌾', onClick: () => switchTab('myCrops') }));
  qa.appendChild(quickAction({ label: t('farmer.actionCheckPrices'), icon: '📈', onClick: () => switchTab('marketPrices') }));
  qa.appendChild(quickAction({ label: t('farmer.actionUpdateProfile'), icon: '✏️', onClick: () => switchTab('profile') }));

  renderOrdersTable(document.getElementById('farmer-orders'));

  const act = document.getElementById('activity');
  if (crops.length === 0 && orders.length === 0) {
    act.innerHTML = `<div class="activity-item"><span class="text-muted">${t('farmer.activityEmpty')}</span></div>`;
  } else {
    const items = [];
    crops.slice(0, 3).forEach((c) => items.push({ text: t('farmer.activityCropAdded', { name: c.name }), time: c.created_at }));
    orders.slice(0, 3).forEach((o) => items.push({ text: t('farmer.activityInquiry', { name: o.crop?.name ?? '—' }), time: o.created_at }));
    items.sort((a, b) => new Date(b.time) - new Date(a.time));
    act.innerHTML = items.slice(0, 6).map((i) => `
      <div class="activity-item">
        <span>${i.text}</span>
        <span class="activity-time">${timeAgo(i.time)}</span>
      </div>
    `).join('');
  }
}

function renderOrdersTable(el) {
  if (orders.length === 0) {
    el.appendChild(emptyState({ title: t('farmer.noOrders'), cta: '', onCta: null }));
    return;
  }
  el.className = 'table-wrap';
  el.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>${t('farmer.orderCrop')}</th>
          <th>${t('farmer.orderBuyer')}</th>
          <th class="text-right">${t('farmer.orderQty')}</th>
          <th class="text-right">${t('farmer.orderTotal')}</th>
          <th>${t('farmer.orderStatus')}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        ${orders.map((o) => {
          const total = o.crop ? formatNPR(Number(o.crop.price) * Number(o.quantity)) : '—';
          let actions = '';
          if (o.status === 'pending') {
            actions = `
              <button class="btn btn-primary btn-sm" data-accept="${o.id}">${t('farmer.accept')}</button>
              <button class="btn btn-outline btn-sm btn-danger" data-cancel="${o.id}">${t('farmer.reject')}</button>
            `;
          } else if (o.status === 'accepted') {
            actions = `
              <button class="btn btn-primary btn-sm" data-complete="${o.id}">${t('farmer.markCompleted')}</button>
              <button class="btn btn-outline btn-sm btn-danger" data-cancel="${o.id}">${t('farmer.cancel')}</button>
            `;
          }
          return `
            <tr>
              <td class="font-semibold">${o.crop?.name ?? '—'}</td>
              <td class="text-muted">${o.wholesaler?.full_name ?? '—'}</td>
              <td class="text-right">${o.quantity} ${t('common.kg')}</td>
              <td class="text-right font-semibold">${total}</td>
              <td>${statusBadge(o.status)}</td>
              <td><div class="flex gap-2">${actions}</div></td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
  el.querySelectorAll('[data-accept]').forEach((btn) =>
    btn.addEventListener('click', () => updateOrderStatus(btn.dataset.accept, 'accepted'))
  );
  el.querySelectorAll('[data-complete]').forEach((btn) =>
    btn.addEventListener('click', () => updateOrderStatus(btn.dataset.complete, 'completed'))
  );
  el.querySelectorAll('[data-cancel]').forEach((btn) =>
    btn.addEventListener('click', () => updateOrderStatus(btn.dataset.cancel, 'cancelled'))
  );
}

async function updateOrderStatus(orderId, status) {
  try {
    await api(`/orders/${orderId}`, { method: 'PATCH', body: { status } });
    const o = orders.find((x) => x.id === orderId);
    if (o) o.status = status;
    showCropToast(t('farmer.orderUpdated'), 'success');
    renderDashboard();
  } catch {
    showCropToast(t('farmer.orderUpdateFailed'), 'error');
  }
}

function renderMyCrops() {
  const body = getDashBody();
  body.innerHTML = `<h3 class="block-title">${t('farmer.myCropsTitle')}</h3><div id="crops-list"></div>`;
  const list = document.getElementById('crops-list');
  if (crops.length === 0) {
    list.appendChild(emptyState({ title: t('farmer.myCropsEmpty'), cta: t('farmer.myCropsEmptyCta'), onCta: () => switchTab('addCrop') }));
    return;
  }
  list.className = 'crop-grid';
  list.innerHTML = crops.map((c) => {
    const img = c.images && c.images.length ? c.images[0].image_url : null;
    const imgHTML = img
      ? `<img src="${img}" alt="${c.name}" loading="lazy" />`
      : imageOrPlaceholder(cropFilename(c), c.name, 'crop-img');
    return `
    <div class="crop-card">
      <div class="crop-card-img">
        ${imgHTML}
        ${c.images && c.images.length > 1 ? `<span class="img-count">+${c.images.length - 1}</span>` : ''}
      </div>
      <div class="crop-card-body">
        <div class="flex items-center justify-between">
          <h3>${c.name}</h3>
          ${statusBadge(c.status)}
        </div>
        <div class="crop-meta mt-2">
          <div class="crop-meta-row">💰 <span>${formatNPR(c.price)}${t('products.perKg')}</span></div>
          <div class="crop-meta-row">📦 <span>${c.quantity_available} ${t('common.kg')}</span></div>
          ${c.location ? `<div class="crop-meta-row">📍 <span>${c.location}</span></div>` : ''}
        </div>
        <div class="crop-card-actions mt-2">
          <button class="btn btn-outline btn-sm" data-edit="${c.id}">✏️ Edit</button>
          <button class="btn btn-outline btn-sm btn-danger" data-delete="${c.id}">🗑 Delete</button>
        </div>
      </div>
    </div>
  `;
  }).join('');
  list.querySelectorAll('[data-edit]').forEach((btn) =>
    btn.addEventListener('click', () => switchTab('editCrop:' + btn.dataset.edit))
  );
  list.querySelectorAll('[data-delete]').forEach((btn) =>
    btn.addEventListener('click', () => confirmDeleteCrop(btn.dataset.delete))
  );
}

function cropFilename(crop) {
  const name = (crop.name || '').toLowerCase().trim();
  const map = {
    rice: 'rice.svg', 'धान': 'rice.svg', paddy: 'rice.svg',
    tomato: 'tomato.svg', 'टमाटर': 'tomato.svg',
    wheat: 'wheat.svg', 'गहुँ': 'wheat.svg',
    onion: 'onion.svg', 'प्याज': 'onion.svg',
    tea: 'tea.svg', 'चिया': 'tea.svg',
    potato: 'potato.svg', 'आलु': 'potato.svg',
  };
  for (const key of Object.keys(map)) {
    if (name.includes(key)) return map[key];
  }
  return name.replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') + '.svg' || 'crop.svg';
}

function confirmDeleteCrop(cropId) {
  const crop = crops.find((c) => c.id === cropId);
  if (!crop) return;
  showCropConfirmModal({
    title: 'Delete Crop',
    message: `Are you sure you want to delete "${crop.name}"? This will also remove all its images. This action cannot be undone.`,
    confirmLabel: 'Delete',
    danger: true,
    onConfirm: async () => {
      try {
        await api(`/crops/${cropId}`, { method: 'DELETE' });
        crops = crops.filter((c) => c.id !== cropId);
        renderMyCrops();
        showCropToast('Crop deleted successfully', 'success');
      } catch {
        showCropToast('Failed to delete crop', 'error');
      }
    },
  });
}

let cropToastRoot;
function showCropToast(message, type = 'success') {
  if (!cropToastRoot) {
    cropToastRoot = document.createElement('div');
    cropToastRoot.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;';
    document.body.appendChild(cropToastRoot);
  }
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  cropToastRoot.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

let cropConfirmRoot;
function showCropConfirmModal({ title, message, confirmLabel, danger, onConfirm }) {
  if (!cropConfirmRoot) {
    cropConfirmRoot = document.createElement('div');
    document.body.appendChild(cropConfirmRoot);
  }
  cropConfirmRoot.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal" style="max-width:420px;">
        <div class="modal-head">
          <h3>${title}</h3>
          <button class="modal-close" data-close>✕</button>
        </div>
        <div class="modal-body">
          <p class="text-muted">${message}</p>
          <div class="flex gap-2 mt-4">
            <button class="btn btn-outline" style="flex:1" data-close>Cancel</button>
            <button class="btn ${danger ? 'btn-danger-solid' : 'btn-primary'}" style="flex:1" id="crop-confirm-btn">${confirmLabel}</button>
          </div>
        </div>
      </div>
    </div>
  `;
  const close = () => { cropConfirmRoot.innerHTML = ''; };
  cropConfirmRoot.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', close));
  cropConfirmRoot.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) close();
  });
  cropConfirmRoot.querySelector('#crop-confirm-btn').addEventListener('click', async () => {
    cropConfirmRoot.querySelector('#crop-confirm-btn').disabled = true;
    await onConfirm();
    close();
  });
}

const CROP_CATEGORIES = ['Vegetable', 'Grain', 'Fruit', 'Pulse', 'Spice', 'Herb', 'Other'];
const CROP_MAX_IMAGES = 5;
const CROP_MAX_IMAGE_SIZE = 5 * 1024 * 1024;
const CROP_ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

function compressImage(file, maxWidth = 1280, quality = 0.8) {
  return new Promise((resolve) => {
    if (!file.type.startsWith('image/')) return resolve(file);
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        let { width, height } = img;
        if (width > maxWidth) {
          height = Math.round((height * maxWidth) / width);
          width = maxWidth;
        }
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, width, height);
        canvas.toBlob(
          (blob) => {
            if (blob) {
              resolve(new File([blob], file.name, { type: blob.type || file.type }));
            } else resolve(file);
          },
          file.type === 'image/png' ? 'image/png' : 'image/jpeg',
          quality
        );
      };
      img.onerror = () => resolve(file);
      img.src = e.target.result;
    };
    reader.onerror = () => resolve(file);
    reader.readAsDataURL(file);
  });
}

function validateImageFile(file) {
  if (!CROP_ALLOWED_TYPES.includes(file.type)) return 'invalid_image_type';
  if (file.size > CROP_MAX_IMAGE_SIZE) return 'image_too_large';
  return null;
}

function fileToDataURL(file) {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => resolve('');
    reader.readAsDataURL(file);
  });
}

function renderCropForm(productId) {
  const isEdit = !!productId;
  let crop = null;
  const body = getDashBody();
  body.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h3 class="block-title" style="margin:0;">${isEdit ? 'Edit Crop' : t('farmer.addCropTitle')}</h3>
      <button id="crop-form-cancel" class="btn btn-outline btn-sm">← Back</button>
    </div>
    <div style="max-width:640px;">
      <form id="crop-form" class="card card-pad form">
        <div class="form-row two">
          <div class="field">
            <label>${t('farmer.cropName')} *</label>
            <input name="name" id="crop-name" required />
          </div>
          <div class="field">
            <label>${t('farmer.cropCategory')}</label>
            <select name="category" id="crop-category">
              ${CROP_CATEGORIES.map((c) => `<option value="${c}">${c}</option>`).join('')}
            </select>
          </div>
          <div class="field">
            <label>${t('farmer.cropQty')} *</label>
            <input name="quantity_available" id="crop-qty" type="number" min="0" inputmode="numeric" required />
          </div>
          <div class="field">
            <label>${t('farmer.cropPrice')} *</label>
            <input name="price" id="crop-price" type="number" min="0" inputmode="numeric" required />
          </div>
          <div class="field">
            <label>${t('farmer.cropHarvest')}</label>
            <input name="harvest_date" id="crop-harvest" type="date" />
          </div>
          <div class="field">
            <label>${t('farmer.cropLocation')} *</label>
            <input name="location" id="crop-location" required />
          </div>
        </div>
        <div class="field">
          <label>${t('farmer.cropDescription')}</label>
          <textarea name="description" id="crop-desc" rows="4"></textarea>
        </div>
        <div class="field">
          <label>Product Images *</label>
          <p class="field-hint">Up to ${CROP_MAX_IMAGES} images. JPG, PNG, or WEBP. Max 5 MB each.</p>
          <div class="dropzone" id="crop-dropzone">
            <div class="dropzone-icon">📷</div>
            <div class="dropzone-text">Drag & drop images here, or click to browse</div>
            <div class="dropzone-hint">JPG, PNG, WEBP — up to 5 MB each</div>
            <input type="file" id="crop-image-input" accept="image/jpeg,image/png,image/webp" multiple />
          </div>
          <div class="upload-progress" id="crop-upload-progress">
            <div class="upload-progress-bar" id="crop-upload-bar"></div>
          </div>
          <div class="image-preview-grid" id="crop-image-preview"></div>
        </div>
        ${isEdit ? `
          <div class="field" id="existing-crop-images-field">
            <label>Current Images (click to remove)</label>
            <div id="existing-crop-images" class="image-preview-grid"></div>
          </div>
        ` : ''}
        <p id="crop-form-error" class="form-error" style="display:none;"></p>
        <div class="flex gap-2 mt-2">
          <button type="submit" class="btn btn-primary" id="crop-form-submit">${isEdit ? 'Save Changes' : t('farmer.addCropSubmit')}</button>
          <button type="button" id="crop-form-cancel-btn" class="btn btn-outline">Cancel</button>
        </div>
      </form>
    </div>
  `;

  body.querySelector('#crop-form-cancel').addEventListener('click', () => switchTab('myCrops'));
  body.querySelector('#crop-form-cancel-btn').addEventListener('click', () => switchTab('myCrops'));

  const form = body.querySelector('#crop-form');
  const errorEl = body.querySelector('#crop-form-error');
  const submitBtn = body.querySelector('#crop-form-submit');
  const dropzone = body.querySelector('#crop-dropzone');
  const imageInput = body.querySelector('#crop-image-input');
  const previewEl = body.querySelector('#crop-image-preview');
  const progressEl = body.querySelector('#crop-upload-progress');
  const progressBar = body.querySelector('#crop-upload-bar');
  let selectedFiles = [];
  let removeIds = [];

  // If editing, load the crop data
  if (isEdit) {
    (async () => {
      try {
        const data = await api(`/crops/${productId}`);
        crop = data.crop;
        body.querySelector('#crop-name').value = crop.name || '';
        body.querySelector('#crop-category').value = crop.category || 'Vegetable';
        body.querySelector('#crop-qty').value = crop.quantity_available || '';
        body.querySelector('#crop-price').value = crop.price || '';
        body.querySelector('#crop-harvest').value = crop.harvest_date || '';
        body.querySelector('#crop-location').value = crop.location || '';
        body.querySelector('#crop-desc').value = crop.description || '';
        if (crop.images && crop.images.length) {
          const existingEl = body.querySelector('#existing-crop-images');
          existingEl.innerHTML = crop.images.map((img) => `
            <div class="image-preview-item" data-img-id="${img.id}">
              <img src="${img.image_url}" alt="" loading="lazy" />
              <button type="button" class="image-remove-btn" data-remove="${img.id}">✕</button>
            </div>
          `).join('');
          existingEl.querySelectorAll('[data-remove]').forEach((btn) => {
            btn.addEventListener('click', () => {
              removeIds.push(btn.dataset.remove);
              existingEl.querySelector(`[data-img-id="${btn.dataset.remove}"]`).remove();
            });
          });
        }
      } catch {
        showCropToast('Failed to load crop', 'error');
        switchTab('myCrops');
      }
    })();
  }

  // Dropzone click + drag events
  dropzone.addEventListener('click', () => imageInput.click());
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    handleFiles(Array.from(e.dataTransfer.files));
  });
  imageInput.addEventListener('change', () => {
    handleFiles(Array.from(imageInput.files));
    imageInput.value = '';
  });

  async function handleFiles(newFiles) {
    for (const file of newFiles) {
      const err = validateImageFile(file);
      if (err) {
        showCropToast(err === 'invalid_image_type' ? 'Only JPG, PNG, and WEBP images are allowed' : 'Image must be under 5 MB', 'error');
        continue;
      }
      if (selectedFiles.length >= CROP_MAX_IMAGES) {
        showCropToast(`Maximum ${CROP_MAX_IMAGES} images allowed`, 'error');
        break;
      }
      selectedFiles.push(file);
      const preview = await fileToDataURL(file);
      const item = document.createElement('div');
      item.className = 'image-preview-item';
      item.innerHTML = `<img src="${preview}" alt="" /><button type="button" class="image-remove-btn" data-idx="${selectedFiles.length - 1}">✕</button>`;
      item.querySelector('[data-idx]').addEventListener('click', () => {
        const idx = Number(item.querySelector('[data-idx]').dataset.idx);
        selectedFiles.splice(idx, 1);
        item.remove();
      });
      previewEl.appendChild(item);
    }
  }

  // Submit
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorEl.style.display = 'none';

    const name = body.querySelector('#crop-name').value.trim();
    const price = Number(body.querySelector('#crop-price').value);
    const quantity_available = Number(body.querySelector('#crop-qty').value);
    const location = body.querySelector('#crop-location').value.trim();

    if (!name) return cropSetError('Crop name is required');
    if (!price || price <= 0) return cropSetError('Price must be greater than 0');
    if (!quantity_available || quantity_available < 0) return cropSetError('Quantity must be 0 or greater');
    if (!location) return cropSetError('Location is required');

    submitBtn.disabled = true;
    submitBtn.textContent = 'Uploading...';
    progressEl.classList.add('active');
    progressBar.style.width = '10%';

    try {
      const fd = new FormData();
      fd.append('name', name);
      fd.append('category', body.querySelector('#crop-category').value);
      fd.append('price', String(price));
      fd.append('quantity_available', String(quantity_available));
      fd.append('location', location);
      fd.append('harvest_date', body.querySelector('#crop-harvest').value);
      fd.append('description', body.querySelector('#crop-desc').value);
      for (const file of selectedFiles) {
        const compressed = await compressImage(file);
        fd.append('images', compressed);
      }
      if (isEdit && removeIds.length) {
        fd.append('remove_images', JSON.stringify(removeIds));
      }

      progressBar.style.width = '50%';
      const url = isEdit ? `/api/crops/${productId}` : '/api/crops';
      const res = await fetch(url, {
        method: isEdit ? 'PATCH' : 'POST',
        credentials: 'same-origin',
        body: fd,
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw Object.assign(new Error(data.error || 'server_error'), { code: data.error });
      }
      progressBar.style.width = '100%';
      showCropToast(isEdit ? 'Crop updated successfully' : 'Crop added successfully', 'success');
      await load();
      setTimeout(() => switchTab('myCrops'), 600);
    } catch (err) {
      const code = errCode(err);
      const msg = {
        'too_many_images': `Maximum ${CROP_MAX_IMAGES} images allowed`,
        'invalid_image_type': 'Only JPG, PNG, and WEBP images are allowed',
        'image_too_large': 'Image must be under 5 MB',
        'missing_fields': 'Please fill in all required fields',
      }[code] || 'Failed to save crop. Please try again.';
      cropSetError(msg);
      submitBtn.disabled = false;
      submitBtn.textContent = isEdit ? 'Save Changes' : t('farmer.addCropSubmit');
      progressEl.classList.remove('active');
      progressBar.style.width = '0';
    }
  });

  function cropSetError(msg) {
    errorEl.textContent = msg;
    errorEl.style.display = 'block';
  }
}

function renderMarketPrices() {
  const body = getDashBody();
  body.innerHTML = `<h3 class="block-title">${t('farmer.marketPrices')}</h3><div id="prices"></div>`;
  const el = document.getElementById('prices');
  if (prices.length === 0) {
    el.innerHTML = `<div class="empty">${t('prices.empty')}</div>`;
    return;
  }
  el.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>${t('prices.product')}</th>
            <th>${t('prices.unit')}</th>
            <th class="text-right">${t('prices.min')}</th>
            <th class="text-right">${t('prices.max')}</th>
            <th class="text-right">${t('prices.avg')}</th>
            <th>${t('prices.trend')}</th>
            <th>${t('farmer.yourPrice')}</th>
          </tr>
        </thead>
        <tbody>
          ${prices.map((r) => {
            const mine = crops.find((c) => c.name.toLowerCase() === r.product.toLowerCase());
            const yourCell = mine
              ? `<span class="font-semibold ${Number(mine.price) > Number(r.avg_price) ? 'text-amber-600' : Number(mine.price) < Number(r.avg_price) ? 'text-green-600' : ''}" style="${Number(mine.price) > Number(r.avg_price) ? 'color:#b45309;' : Number(mine.price) < Number(r.avg_price) ? 'color:#166534;' : ''}">${formatNPR(mine.price)}</span>`
              : `<span class="text-muted text-xs">${t('farmer.notListed')}</span>`;
            const trendIcon = r.trend === 'up' ? '↑' : r.trend === 'down' ? '↓' : '→';
            const trendCls = r.trend === 'up' ? 'trend-up' : r.trend === 'down' ? 'trend-down' : 'trend-stable';
            return `
              <tr>
                <td class="font-semibold">${r.product}</td>
                <td class="text-muted">${r.unit}</td>
                <td class="text-right">${formatNPR(r.min_price)}</td>
                <td class="text-right">${formatNPR(r.max_price)}</td>
                <td class="text-right font-semibold">${formatNPR(r.avg_price)}</td>
                <td><span class="trend ${trendCls}">${trendIcon} ${t('trend.' + r.trend)}</span></td>
                <td>${yourCell}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderProfile() {
  const body = getDashBody();
  const memberSince = new Date(me.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
  body.innerHTML = `
    <h3 class="block-title">${t('farmer.profileTitle')}</h3>
    <div style="max-width:640px;">
      <div class="profile-card-view card card-pad">
        <div class="profile-card-top">
          <div id="avatar-slot"></div>
          <div class="profile-card-info">
            <h2 class="profile-card-name">${me.full_name || '—'}</h2>
            <div class="profile-card-role">
              <span class="badge badge-green">${t('farmer.role')}</span>
            </div>
            <div class="profile-card-meta">
              <div class="profile-meta-row">📱 <span>${me.phone || '—'}</span></div>
              <div class="profile-meta-row">📅 <span>${memberSince}</span></div>
            </div>
          </div>
        </div>
        <button type="button" class="btn btn-primary" id="edit-profile-btn">${t('farmer.editProfile') || 'Edit Profile'}</button>
      </div>

      <form id="profile-form" class="card card-pad form" style="display:none;margin-top:16px;">
        <div class="profile-edit-avatar">
          <div id="avatar-edit-slot"></div>
        </div>
        <div class="form-row two">
          <div class="field">
            <label>${t('farmer.fullName')}</label>
            <input name="full_name" required value="${me.full_name || ''}" />
          </div>
          <div class="field">
            <label>${t('farmer.phone')}</label>
            <input name="phone" type="tel" inputmode="numeric" value="${me.phone || ''}" disabled />
          </div>
          <div class="field">
            <label>${t('farmer.farmLocation')}</label>
            <input name="farm_location" value="${me.farm_location || ''}" />
          </div>
          <div class="field">
            <label>${t('farmer.yearsExperience')}</label>
            <input name="years_experience" type="number" min="0" inputmode="numeric" value="${me.years_experience ?? ''}" />
          </div>
        </div>
        <div class="field">
          <label>${t('farmer.aboutFarm')}</label>
          <textarea name="about_farm" rows="4">${me.about_farm || ''}</textarea>
        </div>
        <p id="profile-saved" class="form-success" style="display:none;">${t('farmer.profileSaved')}</p>
        <div class="flex gap-2">
          <button type="submit" class="btn btn-primary" id="profile-save-btn">${t('farmer.save')}</button>
          <button type="button" id="cancel-btn" class="btn btn-outline">${t('farmer.cancel') || 'Cancel'}</button>
        </div>
      </form>
    </div>
  `;

  // Render avatar in view mode
  const viewSlot = document.getElementById('avatar-slot');
  viewSlot.innerHTML = `
    <div class="avatar large green">
      ${me.avatar_url ? `<img src="${me.avatar_url}" alt="${me.full_name || ''}" />` : `<span>${(me.full_name || '?').slice(0, 1)}</span>`}
    </div>
  `;

  // Edit button
  document.getElementById('edit-profile-btn').addEventListener('click', () => {
    document.querySelector('.profile-card-view').style.display = 'none';
    const form = document.getElementById('profile-form');
    form.style.display = 'block';

    // Render avatar uploader in edit mode
    const editSlot = document.getElementById('avatar-edit-slot');
    let avatarUploader;
    import('../scripts/avatar-upload.js').then(({ renderAvatarUploader }) => {
      avatarUploader = renderAvatarUploader(editSlot, {
        avatarUrl: me.avatar_url,
        fullName: me.full_name,
        color: 'green',
        onUploaded: (newUrl) => {
          me.avatar_url = newUrl;
          resetCurrentUser();
          // Update view-mode avatar
          viewSlot.innerHTML = `<div class="avatar large green"><img src="${newUrl}" alt="${me.full_name || ''}" /></div>`;
        },
        onProgressChange: (uploading) => {
          document.getElementById('profile-save-btn').disabled = uploading;
        },
      });
    });
  });

  // Cancel
  document.getElementById('cancel-btn').addEventListener('click', () => {
    document.querySelector('.profile-card-view').style.display = 'block';
    document.getElementById('profile-form').style.display = 'none';
  });

  // Save (only text fields — avatar handled separately)
  const form = document.getElementById('profile-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const patchBody = {};
    for (const [k, v] of fd.entries()) {
      if (k === 'phone') continue; // phone is disabled, don't send
      patchBody[k] = v;
    }
    try {
      const data = await api('/me', { method: 'PATCH', body: patchBody });
      me = data.user;
      resetCurrentUser();
      document.getElementById('profile-saved').style.display = 'block';
      setTimeout(() => {
        document.getElementById('profile-saved').style.display = 'none';
        document.querySelector('.profile-card-view').style.display = 'block';
        document.getElementById('profile-form').style.display = 'none';
        renderProfile();
      }, 1000);
    } catch {
      // ignore
    }
  });
}

function switchTab(k) {
  tab = k;
  document.querySelectorAll('[data-tab]').forEach((b) => b.classList.toggle('active', b.dataset.tab === k));
  if (k === 'dashboard') renderDashboard();
  else if (k === 'myProducts') renderMyProducts(getDashBody(), (productId) => {
    if (productId) {
      switchTab('editProduct:' + productId);
    } else {
      switchTab('addProduct');
    }
  }, () => switchTab('addProduct'));
  else if (k === 'myCrops') renderMyCrops();
  else if (k === 'addCrop') renderCropForm(null);
  else if (k.startsWith('editCrop:')) renderCropForm(k.split(':')[1]);
  else if (k === 'marketPrices') renderMarketPrices();
  else if (k === 'statement') renderStatement(getDashBody(), 'farmer');
  else if (k === 'reviews') renderReviews();
  else if (k === 'profile') renderProfile();
  else if (k === 'addProduct') renderProductForm(getDashBody(), null, () => switchTab('myProducts'));
  else if (k.startsWith('editProduct:')) renderProductForm(getDashBody(), k.split(':')[1], () => switchTab('myProducts'));
}

async function renderReviews() {
  const body = getDashBody();
  body.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h3 class="block-title" style="margin:0;">${t('reviews.aboutYou')}</h3>
      <button id="rev-add" class="btn btn-primary btn-sm">⭐ ${t('reviews.leaveReview')}</button>
    </div>
    <div id="rev-summary"></div>
    <div id="rev-list-mount"></div>
  `;
  body.querySelector('#rev-add').addEventListener('click', () => openLeaveReviewModal({ onDone: renderReviews }));
  const { reviews, average, count } = await fetchReviewsFor(me.id);
  body.querySelector('#rev-summary').innerHTML = ratingBadge({ average, count });
  renderReviewList(body.querySelector('#rev-list-mount'), reviews, { heading: '' });
}

async function init() {
  resetCurrentUser();
  me = await currentUser();
  if (!me) {
    window.location.href = '/login';
    return;
  }
  if (me.role !== 'farmer') {
    window.location.href = me.role === 'admin' ? '/admin' : '/wholesaler';
    return;
  }
  await load();
  await renderDashboardShell({
    role: 'farmer',
    active: tab,
    welcome: t('farmer.welcome', { name: me.full_name }),
    tabs: tabs(),
    onTab: switchTab,
  });
  switchTab(tab);

  onLangChange(async () => {
    await renderDashboardShell({
      role: 'farmer',
      active: tab,
      welcome: t('farmer.welcome', { name: me.full_name }),
      tabs: tabs(),
      onTab: switchTab,
    });
    switchTab(tab);
  });
}

init();
