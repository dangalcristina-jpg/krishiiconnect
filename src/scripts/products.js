import { t, formatNPR, timeAgo } from './i18n.js';
import { api, errCode } from './api.js';
import { emptyState, statusBadge } from './dashboard.js';

// ---------- State ----------
let products = [];
let loading = false;

// ---------- Constants ----------
const CATEGORIES = ['Vegetables', 'Fruits', 'Grains', 'Dairy', 'Herbs', 'Spices', 'Pulses', 'Others'];
const UNITS = ['kg', 'ton', 'sack', 'crate', 'dozen', 'liter'];
const AVAILABILITY = ['Available', 'Limited Stock', 'Sold Out'];
const MAX_IMAGES = 5;
const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

// ---------- Toast ----------
let toastRoot;
function showToast(message, type = 'success') {
  if (!toastRoot) {
    toastRoot = document.createElement('div');
    toastRoot.id = 'toast-root';
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

// ---------- API helpers ----------
async function fetchProducts() {
  const data = await api('/products?mine=true');
  return data.products || [];
}

async function createProduct(formData) {
  const res = await fetch('/api/products', {
    method: 'POST',
    credentials: 'same-origin',
    body: formData,
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw Object.assign(new Error(data.error || 'server_error'), { code: data.error });
  }
  return res.json();
}

async function updateProduct(id, formData) {
  const res = await fetch(`/api/products/${id}`, {
    method: 'PATCH',
    credentials: 'same-origin',
    body: formData,
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw Object.assign(new Error(data.error || 'server_error'), { code: data.error });
  }
  return res.json();
}

async function deleteProduct(id) {
  return api(`/products/${id}`, { method: 'DELETE' });
}

// ---------- Image helpers ----------
function compressImage(file, maxWidth = 1280, quality = 0.8) {
  return new Promise((resolve, reject) => {
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
              const compressed = new File([blob], file.name, { type: blob.type || file.type });
              resolve(compressed);
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
  if (!ALLOWED_TYPES.includes(file.type)) return 'invalid_image_type';
  if (file.size > MAX_IMAGE_SIZE) return 'image_too_large';
  return null;
}

// ---------- Availability badge ----------
function availabilityBadge(status) {
  const cls = { 'Available': 'badge-green', 'Limited Stock': 'badge-amber', 'Sold Out': 'badge-gray' }[status] || 'badge-gray';
  return `<span class="badge ${cls}">${status}</span>`;
}

// ---------- My Products list ----------
export async function renderMyProducts(bodyEl, onEdit, onAddNew) {
  bodyEl.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h3 class="block-title" style="margin:0;">My Products</h3>
      <button id="add-product-btn" class="btn btn-primary btn-sm">+ Add Product</button>
    </div>
    <div id="products-container"></div>
  `;
  bodyEl.querySelector('#add-product-btn').addEventListener('click', onAddNew);

  const container = bodyEl.querySelector('#products-container');
  container.innerHTML = renderSkeletons(4);

  try {
    products = await fetchProducts();
    renderProductCards(container, onEdit);
  } catch (err) {
    container.innerHTML = `<div class="empty"><p>Failed to load products. Please try again.</p></div>`;
  }
}

function renderSkeletons(count) {
  return `<div class="crop-grid">${Array.from({ length: count }).map(() => `
    <div class="crop-card skeleton-card">
      <div class="skeleton skeleton-img"></div>
      <div class="crop-card-body">
        <div class="skeleton skeleton-line w-60"></div>
        <div class="skeleton skeleton-line w-40"></div>
        <div class="skeleton skeleton-line w-80"></div>
      </div>
    </div>
  `).join('')}</div>`;
}

function renderProductCards(container, onEdit) {
  if (products.length === 0) {
    container.innerHTML = '';
    container.appendChild(emptyState({
      title: 'You haven\'t added any products yet.',
      cta: '+ Add Your First Product',
      onCta: () => onEdit(),
    }));
    return;
  }
  container.className = 'crop-grid';
  container.innerHTML = products.map(productCard).join('');
  container.querySelectorAll('[data-edit]').forEach((btn) =>
    btn.addEventListener('click', () => onEdit(btn.dataset.edit))
  );
  container.querySelectorAll('[data-delete]').forEach((btn) =>
    btn.addEventListener('click', () => confirmDelete(btn.dataset.delete, container, onEdit))
  );
}

function productCard(p) {
  const img = p.images && p.images.length ? p.images[0].image_url : null;
  const imgHTML = img
    ? `<img src="${img}" alt="${p.product_name}" loading="lazy" />`
    : `<div class="crop-img-placeholder">🖼️</div>`;
  const extraImgs = p.images && p.images.length > 1 ? `<span class="img-count">+${p.images.length - 1}</span>` : '';
  return `
    <div class="crop-card product-card">
      <div class="crop-card-img">
        ${imgHTML}
        ${extraImgs}
        <div class="product-card-badges">
          ${availabilityBadge(p.availability)}
        </div>
      </div>
      <div class="crop-card-body">
        <h3>${p.product_name}</h3>
        <div class="crop-meta">
          <div class="crop-meta-row">🏷️ <span>${p.category}</span></div>
          <div class="crop-meta-row">💰 <span>${formatNPR(p.price)} / ${p.unit}</span></div>
          <div class="crop-meta-row">📦 <span>${p.quantity} ${p.unit}${p.quantity !== 1 ? 's' : ''}</span></div>
          <div class="crop-meta-row">📍 <span>${p.district}${p.municipality ? ', ' + p.municipality : ''}</span></div>
          <div class="crop-meta-row">📅 <span>${timeAgo(p.created_at)}</span></div>
        </div>
        <div class="crop-card-actions">
          <button class="btn btn-outline btn-sm" data-edit="${p.id}">✏️ Edit</button>
          <button class="btn btn-outline btn-sm btn-danger" data-delete="${p.id}">🗑 Delete</button>
        </div>
      </div>
    </div>
  `;
}

// ---------- Delete confirmation ----------
async function confirmDelete(productId, container, onEdit) {
  const product = products.find((p) => p.id === productId);
  if (!product) return;
  showConfirmModal({
    title: 'Delete Product',
    message: `Are you sure you want to delete "${product.product_name}"? This will also remove all its images. This action cannot be undone.`,
    confirmLabel: 'Delete',
    danger: true,
    onConfirm: async () => {
      try {
        await deleteProduct(productId);
        products = products.filter((p) => p.id !== productId);
        renderProductCards(container, onEdit);
        showToast('Product deleted successfully', 'success');
      } catch (err) {
        showToast('Failed to delete product', 'error');
      }
    },
  });
}

// ---------- Add/Edit form ----------
export async function renderProductForm(bodyEl, productId, onDone) {
  let product = null;
  if (productId) {
    try {
      const data = await api(`/products/${productId}`);
      product = data.product;
    } catch {
      showToast('Failed to load product', 'error');
      onDone();
      return;
    }
  }

  const isEdit = !!product;
  bodyEl.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h3 class="block-title" style="margin:0;">${isEdit ? 'Edit Product' : 'Add Product'}</h3>
      <button id="form-cancel" class="btn btn-outline btn-sm">← Back</button>
    </div>
    <div style="max-width:640px;">
      <form id="product-form" class="card card-pad form" enctype="multipart/form-data">
        <div class="form-row two">
          <div class="field">
            <label>Product Name *</label>
            <input name="product_name" required value="${product?.product_name || ''}" />
          </div>
          <div class="field">
            <label>Category *</label>
            <select name="category" required>
              ${CATEGORIES.map((c) => `<option value="${c}" ${product?.category === c ? 'selected' : ''}>${c}</option>`).join('')}
            </select>
          </div>
        </div>
        <div class="field">
          <label>Description</label>
          <textarea name="description" rows="3">${product?.description || ''}</textarea>
        </div>
        <div class="form-row three">
          <div class="field">
            <label>Price (रु) *</label>
            <input name="price" type="number" min="0.01" step="0.01" inputmode="decimal" required value="${product?.price || ''}" />
          </div>
          <div class="field">
            <label>Quantity *</label>
            <input name="quantity" type="number" min="0" step="0.01" inputmode="decimal" required value="${product?.quantity || ''}" />
          </div>
          <div class="field">
            <label>Unit *</label>
            <select name="unit" required>
              ${UNITS.map((u) => `<option value="${u}" ${product?.unit === u ? 'selected' : ''}>${u}</option>`).join('')}
            </select>
          </div>
        </div>
        <div class="form-row two">
          <div class="field">
            <label>District *</label>
            <input name="district" required value="${product?.district || ''}" />
          </div>
          <div class="field">
            <label>Municipality</label>
            <input name="municipality" value="${product?.municipality || ''}" />
          </div>
        </div>
        <div class="form-row two">
          <div class="field">
            <label>Harvest Date</label>
            <input name="harvest_date" type="date" value="${product?.harvest_date || ''}" />
          </div>
          <div class="field">
            <label>Availability</label>
            <select name="availability">
              ${AVAILABILITY.map((a) => `<option value="${a}" ${product?.availability === a ? 'selected' : ''}>${a}</option>`).join('')}
            </select>
          </div>
        </div>
        <div class="field">
          <label>Product Images ${isEdit ? '(add new)' : ''}</label>
          <p class="field-hint">Up to ${MAX_IMAGES} images. JPG, PNG, or WEBP. Max 5 MB each.</p>
          <input id="image-input" name="images" type="file" accept="image/jpeg,image/png,image/webp" multiple />
          <div id="image-preview" class="image-preview-grid"></div>
        </div>
        ${isEdit ? `
          <div class="field" id="existing-images-field">
            <label>Current Images (click to remove)</label>
            <div id="existing-images" class="image-preview-grid"></div>
          </div>
        ` : ''}
        <p id="form-error" class="form-error" style="display:none;"></p>
        <div class="flex gap-2 mt-2">
          <button type="submit" class="btn btn-primary" id="form-submit">${isEdit ? 'Save Changes' : 'Add Product'}</button>
          <button type="button" id="form-cancel-btn" class="btn btn-outline">Cancel</button>
        </div>
      </form>
    </div>
  `;

  const form = bodyEl.querySelector('#product-form');
  const errorEl = bodyEl.querySelector('#form-error');
  const submitBtn = bodyEl.querySelector('#form-submit');
  const imageInput = bodyEl.querySelector('#image-input');
  const previewEl = bodyEl.querySelector('#image-preview');
  let selectedFiles = [];
  let removeIds = [];

  // Existing images (edit mode)
  if (isEdit && product.images && product.images.length) {
    const existingEl = bodyEl.querySelector('#existing-images');
    existingEl.innerHTML = product.images.map((img) => `
      <div class="image-preview-item" data-img-id="${img.id}">
        <img src="${img.image_url}" alt="" loading="lazy" />
        <button type="button" class="image-remove-btn" data-remove="${img.id}">✕</button>
      </div>
    `).join('');
    existingEl.querySelectorAll('[data-remove]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.remove;
        removeIds.push(id);
        const item = existingEl.querySelector(`[data-img-id="${id}"]`);
        if (item) item.remove();
      });
    });
  }

  // New image selection + preview
  imageInput.addEventListener('change', async () => {
    const newFiles = Array.from(imageInput.files);
    for (const file of newFiles) {
      const err = validateImageFile(file);
      if (err) {
        showToast(err === 'invalid_image_type' ? 'Only JPG, PNG, and WEBP images are allowed' : 'Image must be under 5 MB', 'error');
        continue;
      }
      if (selectedFiles.length >= MAX_IMAGES) {
        showToast(`Maximum ${MAX_IMAGES} images allowed`, 'error');
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
    imageInput.value = '';
  });

  // Cancel
  bodyEl.querySelector('#form-cancel').addEventListener('click', onDone);
  bodyEl.querySelector('#form-cancel-btn').addEventListener('click', onDone);

  // Submit
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorEl.style.display = 'none';

    const fd = new FormData(form);
    // Basic validation
    const price = Number(fd.get('price'));
    const quantity = Number(fd.get('quantity'));
    if (!fd.get('product_name')?.trim()) return setError('Product name is required');
    if (!fd.get('category')) return setError('Category is required');
    if (!price || price <= 0) return setError('Price must be greater than 0');
    if (quantity < 0 || isNaN(quantity)) return setError('Quantity must be 0 or greater');
    if (!fd.get('district')?.trim()) return setError('District is required');

    // Compress and append images
    submitBtn.disabled = true;
    submitBtn.textContent = 'Uploading...';
    try {
      for (const file of selectedFiles) {
        const compressed = await compressImage(file);
        fd.append('images', compressed);
      }
      if (isEdit && removeIds.length) {
        fd.append('remove_images', JSON.stringify(removeIds));
      }

      if (isEdit) {
        await updateProduct(product.id, fd);
        showToast('Product updated successfully', 'success');
      } else {
        await createProduct(fd);
        showToast('Product added successfully', 'success');
      }
      onDone();
    } catch (err) {
      const code = errCode(err);
      const msg = {
        'too_many_images': `Maximum ${MAX_IMAGES} images allowed`,
        'invalid_image_type': 'Only JPG, PNG, and WEBP images are allowed',
        'image_too_large': 'Image must be under 5 MB',
        'invalid_price': 'Price must be greater than 0',
        'invalid_quantity': 'Quantity must be 0 or greater',
        'invalid_category': 'Invalid category',
        'invalid_unit': 'Invalid unit',
        'invalid_availability': 'Invalid availability',
        'missing_name': 'Product name is required',
        'missing_district': 'District is required',
      }[code] || 'Failed to save product. Please try again.';
      setError(msg);
      submitBtn.disabled = false;
      submitBtn.textContent = isEdit ? 'Save Changes' : 'Add Product';
    }
  });

  function setError(msg) {
    errorEl.textContent = msg;
    errorEl.style.display = 'block';
  }
}

function fileToDataURL(file) {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => resolve('');
    reader.readAsDataURL(file);
  });
}

// ---------- Confirm modal ----------
let confirmRoot;
function showConfirmModal({ title, message, confirmLabel, danger, onConfirm }) {
  if (!confirmRoot) {
    confirmRoot = document.createElement('div');
    confirmRoot.id = 'confirm-root';
    document.body.appendChild(confirmRoot);
  }
  confirmRoot.innerHTML = `
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
            <button class="btn ${danger ? 'btn-danger-solid' : 'btn-primary'}" style="flex:1" id="confirm-btn">${confirmLabel}</button>
          </div>
        </div>
      </div>
    </div>
  `;
  const close = () => { confirmRoot.innerHTML = ''; };
  confirmRoot.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', close));
  confirmRoot.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) close();
  });
  confirmRoot.querySelector('#confirm-btn').addEventListener('click', async () => {
    confirmRoot.querySelector('#confirm-btn').disabled = true;
    await onConfirm();
    close();
  });
}

// ---------- Export for dashboard integration ----------
export { CATEGORIES, UNITS, AVAILABILITY };
