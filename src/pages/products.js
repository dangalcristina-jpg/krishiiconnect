import { t, imageOrPlaceholder, cropImageSrc, formatNPR } from '../scripts/i18n.js';
import { api } from '../scripts/api.js';
import { renderNavbar, renderFooter, currentUser, resetCurrentUser, onLangChange } from '../scripts/shared.js';

function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
}

function cropCardHTML(crop) {
  const img = cropImageSrc(crop);
  const imgHTML = img.kind === 'url'
    ? `<img src="${img.src}" alt="${crop.name}" loading="lazy" />`
    : imageOrPlaceholder(img.file, crop.name, 'crop-img');
  return `
    <div class="crop-card">
      <div class="crop-card-img">
        ${imgHTML}
        <div class="crop-price">${formatNPR(crop.price)}${t('products.perKg')}</div>
      </div>
      <div class="crop-card-body">
        <h3>${crop.name}</h3>
        <div class="crop-meta">
          <div class="crop-meta-row">👤 <span>${crop.farmer?.full_name || t('products.farmer')}</span></div>
          <div class="crop-meta-row">📦 <span>${crop.quantity_available} ${t('common.kg')} ${t('products.available').toLowerCase()}</span></div>
          ${crop.location ? `<div class="crop-meta-row">📍 <span>${crop.location}</span></div>` : ''}
        </div>
        <div class="crop-card-actions">
          <button class="btn btn-primary btn-block" data-contact="${crop.id}">${t('products.contact')}</button>
        </div>
      </div>
    </div>
  `;
}

async function renderCrops() {
  const el = document.getElementById('crop-grid');
  if (!el) return;
  el.innerHTML = Array(8).fill('<div class="skeleton"></div>').join('');
  try {
    const data = await api('/crops?status=approved');
    const crops = data.crops || [];
    if (crops.length === 0) {
      el.innerHTML = `<p class="text-muted">${t('products.empty')}</p>`;
      return;
    }
    el.innerHTML = crops.map(cropCardHTML).join('');
    el.querySelectorAll('[data-contact]').forEach((btn) =>
      btn.addEventListener('click', () => openContactModal(btn.dataset.contact))
    );
  } catch {
    el.innerHTML = `<p class="text-muted">${t('common.error')}</p>`;
  }
}

async function openContactModal(cropId) {
  const me = await currentUser();
  if (!me) {
    showModal({ body: `<p class="text-muted">${t('contactModal.loginRequired')}</p>
      <div class="flex gap-2 mt-4">
        <a href="/login" class="btn btn-primary" style="flex:1">${t('contactModal.login')}</a>
        <a href="/register" class="btn btn-outline" style="flex:1">${t('contactModal.register')}</a>
      </div>` });
    return;
  }
  if (me.role !== 'wholesaler') {
    showModal({ body: `<p class="text-muted">${t('contactModal.wrongRole')}</p>` });
    return;
  }
  let crop = null;
  try {
    const data = await api('/crops?status=approved');
    crop = (data.crops || []).find((c) => c.id === cropId);
  } catch {}
  if (!crop) return;
  showModal({
    body: `
      <p class="text-muted mb-4">${t('contactModal.subtitle')}</p>
      <div class="card card-pad mb-4">
        <div style="display:flex;align-items:center;gap:12px;">
          <div style="width:48px;height:48px;border-radius:8px;background:var(--green-100);color:var(--green-dark);display:grid;place-items:center;font-weight:600;">${crop.name.slice(0, 1)}</div>
          <div>
            <div class="font-semibold">${crop.name}</div>
            <div class="text-xs text-muted">${formatNPR(crop.price)}${t('products.perKg')} · ${crop.quantity_available} ${t('common.kg')}</div>
          </div>
        </div>
      </div>
      <div class="field">
        <label>${t('contactModal.quantity')}</label>
        <input id="qty-input" type="number" min="1" max="${crop.quantity_available}" value="${Math.min(10, crop.quantity_available || 1)}" inputmode="numeric" />
      </div>
      <p id="qty-error" class="form-error" style="display:none;"></p>
      <div class="flex gap-2 mt-4">
        <button class="btn btn-outline" style="flex:1" data-close>${t('contactModal.cancel')}</button>
        <button id="qty-submit" class="btn btn-primary" style="flex:1">${t('contactModal.submit')}</button>
      </div>
    `,
    onMount: (root) => {
      root.querySelector('#qty-submit').addEventListener('click', async () => {
        const qty = Number(root.querySelector('#qty-input').value);
        const err = root.querySelector('#qty-error');
        err.style.display = 'none';
        try {
          await api('/orders', { method: 'POST', body: { crop_id: crop.id, quantity: qty } });
          root.querySelector('.modal-body').innerHTML = `<p class="font-semibold" style="color:var(--green-dark);text-align:center;padding:24px;">${t('contactModal.success')}</p>`;
          setTimeout(() => (root.innerHTML = ''), 1200);
        } catch {
          err.textContent = t('common.error');
          err.style.display = 'block';
        }
      });
    },
  });
}

function showModal({ body, onMount }) {
  const root = document.getElementById('modal-root');
  if (!root) return;
  root.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head">
          <h3>${t('contactModal.title')}</h3>
          <button class="modal-close" data-close>✕</button>
        </div>
        <div class="modal-body">${body}</div>
      </div>
    </div>
  `;
  const close = () => (root.innerHTML = '');
  root.querySelector('[data-close]').addEventListener('click', close);
  root.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) close();
  });
  if (onMount) onMount(root);
}

async function init() {
  resetCurrentUser();
  await renderNavbar('/products');
  renderFooter();
  applyTranslations();
  await renderCrops();
  onLangChange(async () => {
    await renderNavbar('/products');
    renderFooter();
    applyTranslations();
    await renderCrops();
  });
}

init();
