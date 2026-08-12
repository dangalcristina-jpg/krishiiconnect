import { t, getLang, imageOrPlaceholder, cropImageSrc, formatNPR } from './i18n.js';
import { api } from './api.js';
import { currentUser } from './shared.js';

let allCrops = [];

function createModalRoot() {
  const r = document.createElement('div');
  r.id = 'modal-root';
  document.body.appendChild(r);
  return r;
}

// ---------- Product Details Modal ----------
export async function openProductModal(cropId, crops) {
  if (crops) allCrops = crops;
  const root = document.getElementById('modal-root') || createModalRoot();
  root.innerHTML = `<div class="modal-backdrop"><div class="modal" style="max-width:680px;"><div class="modal-body" style="padding:24px;"><div class="skeleton" style="height:300px;"></div></div></div></div>`;
  root.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) root.innerHTML = '';
  });
  try {
    const data = await api(`/crops/${cropId}`);
    const crop = data.crop;
    if (!crop) { root.innerHTML = ''; return; }
    const me = await currentUser();
    const images = crop.images || [];
    const mainImg = images.length > 0 ? images[0].image_url : null;
    const galleryHTML = images.length > 0
      ? `<div class="product-modal-gallery">
          <div class="product-modal-main-img">
            <img id="modal-main-img" src="${mainImg}" alt="${crop.name}" />
          </div>
          ${images.length > 1 ? `<div class="product-modal-thumbs">
            ${images.map((img, i) => `<button class="product-modal-thumb ${i === 0 ? 'active' : ''}" data-img="${img.image_url}"><img src="${img.image_url}" alt="" loading="lazy" /></button>`).join('')}
          </div>` : ''}
        </div>`
      : `<div class="product-modal-main-img"><div class="crop-img-placeholder">🖼️</div></div>`;
    const related = allCrops.filter((c) => c.id !== crop.id && c.category === crop.category).slice(0, 4);
    const relatedHTML = related.length > 0
      ? `<div class="product-modal-related">
          <h4>${t('home.relatedProducts')}</h4>
          <div class="related-grid">
            ${related.map((r) => {
              const rImg = cropImageSrc(r);
              const rImgHTML = rImg.kind === 'url' ? `<img src="${rImg.src}" alt="${r.name}" loading="lazy" />` : imageOrPlaceholder(rImg.file, r.name, 'crop-img');
              return `<button class="related-card" data-view="${r.id}">${rImgHTML}<span>${r.name}</span><span class="related-price">${formatNPR(r.price)}</span></button>`;
            }).join('')}
          </div>
        </div>`
      : '';
    const phoneHTML = me
      ? `<div class="crop-meta-row">📱 <span>${crop.farmer?.phone || '—'}</span></div>`
      : `<div class="crop-meta-row">📱 <span class="text-muted">${t('home.phoneLoginRequired')}</span></div>`;
    const harvestDate = crop.harvest_date
      ? new Date(crop.harvest_date).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })
      : '—';
    root.innerHTML = `
      <div class="modal-backdrop">
        <div class="modal" style="max-width:680px;">
          <div class="modal-head">
            <h3>${crop.name}</h3>
            <button class="modal-close" data-close>✕</button>
          </div>
          <div class="modal-body">
            ${galleryHTML}
            <div class="product-modal-info">
              <div class="product-modal-price">${formatNPR(crop.price)}${t('products.perKg')}</div>
              <div class="product-modal-badges">
                ${crop.quantity_available > 0 ? `<span class="badge badge-green">${t('home.inStock')}</span>` : `<span class="badge badge-gray">${t('home.soldOut')}</span>`}
                ${crop.category ? `<span class="badge badge-blue">${crop.category}</span>` : ''}
                ${crop.farmer?.phone_verified ? `<span class="badge badge-amber">${t('home.verifiedFarmer')}</span>` : ''}
              </div>
              ${crop.description ? `<p class="product-modal-desc">${crop.description}</p>` : ''}
              <div class="product-modal-details">
                <div class="crop-meta-row">👤 <span>${crop.farmer?.full_name || '—'}</span></div>
                <div class="crop-meta-row">📍 <span>${t('home.district')}: ${crop.location || '—'}</span></div>
                <div class="crop-meta-row">📦 <span>${t('home.quantityAvailable')}: ${crop.quantity_available} ${crop.unit || 'kg'}</span></div>
                <div class="crop-meta-row">📅 <span>${t('home.harvestDate')}: ${harvestDate}</span></div>
                <div class="crop-meta-row">🏷️ <span>${t('home.category')}: ${crop.category || '—'}</span></div>
                ${crop.farmer?.business_name ? `<div class="crop-meta-row">🏪 <span>${t('home.businessName')}: ${crop.farmer.business_name}</span></div>` : ''}
                ${phoneHTML}
              </div>
              <div class="crop-card-actions mt-4">
                <button class="btn btn-primary" data-contact="${crop.id}">${t('home.contactFarmer')}</button>
              </div>
              ${relatedHTML}
            </div>
          </div>
        </div>
      </div>
    `;
    const close = () => (root.innerHTML = '');
    root.querySelector('[data-close]').addEventListener('click', close);
    root.querySelector('.modal-backdrop').addEventListener('click', (e) => {
      if (e.target.classList.contains('modal-backdrop')) close();
    });
    root.querySelectorAll('[data-img]').forEach((thumb) => {
      thumb.addEventListener('click', () => {
        root.querySelector('#modal-main-img').src = thumb.dataset.img;
        root.querySelectorAll('[data-img]').forEach((tm) => tm.classList.remove('active'));
        thumb.classList.add('active');
      });
    });
    root.querySelector('[data-contact]')?.addEventListener('click', () => {
      close();
      openContactModal(crop.id);
    });
    root.querySelectorAll('[data-view]').forEach((btn) => {
      btn.addEventListener('click', () => {
        close();
        openProductModal(btn.dataset.view, allCrops);
      });
    });
  } catch {
    root.innerHTML = `<div class="modal-backdrop"><div class="modal"><div class="modal-body"><p>${t('common.error')}</p></div></div></div>`;
  }
}

// ---------- Contact Modal (order) ----------
export async function openContactModal(cropId, crops) {
  if (crops) allCrops = crops;
  const me = await currentUser();
  if (!me) { showModalLogin(); return; }
  if (me.role !== 'wholesaler') { showModalWrongRole(); return; }
  let crop = allCrops.find((c) => c.id === cropId);
  if (!crop) {
    try { const data = await api(`/crops/${cropId}`); crop = data.crop; } catch { return; }
  }
  if (!crop) return;
  showModalOrder(crop);
}

function showModalLogin() {
  const root = document.getElementById('modal-root') || createModalRoot();
  root.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head"><h3>${t('contactModal.title')}</h3><button class="modal-close" data-close>✕</button></div>
        <div class="modal-body">
          <p class="text-muted">${t('contactModal.loginRequired')}</p>
          <div class="flex gap-2 mt-4">
            <a href="/login" class="btn btn-primary" style="flex:1">${t('contactModal.login')}</a>
            <a href="/register" class="btn btn-outline" style="flex:1">${t('contactModal.register')}</a>
          </div>
        </div>
      </div>
    </div>
  `;
  root.querySelector('[data-close]').addEventListener('click', () => (root.innerHTML = ''));
  root.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) root.innerHTML = '';
  });
}

function showModalWrongRole() {
  const root = document.getElementById('modal-root') || createModalRoot();
  root.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head"><h3>${t('contactModal.title')}</h3><button class="modal-close" data-close>✕</button></div>
        <div class="modal-body"><p class="text-muted">${t('contactModal.wrongRole')}</p></div>
      </div>
    </div>
  `;
  root.querySelector('[data-close]').addEventListener('click', () => (root.innerHTML = ''));
  root.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) root.innerHTML = '';
  });
}

function showModalOrder(crop) {
  const root = document.getElementById('modal-root') || createModalRoot();
  root.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head"><h3>${t('contactModal.title')}</h3><button class="modal-close" data-close>✕</button></div>
        <div class="modal-body">
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
        </div>
      </div>
    </div>
  `;
  const close = () => (root.innerHTML = '');
  root.querySelector('[data-close]').addEventListener('click', close);
  root.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) close();
  });
  root.querySelector('#qty-submit').addEventListener('click', async () => {
    const qty = Number(root.querySelector('#qty-input').value);
    const err = root.querySelector('#qty-error');
    err.style.display = 'none';
    try {
      await api('/orders', { method: 'POST', body: { crop_id: crop.id, quantity: qty } });
      root.querySelector('.modal-body').innerHTML = `<p class="font-semibold" style="color:var(--green-dark);text-align:center;padding:24px;">${t('contactModal.success')}</p>`;
      setTimeout(close, 1200);
    } catch {
      err.textContent = t('common.error');
      err.style.display = 'block';
    }
  });
}
