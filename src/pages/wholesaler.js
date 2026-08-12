import { t, formatNPR, timeAgo, imageOrPlaceholder, cropImageSrc } from '../scripts/i18n.js';
import { api } from '../scripts/api.js';
import { currentUser, resetCurrentUser, onLangChange } from '../scripts/shared.js';
import { renderDashboardShell, getDashBody, statCard, quickAction, emptyState, statusBadge } from '../scripts/dashboard.js';
import { renderStatement } from '../scripts/statement.js';
import { fetchReviewsFor, renderReviewList, ratingBadge, openLeaveReviewModal, starRow } from '../scripts/reviews.js';
import { renderAvatarUploader } from '../scripts/avatar-upload.js';

let me = null;
let tab = 'dashboard';
let crops = [];
let prices = [];
let orders = [];

async function load() {
  const [c, p, o] = await Promise.all([
    api('/crops?status=approved'),
    api('/prices'),
    api('/orders'),
  ]);
  crops = c.crops || [];
  prices = p.prices || [];
  orders = o.orders || [];
}

function tabs() {
  return [
    { key: 'dashboard', label: t('wholesaler.dashboard'), icon: '📊' },
    { key: 'browseCrops', label: t('wholesaler.browseCrops'), icon: '🔍' },
    { key: 'myOrders', label: t('wholesaler.myOrders'), icon: '🛒' },
    { key: 'marketPrices', label: t('wholesaler.marketPrices'), icon: '📈' },
    { key: 'statement', label: t('wholesaler.statement'), icon: '🧾' },
    { key: 'reviews', label: t('reviews.title'), icon: '⭐' },
    { key: 'profile', label: t('wholesaler.profile'), icon: '👤' },
  ];
}

function cropCardHTML(crop) {
  const img = cropImageSrc(crop);
  const imgHTML = img.kind === 'url'
    ? `<img src="${img.src}" alt="${crop.name}" loading="lazy" />`
    : imageOrPlaceholder(img.file, crop.name, 'crop-img');
  const farmerId = crop.farmer?.id;
  const ratingHTML = farmerId
    ? `<div class="crop-meta-row farmer-rating" data-farmer="${farmerId}">⭐ <span class="text-muted">…</span></div>`
    : '';
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
          ${ratingHTML}
          <div class="crop-meta-row">📦 <span>${crop.quantity_available} ${t('common.kg')}</span></div>
          ${crop.location ? `<div class="crop-meta-row">📍 <span>${crop.location}</span></div>` : ''}
        </div>
        <div class="crop-card-actions">
          <button class="btn btn-primary btn-block" data-contact="${crop.id}">${t('products.contact')}</button>
        </div>
      </div>
    </div>
  `;
}

async function hydrateFarmerRatings(rootEl) {
  const slots = rootEl.querySelectorAll('.farmer-rating[data-farmer]');
  if (!slots.length) return;
  const byFarmer = new Map();
  slots.forEach((s) => {
    const id = s.dataset.farmer;
    if (!byFarmer.has(id)) byFarmer.set(id, []);
    byFarmer.get(id).push(s);
  });
  await Promise.all([...byFarmer.keys()].map(async (id) => {
    const { average, count } = await fetchReviewsFor(id);
    const html = count
      ? `<span class="stars-inline">${starRow(Math.round(average))}</span> <span class="text-muted">${average.toFixed(1)} (${count})</span>`
      : `<span class="text-muted text-xs">${t('reviews.noReviews')}</span>`;
    byFarmer.get(id).forEach((s) => { s.innerHTML = '⭐ ' + html; });
  }));
}

function renderDashboard() {
  const totalOrders = orders.length;
  const farmersContacted = new Set(orders.map((o) => o.farmer_id)).size;
  const totalSpent = orders
    .filter((o) => o.status === 'completed' && o.crop)
    .reduce((s, o) => s + Number(o.crop.price) * Number(o.quantity), 0);

  const body = getDashBody();
  body.innerHTML = `
    <div class="block">
      <div class="stats">
        ${statCard({ label: t('wholesaler.statTotalOrders'), value: totalOrders, icon: '🛒', color: 'orange' })}
        ${statCard({ label: t('wholesaler.statFarmersContacted'), value: farmersContacted, icon: '👥' })}
        ${statCard({ label: t('wholesaler.statTotalSpent'), value: formatNPR(totalSpent), icon: '💰', color: 'orange' })}
      </div>
    </div>
    <div class="block">
      <h3 class="block-title">${t('wholesaler.quickActions')}</h3>
      <div class="quick-actions" id="quick-actions"></div>
    </div>
    <div class="block">
      <h3 class="block-title">${t('wholesaler.featuredToday')}</h3>
      <div class="crop-grid" id="featured"></div>
    </div>
  `;
  const qa = document.getElementById('quick-actions');
  qa.appendChild(quickAction({ label: t('wholesaler.actionBrowseCrops'), icon: '🔍', onClick: () => switchTab('browseCrops') }));
  qa.appendChild(quickAction({ label: t('wholesaler.actionMyOrders'), icon: '🛒', onClick: () => switchTab('myOrders') }));
  qa.appendChild(quickAction({ label: t('wholesaler.actionMarketPrices'), icon: '📈', onClick: () => switchTab('marketPrices') }));
  qa.appendChild(quickAction({ label: t('wholesaler.actionUpdateProfile'), icon: '✏️', onClick: () => switchTab('profile') }));

  const feat = document.getElementById('featured');
  if (crops.length === 0) {
    feat.innerHTML = `<p class="text-muted">${t('products.empty')}</p>`;
  } else {
    feat.innerHTML = crops.slice(0, 3).map(cropCardHTML).join('');
    feat.querySelectorAll('[data-contact]').forEach((btn) =>
      btn.addEventListener('click', () => openContact(btn.dataset.contact))
    );
    hydrateFarmerRatings(feat);
  }
}

let filters = { crop: '', price: '', location: '', applied: { crop: '', price: '', location: '' } };

function renderBrowse() {
  const body = getDashBody();
  const cropNames = Array.from(new Set(crops.map((c) => c.name))).sort();
  body.innerHTML = `
    <h3 class="block-title">${t('wholesaler.browseTitle')}</h3>
    <div class="filters">
      <div class="field">
        <label>${t('wholesaler.filterCrop')}</label>
        <select id="f-crop">
          <option value="">${t('wholesaler.allCrops')}</option>
          ${cropNames.map((n) => `<option value="${n}" ${filters.crop === n ? 'selected' : ''}>${n}</option>`).join('')}
        </select>
      </div>
      <div class="field">
        <label>${t('wholesaler.priceRange')}</label>
        <select id="f-price">
          <option value="">${t('wholesaler.anyPrice')}</option>
          <option value="lt50" ${filters.price === 'lt50' ? 'selected' : ''}>&lt; ${formatNPR(50)}</option>
          <option value="50-100" ${filters.price === '50-100' ? 'selected' : ''}>${formatNPR(50)} – ${formatNPR(100)}</option>
          <option value="gt100" ${filters.price === 'gt100' ? 'selected' : ''}>&gt; ${formatNPR(100)}</option>
        </select>
      </div>
      <div class="field">
        <label>${t('wholesaler.location')}</label>
        <input id="f-location" value="${filters.location}" />
      </div>
      <div class="flex gap-2">
        <button id="f-apply" class="btn btn-primary" style="flex:1">${t('wholesaler.apply')}</button>
        <button id="f-clear" class="btn btn-outline">${t('wholesaler.clear')}</button>
      </div>
    </div>
    <div id="browse-grid"></div>
  `;
  document.getElementById('f-apply').addEventListener('click', () => {
    filters.crop = document.getElementById('f-crop').value;
    filters.price = document.getElementById('f-price').value;
    filters.location = document.getElementById('f-location').value;
    filters.applied = { ...filters };
    renderBrowseGrid();
  });
  document.getElementById('f-clear').addEventListener('click', () => {
    filters = { crop: '', price: '', location: '', applied: { crop: '', price: '', location: '' } };
    renderBrowse();
  });
  renderBrowseGrid();
}

function renderBrowseGrid() {
  const el = document.getElementById('browse-grid');
  const filtered = crops.filter((c) => {
    if (filters.applied.crop && c.name !== filters.applied.crop) return false;
    if (filters.applied.location && !(c.location || '').toLowerCase().includes(filters.applied.location.toLowerCase())) return false;
    if (filters.applied.price) {
      const p = Number(c.price);
      if (filters.applied.price === 'lt50' && p >= 50) return false;
      if (filters.applied.price === '50-100' && (p < 50 || p > 100)) return false;
      if (filters.applied.price === 'gt100' && p <= 100) return false;
    }
    return true;
  });
  if (filtered.length === 0) {
    el.innerHTML = '';
    el.appendChild(emptyState({ title: t('wholesaler.browseEmpty') }));
    return;
  }
  el.className = 'crop-grid';
  el.innerHTML = filtered.map(cropCardHTML).join('');
  el.querySelectorAll('[data-contact]').forEach((btn) =>
    btn.addEventListener('click', () => openContact(btn.dataset.contact))
  );
  hydrateFarmerRatings(el);
}

let orderSub = 'pending';

function renderOrders() {
  const body = getDashBody();
  body.innerHTML = `
    <h3 class="block-title">${t('wholesaler.ordersTitle')}</h3>
    <div class="subtabs" id="order-subtabs">
      <button class="subtab ${orderSub === 'pending' ? 'active' : ''}" data-sub="pending">${t('wholesaler.ordersPending')}</button>
      <button class="subtab ${orderSub === 'completed' ? 'active' : ''}" data-sub="completed">${t('wholesaler.ordersCompleted')}</button>
      <button class="subtab ${orderSub === 'contacts' ? 'active' : ''}" data-sub="contacts">${t('wholesaler.ordersContacts')}</button>
    </div>
    <div id="orders-list"></div>
  `;
  document.querySelectorAll('[data-sub]').forEach((b) =>
    b.addEventListener('click', () => {
      orderSub = b.dataset.sub;
      renderOrders();
    })
  );
  const list = document.getElementById('orders-list');
  let rows = [];
  let emptyKey = '';
  if (orderSub === 'pending') {
    rows = orders.filter((o) => o.status === 'pending');
    emptyKey = 'ordersPendingEmpty';
  } else if (orderSub === 'completed') {
    rows = orders.filter((o) => o.status === 'completed');
    emptyKey = 'ordersCompletedEmpty';
  } else {
    rows = orders.filter((o) => o.farmer);
    emptyKey = 'ordersContactsEmpty';
  }
  if (rows.length === 0) {
    list.innerHTML = '';
    list.appendChild(emptyState({ title: t('wholesaler.' + emptyKey) }));
    return;
  }
  list.innerHTML = rows.map((o) => `
    <div class="order-card">
      <div>
        <div class="order-name">${o.crop?.name ?? '—'}</div>
        <div class="order-meta">${o.farmer?.full_name ?? '—'} · ${o.quantity} ${t('common.kg')}</div>
      </div>
      <div class="flex items-center gap-3">
        <div class="text-sm">${o.crop ? formatNPR(Number(o.crop.price) * Number(o.quantity)) : ''}</div>
        ${statusBadge(o.status)}
        <div class="text-xs text-muted">${timeAgo(o.created_at)}</div>
      </div>
    </div>
  `).join('');
}

function renderMarketPrices() {
  const body = getDashBody();
  body.innerHTML = `<h3 class="block-title">${t('wholesaler.marketPrices')}</h3><div id="prices"></div>`;
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
            <th>${t('wholesaler.availableFarmers')}</th>
          </tr>
        </thead>
        <tbody>
          ${prices.map((r) => {
            const n = crops.filter((c) => c.name.toLowerCase() === r.product.toLowerCase()).length;
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
                <td><span class="font-semibold" style="color:var(--green-dark);">${n}</span></td>
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
    <h3 class="block-title">${t('wholesaler.profileTitle')}</h3>
    <div style="max-width:640px;">
      <div class="profile-card-view card card-pad">
        <div class="profile-card-top">
          <div id="avatar-slot"></div>
          <div class="profile-card-info">
            <h2 class="profile-card-name">${me.full_name || '—'}</h2>
            <div class="profile-card-role">
              <span class="badge badge-amber">${t('wholesaler.role') || 'Wholesaler'}</span>
            </div>
            <div class="profile-card-meta">
              <div class="profile-meta-row">📱 <span>${me.phone || '—'}</span></div>
              <div class="profile-meta-row">🏪 <span>${me.business_name || '—'}</span></div>
              <div class="profile-meta-row">📅 <span>${memberSince}</span></div>
            </div>
          </div>
        </div>
        <button type="button" class="btn btn-primary" id="edit-profile-btn">${t('wholesaler.editProfile') || 'Edit Profile'}</button>
      </div>

      <form id="profile-form" class="card card-pad form" style="display:none;margin-top:16px;">
        <div class="profile-edit-avatar">
          <div id="avatar-edit-slot"></div>
        </div>
        <div class="form-row two">
          <div class="field">
            <label>${t('wholesaler.fullName')}</label>
            <input name="full_name" required value="${me.full_name || ''}" />
          </div>
          <div class="field">
            <label>${t('wholesaler.businessName')}</label>
            <input name="business_name" value="${me.business_name || ''}" />
          </div>
          <div class="field">
            <label>${t('wholesaler.phone')}</label>
            <input name="phone" type="tel" inputmode="numeric" value="${me.phone || ''}" disabled />
          </div>
          <div class="field">
            <label>${t('wholesaler.businessLocation')}</label>
            <input name="business_location" value="${me.business_location || ''}" />
          </div>
          <div class="field">
            <label>${t('wholesaler.yearsInBusiness')}</label>
            <input name="years_in_business" type="number" min="0" inputmode="numeric" value="${me.years_in_business ?? ''}" />
          </div>
          <div class="field">
            <label>${t('wholesaler.storageCapacity')}</label>
            <input name="storage_capacity_tons" type="number" min="0" inputmode="numeric" value="${me.storage_capacity_tons ?? ''}" />
          </div>
        </div>
        <div class="field">
          <label>${t('wholesaler.aboutBusiness')}</label>
          <textarea name="about_farm" rows="4">${me.about_farm || ''}</textarea>
        </div>
        <p id="profile-saved" class="form-success" style="display:none;">${t('wholesaler.profileSaved')}</p>
        <div class="flex gap-2">
          <button type="submit" class="btn btn-primary" id="profile-save-btn">${t('wholesaler.save')}</button>
          <button type="button" id="cancel-btn" class="btn btn-outline">${t('wholesaler.cancel') || 'Cancel'}</button>
        </div>
      </form>
    </div>
  `;

  // Render avatar in view mode
  const viewSlot = document.getElementById('avatar-slot');
  viewSlot.innerHTML = `
    <div class="avatar large orange">
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
    import('../scripts/avatar-upload.js').then(({ renderAvatarUploader }) => {
      renderAvatarUploader(editSlot, {
        avatarUrl: me.avatar_url,
        fullName: me.full_name,
        color: 'orange',
        onUploaded: (newUrl) => {
          me.avatar_url = newUrl;
          resetCurrentUser();
          viewSlot.innerHTML = `<div class="avatar large orange"><img src="${newUrl}" alt="${me.full_name || ''}" /></div>`;
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
      if (k === 'phone') continue;
      if (k === 'years_in_business' || k === 'storage_capacity_tons') {
        patchBody[k] = v === '' ? null : Number(v);
      } else {
        patchBody[k] = v;
      }
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

async function openContact(cropId) {
  const crop = crops.find((c) => c.id === cropId);
  if (!crop) return;
  const body = getDashBody();
  // Use a modal
  showModal(`
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
  `, async (root) => {
    root.querySelector('#qty-submit').addEventListener('click', async () => {
      const qty = Number(root.querySelector('#qty-input').value);
      const err = root.querySelector('#qty-error');
      err.style.display = 'none';
      try {
        await api('/orders', { method: 'POST', body: { crop_id: crop.id, quantity: qty } });
        root.querySelector('.modal-body').innerHTML = `<p class="font-semibold" style="color:var(--green-dark);text-align:center;padding:24px;">${t('contactModal.success')}</p>`;
        await load();
        setTimeout(() => closeModal(), 1200);
      } catch {
        err.textContent = t('common.error');
        err.style.display = 'block';
      }
    });
  });
}

let modalRoot;
function showModal(html, onMount) {
  if (!modalRoot) {
    modalRoot = document.createElement('div');
    modalRoot.id = 'modal-root';
    document.body.appendChild(modalRoot);
  }
  modalRoot.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head">
          <h3>${t('contactModal.title')}</h3>
          <button class="modal-close" data-close>✕</button>
        </div>
        <div class="modal-body">${html}</div>
      </div>
    </div>
  `;
  modalRoot.querySelector('[data-close]').addEventListener('click', closeModal);
  modalRoot.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) closeModal();
  });
  if (onMount) onMount(modalRoot);
}
function closeModal() {
  if (modalRoot) modalRoot.innerHTML = '';
}

function switchTab(k) {
  tab = k;
  document.querySelectorAll('[data-tab]').forEach((b) => b.classList.toggle('active', b.dataset.tab === k));
  if (k === 'dashboard') renderDashboard();
  else if (k === 'browseCrops') renderBrowse();
  else if (k === 'myOrders') renderOrders();
  else if (k === 'marketPrices') renderMarketPrices();
  else if (k === 'statement') renderStatement(getDashBody(), 'wholesaler');
  else if (k === 'reviews') renderReviews();
  else if (k === 'profile') renderProfile();
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
  if (me.role !== 'wholesaler') {
    window.location.href = me.role === 'admin' ? '/admin' : '/farmer';
    return;
  }
  await load();
  await renderDashboardShell({
    role: 'wholesaler',
    active: tab,
    welcome: t('wholesaler.welcome', { name: me.full_name }),
    tabs: tabs(),
    onTab: switchTab,
  });
  switchTab(tab);

  onLangChange(async () => {
    await renderDashboardShell({
      role: 'wholesaler',
      active: tab,
      welcome: t('wholesaler.welcome', { name: me.full_name }),
      tabs: tabs(),
      onTab: switchTab,
    });
    switchTab(tab);
  });
}

init();
