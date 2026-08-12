import { t, formatNPR, timeAgo } from '../scripts/i18n.js';
import { api } from '../scripts/api.js';
import { currentUser, resetCurrentUser, onLangChange } from '../scripts/shared.js';
import { renderDashboardShell, getDashBody, statCard, statusBadge } from '../scripts/dashboard.js';

let me = null;
let tab = 'dashboard';
let users = [];
let pendingCrops = [];
let allOrders = [];
let prices = [];

async function load() {
  const [u, pc, o, p] = await Promise.all([
    api('/admin/users'),
    api('/admin/crops/pending'),
    api('/admin/orders'),
    api('/prices'),
  ]);
  users = u.users || [];
  pendingCrops = pc.crops || [];
  allOrders = o.orders || [];
  prices = p.prices || [];
}

function tabs() {
  return [
    { key: 'dashboard', label: t('admin.dashboard'), icon: '📊' },
    { key: 'users', label: t('admin.users'), icon: '👥' },
    { key: 'pendingCrops', label: t('admin.pendingCrops'), icon: '🌾' },
    { key: 'orders', label: t('admin.orders'), icon: '🛒' },
    { key: 'marketPrices', label: t('admin.marketPrices'), icon: '📈' },
  ];
}

function renderDashboard() {
  const activeCrops = users.length ? '' : ''; // not needed for stat
  const totalOrders = allOrders.length;
  const totalKg = allOrders.reduce((s, o) => s + Number(o.quantity), 0);
  const totalUsers = users.length;
  // Active crops = approved crops; we don't have a direct endpoint, approximate from pending + a fetch
  const body = getDashBody();
  body.innerHTML = `
    <div class="stats four">
      ${statCard({ label: t('admin.statActiveCrops'), value: '—', icon: '🌾' })}
      ${statCard({ label: t('admin.statTotalOrders'), value: totalOrders, icon: '🛒', color: 'orange' })}
      ${statCard({ label: t('admin.statTotalKg'), value: `${totalKg} ${t('common.kg')}`, icon: '📦', color: 'orange' })}
      ${statCard({ label: t('admin.statTotalUsers'), value: totalUsers, icon: '👥', color: 'gray' })}
    </div>
  `;
  // Fetch approved count
  api('/crops?status=approved').then((d) => {
    const cards = body.querySelectorAll('.stat-value');
    if (cards[0]) cards[0].textContent = String((d.crops || []).length);
  }).catch(() => {});
}

function renderUsers() {
  const body = getDashBody();
  body.innerHTML = `<h3 class="block-title">${t('admin.usersTitle')}</h3><div id="users-table"></div>`;
  const el = document.getElementById('users-table');
  if (users.length === 0) {
    el.innerHTML = `<div class="empty">${t('admin.usersEmpty')}</div>`;
    return;
  }
  el.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>${t('admin.userName')}</th>
            <th>${t('admin.userBusiness')}</th>
            <th>${t('admin.userPhone')}</th>
            <th>${t('admin.userRole')}</th>
            <th>${t('admin.userStatus')}</th>
            <th>${t('admin.userActions')}</th>
          </tr>
        </thead>
        <tbody>
          ${users.map((u) => `
            <tr>
              <td class="font-semibold">${u.full_name}</td>
              <td class="text-muted">${u.business_name || '—'}</td>
              <td class="text-muted">${u.phone}</td>
              <td>${t('role.' + u.role)}</td>
              <td>${statusBadge(u.status)}</td>
              <td>
                ${u.role !== 'admin' ? (
                  u.status === 'suspended' || u.status === 'banned'
                    ? `<button class="btn btn-sm btn-primary" data-activate="${u.id}">${t('admin.activate')}</button>`
                    : `<button class="btn btn-sm btn-outline" data-suspend="${u.id}">${t('admin.suspend')}</button>`
                ) : ''}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
  el.querySelectorAll('[data-activate]').forEach((b) =>
    b.addEventListener('click', async () => {
      await api('/admin/users/' + b.dataset.activate, { method: 'PATCH', body: { status: 'active' } });
      await load();
      renderUsers();
    })
  );
  el.querySelectorAll('[data-suspend]').forEach((b) =>
    b.addEventListener('click', async () => {
      await api('/admin/users/' + b.dataset.suspend, { method: 'PATCH', body: { status: 'suspended' } });
      await load();
      renderUsers();
    })
  );
}

function renderPending() {
  const body = getDashBody();
  body.innerHTML = `<h3 class="block-title">${t('admin.pendingTitle')}</h3><div id="pending-table"></div>`;
  const el = document.getElementById('pending-table');
  if (pendingCrops.length === 0) {
    el.innerHTML = `<div class="empty">${t('admin.pendingEmpty')}</div>`;
    return;
  }
  el.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>${t('admin.pendingCrop')}</th>
            <th>${t('admin.pendingFarmer')}</th>
            <th class="text-right">${t('admin.pendingPrice')}</th>
            <th class="text-right">${t('admin.pendingQuantity')}</th>
            <th>${t('admin.userActions')}</th>
          </tr>
        </thead>
        <tbody>
          ${pendingCrops.map((c) => `
            <tr>
              <td class="font-semibold">${c.name}</td>
              <td class="text-muted">${c.farmer?.full_name || '—'}</td>
              <td class="text-right">${formatNPR(c.price)}</td>
              <td class="text-right">${c.quantity_available} ${t('common.kg')}</td>
              <td>
                <div class="flex gap-2">
                  <button class="btn btn-sm btn-primary" data-approve="${c.id}">${t('admin.approve')}</button>
                  <button class="btn btn-sm btn-outline" data-reject="${c.id}">${t('admin.reject')}</button>
                </div>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
  el.querySelectorAll('[data-approve]').forEach((b) =>
    b.addEventListener('click', async () => {
      await api('/crops/' + b.dataset.approve, { method: 'PATCH', body: { status: 'approved' } });
      await load();
      renderPending();
    })
  );
  el.querySelectorAll('[data-reject]').forEach((b) =>
    b.addEventListener('click', async () => {
      await api('/crops/' + b.dataset.reject, { method: 'PATCH', body: { status: 'rejected' } });
      await load();
      renderPending();
    })
  );
}

function renderOrders() {
  const body = getDashBody();
  body.innerHTML = `<h3 class="block-title">${t('admin.ordersTitle')}</h3><div id="orders-table"></div>`;
  const el = document.getElementById('orders-table');
  if (allOrders.length === 0) {
    el.innerHTML = `<div class="empty">${t('admin.ordersEmpty')}</div>`;
    return;
  }
  el.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>${t('admin.ordersBuyer')}</th>
            <th>${t('admin.ordersSeller')}</th>
            <th>${t('admin.ordersCrop')}</th>
            <th class="text-right">${t('admin.ordersQuantity')}</th>
            <th>${t('admin.ordersStatus')}</th>
            <th>${t('admin.ordersDate')}</th>
          </tr>
        </thead>
        <tbody>
          ${allOrders.map((o) => `
            <tr>
              <td>${o.wholesaler?.full_name || '—'}</td>
              <td>${o.farmer?.full_name || '—'}</td>
              <td class="font-semibold">${o.crop?.name || '—'}</td>
              <td class="text-right">${o.quantity} ${t('common.kg')}</td>
              <td>${statusBadge(o.status)}</td>
              <td class="text-xs text-muted">${timeAgo(o.created_at)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

let editingPriceId = null;

function renderMarketPrices() {
  const body = getDashBody();
  body.innerHTML = `
    <div class="card card-pad mb-6">
      <h3 class="block-title">${editingPriceId ? t('admin.pricesUpdate') : t('admin.pricesAdd')}</h3>
      <form id="price-form" class="form">
        <div class="form-row two">
          <div class="field">
            <label>${t('admin.pricesProduct')}</label>
            <input name="product" id="p-product" required />
          </div>
          <div class="field">
            <label>${t('admin.pricesUnit')}</label>
            <input name="unit" id="p-unit" value="kg" />
          </div>
          <div class="field">
            <label>${t('admin.pricesMin')}</label>
            <input name="min_price" id="p-min" type="number" min="0" inputmode="numeric" required />
          </div>
          <div class="field">
            <label>${t('admin.pricesMax')}</label>
            <input name="max_price" id="p-max" type="number" min="0" inputmode="numeric" required />
          </div>
          <div class="field">
            <label>${t('admin.pricesAvg')}</label>
            <input name="avg_price" id="p-avg" type="number" min="0" inputmode="numeric" required />
          </div>
          <div class="field">
            <label>${t('admin.pricesTrend')}</label>
            <select name="trend" id="p-trend">
              <option value="up">${t('admin.pricesUp')}</option>
              <option value="down">${t('admin.pricesDown')}</option>
              <option value="stable">${t('admin.pricesStable')}</option>
            </select>
          </div>
        </div>
        <p id="price-saved" class="form-success" style="display:none;">${t('admin.pricesSaved')}</p>
        <div class="flex gap-2">
          <button type="submit" class="btn btn-primary">${t('admin.pricesSave')}</button>
          ${editingPriceId ? `<button type="button" id="cancel-edit" class="btn btn-outline">${t('common.cancel')}</button>` : ''}
        </div>
      </form>
    </div>
    <h3 class="block-title">${t('admin.pricesTitle')}</h3>
    <div id="prices-table"></div>
  `;

  const form = document.getElementById('price-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      product: document.getElementById('p-product').value,
      unit: document.getElementById('p-unit').value || 'kg',
      min_price: Number(document.getElementById('p-min').value),
      max_price: Number(document.getElementById('p-max').value),
      avg_price: Number(document.getElementById('p-avg').value),
      trend: document.getElementById('p-trend').value,
    };
    try {
      if (editingPriceId) {
        await api('/prices/' + editingPriceId, { method: 'PATCH', body: payload });
      } else {
        await api('/prices', { method: 'POST', body: payload });
      }
      editingPriceId = null;
      document.getElementById('price-saved').style.display = 'block';
      setTimeout(() => { document.getElementById('price-saved').style.display = 'none'; }, 1500);
      form.reset();
      document.getElementById('p-unit').value = 'kg';
      await load();
      renderMarketPrices();
    } catch {
      // ignore
    }
  });
  if (editingPriceId) {
    document.getElementById('cancel-edit').addEventListener('click', () => {
      editingPriceId = null;
      renderMarketPrices();
    });
  }

  const el = document.getElementById('prices-table');
  if (prices.length === 0) {
    el.innerHTML = `<div class="empty">${t('admin.pricesEmpty')}</div>`;
    return;
  }
  el.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>${t('admin.pricesProduct')}</th>
            <th>${t('admin.pricesUnit')}</th>
            <th class="text-right">${t('admin.pricesMin')}</th>
            <th class="text-right">${t('admin.pricesMax')}</th>
            <th class="text-right">${t('admin.pricesAvg')}</th>
            <th>${t('admin.pricesTrend')}</th>
            <th>${t('admin.userActions')}</th>
          </tr>
        </thead>
        <tbody>
          ${prices.map((p) => {
            const trendIcon = p.trend === 'up' ? '↑' : p.trend === 'down' ? '↓' : '→';
            const trendCls = p.trend === 'up' ? 'trend-up' : p.trend === 'down' ? 'trend-down' : 'trend-stable';
            return `
              <tr>
                <td class="font-semibold">${p.product}</td>
                <td class="text-muted">${p.unit}</td>
                <td class="text-right">${formatNPR(p.min_price)}</td>
                <td class="text-right">${formatNPR(p.max_price)}</td>
                <td class="text-right">${formatNPR(p.avg_price)}</td>
                <td><span class="trend ${trendCls}">${trendIcon} ${t('trend.' + p.trend)}</span></td>
                <td>
                  <div class="flex gap-2">
                    <button class="btn btn-sm btn-outline" data-edit="${p.id}">${t('admin.pricesUpdate')}</button>
                    <button class="btn btn-sm btn-outline" data-delete="${p.id}" style="color:#dc2626;">${t('admin.pricesDelete')}</button>
                  </div>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
  el.querySelectorAll('[data-edit]').forEach((b) =>
    b.addEventListener('click', () => {
      const p = prices.find((x) => x.id === b.dataset.edit);
      if (!p) return;
      editingPriceId = p.id;
      renderMarketPrices();
      document.getElementById('p-product').value = p.product;
      document.getElementById('p-unit').value = p.unit;
      document.getElementById('p-min').value = p.min_price;
      document.getElementById('p-max').value = p.max_price;
      document.getElementById('p-avg').value = p.avg_price;
      document.getElementById('p-trend').value = p.trend;
    })
  );
  el.querySelectorAll('[data-delete]').forEach((b) =>
    b.addEventListener('click', async () => {
      await api('/prices/' + b.dataset.delete, { method: 'DELETE' });
      await load();
      renderMarketPrices();
    })
  );
}

function switchTab(k) {
  tab = k;
  document.querySelectorAll('[data-tab]').forEach((b) => b.classList.toggle('active', b.dataset.tab === k));
  if (k === 'dashboard') renderDashboard();
  else if (k === 'users') renderUsers();
  else if (k === 'pendingCrops') renderPending();
  else if (k === 'orders') renderOrders();
  else if (k === 'marketPrices') renderMarketPrices();
}

async function init() {
  resetCurrentUser();
  me = await currentUser();
  if (!me) {
    window.location.href = '/admin/login';
    return;
  }
  if (me.role !== 'admin') {
    window.location.href = '/';
    return;
  }
  await load();
  await renderDashboardShell({
    role: 'admin',
    active: tab,
    welcome: t('admin.welcome'),
    tabs: tabs(),
    onTab: switchTab,
  });
  switchTab(tab);

  onLangChange(async () => {
    await renderDashboardShell({
      role: 'admin',
      active: tab,
      welcome: t('admin.welcome'),
      tabs: tabs(),
      onTab: switchTab,
    });
    switchTab(tab);
  });
}

init();
