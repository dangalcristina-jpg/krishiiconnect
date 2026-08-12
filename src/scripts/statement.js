import { t, formatNPR } from './i18n.js';
import { api } from './api.js';
import { emptyState, statusBadge } from './dashboard.js';

// Render a transaction statement for the current user.
// `role` is 'farmer' | 'wholesaler' | 'admin'.
// `mountEl` is the dashboard body element to render into.
export async function renderStatement(mountEl, role) {
  const filters = { from: '', to: '', status: '', applied: { from: '', to: '', status: '' } };

  mountEl.innerHTML = `
    <h3 class="block-title">${t('statement.title')}</h3>
    <p class="text-muted mb-4">${t('statement.subtitle')}</p>
    <div class="filters statement-filters">
      <div class="field">
        <label>${t('statement.from')}</label>
        <input id="st-from" type="date" />
      </div>
      <div class="field">
        <label>${t('statement.to')}</label>
        <input id="st-to" type="date" />
      </div>
      <div class="field">
        <label>${t('statement.status')}</label>
        <select id="st-status">
          <option value="">${t('statement.allStatuses')}</option>
          <option value="pending">${t('status.pending')}</option>
          <option value="completed">${t('status.completed')}</option>
          <option value="cancelled">${t('status.cancelled')}</option>
        </select>
      </div>
      <div class="flex gap-2" style="align-self:flex-end;">
        <button id="st-apply" class="btn btn-primary" style="flex:1">${t('statement.apply')}</button>
        <button id="st-clear" class="btn btn-outline">${t('statement.clear')}</button>
      </div>
    </div>
    <div id="st-summary"></div>
    <div id="st-table"></div>
    <div class="flex gap-2 mt-4">
      <button id="st-export" class="btn btn-outline btn-sm">${t('statement.export')}</button>
    </div>
  `;

  const tableEl = mountEl.querySelector('#st-table');
  const summaryEl = mountEl.querySelector('#st-summary');

  mountEl.querySelector('#st-apply').addEventListener('click', () => {
    filters.applied = {
      from: mountEl.querySelector('#st-from').value,
      to: mountEl.querySelector('#st-to').value,
      status: mountEl.querySelector('#st-status').value,
    };
    renderTable();
  });
  mountEl.querySelector('#st-clear').addEventListener('click', () => {
    filters.applied = { from: '', to: '', status: '' };
    mountEl.querySelector('#st-from').value = '';
    mountEl.querySelector('#st-to').value = '';
    mountEl.querySelector('#st-status').value = '';
    renderTable();
  });
  mountEl.querySelector('#st-export').addEventListener('click', exportCSV);

  let lastOrders = [];

  async function renderTable() {
    const params = new URLSearchParams();
    if (filters.applied.from) params.set('from', filters.applied.from);
    if (filters.applied.to) params.set('to', filters.applied.to);
    if (filters.applied.status) params.set('status', filters.applied.status);
    const qs = params.toString();
    try {
      const data = await api('/statement' + (qs ? '?' + qs : ''));
      lastOrders = data.orders || [];
      const total = data.total || 0;
      const count = data.count || 0;
      const completedCount = data.completedCount || 0;

      summaryEl.innerHTML = `
        <div class="stats" style="margin-bottom:16px;">
          <div class="stat"><div><div class="stat-label">${t('statement.count')}</div><div class="stat-value">${count}</div></div></div>
          <div class="stat"><div><div class="stat-label">${t('statement.completedCount')}</div><div class="stat-value">${completedCount}</div></div></div>
          <div class="stat"><div><div class="stat-label">${t('statement.grandTotal')}</div><div class="stat-value">${formatNPR(total)}</div></div></div>
        </div>
      `;

      if (!lastOrders.length) {
        tableEl.innerHTML = '';
        tableEl.appendChild(emptyState({ title: t('statement.empty') }));
        return;
      }

      const counterpartKey = role === 'farmer' ? 'statement.counterpart' : role === 'wholesaler' ? 'statement.counterpartSeller' : 'statement.counterpartSeller';
      tableEl.innerHTML = `
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>${t('statement.date')}</th>
                <th>${t('statement.crop')}</th>
                <th class="text-right">${t('statement.qty')}</th>
                <th class="text-right">${t('statement.price')}</th>
                <th class="text-right">${t('statement.amount')}</th>
                <th>${t(counterpartKey)}</th>
                <th>${t('statement.statusCol')}</th>
              </tr>
            </thead>
            <tbody>
              ${lastOrders.map((o) => {
                const counterpart = role === 'farmer' ? o.wholesaler : role === 'wholesaler' ? o.farmer : (o.wholesaler || o.farmer);
                const counterpartName = counterpart?.full_name || counterpart?.business_name || '—';
                const price = o.crop ? Number(o.crop.price) : 0;
                return `
                  <tr>
                    <td>${new Date(o.created_at).toLocaleDateString()}</td>
                    <td class="font-semibold">${o.crop?.name ?? '—'}</td>
                    <td class="text-right">${o.quantity} ${t('common.kg')}</td>
                    <td class="text-right">${formatNPR(price)}</td>
                    <td class="text-right font-semibold">${formatNPR(o.amount)}</td>
                    <td>${counterpartName}</td>
                    <td>${statusBadge(o.status)}</td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      `;
    } catch {
      tableEl.innerHTML = `<p class="form-error">${t('common.error')}</p>`;
    }
  }

  function exportCSV() {
    if (!lastOrders.length) return;
    const counterpartKey = role === 'farmer' ? 'wholesaler' : 'farmer';
    const header = ['Date', 'Crop', 'Quantity (kg)', 'Price/kg', 'Amount', 'Counterpart', 'Status'];
    const rows = lastOrders.map((o) => {
      const c = o[counterpartKey];
      const name = c?.full_name || c?.business_name || '';
      const price = o.crop ? Number(o.crop.price) : 0;
      return [
        new Date(o.created_at).toLocaleDateString(),
        o.crop?.name ?? '',
        o.quantity,
        price,
        o.amount,
        name,
        o.status,
      ];
    });
    const csv = [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `statement-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function csvCell(v) {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }

  await renderTable();
}
