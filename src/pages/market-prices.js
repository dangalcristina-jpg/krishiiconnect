import { t, formatNPR, trendClass, trendIcon } from '../scripts/i18n.js';
import { api } from '../scripts/api.js';
import { renderNavbar, renderFooter, resetCurrentUser, onLangChange } from '../scripts/shared.js';

function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
}

function tableHTML(rows) {
  if (rows.length === 0) {
    return `<div class="empty">${t('prices.empty')}</div>`;
  }
  return `
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
          </tr>
        </thead>
        <tbody>
          ${rows.map((r) => `
            <tr>
              <td class="font-semibold">${r.product}</td>
              <td class="text-muted">${r.unit}</td>
              <td class="text-right">${formatNPR(r.min_price)}</td>
              <td class="text-right">${formatNPR(r.max_price)}</td>
              <td class="text-right font-semibold">${formatNPR(r.avg_price)}</td>
              <td><span class="trend ${trendClass(r.trend)}">${trendIcon(r.trend)} ${t('trend.' + r.trend)}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

async function renderPrices() {
  const el = document.getElementById('price-table');
  if (!el) return;
  el.innerHTML = `<div class="skeleton" style="height:240px;"></div>`;
  try {
    const data = await api('/prices');
    el.innerHTML = tableHTML(data.prices || []);
  } catch {
    el.innerHTML = `<p class="text-muted">${t('common.error')}</p>`;
  }
}

async function init() {
  resetCurrentUser();
  await renderNavbar('/market-prices');
  renderFooter();
  applyTranslations();
  await renderPrices();
  onLangChange(async () => {
    await renderNavbar('/market-prices');
    renderFooter();
    applyTranslations();
    await renderPrices();
  });
}

init();
