import { t } from '../scripts/i18n.js';
import { renderNavbar, renderFooter, resetCurrentUser, onLangChange } from '../scripts/shared.js';

function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
}

function renderFeatures() {
  const el = document.getElementById('features');
  if (!el) return;
  const items = [
    { icon: '🌱', title: t('feature.directFarmers'), desc: t('feature.directFarmersDesc') },
    { icon: '⚖️', title: t('feature.fairPricing'), desc: t('feature.fairPricingDesc') },
    { icon: '🚚', title: t('feature.fastDelivery'), desc: t('feature.fastDeliveryDesc') },
  ];
  el.innerHTML = items.map((f) => `
    <div class="feature">
      <div class="feature-icon">${f.icon}</div>
      <h3>${f.title}</h3>
      <p>${f.desc}</p>
    </div>
  `).join('');
}

async function init() {
  resetCurrentUser();
  await renderNavbar('/about');
  renderFooter();
  applyTranslations();
  renderFeatures();
  onLangChange(async () => {
    await renderNavbar('/about');
    renderFooter();
    applyTranslations();
    renderFeatures();
  });
}

init();
