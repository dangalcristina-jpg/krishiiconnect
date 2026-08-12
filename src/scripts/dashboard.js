import { t, getLang, setLang } from './i18n.js';
import { api } from './api.js';
import { currentUser } from './shared.js';

// Render the dashboard shell (header + tabs) into #app.
// role: 'farmer' | 'wholesaler' | 'admin'
export async function renderDashboardShell({ role, active, welcome, tabs, onTab }) {
  const headerClass = role === 'farmer' ? 'green' : role === 'wholesaler' ? 'orange' : 'dark';
  const tabColorClass = role === 'farmer' ? '' : role === 'wholesaler' ? 'orange' : 'dark';
  const lang = getLang();

  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="dash">
      <header class="dash-header ${headerClass}">
        <div class="container dash-header-inner">
          <a href="/" class="dash-brand">
            <img src="/images/logo.png" class="dash-brand-logo" alt="Krishi Connect" />
            <span>Krishi Connect</span>
          </a>
          <div class="dash-actions">
            <button id="lang-toggle" class="dash-action-btn">🌐 ${t('nav.toggleLang')}</button>
            <div class="dash-user-avatar" id="dash-user-avatar"></div>
            <button id="logout-btn" class="dash-action-btn">⎋ <span class="dash-logout-label">${t('nav.logout')}</span></button>
          </div>
        </div>
        <div class="container">
          <div class="dash-welcome">${welcome}</div>
        </div>
      </header>
      <div class="container">
        <div class="dash-tabs" id="dash-tabs">
          ${tabs.map((tab) => `
            <button class="dash-tab ${tabColorClass} ${tab.key === active ? 'active' : ''}" data-tab="${tab.key}">
              <span>${tab.icon}</span> ${tab.label}
            </button>
          `).join('')}
        </div>
      </div>
      <div class="container dash-body" id="dash-body"></div>
    </div>
  `;

  document.querySelectorAll('[data-tab]').forEach((btn) => {
    btn.addEventListener('click', () => onTab(btn.dataset.tab));
  });
  document.getElementById('lang-toggle').addEventListener('click', () => setLang(lang === 'en' ? 'ne' : 'en'));
  document.getElementById('logout-btn').addEventListener('click', async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch {}
    window.location.href = '/';
  });

  // Render avatar in dashboard header
  const avatarEl = document.getElementById('dash-user-avatar');
  if (avatarEl) {
    const me = await currentUser();
    if (me) {
      avatarEl.innerHTML = me.avatar_url
        ? `<img src="${me.avatar_url}" alt="${me.full_name || ''}" />`
        : `<span>${(me.full_name || '?').slice(0, 1)}</span>`;
      avatarEl.title = me.full_name || '';
      avatarEl.addEventListener('click', () => {
        const profileTab = document.querySelector('[data-tab="profile"]');
        if (profileTab) profileTab.click();
      });
    }
  }
}

export function getDashBody() {
  return document.getElementById('dash-body');
}

export function statCard({ label, value, icon, color = 'green' }) {
  return `
    <div class="stat">
      <div>
        <div class="stat-label">${label}</div>
        <div class="stat-value">${value}</div>
      </div>
      <div class="stat-icon ${color}">${icon}</div>
    </div>
  `;
}

export function quickAction({ label, icon, onClick }) {
  const btn = document.createElement('button');
  btn.className = 'quick-action';
  btn.innerHTML = `
    <span class="quick-action-icon">${icon}</span>
    <span class="quick-action-label">${label}</span>
  `;
  btn.addEventListener('click', onClick);
  return btn;
}

export function emptyState({ title, cta, onCta }) {
  const div = document.createElement('div');
  div.className = 'empty';
  div.innerHTML = `<p>${title}</p>`;
  if (cta && onCta) {
    const btn = document.createElement('button');
    btn.className = 'btn btn-primary';
    btn.textContent = cta;
    btn.addEventListener('click', onCta);
    div.appendChild(btn);
  }
  return div;
}

export function statusBadge(status) {
  const cls = {
    pending: 'badge-amber', approved: 'badge-green', rejected: 'badge-red', sold_out: 'badge-gray',
    completed: 'badge-green', cancelled: 'badge-red', accepted: 'badge-blue',
    active: 'badge-green', suspended: 'badge-amber', banned: 'badge-red',
  }[status] || 'badge-gray';
  return `<span class="badge ${cls}">${t('status.' + status)}</span>`;
}
