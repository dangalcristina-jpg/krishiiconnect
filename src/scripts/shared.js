import { t, getLang, setLang } from './i18n.js';
import { api } from './api.js';

// Render the shared navbar into #navbar.
export async function renderNavbar(active) {
  const me = await currentUser();
  const lang = getLang();
  const links = [
    { to: '/', key: 'nav.home' },
    { to: '/products', key: 'nav.products' },
    { to: '/market-prices', key: 'nav.marketPrices' },
    { to: '/about', key: 'nav.about' },
    { to: '/contact', key: 'nav.contact' },
  ];
  const isActive = (to) => (to === '/' ? active === '/' : active && active.startsWith(to));
  const dashboardLink = me
    ? me.role === 'admin' ? '/admin' : me.role === 'farmer' ? '/farmer' : '/wholesaler'
    : null;

  const el = document.getElementById('navbar');
  if (!el) return;
  el.innerHTML = `
    <header class="navbar">
      <div class="container navbar-inner">
        <a href="/" class="brand">
          <img src="/images/logo.png" class="brand-logo" alt="${t('brand.name')}" />
          <span class="brand-name">${t('brand.name')}</span>
        </a>
        <nav class="nav-links">
          ${links.map((l) => `<a href="${l.to}" class="nav-link ${isActive(l.to) ? 'active' : ''}">${t(l.key)}</a>`).join('')}
        </nav>
        <div class="nav-right">
          <button id="lang-toggle" class="nav-icon-btn" type="button" title="${t('nav.toggleLang')}">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            <span class="nav-icon-label">${lang === 'en' ? 'EN' : 'ने'}</span>
          </button>
          ${me ? `
            <a href="${dashboardLink || '/'}" class="nav-icon-btn" title="${t('nav.dashboard')}">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>
            </a>
            <button id="logout-btn" class="nav-icon-btn" title="${t('nav.logout')}">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            </button>
          ` : `
            <a href="/login" class="nav-icon-btn" title="${t('nav.login')}">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            </a>
          `}
          <a href="/admin/login" class="nav-icon-btn nav-admin-icon" title="Admin">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </a>
          <button id="hamburger" class="hamburger" aria-label="Menu">☰</button>
        </div>
      </div>
      <div class="container">
        <div id="mobile-menu" class="mobile-menu">
          ${links.map((l) => `<a href="${l.to}" class="nav-link ${isActive(l.to) ? 'active' : ''}">${t(l.key)}</a>`).join('')}
          <button id="lang-toggle-m" class="lang-toggle" type="button">${t('nav.toggleLang')}</button>
          ${me ? `
            ${dashboardLink ? `<a href="${dashboardLink}" class="btn btn-primary">${t('nav.dashboard')}</a>` : ''}
            <button id="logout-btn-m" class="btn btn-outline">${t('nav.logout')}</button>
          ` : `<a href="/login" class="btn btn-primary">${t('nav.login')}</a>`}
          <a href="/admin/login" class="nav-link" style="color:var(--muted);font-size:13px;">Admin</a>
        </div>
      </div>
    </header>
  `;

  // Wire up interactions
  const toggleMenu = () => document.getElementById('mobile-menu').classList.toggle('open');
  const hamburger = document.getElementById('hamburger');
  if (hamburger) hamburger.addEventListener('click', toggleMenu);

  const toggleLang = () => setLang(lang === 'en' ? 'ne' : 'en');
  document.getElementById('lang-toggle')?.addEventListener('click', toggleLang);
  document.getElementById('lang-toggle-m')?.addEventListener('click', toggleLang);

  const doLogout = async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch {}
    window.location.href = '/';
  };
  document.getElementById('logout-btn')?.addEventListener('click', doLogout);
  document.getElementById('logout-btn-m')?.addEventListener('click', doLogout);
}

export function renderFooter() {
  const el = document.getElementById('footer');
  if (!el) return;
  el.innerHTML = `
    <footer class="footer">
      <div class="container footer-inner">
        <div>
          <div class="brand"><img src="/images/logo.png" class="brand-logo" alt="${t('brand.name')}" /><span class="brand-name">${t('brand.name')}</span></div>
          <p class="text-sm text-muted mt-2">${t('brand.tagline')} — ${t('home.heroDesc')}</p>
          <div class="footer-social">
            <a href="#" aria-label="Facebook"><svg viewBox="0 0 24 24"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg></a>
            <a href="#" aria-label="Instagram"><svg viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.741 0 8.333.014 7.053.072 2.695.272.273 2.69.073 7.052.014 8.333 0 8.741 0 12c0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98C8.333 23.986 8.741 24 12 24c3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98C15.668.014 15.259 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zM12 16a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 100 2.881 1.44 1.44 0 000-2.881z"/></svg></a>
            <a href="#" aria-label="LinkedIn"><svg viewBox="0 0 24 24"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.063 2.063 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg></a>
            <a href="#" aria-label="YouTube"><svg viewBox="0 0 24 24"><path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/></svg></a>
          </div>
        </div>
        <div>
          <h4>${t('nav.products')}</h4>
          <ul>
            <li><a href="/products">${t('nav.products')}</a></li>
            <li><a href="/market-prices">${t('nav.marketPrices')}</a></li>
            <li><a href="/about">${t('nav.about')}</a></li>
            <li><a href="/contact">${t('nav.contact')}</a></li>
          </ul>
        </div>
        <div>
          <h4>${t('nav.contact')}</h4>
          <ul>
            <li>hello@krishiconnect.np</li>
            <li>+977 1-4444444</li>
            <li>Kathmandu, Nepal</li>
          </ul>
        </div>
        <div>
          <h4>${t('home.followUs')}</h4>
          <ul>
            <li><a href="#">${t('home.privacyPolicy')}</a></li>
            <li><a href="#">${t('home.terms')}</a></li>
            <li><a href="#">${t('home.faqTitle')}</a></li>
            <li><a href="#">${t('home.helpCenter')}</a></li>
          </ul>
        </div>
      </div>
      <div class="footer-bottom">© ${new Date().getFullYear()} ${t('brand.name')}. ${t('brand.tagline')}.</div>
    </footer>
  `;
}

let _me = undefined;
export async function currentUser() {
  if (_me !== undefined) return _me;
  try {
    const data = await api('/auth/me');
    _me = data.user || null;
  } catch {
    _me = null;
  }
  return _me;
}
export function resetCurrentUser() { _me = undefined; }

// Re-render text on language change.
export function onLangChange(cb) {
  document.addEventListener('langchange', () => cb());
}
