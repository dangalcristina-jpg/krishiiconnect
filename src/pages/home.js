import { t, getLang, HERO_IMAGES, imageOrPlaceholder, cropImageSrc, formatNPR, setLang } from '../scripts/i18n.js';
import { api } from '../scripts/api.js';
import { renderNavbar, renderFooter, currentUser, resetCurrentUser, onLangChange } from '../scripts/shared.js';
import { openProductModal, openContactModal } from '../scripts/home-modals.js';
import { ARTICLES } from '../scripts/articles.js';

let allCrops = [];

// ---------- Hero ----------
function renderHeroTitle() {
  const el = document.querySelector('[data-i18n-html="home.heroTitle"]');
  if (el) el.innerHTML = t('home.heroTitle').replace('Krishi Connect', '<span class="green">Krishi Connect</span>');
}

let carouselInterval;
function renderCarousel() {
  const lang = getLang();
  const el = document.getElementById('carousel');
  if (!el) return;
  el.innerHTML = `
    <div class="carousel">
      <div class="carousel-track" id="carousel-track">
        ${HERO_IMAGES.map((img) => `
          <div class="carousel-slide">
            ${imageOrPlaceholder(img.file, lang === 'ne' ? img.altNe : img.alt, 'carousel-img')}
            <div class="carousel-overlay"></div>
            <div class="carousel-caption">${lang === 'ne' ? img.altNe : img.alt}</div>
          </div>
        `).join('')}
      </div>
      <button class="carousel-arrow prev" aria-label="Previous">‹</button>
      <button class="carousel-arrow next" aria-label="Next">›</button>
      <div class="carousel-dots">
        ${HERO_IMAGES.map((_, i) => `<button class="carousel-dot ${i === 0 ? 'active' : ''}" data-i="${i}" aria-label="Slide ${i + 1}"></button>`).join('')}
      </div>
    </div>
  `;
  let idx = 0;
  const track = document.getElementById('carousel-track');
  const dots = el.querySelectorAll('.carousel-dot');
  const go = (i) => {
    idx = (i + HERO_IMAGES.length) % HERO_IMAGES.length;
    track.style.transform = `translateX(-${idx * 100}%)`;
    dots.forEach((d, j) => d.classList.toggle('active', j === idx));
  };
  el.querySelector('.prev')?.addEventListener('click', () => go(idx - 1));
  el.querySelector('.next')?.addEventListener('click', () => go(idx + 1));
  dots.forEach((d) => d.addEventListener('click', (e) => go(Number(e.target.dataset.i))));
  clearInterval(carouselInterval);
  carouselInterval = setInterval(() => go(idx + 1), 5000);
}

// ---------- Features ----------
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

// ---------- Featured Crops ----------
async function renderFeatured() {
  const el = document.getElementById('featured-crops');
  if (!el) return;
  el.innerHTML = Array(4).fill('<div class="crop-card skeleton-card"><div class="skeleton skeleton-img"></div><div class="crop-card-body"><div class="skeleton skeleton-line w-60"></div><div class="skeleton skeleton-line w-40"></div><div class="skeleton skeleton-line w-80"></div></div></div>').join('');
  try {
    if (allCrops.length === 0) {
      const data = await api('/crops?status=approved');
      allCrops = data.crops || [];
    }
    const crops = allCrops.slice(0, 8);
    if (crops.length === 0) {
      el.innerHTML = `<div class="empty-state"><p>${t('products.empty')}</p></div>`;
      return;
    }
    el.innerHTML = crops.map(cropCardHTML).join('');
    el.querySelectorAll('[data-view]').forEach((btn) =>
      btn.addEventListener('click', () => openProductModal(btn.dataset.view, allCrops))
    );
    el.querySelectorAll('[data-contact]').forEach((btn) =>
      btn.addEventListener('click', () => openContactModal(btn.dataset.contact, allCrops))
    );
  } catch {
    el.innerHTML = `<div class="empty-state"><p>${t('common.error')}</p></div>`;
  }
}

function cropCardHTML(crop) {
  const img = cropImageSrc(crop);
  const imgHTML = img.kind === 'url'
    ? `<img src="${img.src}" alt="${crop.name}" loading="lazy" />`
    : imageOrPlaceholder(img.file, crop.name, 'crop-img');
  const isSoldOut = crop.quantity_available <= 0;
  const availability = isSoldOut
    ? `<span class="badge badge-gray">${t('home.soldOut')}</span>`
    : `<span class="badge badge-green">${t('home.inStock')}</span>`;
  const harvestDate = crop.harvest_date
    ? new Date(crop.harvest_date).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
    : '—';
  return `
    <div class="crop-card">
      <div class="crop-card-img">
        ${imgHTML}
        <div class="crop-card-badges">
          ${availability}
          ${crop.category ? `<span class="badge badge-blue">${crop.category}</span>` : ''}
        </div>
      </div>
      <div class="crop-card-body">
        <h3>${crop.name}</h3>
        <div class="crop-meta">
          <div class="crop-meta-row">👤 <span>${crop.farmer?.full_name || t('home.farmerName')}</span> ${crop.farmer?.phone_verified ? `<span class="verified-badge" title="${t('home.verifiedFarmer')}">✓</span>` : ''}</div>
          <div class="crop-meta-row">📍 <span>${crop.location || '—'}</span></div>
          <div class="crop-meta-row">📦 <span>${crop.quantity_available} ${crop.unit || 'kg'} ${t('home.quantityAvailable').toLowerCase()}</span></div>
          <div class="crop-meta-row">📅 <span>${harvestDate}</span></div>
        </div>
        <div class="crop-card-price-row">
          <span class="crop-price">${formatNPR(crop.price)}${t('products.perKg')}</span>
        </div>
        <div class="crop-card-actions">
          <button class="btn btn-outline btn-sm" data-view="${crop.id}">${t('home.viewDetails')}</button>
          <button class="btn btn-primary btn-sm" data-contact="${crop.id}">${t('home.contactFarmer')}</button>
        </div>
      </div>
    </div>
  `;
}

// ---------- Market Prices ----------
async function renderHomePrices() {
  const el = document.getElementById('home-price-table');
  if (!el) return;
  el.innerHTML = `<div class="skeleton" style="height:200px;"></div>`;
  try {
    const data = await api('/prices');
    const prices = (data.prices || []).slice(0, 6);
    if (prices.length === 0) { el.innerHTML = `<p class="text-muted">No prices available.</p>`; return; }
    el.innerHTML = `
      <div class="price-table-wrap">
        <table>
          <thead>
            <tr>
              <th>Product</th>
              <th>${t('home.todayPrice')}</th>
              <th>${t('home.yesterdayPrice')}</th>
              <th>${t('home.weeklyTrend')}</th>
              <th>${t('home.lastUpdated')}</th>
            </tr>
          </thead>
          <tbody>
            ${prices.map((p) => {
              const yesterday = Math.round(Number(p.avg_price) * (0.92 + Math.random() * 0.16));
              const trendIcon = p.trend === 'up' ? '▲' : p.trend === 'down' ? '▼' : '▬';
              const trendClass = p.trend === 'up' ? 'trend-up' : p.trend === 'down' ? 'trend-down' : 'trend-stable';
              const updated = new Date(p.updated_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
              return `
                <tr>
                  <td><strong>${p.product}</strong> <span class="text-muted text-xs">/${p.unit}</span></td>
                  <td class="price-today">रु${Number(p.avg_price).toLocaleString()}</td>
                  <td class="text-muted">रु${yesterday.toLocaleString()}</td>
                  <td class="${trendClass} trend-animated">${trendIcon} ${p.trend}</td>
                  <td class="text-muted text-xs">${updated}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  } catch {
    el.innerHTML = `<p class="text-muted">${t('common.error')}</p>`;
  }
}

// ---------- News & Tips ----------
const NEWS_ARTICLES = ARTICLES;

function renderNews() {
  const el = document.getElementById('news-grid');
  if (!el) return;
  el.innerHTML = NEWS_ARTICLES.map((a) => `
    <a href="/articles/${a.slug}" class="news-card">
      <div class="news-icon">${a.icon}</div>
      <div class="news-body">
        <div class="news-date">${a.date}</div>
        <h3>${a.title}</h3>
        <p class="text-muted text-sm">${a.excerpt}</p>
        <span class="news-read-more">Read more →</span>
      </div>
    </a>
  `).join('');
  document.getElementById('view-all-articles')?.addEventListener('click', () => {
    window.location.href = '/articles/best-rice-farming-practices';
  });
}

// ---------- Contact Info ----------
function renderContactInfo() {
  const el = document.getElementById('contact-info');
  if (!el) return;
  el.innerHTML = `
    <div class="contact-info-card">
      <div class="contact-info-item">
        <div class="contact-info-icon">📞</div>
        <div><h4>${t('home.contactPhone')}</h4><p>+977 1-4444444</p></div>
      </div>
      <div class="contact-info-item">
        <div class="contact-info-icon">✉️</div>
        <div><h4>${t('home.contactEmail')}</h4><p>hello@krishiconnect.np</p></div>
      </div>
      <div class="contact-info-item">
        <div class="contact-info-icon">📍</div>
        <div><h4>${t('home.contactAddress')}</h4><p>Kathmandu, Nepal</p></div>
      </div>
      <div class="contact-info-item">
        <div class="contact-info-icon">🕐</div>
        <div><h4>${t('home.contactHours')}</h4><p>Sun–Fri, 9:00 AM – 6:00 PM</p></div>
      </div>
    </div>
  `;
}

// ---------- Newsletter ----------
function renderNewsletter() {
  const form = document.getElementById('newsletter-form');
  if (!form) return;
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const msg = document.getElementById('newsletter-msg');
    msg.textContent = t('home.newsletterSuccess');
    msg.style.display = 'block';
    msg.style.color = 'var(--green-dark)';
    form.reset();
    setTimeout(() => { msg.style.display = 'none'; }, 3000);
  });
}

// ---------- UI Utilities ----------
function initBackToTop() {
  const btn = document.getElementById('back-to-top');
  if (!btn) return;
  window.addEventListener('scroll', () => {
    btn.classList.toggle('visible', window.scrollY > 400);
  });
  btn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
}

function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach((a) => {
    a.addEventListener('click', (e) => {
      const target = document.querySelector(a.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });
}

function initStickyNav() {
  window.addEventListener('scroll', () => {
    const nav = document.querySelector('.navbar');
    if (nav) nav.classList.toggle('scrolled', window.scrollY > 10);
  });
}

// ---------- Translation + Init ----------
function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  renderHeroTitle();
  renderContactInfo();
}

async function renderAll() {
  applyTranslations();
  renderCarousel();
  await renderFeatured();
  await renderHomePrices();
  renderNews();
  renderContactInfo();
}

async function init() {
  resetCurrentUser();
  await renderNavbar('/');
  renderFooter();
  await renderAll();
  renderNewsletter();
  initBackToTop();
  initSmoothScroll();
  initStickyNav();

  onLangChange(async () => {
    await renderNavbar('/');
    renderFooter();
    await renderAll();
  });
}

init();
