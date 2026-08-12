import { renderNavbar, renderFooter, resetCurrentUser, onLangChange } from '../scripts/shared.js';
import { ARTICLES, getArticle, getRelatedArticles } from '../scripts/articles.js';

function getSlugFromUrl() {
  const parts = window.location.pathname.split('/');
  const idx = parts.indexOf('articles');
  if (idx !== -1 && parts[idx + 1]) return decodeURIComponent(parts[idx + 1]);
  return null;
}

function renderArticle(article) {
  const root = document.getElementById('article-root');
  if (!article) {
    root.innerHTML = `
      <div class="container" style="padding:80px 16px;text-align:center;">
        <h1 style="font-size:2rem;margin-bottom:12px;">Article not found</h1>
        <p class="text-muted" style="margin-bottom:24px;">The article you are looking for does not exist.</p>
        <a href="/" class="btn btn-primary">Back to Home</a>
      </div>
    `;
    return;
  }

  const related = getRelatedArticles(article.slug, 3);

  root.innerHTML = `
    <article class="article-page">
      <div class="article-hero" style="background-image:url('${article.heroImage}')">
        <div class="article-hero-overlay"></div>
        <div class="container article-hero-content">
          <div class="article-hero-icon">${article.icon}</div>
          <h1 class="article-title">${article.title}</h1>
          <div class="article-meta">
            <span class="article-date">📅 ${article.date}</span>
            <span class="article-author">Krishi Connect</span>
          </div>
        </div>
      </div>
      <div class="container article-body-wrap">
        <a href="/" class="btn btn-outline btn-sm article-back-btn">← Back to Articles</a>
        <p class="article-excerpt">${article.excerpt}</p>
        ${article.sections.map((s) => `
          <section class="article-section">
            <h2>${s.heading}</h2>
            <p>${s.body}</p>
          </section>
        `).join('')}
        <section class="article-tips">
          <h2>💡 Tips for Nepali Farmers</h2>
          <ul>
            ${article.tips.map((tip) => `<li>${tip}</li>`).join('')}
          </ul>
        </section>
        <section class="article-related">
          <h2>Related Articles</h2>
          <div class="news-grid">
            ${related.map((a) => `
              <a href="/articles/${a.slug}" class="news-card">
                <div class="news-icon">${a.icon}</div>
                <div class="news-body">
                  <div class="news-date">${a.date}</div>
                  <h3>${a.title}</h3>
                  <p class="text-muted text-sm">${a.excerpt}</p>
                  <span class="news-read-more">Read more →</span>
                </div>
              </a>
            `).join('')}
          </div>
        </section>
      </div>
    </article>
  `;

  document.title = `${article.title} — Krishi Connect`;
  window.scrollTo(0, 0);
}

function initBackToTop() {
  const btn = document.getElementById('back-to-top');
  if (!btn) return;
  window.addEventListener('scroll', () => {
    btn.classList.toggle('visible', window.scrollY > 400);
  });
  btn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
}

async function init() {
  resetCurrentUser();
  await renderNavbar('/');
  renderFooter();
  const slug = getSlugFromUrl();
  renderArticle(getArticle(slug));
  initBackToTop();
  onLangChange(async () => {
    await renderNavbar('/');
    renderFooter();
  });
}

init();
