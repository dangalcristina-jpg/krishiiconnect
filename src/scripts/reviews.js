import { t, formatNPR, timeAgo } from './i18n.js';
import { api } from './api.js';
import { emptyState, statusBadge } from './dashboard.js';

// Render N gold stars (filled) + (5-N) empty stars as a single inline string.
export function starRow(rating) {
  const r = Math.max(0, Math.min(5, Number(rating) || 0));
  let out = '';
  for (let i = 1; i <= 5; i++) {
    out += i <= r ? '<span class="star">★</span>' : '<span class="star empty">★</span>';
  }
  return out;
}

// Fetch reviews received by a given user id. Returns { reviews, average, count }.
export async function fetchReviewsFor(userId) {
  try {
    const data = await api(`/reviews?user_id=${encodeURIComponent(userId)}`);
    return { reviews: data.reviews || [], average: data.average || 0, count: data.count || 0 };
  } catch {
    return { reviews: [], average: 0, count: 0 };
  }
}

// Render a compact "average rating" badge for use on profile cards / crop listings.
export function ratingBadge({ average, count }) {
  if (!count) return `<span class="rating-badge none">${t('reviews.noReviews')}</span>`;
  return `
    <span class="rating-badge">
      <span class="stars-inline">${starRow(Math.round(average))}</span>
      <span class="rating-text">${t('reviews.average', { avg: average.toFixed(1), count })}</span>
    </span>
  `;
}

// Render a list of individual reviews (newest first) inside a container.
// `heading` is the title to show above the list. Shows up to `limit` reviews,
// and a "See all reviews" toggle if there are more.
export function renderReviewList(container, reviews, { heading, limit = 3 }) {
  container.innerHTML = `<h3 class="block-title">${heading}</h3><div id="rev-list"></div>`;
  const list = container.querySelector('#rev-list');
  if (!reviews.length) {
    list.appendChild(emptyState({ title: t('reviews.noReviews') }));
    return;
  }
  const shown = reviews.slice(0, limit);
  list.innerHTML = shown.map(reviewCardHTML).join('');
  if (reviews.length > limit) {
    const btn = document.createElement('button');
    btn.className = 'btn btn-outline btn-sm';
    btn.style.marginTop = '12px';
    btn.textContent = t('reviews.seeAll');
    btn.addEventListener('click', () => {
      list.innerHTML = reviews.map(reviewCardHTML).join('');
      btn.remove();
    });
    list.appendChild(btn);
  }
}

function reviewCardHTML(r) {
  const reviewerName = r.reviewer?.full_name || t('reviews.you');
  const order = r.order;
  const date = new Date(r.created_at).toLocaleDateString();
  const amount = order?.crop ? formatNPR(Number(order.crop.price) * Number(order.quantity)) : '';
  const orderDate = order ? new Date(order.created_at).toLocaleDateString() : '';
  const label = t('reviews.verified') + (amount ? ` — ${amount}` : '') + (orderDate ? ` ${t('reviews.orderOn', { date: orderDate })}` : '');
  return `
    <div class="review-card">
      <div class="review-head">
        <div class="review-stars">${starRow(r.rating)}</div>
        <div class="review-meta">
          <span class="review-author">${t('reviews.by', { name: reviewerName })}</span>
          <span class="review-date">${timeAgo(r.created_at)}</span>
        </div>
      </div>
      <div class="review-verified">${label}</div>
      ${r.comment ? `<p class="review-comment">${escapeHTML(r.comment)}</p>` : ''}
    </div>
  `;
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Modal-based "leave a review" flow. Fetches the caller's eligible completed
// orders and lets them pick one + enter a rating + optional comment.
export async function openLeaveReviewModal({ onDone }) {
  let eligible = [];
  try {
    const data = await api('/reviews/eligible');
    eligible = data.orders || [];
  } catch {
    eligible = [];
  }

  const root = document.createElement('div');
  root.id = 'modal-root';
  document.body.appendChild(root);
  root.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head">
          <h3>${t('reviews.leaveReview')}</h3>
          <button class="modal-close" data-close>✕</button>
        </div>
        <div class="modal-body">
          <p class="text-muted mb-4">${t('reviews.leaveReviewDesc')}</p>
          ${eligible.length === 0
            ? `<p class="text-muted">${t('reviews.noEligible')}</p>`
            : `
              <div class="field">
                <label>${t('reviews.selectOrder')}</label>
                <select id="rev-order">
                  ${eligible.map((o) => `
                    <option value="${o.id}">
                      ${o.crop?.name ?? '—'} · ${formatNPR(o.crop ? Number(o.crop.price) * Number(o.quantity) : 0)} · ${new Date(o.created_at).toLocaleDateString()}
                    </option>
                  `).join('')}
                </select>
              </div>
              <div class="field">
                <label>${t('reviews.rating')}</label>
                <div class="star-input" id="star-input">
                  ${[1, 2, 3, 4, 5].map((n) => `<button type="button" class="star-btn" data-val="${n}">★</button>`).join('')}
                </div>
              </div>
              <div class="field">
                <label>${t('reviews.comment')}</label>
                <textarea id="rev-comment" rows="4" maxlength="500"></textarea>
              </div>
              <p id="rev-error" class="form-error" style="display:none;"></p>
              <div class="flex gap-2 mt-4">
                <button class="btn btn-outline" style="flex:1" data-close>${t('reviews.cancel')}</button>
                <button id="rev-submit" class="btn btn-primary" style="flex:1" disabled>${t('reviews.submit')}</button>
              </div>
            `}
        </div>
      </div>
    </div>
  `;
  const close = () => { root.remove(); };
  root.querySelector('[data-close]').addEventListener('click', close);
  root.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) close();
  });

  if (eligible.length === 0) return;

  let chosenRating = 0;
  const submitBtn = root.querySelector('#rev-submit');
  const starBtns = root.querySelectorAll('.star-btn');
  starBtns.forEach((b) => {
    b.addEventListener('click', () => {
      chosenRating = Number(b.dataset.val);
      starBtns.forEach((bb) => bb.classList.toggle('filled', Number(bb.dataset.val) <= chosenRating));
      submitBtn.disabled = false;
    });
  });

  submitBtn.addEventListener('click', async () => {
    const orderId = root.querySelector('#rev-order').value;
    const comment = root.querySelector('#rev-comment').value;
    const errEl = root.querySelector('#rev-error');
    errEl.style.display = 'none';
    try {
      await api('/reviews', { method: 'POST', body: { order_id: orderId, rating: chosenRating, comment } });
      root.querySelector('.modal-body').innerHTML = `<p class="font-semibold" style="color:var(--green-dark);text-align:center;padding:24px;">${t('reviews.success')}</p>`;
      setTimeout(() => { close(); if (onDone) onDone(); }, 1200);
    } catch (e) {
      errEl.textContent = t('reviews.error');
      errEl.style.display = 'block';
    }
  });
}
