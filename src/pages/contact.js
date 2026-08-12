import { t } from '../scripts/i18n.js';
import { api } from '../scripts/api.js';
import { renderNavbar, renderFooter, resetCurrentUser, onLangChange } from '../scripts/shared.js';

function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
}

function setStatus(kind, msg) {
  const el = document.getElementById('contact-status');
  if (!el) return;
  el.style.display = 'block';
  el.textContent = msg;
  el.className = kind === 'ok' ? 'form-success' : 'form-error';
}

async function init() {
  resetCurrentUser();
  await renderNavbar('/contact');
  renderFooter();
  applyTranslations();

  const form = document.getElementById('contact-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const submitBtn = document.getElementById('contact-submit');
    submitBtn.disabled = true;
    submitBtn.textContent = t('common.loading');
    const name = form.name.value.trim();
    const email = form.email.value.trim();
    const message = form.message.value.trim();
    try {
      await api('/contacts', { method: 'POST', body: { name, email, message } });
      setStatus('ok', t('contact.success'));
      form.reset();
    } catch {
      setStatus('err', t('contact.error'));
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = t('contact.submit');
    }
  });

  onLangChange(async () => {
    await renderNavbar('/contact');
    renderFooter();
    applyTranslations();
  });
}

init();
