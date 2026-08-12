import { t } from '../scripts/i18n.js';
import { api, errCode } from '../scripts/api.js';
import { renderNavbar, renderFooter, currentUser, resetCurrentUser, onLangChange } from '../scripts/shared.js';

function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
}

function setError(msg) {
  const el = document.getElementById('login-error');
  if (!el) return;
  if (msg) {
    el.textContent = msg;
    el.style.display = 'block';
  } else {
    el.style.display = 'none';
  }
}

async function init() {
  resetCurrentUser();
  await renderNavbar('/admin/login');
  renderFooter();
  applyTranslations();

  const me = await currentUser();
  if (me) {
    window.location.href = me.role === 'admin' ? '/admin' : '/';
    return;
  }

  const form = document.getElementById('admin-login-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    setError(null);
    const submit = document.getElementById('login-submit');
    submit.disabled = true;
    submit.textContent = t('common.loading');
    const phone = form.phone.value.trim();
    const pin = form.pin.value.trim();
    try {
      const data = await api('/auth/login', { method: 'POST', body: { phone, pin } });
      if (data.user.role !== 'admin') {
        setError(t('auth.invalidCreds'));
        // Log out the non-admin session we just created
        try { await api('/auth/logout', { method: 'POST' }); } catch {}
        submit.disabled = false;
        submit.textContent = t('auth.login');
        return;
      }
      window.location.href = '/admin';
    } catch (err) {
      const code = errCode(err);
      setError(t(code === 'invalid_creds' ? 'auth.invalidCreds' : code === 'suspended' ? 'auth.suspended' : 'auth.genericError'));
      submit.disabled = false;
      submit.textContent = t('auth.login');
    }
  });

  onLangChange(async () => {
    await renderNavbar('/admin/login');
    renderFooter();
    applyTranslations();
  });
}

init();
