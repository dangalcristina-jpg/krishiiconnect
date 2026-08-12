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

const errorMessages = {
  invalid_creds: 'Invalid phone number or PIN.',
  suspended: 'Your account has been suspended. Please contact support.',
  generic: 'Something went wrong. Please try again.',
  missing_fields: 'Please fill in all fields.',
  invalid_phone: 'Please enter a valid Nepal mobile number.',
  invalid_pin: 'PIN must be exactly 4 digits.',
  pin_mismatch: 'PIN and Confirm PIN do not match.',
  invalid_otp: 'Invalid or expired OTP code. Please try again.',
  not_found: 'No account found with this phone number.',
  cooldown: 'Please wait before requesting another OTP.',
};

function cooldownTimer(btn, seconds) {
  let remaining = seconds;
  btn.disabled = true;
  btn.textContent = `Resend (${remaining}s)`;
  const interval = setInterval(() => {
    remaining--;
    if (remaining <= 0) {
      clearInterval(interval);
      btn.disabled = false;
      btn.textContent = 'Resend OTP';
    } else {
      btn.textContent = `Resend (${remaining}s)`;
    }
  }, 1000);
}

async function init() {
  resetCurrentUser();
  await renderNavbar('/login');
  renderFooter();
  applyTranslations();

  const me = await currentUser();
  if (me) {
    redirectByRole(me);
    return;
  }

  const form = document.getElementById('login-form');
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
      redirectByRole(data.user);
    } catch (err) {
      const code = errCode(err);
      setError(errorMessages[code] || errorMessages.generic);
      submit.disabled = false;
      submit.textContent = t('auth.login');
    }
  });

  // Forgot PIN flow
  const forgotLink = document.getElementById('forgot-pin-link');
  if (forgotLink) {
    forgotLink.addEventListener('click', (e) => {
      e.preventDefault();
      openForgotPinModal();
    });
  }

  onLangChange(async () => {
    await renderNavbar('/login');
    renderFooter();
    applyTranslations();
  });
}

function redirectByRole(user) {
  if (user.role === 'admin') window.location.href = '/admin';
  else if (user.role === 'farmer') window.location.href = '/farmer';
  else window.location.href = '/wholesaler';
}

let forgotRoot;
function openForgotPinModal() {
  if (!forgotRoot) {
    forgotRoot = document.createElement('div');
    forgotRoot.id = 'forgot-root';
    document.body.appendChild(forgotRoot);
  }
  let phoneVerified = false;
  forgotRoot.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal" style="max-width:440px;">
        <div class="modal-head">
          <h3>Reset PIN</h3>
          <button class="modal-close" data-close>✕</button>
        </div>
        <div class="modal-body">
          <div class="field">
            <label>Phone Number</label>
            <div class="otp-row">
              <input id="fp-phone" type="tel" inputmode="numeric" placeholder="98XXXXXXXX" />
              <button type="button" id="fp-send-otp" class="btn btn-outline btn-sm">Send OTP</button>
            </div>
          </div>
          <div class="field" id="fp-otp-field" style="display:none;">
            <label>OTP Code</label>
            <div class="otp-row">
              <input id="fp-otp" type="text" inputmode="numeric" maxlength="4" placeholder="4-digit code" />
              <button type="button" id="fp-verify-otp" class="btn btn-outline btn-sm">Verify</button>
            </div>
            <p class="field-hint" id="fp-otp-hint"></p>
          </div>
          <div class="form-row two" id="fp-pin-fields" style="display:none;">
            <div class="field">
              <label>New PIN</label>
              <input id="fp-new-pin" type="password" inputmode="numeric" maxlength="4" placeholder="••••" />
            </div>
            <div class="field">
              <label>Confirm PIN</label>
              <input id="fp-confirm-pin" type="password" inputmode="numeric" maxlength="4" placeholder="••••" />
            </div>
          </div>
          <p id="fp-error" class="form-error" style="display:none;"></p>
          <button type="button" id="fp-submit" class="btn btn-primary btn-block mt-2" style="display:none;">Reset PIN</button>
        </div>
      </div>
    </div>
  `;
  const close = () => { forgotRoot.innerHTML = ''; };
  forgotRoot.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', close));
  forgotRoot.querySelector('.modal-backdrop').addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-backdrop')) close();
  });

  const fpError = forgotRoot.querySelector('#fp-error');
  function fpSetError(msg) {
    if (msg) { fpError.textContent = msg; fpError.style.display = 'block'; }
    else fpError.style.display = 'none';
  }

  // Send OTP
  forgotRoot.querySelector('#fp-send-otp').addEventListener('click', async () => {
    fpSetError(null);
    const phone = forgotRoot.querySelector('#fp-phone').value.trim();
    if (!phone) { fpSetError('Please enter your phone number.'); return; }
    const btn = forgotRoot.querySelector('#fp-send-otp');
    btn.disabled = true;
    btn.textContent = 'Sending...';
    try {
      const data = await api('/auth/send-otp', { method: 'POST', body: { phone, purpose: 'reset_pin' } });
      forgotRoot.querySelector('#fp-otp-field').style.display = 'block';
      phoneVerified = false;
      const hint = forgotRoot.querySelector('#fp-otp-hint');
      if (data.demo_code) {
        hint.textContent = `Demo mode: your OTP is ${data.demo_code}`;
        hint.style.color = 'var(--green)';
      }
      cooldownTimer(btn, data.cooldown || 30);
    } catch (err) {
      const code = errCode(err);
      fpSetError(errorMessages[code] || errorMessages.generic);
      btn.disabled = false;
      btn.textContent = 'Send OTP';
    }
  });

  // Verify OTP
  forgotRoot.querySelector('#fp-verify-otp').addEventListener('click', async () => {
    fpSetError(null);
    const phone = forgotRoot.querySelector('#fp-phone').value.trim();
    const otp = forgotRoot.querySelector('#fp-otp').value.trim();
    if (!otp) { fpSetError('Please enter the OTP code.'); return; }
    const btn = forgotRoot.querySelector('#fp-verify-otp');
    btn.disabled = true;
    btn.textContent = 'Verifying...';
    try {
      await api('/auth/verify-otp', { method: 'POST', body: { phone, code: otp, purpose: 'reset_pin' } });
      phoneVerified = true;
      const hint = forgotRoot.querySelector('#fp-otp-hint');
      hint.textContent = 'Phone verified! Set your new PIN.';
      hint.style.color = 'var(--green)';
      btn.textContent = 'Verified';
      btn.style.background = 'var(--green)';
      btn.style.color = '#fff';
      btn.style.borderColor = 'var(--green)';
      forgotRoot.querySelector('#fp-pin-fields').style.display = 'grid';
      forgotRoot.querySelector('#fp-submit').style.display = 'block';
    } catch (err) {
      const code = errCode(err);
      fpSetError(errorMessages[code] || errorMessages.invalid_otp);
      phoneVerified = false;
      btn.disabled = false;
      btn.textContent = 'Verify';
    }
  });

  // Submit new PIN
  forgotRoot.querySelector('#fp-submit').addEventListener('click', async () => {
    fpSetError(null);
    const phone = forgotRoot.querySelector('#fp-phone').value.trim();
    const newPin = forgotRoot.querySelector('#fp-new-pin').value.trim();
    const confirmPin = forgotRoot.querySelector('#fp-confirm-pin').value.trim();
    if (!/^\d{4}$/.test(newPin)) { fpSetError('PIN must be exactly 4 digits.'); return; }
    if (newPin !== confirmPin) { fpSetError('PIN and Confirm PIN do not match.'); return; }
    const btn = forgotRoot.querySelector('#fp-submit');
    btn.disabled = true;
    btn.textContent = 'Resetting...';
    try {
      const otp = forgotRoot.querySelector('#fp-otp').value.trim();
      await api('/auth/reset-pin', { method: 'POST', body: { phone, otp_code: otp, new_pin: newPin, confirm_pin: confirmPin } });
      close();
      setError('PIN reset successfully. You can now log in with your new PIN.');
      document.getElementById('login-error').style.color = 'var(--green)';
    } catch (err) {
      const code = errCode(err);
      fpSetError(errorMessages[code] || errorMessages.generic);
      btn.disabled = false;
      btn.textContent = 'Reset PIN';
    }
  });
}

init();
