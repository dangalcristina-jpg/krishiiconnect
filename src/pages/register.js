import { t } from '../scripts/i18n.js';
import { api, errCode } from '../scripts/api.js';
import { renderNavbar, renderFooter, currentUser, resetCurrentUser, onLangChange } from '../scripts/shared.js';

function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
}

function setError(msg) {
  const el = document.getElementById('register-error');
  if (!el) return;
  if (msg) {
    el.textContent = msg;
    el.style.display = 'block';
  } else {
    el.style.display = 'none';
  }
}

function setRole(role) {
  const farmer = document.getElementById('role-farmer');
  const wholesaler = document.getElementById('role-wholesaler');
  const biz = document.getElementById('business-field');
  if (role === 'farmer') {
    farmer.style.background = 'var(--green)';
    farmer.style.color = '#fff';
    wholesaler.style.background = '#fff';
    wholesaler.style.color = 'var(--text)';
    wholesaler.style.border = '1px solid var(--border)';
    biz.style.display = 'none';
  } else {
    wholesaler.style.background = 'var(--orange)';
    wholesaler.style.color = '#fff';
    farmer.style.background = '#fff';
    farmer.style.color = 'var(--text)';
    farmer.style.border = '1px solid var(--border)';
    biz.style.display = 'block';
  }
  farmer.dataset.role = role;
}

const errorMessages = {
  missing_fields: 'Please fill in all required fields.',
  invalid_phone: 'Please enter a valid Nepal mobile number (98XXXXXXXX).',
  invalid_pin: 'PIN must be exactly 4 digits.',
  pin_mismatch: 'PIN and Confirm PIN do not match.',
  invalid_role: 'Please select a valid role.',
  missing_business_name: 'Business Name is required for wholesalers.',
  otp_required: 'Please verify your phone number with the OTP code first.',
  invalid_otp: 'Invalid or expired OTP code. Please try again.',
  exists: 'An account with this phone number already exists.',
  cooldown: 'Please wait before requesting another OTP.',
  not_verified: 'Please verify your phone number first.',
  generic: 'Something went wrong. Please try again.',
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
  await renderNavbar('/register');
  renderFooter();
  applyTranslations();

  const me = await currentUser();
  if (me) {
    redirectByRole(me);
    return;
  }

  let role = 'farmer';
  let phoneVerified = false;
  const params = new URLSearchParams(window.location.search);
  if (params.get('role') === 'wholesaler') {
    role = 'wholesaler';
  }
  setRole(role);

  document.getElementById('role-farmer').addEventListener('click', () => {
    role = 'farmer';
    setRole(role);
  });
  document.getElementById('role-wholesaler').addEventListener('click', () => {
    role = 'wholesaler';
    setRole(role);
  });

  // OTP send
  const sendOtpBtn = document.getElementById('send-otp-btn');
  const otpField = document.getElementById('otp-field');
  const otpHint = document.getElementById('otp-hint');
  sendOtpBtn.addEventListener('click', async () => {
    setError(null);
    const phone = document.getElementById('phone').value.trim();
    if (!phone) { setError('Please enter your phone number first.'); return; }
    sendOtpBtn.disabled = true;
    sendOtpBtn.textContent = 'Sending...';
    try {
      const data = await api('/auth/send-otp', { method: 'POST', body: { phone, purpose: 'register' } });
      otpField.style.display = 'block';
      phoneVerified = false;
      if (data.demo_code) {
        otpHint.textContent = `Demo mode: your OTP is ${data.demo_code}`;
        otpHint.style.color = 'var(--green)';
      }
      cooldownTimer(sendOtpBtn, data.cooldown || 30);
    } catch (err) {
      const code = errCode(err);
      setError(errorMessages[code] || errorMessages.generic);
      sendOtpBtn.disabled = false;
      sendOtpBtn.textContent = 'Send OTP';
    }
  });

  // OTP verify
  const verifyOtpBtn = document.getElementById('verify-otp-btn');
  verifyOtpBtn.addEventListener('click', async () => {
    setError(null);
    const phone = document.getElementById('phone').value.trim();
    const otp_code = document.getElementById('otp_code').value.trim();
    if (!otp_code) { setError('Please enter the OTP code.'); return; }
    verifyOtpBtn.disabled = true;
    verifyOtpBtn.textContent = 'Verifying...';
    try {
      await api('/auth/verify-otp', { method: 'POST', body: { phone, code: otp_code, purpose: 'register' } });
      phoneVerified = true;
      otpHint.textContent = 'Phone verified!';
      otpHint.style.color = 'var(--green)';
      verifyOtpBtn.textContent = 'Verified';
      verifyOtpBtn.style.background = 'var(--green)';
      verifyOtpBtn.style.color = '#fff';
      verifyOtpBtn.style.borderColor = 'var(--green)';
    } catch (err) {
      const code = errCode(err);
      setError(errorMessages[code] || errorMessages.invalid_otp);
      phoneVerified = false;
      verifyOtpBtn.disabled = false;
      verifyOtpBtn.textContent = 'Verify';
    }
  });

  const form = document.getElementById('register-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    setError(null);

    const full_name = form.full_name.value.trim();
    const phone = form.phone.value.trim();
    const pin = form.pin.value.trim();
    const confirm_pin = form.confirm_pin.value.trim();
    const business_name = role === 'wholesaler' ? form.business_name.value.trim() : undefined;
    const otp_code = form.otp_code ? form.otp_code.value.trim() : '';

    if (!full_name) { setError('Full Name is required.'); return; }
    if (!phone) { setError('Phone Number is required.'); return; }
    if (!/^\d{4}$/.test(pin)) { setError('PIN must be exactly 4 digits.'); return; }
    if (pin !== confirm_pin) { setError('PIN and Confirm PIN do not match.'); return; }
    if (role === 'wholesaler' && !business_name) { setError('Business Name is required for wholesalers.'); return; }
    if (!phoneVerified) { setError('Please verify your phone number with the OTP code first.'); return; }

    const submit = document.getElementById('register-submit');
    submit.disabled = true;
    submit.textContent = t('common.loading');
    try {
      await api('/auth/register', { method: 'POST', body: { full_name, phone, pin, confirm_pin, role, business_name, otp_code } });
      document.getElementById('register-success').style.display = 'block';
      setTimeout(() => {
        window.location.href = role === 'farmer' ? '/farmer' : '/wholesaler';
      }, 800);
    } catch (err) {
      const code = errCode(err);
      setError(errorMessages[code] || errorMessages.generic);
      submit.disabled = false;
      submit.textContent = t('auth.register');
    }
  });

  onLangChange(async () => {
    await renderNavbar('/register');
    renderFooter();
    applyTranslations();
  });
}

function redirectByRole(user) {
  if (user.role === 'admin') window.location.href = '/admin';
  else if (user.role === 'farmer') window.location.href = '/farmer';
  else window.location.href = '/wholesaler';
}

init();
