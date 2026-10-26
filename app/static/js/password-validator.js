/**
 * Blogg - Real-time Password Requirements & Strength Validator
 * Dynamically validates password complexity requirements on input.
 */
document.addEventListener('DOMContentLoaded', function () {
  const passwordInput = document.getElementById('password');
  if (!passwordInput) return;

  const confirmPasswordInput = document.getElementById('password2');

  // Create Requirements Card DOM
  const requirementsCard = document.createElement('div');
  requirementsCard.className = 'password-requirements-card';
  requirementsCard.id = 'password-requirements-panel';
  requirementsCard.setAttribute('aria-live', 'polite');

  requirementsCard.innerHTML = `
    <div class="password-strength-header">
      <span class="password-strength-title">Password requirements</span>
      <span class="password-strength-badge" id="password-strength-badge">0 / 5</span>
    </div>
    <div class="password-strength-meter" aria-hidden="true">
      <div class="password-strength-bar" id="str-bar-1"></div>
      <div class="password-strength-bar" id="str-bar-2"></div>
      <div class="password-strength-bar" id="str-bar-3"></div>
      <div class="password-strength-bar" id="str-bar-4"></div>
      <div class="password-strength-bar" id="str-bar-5"></div>
    </div>
    <ul class="requirements-list">
      <li id="req-length" class="req-item unmet">
        <span class="req-icon" aria-hidden="true">✕</span>
        <span class="req-text">At least 8 characters</span>
      </li>
      <li id="req-uppercase" class="req-item unmet">
        <span class="req-icon" aria-hidden="true">✕</span>
        <span class="req-text">One uppercase letter (A-Z)</span>
      </li>
      <li id="req-lowercase" class="req-item unmet">
        <span class="req-icon" aria-hidden="true">✕</span>
        <span class="req-text">One lowercase letter (a-z)</span>
      </li>
      <li id="req-number" class="req-item unmet">
        <span class="req-icon" aria-hidden="true">✕</span>
        <span class="req-text">One number (0-9)</span>
      </li>
      <li id="req-special" class="req-item unmet">
        <span class="req-icon" aria-hidden="true">✕</span>
        <span class="req-text">One special character (!@#$%^&*...)</span>
      </li>
    </ul>
  `;

  // Insert after the password field's form-group or the password input
  const passwordGroup = passwordInput.closest('.form-group') || passwordInput.parentElement;
  if (passwordGroup && passwordGroup.parentNode) {
    passwordGroup.parentNode.insertBefore(requirementsCard, passwordGroup.nextSibling);
  } else {
    passwordInput.insertAdjacentElement('afterend', requirementsCard);
  }

  // Create Confirm Password match hint if password2 exists
  let matchHint = null;
  if (confirmPasswordInput) {
    matchHint = document.createElement('div');
    matchHint.className = 'password-match-hint';
    matchHint.id = 'password-match-hint';
    matchHint.innerHTML = `
      <span class="match-icon" aria-hidden="true">✕</span>
      <span class="match-text">Passwords must match</span>
    `;
    const confirmGroup = confirmPasswordInput.closest('.form-group') || confirmPasswordInput.parentElement;
    if (confirmGroup) {
      confirmGroup.appendChild(matchHint);
    } else {
      confirmPasswordInput.insertAdjacentElement('afterend', matchHint);
    }
  }

  // Add Show/Hide Toggle button to password fields
  function setupToggleVisibility(input) {
    if (!input || input.dataset.hasToggle) return;
    input.dataset.hasToggle = 'true';

    const wrapper = document.createElement('div');
    wrapper.className = 'password-input-wrapper';
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);

    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'password-toggle-btn';
    toggleBtn.setAttribute('aria-label', 'Toggle password visibility');
    toggleBtn.setAttribute('tabindex', '-1');
    toggleBtn.innerHTML = `
      <svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
        <circle cx="12" cy="12" r="3"></circle>
      </svg>
      <svg class="eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none;">
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
        <line x1="1" y1="1" x2="23" y2="23"></line>
      </svg>
    `;

    toggleBtn.addEventListener('click', function () {
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      const eyeOpen = toggleBtn.querySelector('.eye-open');
      const eyeClosed = toggleBtn.querySelector('.eye-closed');
      if (eyeOpen && eyeClosed) {
        eyeOpen.style.display = isPassword ? 'none' : 'inline-block';
        eyeClosed.style.display = isPassword ? 'inline-block' : 'none';
      }
    });

    wrapper.appendChild(toggleBtn);
  }

  setupToggleVisibility(passwordInput);
  if (confirmPasswordInput) {
    setupToggleVisibility(confirmPasswordInput);
  }

  // Requirement elements
  const reqLength = document.getElementById('req-length');
  const reqUpper = document.getElementById('req-uppercase');
  const reqLower = document.getElementById('req-lowercase');
  const reqNumber = document.getElementById('req-number');
  const reqSpecial = document.getElementById('req-special');
  const strengthBadge = document.getElementById('password-strength-badge');
  const bars = [
    document.getElementById('str-bar-1'),
    document.getElementById('str-bar-2'),
    document.getElementById('str-bar-3'),
    document.getElementById('str-bar-4'),
    document.getElementById('str-bar-5')
  ];

  function updateRequirement(el, isMet, isTouched) {
    if (!el) return;
    const icon = el.querySelector('.req-icon');
    if (isMet) {
      el.classList.remove('unmet', 'touched');
      el.classList.add('met');
      if (icon) icon.textContent = '✓';
    } else {
      el.classList.remove('met');
      el.classList.add('unmet');
      if (isTouched) {
        el.classList.add('touched');
      } else {
        el.classList.remove('touched');
      }
      if (icon) icon.textContent = '✕';
    }
  }

  function evaluatePassword() {
    const val = passwordInput.value || '';
    const isTouched = val.length > 0;

    const hasLength = val.length >= 8;
    const hasUpper = /[A-Z]/.test(val);
    const hasLower = /[a-z]/.test(val);
    const hasNumber = /\d/.test(val);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(val);

    updateRequirement(reqLength, hasLength, isTouched);
    updateRequirement(reqUpper, hasUpper, isTouched);
    updateRequirement(reqLower, hasLower, isTouched);
    updateRequirement(reqNumber, hasNumber, isTouched);
    updateRequirement(reqSpecial, hasSpecial, isTouched);

    const score = [hasLength, hasUpper, hasLower, hasNumber, hasSpecial].filter(Boolean).length;

    // Strength levels configuration
    const levels = [
      { text: 'Too weak', class: 'active-weak', color: '#ef4444' },
      { text: 'Weak', class: 'active-weak', color: '#ef4444' },
      { text: 'Fair', class: 'active-fair', color: '#f97316' },
      { text: 'Good', class: 'active-good', color: '#eab308' },
      { text: 'Strong', class: 'active-strong', color: '#3b82f6' },
      { text: 'Very strong', class: 'active-very-strong', color: '#22c55e' }
    ];

    const currentLevel = isTouched ? levels[score] : { text: '0 / 5', class: '', color: 'var(--text-muted)' };
    if (strengthBadge) {
      strengthBadge.textContent = isTouched ? `${currentLevel.text} (${score}/5)` : '0 / 5';
      strengthBadge.style.color = isTouched ? currentLevel.color : 'var(--text-muted)';
    }

    bars.forEach((bar, index) => {
      if (!bar) return;
      bar.className = 'password-strength-bar';
      if (isTouched && index < score) {
        bar.classList.add(currentLevel.class);
      }
    });

    evaluateMatch();
  }

  function evaluateMatch() {
    if (!confirmPasswordInput || !matchHint) return;
    const pwd = passwordInput.value || '';
    const pwd2 = confirmPasswordInput.value || '';

    if (!pwd2) {
      matchHint.className = 'password-match-hint';
      return;
    }

    const icon = matchHint.querySelector('.match-icon');
    const text = matchHint.querySelector('.match-text');

    if (pwd === pwd2 && pwd.length > 0) {
      matchHint.className = 'password-match-hint matched';
      if (icon) icon.textContent = '✓';
      if (text) text.textContent = 'Passwords match';
    } else {
      matchHint.className = 'password-match-hint mismatched';
      if (icon) icon.textContent = '✕';
      if (text) text.textContent = 'Passwords do not match';
    }
  }

  // Event Listeners
  passwordInput.addEventListener('input', evaluatePassword);
  passwordInput.addEventListener('focus', function () {
    requirementsCard.classList.add('focused');
  });

  if (confirmPasswordInput) {
    confirmPasswordInput.addEventListener('input', evaluateMatch);
  }

  // Initial evaluation in case of autofill
  if (passwordInput.value) {
    evaluatePassword();
  }
});
