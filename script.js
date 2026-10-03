/**
 * CYBERTEX - Enterprise Cybersecurity Sign-In Logic
 * Clean, accessible, zero frontend credential storage.
 */

// Configurable authentication endpoint
const AUTH_ENDPOINT = "/api/auth/login";

// DOM Elements
const form = document.getElementById("signin-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const emailError = document.getElementById("email-error");
const passwordError = document.getElementById("password-error");
const formAlert = document.getElementById("form-alert");
const submitBtn = document.getElementById("submit-btn");
const btnText = submitBtn.querySelector(".btn-text");
const passwordToggle = document.getElementById("password-toggle");
const eyeIcon = document.getElementById("eye-icon");
const eyeOffIcon = document.getElementById("eye-off-icon");

/**
 * Standard RFC-compliant email validation regex
 * Ensures non-empty local & domain parts with a valid TLD
 */
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Toggle password visibility between masked and plain text
 */
function togglePasswordVisibility() {
  const isCurrentlyPassword = passwordInput.getAttribute("type") === "password";

  if (isCurrentlyPassword) {
    passwordInput.setAttribute("type", "text");
    passwordToggle.setAttribute("aria-label", "Hide password");
    passwordToggle.setAttribute("title", "Hide password");
    eyeIcon.classList.add("hidden");
    eyeOffIcon.classList.remove("hidden");
  } else {
    passwordInput.setAttribute("type", "password");
    passwordToggle.setAttribute("aria-label", "Show password");
    passwordToggle.setAttribute("title", "Show password");
    eyeIcon.classList.remove("hidden");
    eyeOffIcon.classList.add("hidden");
  }
}

/**
 * Display an accessible field-level error message
 * @param {HTMLInputElement} inputEl
 * @param {HTMLElement} errorEl
 * @param {string} message
 */
function showFieldError(inputEl, errorEl, message) {
  inputEl.classList.add("is-invalid");
  inputEl.setAttribute("aria-invalid", "true");
  errorEl.textContent = message;
}

/**
 * Clear a field-level error message
 * @param {HTMLInputElement} inputEl
 * @param {HTMLElement} errorEl
 */
function clearFieldError(inputEl, errorEl) {
  if (inputEl.classList.contains("is-invalid")) {
    inputEl.classList.remove("is-invalid");
    inputEl.removeAttribute("aria-invalid");
    errorEl.textContent = "";
  }
}

/**
 * Display a global form alert message (e.g. server error or 401)
 * @param {string} message
 */
function showFormAlert(message) {
  formAlert.textContent = message;
  formAlert.removeAttribute("hidden");
}

/**
 * Clear the global form alert message
 */
function clearFormAlert() {
  if (!formAlert.hasAttribute("hidden")) {
    formAlert.textContent = "";
    formAlert.setAttribute("hidden", "");
  }
}

/**
 * Update the submit button state during network requests
 * @param {boolean} isLoading
 */
function setLoading(isLoading) {
  if (isLoading) {
    submitBtn.disabled = true;
    submitBtn.classList.add("is-loading");
    btnText.textContent = "Signing in…";
  } else {
    submitBtn.disabled = false;
    submitBtn.classList.remove("is-loading");
    btnText.textContent = "Sign In";
  }
}

/**
 * Wrap authentication in a single function sending POST to AUTH_ENDPOINT
 * Sends credentials only in request body; no client storage of credentials.
 * @param {string} email
 * @param {string} password
 * @returns {Promise<Response>}
 */
async function submitCredentials(email, password) {
  return await fetch(AUTH_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    credentials: "include",
    body: JSON.stringify({ email, password })
  });
}

/**
 * Validate form inputs and handle authentication submission
 * @param {Event} e
 */
async function handleFormSubmit(e) {
  e.preventDefault();

  clearFormAlert();

  const emailValue = emailInput.value.trim();
  const passwordValue = passwordInput.value;

  let isValid = true;
  let firstInvalidInput = null;

  // Validate Email
  if (!emailValue) {
    showFieldError(emailInput, emailError, "Email address is required.");
    isValid = false;
    firstInvalidInput = firstInvalidInput || emailInput;
  } else if (!EMAIL_REGEX.test(emailValue)) {
    showFieldError(emailInput, emailError, "Enter a valid email address.");
    isValid = false;
    firstInvalidInput = firstInvalidInput || emailInput;
  } else {
    clearFieldError(emailInput, emailError);
  }

  // Validate Password
  if (!passwordValue) {
    showFieldError(passwordInput, passwordError, "Password is required.");
    isValid = false;
    firstInvalidInput = firstInvalidInput || passwordInput;
  } else {
    clearFieldError(passwordInput, passwordError);
  }

  // Focus the first invalid element if validation failed
  if (!isValid) {
    if (firstInvalidInput) {
      firstInvalidInput.focus();
    }
    return;
  }

  // Set loading state
  setLoading(true);

  try {
    const response = await submitCredentials(emailValue, passwordValue);

    if (response.status === 401) {
      showFormAlert("Incorrect email or password.");
      passwordInput.focus();
    } else if (!response.ok) {
      showFormAlert("Unable to sign in right now. Please try again.");
    } else {
      // Successful server response (if backend is active)
      // Per specification: Do NOT simulate a successful login or store credentials in localStorage/sessionStorage/cookies.
    }
  } catch (error) {
    // Catches network errors, CORS issues, or unavailable backend
    showFormAlert("Unable to sign in right now. Please try again.");
  } finally {
    setLoading(false);
  }
}

// Event Listeners
form.addEventListener("submit", handleFormSubmit);

// Clear errors as soon as the user starts typing
emailInput.addEventListener("input", () => {
  clearFieldError(emailInput, emailError);
  clearFormAlert();
});

passwordInput.addEventListener("input", () => {
  clearFieldError(passwordInput, passwordError);
  clearFormAlert();
});

// Toggle password mask visibility
passwordToggle.addEventListener("click", togglePasswordVisibility);

/* ==========================================================================
   Google Identity Services (GIS) Integration
   ========================================================================== */

const GOOGLE_AUTH_ENDPOINT = "/api/auth/google";
let currentClientId = null;

/**
 * Handle the credential response received from Google
 * Securely sends the ID token to the backend for verification
 * @param {Object} response
 */
async function handleGoogleCredential(response) {
  clearFormAlert();
  
  try {
    const res = await fetch(GOOGLE_AUTH_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      // send credentials (cookies) in case CSRF is needed, and send the google credential
      credentials: "include",
      body: JSON.stringify({ credential: response.credential })
    });
    
    if (!res.ok) {
      showFormAlert("We couldn't verify your Google account. Please try again.");
    } else {
      // Backend returned success and set secure cookies, redirect to dashboard
      window.location.href = "/dashboard.html";
    }
  } catch (error) {
    showFormAlert("Unable to sign in right now. Please try again.");
  }
}

/**
 * Render the Google button dynamically based on the submit button's width
 */
function renderGoogleButton() {
  if (!currentClientId || !window.google || !window.google.accounts) return;
  
  const container = document.getElementById("google-button-container");
  const submitBtn = document.getElementById("submit-btn");
  
  if (!container || !submitBtn) return;
  
  // Clear any existing button iframe
  container.innerHTML = "";
  
  const btnWidth = submitBtn.offsetWidth || 320;
  
  google.accounts.id.renderButton(
    container,
    { 
      theme: "outline", 
      size: "large", 
      type: "standard", 
      shape: "rectangular", 
      text: "continue_with", 
      width: btnWidth
    }
  );
}

/**
 * Fetch config and initialize Google Identity Services
 */
async function initGoogleAuth() {
  try {
    const res = await fetch('/api/config');
    if (!res.ok) return;
    
    const data = await res.json();
    currentClientId = data.client_id;
    
    if (currentClientId) {
      const checkGoogle = setInterval(() => {
        if (window.google && window.google.accounts && window.google.accounts.id) {
          clearInterval(checkGoogle);
          
          google.accounts.id.initialize({
            client_id: currentClientId,
            callback: handleGoogleCredential,
            context: 'signin',
            ux_mode: 'popup'
          });
          
          renderGoogleButton();
          
          // Re-render button on window resize to match submit button width
          window.addEventListener('resize', () => {
            // Debounce the resize slightly
            clearTimeout(window.googleResizeTimer);
            window.googleResizeTimer = setTimeout(renderGoogleButton, 150);
          });
        }
      }, 100);
    } else {
      console.warn("Google Client ID is not configured. Please configure it in the backend.");
    }
  } catch (err) {
    console.error("Failed to load Google Client ID", err);
  }
}

// Initialize GIS after window load
window.addEventListener("load", initGoogleAuth);
