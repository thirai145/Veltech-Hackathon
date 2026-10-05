/**
 * CYBERTEX - Enterprise Cybersecurity Sign-In Logic
 */

const AUTH_ENDPOINT = "/api/auth/login";
const GOOGLE_AUTH_ENDPOINT = "/api/auth/google";

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

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function togglePasswordVisibility() {
  const isCurrentlyPassword = passwordInput.getAttribute("type") === "password";
  if (isCurrentlyPassword) {
    passwordInput.setAttribute("type", "text");
    eyeIcon.classList.add("hidden");
    eyeOffIcon.classList.remove("hidden");
  } else {
    passwordInput.setAttribute("type", "password");
    eyeIcon.classList.remove("hidden");
    eyeOffIcon.classList.add("hidden");
  }
}

function showFieldError(inputEl, errorEl, message) {
  inputEl.classList.add("is-invalid");
  errorEl.textContent = message;
}

function clearFieldError(inputEl, errorEl) {
  inputEl.classList.remove("is-invalid");
  errorEl.textContent = "";
}

function showFormAlert(message) {
  formAlert.textContent = message;
  formAlert.removeAttribute("hidden");
}

function clearFormAlert() {
  formAlert.textContent = "";
  formAlert.setAttribute("hidden", "");
}

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

async function handleFormSubmit(e) {
  e.preventDefault();
  clearFormAlert();
  // Standard sign-in is disabled for the hackathon demo, prioritizing Google Sign-In
  showFormAlert("Please use 'Sign in with Google' to access the CYBERTEX Phishing Radar.");
}

form.addEventListener("submit", handleFormSubmit);
passwordToggle.addEventListener("click", togglePasswordVisibility);

/* ==========================================================================
   Google Identity Services (GIS) Integration (OAuth2 Code Flow)
   ========================================================================== */

let currentClientId = null;
let codeClient = null;

async function handleGoogleAuthCode(response) {
  clearFormAlert();
  
  if (response.error) {
     showFormAlert("Google Sign-In was cancelled or failed.");
     return;
  }
  
  try {
    const res = await fetch(GOOGLE_AUTH_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: response.code })
    });
    
    if (!res.ok) {
      const err = await res.json();
      showFormAlert(err.error || "We couldn't verify your Google account. Please try again.");
    } else {
      window.location.href = "/dashboard.html";
    }
  } catch (error) {
    showFormAlert("Unable to sign in right now. Please try again.");
  }
}

function renderGoogleButton() {
  const container = document.getElementById("google-button-container");
  if (!container) return;
  
  container.innerHTML = `
    <button type="button" id="custom-google-btn" class="signin-button" style="background-color: white; color: black; border: 1px solid #ccc; display: flex; align-items: center; justify-content: center; gap: 10px;">
      <svg width="18" height="18" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
      Sign in with Google
    </button>
  `;
  
  document.getElementById('custom-google-btn').addEventListener('click', () => {
    if (codeClient) {
      codeClient.requestCode();
    }
  });
}

async function initGoogleAuth() {
  try {
    const res = await fetch('/api/config');
    if (!res.ok) return;
    
    const data = await res.json();
    currentClientId = data.client_id;
    
    if (currentClientId) {
      const checkGoogle = setInterval(() => {
        if (window.google && window.google.accounts && window.google.accounts.oauth2) {
          clearInterval(checkGoogle);
          
          codeClient = window.google.accounts.oauth2.initCodeClient({
            client_id: currentClientId,
            scope: 'https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
            ux_mode: 'popup',
            callback: handleGoogleAuthCode,
          });
          
          renderGoogleButton();
        }
      }, 100);
    }
  } catch (err) {
    console.error("Failed to load Google Client ID", err);
  }
}

window.addEventListener("load", initGoogleAuth);
