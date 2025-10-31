<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=social.displayInfo displayWide=(realm.password && social.providers??); bodyClass="sky-genesis-login">
<div class="min-h-screen relative overflow-hidden bg-black">
  <!-- Animated background pattern -->
  <div class="absolute inset-0 opacity-10">
    <div
      class="absolute inset-0"
      style="background-image: radial-gradient(circle at 2px 2px, white 1px, transparent 0); background-size: 40px 40px;"
    />
  </div>

  <!-- Animated gradient orbs -->
  <div class="absolute top-1/4 left-1/4 w-96 h-96 bg-white/5 rounded-full blur-3xl animate-pulse"></div>
  <div class="absolute bottom-1/4 right-1/4 w-96 h-96 bg-white/5 rounded-full blur-3xl animate-pulse" style="animation-delay: 1s;"></div>

  <!-- Main content -->
  <div class="relative z-10 flex items-center justify-center min-h-screen p-4">
    <div class="w-full max-w-md bg-white/95 backdrop-blur-sm border border-gray-200 shadow-2xl rounded-lg">
      <div class="space-y-4 text-center p-8 pb-8">
        <!-- Logo -->
        <div class="flex justify-center">
          <div class="relative">
            <div class="w-16 h-16 bg-black rounded-xl flex items-center justify-center">
              <svg viewBox="0 0 24 24" fill="none" class="w-10 h-10" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M12 2L2 7L12 12L22 7L12 2Z"
                  fill="white"
                  stroke="white"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M2 17L12 22L22 17"
                  stroke="white"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path
                  d="M2 12L12 17L22 12"
                  stroke="white"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
            </div>
          </div>
        </div>

        <div class="space-y-2">
          <h1 class="text-2xl font-bold text-black">Sky Genesis Enterprise</h1>
          <p class="text-gray-600" id="login-description">
            Login or signup below
          </p>
        </div>
      </div>

      <div class="space-y-6 p-6">
        <#if message?has_content>
          <div class="alert alert-${message.type} text-center">
            ${message.summary}
          </div>
        </#if>

        <form id="login-form" action="/sso/auth" method="post" class="space-y-4">
          <!-- Hidden fields for SSO state management -->
          <input type="hidden" name="redirect_uri" value="">
          <input type="hidden" name="state" value="">
          <input type="hidden" name="client_id" value="">

          <div id="email-step" class="space-y-2">
            <label for="username" class="text-sm font-medium text-black block">
              Email
            </label>
            <input
              id="username"
              name="username"
              type="email"
              placeholder="you@example.com"
              value="${(login.username!'')}"
              required
              class="w-full px-3 py-2 bg-white border border-gray-300 text-black placeholder-gray-400 focus:border-black focus:ring-black rounded-md"
            />
          </div>

          <div id="password-step" class="space-y-2 hidden">
            <div class="flex items-center justify-between">
              <label for="password" class="text-sm font-medium text-black">
                Password
              </label>
              <#if realm.resetPasswordAllowed>
                <a href="${url.loginResetCredentialsUrl}" class="text-sm text-gray-500 hover:text-black transition-colors">
                  Forgot password?
                </a>
              </#if>
            </div>
            <input
              id="password"
              name="password"
              type="password"
              placeholder="Enter your password"
              required
              class="w-full px-3 py-2 bg-white border border-gray-300 text-black placeholder-gray-400 focus:border-black focus:ring-black rounded-md"
            />
            <button
              type="button"
              id="back-btn"
              class="text-sm text-gray-500 hover:text-black transition-colors flex items-center gap-1 mt-2"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
              </svg>
              Use a different email
            </button>
          </div>

          <button
            type="submit"
            id="submit-btn"
            class="w-full bg-black hover:bg-gray-800 text-white font-medium py-2 px-4 rounded-md disabled:opacity-50"
            disabled
          >
            Continue
          </button>
        </form>

        <div id="social-section">
          <div class="relative">
            <div class="absolute inset-0 flex items-center">
              <div class="w-full border-t border-gray-200"></div>
            </div>
            <div class="relative flex justify-center text-xs uppercase">
              <span class="bg-white px-2 text-gray-500">Or continue with</span>
            </div>
          </div>

          <div class="grid grid-cols-3 gap-3 mt-4">
            <#list social.providers as p>
              <a href="${p.loginUrl}" class="bg-gray-50 hover:bg-gray-100 border border-gray-200 rounded-md p-3 flex items-center justify-center transition-colors">
                <#if p.providerId == "apple">
                  <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09l.01-.01zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z" />
                  </svg>
                <#elseif p.providerId == "google">
                  <svg class="w-5 h-5" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                  </svg>
                <#elseif p.providerId == "microsoft">
                  <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                    <path fill="#f25022" d="M1 1h10v10H1z"/>
                    <path fill="#00a4ef" d="M13 1h10v10H13z"/>
                    <path fill="#7fba00" d="M1 13h10v10H1z"/>
                    <path fill="#ffb900" d="M13 13h10v10H13z"/>
                  </svg>
                <#else>
                  ${p.displayName}
                </#if>
              </a>
            </#list>
          </div>
        </div>
      </div>

      <div class="flex justify-between text-sm text-gray-500 p-6 pt-6 border-t">
        <a href="#" class="hover:text-black transition-colors">Terms of Service</a>
        <a href="#" class="hover:text-black transition-colors">Privacy Policy</a>
      </div>
    </div>
  </div>
</div>

<script>
  const emailStep = document.getElementById('email-step');
  const passwordStep = document.getElementById('password-step');
  const socialSection = document.getElementById('social-section');
  const submitBtn = document.getElementById('submit-btn');
  const backBtn = document.getElementById('back-btn');
  const loginDescription = document.getElementById('login-description');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const form = document.getElementById('login-form');

  // Get URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const redirectUri = urlParams.get('redirect_uri') || '';
  const state = urlParams.get('state') || '';
  const clientId = urlParams.get('client_id') || '';
  const error = urlParams.get('error');

  // Set hidden field values
  document.querySelector('input[name="redirect_uri"]').value = redirectUri;
  document.querySelector('input[name="state"]').value = state;
  document.querySelector('input[name="client_id"]').value = clientId;

  let currentStep = 'email';

  function updateUI() {
    if (currentStep === 'email') {
      emailStep.classList.remove('hidden');
      passwordStep.classList.add('hidden');
      socialSection.classList.remove('hidden');
      submitBtn.textContent = 'Continue';
      submitBtn.disabled = !usernameInput.value;
      loginDescription.textContent = error ? `Error: ${error}. Login or signup below` : 'Login or signup below';
    } else {
      emailStep.classList.add('hidden');
      passwordStep.classList.remove('hidden');
      socialSection.classList.add('hidden');
      submitBtn.textContent = 'Sign in';
      submitBtn.disabled = !passwordInput.value;
      loginDescription.textContent = `Welcome back, ${usernameInput.value}`;
    }
  }

  usernameInput.addEventListener('input', () => {
    if (currentStep === 'email') {
      submitBtn.disabled = !usernameInput.value;
    }
  });

  passwordInput.addEventListener('input', () => {
    if (currentStep === 'password') {
      submitBtn.disabled = !passwordInput.value;
    }
  });

  submitBtn.addEventListener('click', (e) => {
    if (currentStep === 'email') {
      e.preventDefault();
      currentStep = 'password';
      updateUI();
      passwordInput.focus();
    } else {
      // Let the form submit normally
    }
  });

  backBtn.addEventListener('click', () => {
    currentStep = 'email';
    passwordInput.value = '';
    updateUI();
  });

  // Initialize
  updateUI();
</script>
</@layout.registrationLayout>