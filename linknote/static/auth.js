// Login state
let isLoginEnabled = false;
let isLoggedIn = false;
let userInfo = null;
let loginType = 'oauth';
let emailLoginEnabled = false;
let isPrivateSite = false;
let isAdmin = false;

const AUTHOR_KEY = 'linknote_author';
const LOGIN_CHECK_INTERVAL = 2000; // 2 seconds
const LOGIN_TIMEOUT = 300000; // 5 minutes

const loginDialog = document.getElementById('loginDialog');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const userInfoDiv = document.getElementById('userInfo');
const usernameSpan = document.getElementById('username');
const loginStatusDiv = document.getElementById('loginStatus');


// Function to get CAPTCHA from backend
async function drawCaptcha() {
    try {
        const response = await fetch('/api/captcha');
        const data = await response.json();
        if (data.success) {
            const img = document.getElementById('captchaImage');
            img.src = data.image;
        } else {
            console.error('Failed to get CAPTCHA');
        }
    } catch (error) {
        console.error('Failed to get CAPTCHA:', error);
    }
}


async function requestLogin() {
    try {
        // Get login type first
        const typeResponse = await fetch('/api/login/type');
        const typeResult = await typeResponse.json();

        if (!typeResult.success) {
            throw new Error(typeResult.error);
        }

        loginType = typeResult.type;
        emailLoginEnabled = typeResult.email_enabled;

        // Show appropriate login method
        document.getElementById('oauthLogin').style.display = loginType === 'oauth' ? 'block' : 'none';
        document.getElementById('emailLogin').style.display = loginType === 'email' ? 'block' : 'none';

        if (loginType === 'oauth') {
            loginStatusDiv.textContent = 'Generating login QR code...';
            loginStatusDiv.className = '';

            const response = await fetch('/api/login/request', {
                method: 'POST'
            });
            const result = await response.json();

            if (!result.success) {
                throw new Error(result.error);
            }

            // Generate QR Code
            const qrCodeDiv = document.getElementById('qrCode');
            qrCodeDiv.innerHTML = '';
            await QRCode.toCanvas(qrCodeDiv, result.login_url, {
                width: 256,
                margin: 2
            });

            // Start checking login status
            startLoginCheck();
        }
    } catch (error) {
        loginStatusDiv.textContent = `Login failed: ${error.message}`;
        loginStatusDiv.className = 'error';
    }
}

async function requestEmailLogin() {
    try {
        const email = document.getElementById('loginEmail').value;
        if (!email) {
            throw new Error('Email is required');
        }

        loginStatusDiv.textContent = 'Sending login email...';
        loginStatusDiv.className = '';

        const response = await fetch('/api/login/email/request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
        body: JSON.stringify({ 
            email,
            captcha: document.getElementById('captchaInput').value
        })
        });

        const result = await response.json();
        if (!result.success) {
            throw new Error(result.error);
        }

        loginStatusDiv.textContent = 'Login email sent! Please check your inbox.';
        loginStatusDiv.className = 'success';
        document.getElementById('loginEmail').value = '';
        startLoginCheck();
    } catch (error) {
        loginStatusDiv.textContent = `Login failed: ${error.message}`;
        loginStatusDiv.className = 'error';
    }
}

function startLoginCheck() {
    let startTime = Date.now();
    loginStatusDiv.textContent = 'Waiting for login...';
    loginStatusDiv.className = '';

    loginCheckInterval = setInterval(async () => {
        try {
            // Check timeout
            if (Date.now() - startTime > LOGIN_TIMEOUT) {
                clearInterval(loginCheckInterval);
                loginStatusDiv.textContent = 'Login timeout. Please try again.';
                loginStatusDiv.className = 'error';
                return;
            }

            let response;
            if (loginType === 'email') {
                response = await fetch('/api/login/email/status');
            } else {
                response = await fetch('/api/login/check');
            }
            const result = await response.json();

            if (result.success) {
                clearInterval(loginCheckInterval);
                userInfo = result.user_info || { email: result.email };
                isLoggedIn = true;
                closeLoginDialog();
                updateLoginUI();
                updateActionButtons();
                if (!isPrivateSite || isLoggedIn) {
                    await loadNotes();
                }
            } else if (loginType === 'email' && result.status === 'pending') {
                loginStatusDiv.textContent = `Waiting for login (sent to ${result.email})...`;
            }
        } catch (error) {
            console.error('Failed to check login status:', error);
        }
    }, LOGIN_CHECK_INTERVAL);
}

function updateLoginUI() {
    if (isLoggedIn && userInfo) {
        loginBtn.style.display = 'none';
        userInfoDiv.style.display = 'flex';
        usernameSpan.textContent = userInfo.name || userInfo.email || 'User';
    } else {
        loginBtn.style.display = isLoginEnabled ? 'block' : 'none';
        userInfoDiv.style.display = 'none';
        usernameSpan.textContent = '';
    }
}

function openLoginDialog() {
    loginDialog.classList.add('active');
}

function closeLoginDialog() {
    loginDialog.classList.remove('active');
    if (loginCheckInterval) {
        clearInterval(loginCheckInterval);
        loginCheckInterval = null;
    }
}

async function logout() {
    try {
        await fetch('/api/logout');
        isLoggedIn = false;
        userInfo = null;
        updateLoginUI();
        updateActionButtons();
        if (isPrivateSite) {
            notes = [];
            renderNotes();
        }
    } catch (error) {
        console.error('Failed to logout:', error);
    }
}

// Check if operation is allowed
function requireLogin(operation) {
    if (!isLoginEnabled || isLoggedIn) {
        return true;
    }
    alert('Please login to perform this operation');
    return false;
}

logoutBtn.addEventListener('click', logout);

document.getElementById('cancelLogin').addEventListener('click', closeLoginDialog);

// Login check and initialization
async function checkLoginType() {
    try {
        const response = await fetch('/api/login/type');
        const result = await response.json();
        if (result.success) {
            loginType = result.type;
            emailLoginEnabled = result.email_enabled;
            isPrivateSite = result.private;
            if (emailLoginEnabled)
            {
                isLoginEnabled = true;
                updateLoginUI();
            }   
        }
    } catch (error) {
        console.error('Failed to check login type:', error);
    }
}

async function checkLoginState() {
    try {
        const response = await fetch('/api/login/state');
        const state = await response.json();
        isLoggedIn = state.logged_in;
        isAdmin = state.is_admin;
        if (state.logged_in) {
            userInfo = state.user_info;
            updateLoginUI();
        }
    } catch (error) {
        console.error('Failed to check login state:', error);
    }
}
