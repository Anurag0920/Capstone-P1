const API_URL = window.location.origin;

let items = [];
let currentUser = null;
let token = null;
let regEmail = '';

// Auth header helper (token missing ho to session invalid)
function authHeaders() {
    const t = localStorage.getItem('token');
    if (!t) throw new Error("No session");
    return { 'Authorization': t };
}

document.addEventListener('DOMContentLoaded', () => {
    checkSession();
    renderFeed('All');

    // Scroll pe navbar behavior + menu auto close
    window.addEventListener('scroll', () => {
        const nav = document.getElementById('main-nav');
        if (!nav) return;

        if (window.scrollY > 50) {
            nav.classList.add('scrolled-mode');
        } else {
            nav.classList.remove('scrolled-mode');

            const menu = document.getElementById('mobile-menu');
            const btn = document.getElementById('hamburger-btn');

            if (menu && menu.classList.contains('menu-open')) {
                menu.classList.remove('menu-open');
                btn.classList.remove('active');
            }
        }
    });

    const reportForm = document.getElementById('form-report');
    if (reportForm) reportForm.addEventListener('submit', handleReportSubmit);
});

// Session check on reload
window.checkSession = function () {
    const storedUser = localStorage.getItem('user');
    const storedToken = localStorage.getItem('token');

    if (storedUser && storedToken) {
        currentUser = JSON.parse(storedUser);
        token = storedToken;
        updateNavUI(true);
    } else {
        currentUser = null;
        token = null;
        updateNavUI(false);
    }
};

// Navbar + mobile auth UI sync
window.updateNavUI = function (isLoggedIn) {
    const navAuth = document.getElementById('nav-auth-section');
    const mobileAuth = document.getElementById('mobile-auth-section');

    let html = '';
    if (isLoggedIn) {
        const simpleName = currentUser.username.split('@')[0];
        html = `
            <div class="flex items-center gap-3">
                <button onclick="window.openProfileModal()" class="text-sm text-white font-bold">
                    <i class="fa-solid fa-user-circle mr-1 text-blue-400"></i> ${simpleName}
                </button>
                <button onclick="window.logoutUser()" class="text-xs border border-red-500 text-red-400 px-3 py-1 rounded">Logout</button>
            </div>
        `;
    } else {
        html = `
            <button onclick="window.openAuthModal('login')" class="text-sm text-gray-300 font-bold mr-4">Login</button>
            <button onclick="window.openAuthModal('register')" class="btn !w-auto !h-9 !px-4 !text-xs">Register</button>
        `;
    }

    if (navAuth) navAuth.innerHTML = html;
    if (mobileAuth) mobileAuth.innerHTML = html;
};

window.openAuthModal = function (mode) {
    document.getElementById('modal-auth').classList.remove('hidden');
    toggleAuthMode(mode);
};

// Login/Register view switch
window.toggleAuthMode = function (mode) {
    const loginView = document.getElementById('auth-login-view');
    const regView = document.getElementById('auth-register-view');

    if (mode === 'login') {
        loginView.classList.remove('hidden');
        regView.classList.add('hidden');
    } else {
        loginView.classList.add('hidden');
        regView.classList.remove('hidden');
        document.getElementById('reg-step-1').classList.remove('hidden');
        document.getElementById('reg-step-2').classList.add('hidden');
    }
};

// OTP send (demo mode)
window.sendOtp = async function () {
    const email = document.getElementById('reg-email').value;
    if (!email.endsWith('@gmail.com')) return alert("Use valid @gmail.com");

    regEmail = email;
    const btn = document.querySelector('#reg-step-1 button');
    btn.innerText = "Sending...";
    btn.disabled = true;

    try {
        const res = await fetch(`${API_URL}/auth/send-otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: email })
        });

        const data = await res.json();

        if (res.ok) {
            alert("OTP generated (demo mode)");
            document.getElementById('reg-step-1').classList.add('hidden');
            document.getElementById('reg-step-2').classList.remove('hidden');
        } else {
            alert(data.error);
            btn.disabled = false;
            btn.innerText = "Send OTP";
        }
    } catch {
        alert("Error sending OTP");
        btn.disabled = false;
    }
};

// OTP verify + auto login
window.completeRegistration = async function () {
    const otp = document.getElementById('reg-otp').value.trim();
    const password = document.getElementById('reg-pass').value;

    try {
        const res = await fetch(`${API_URL}/auth/register-complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: regEmail, otp, password })
        });

        const data = await res.json();

        if (res.ok) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify({ username: data.username }));
            location.reload();
        } else alert(data.error);
    } catch {
        alert("Registration failed");
    }
};

// Login flow
window.loginUser = async function () {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-pass').value;

    try {
        const res = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: email, password })
        });

        const data = await res.json();
        if (!res.ok) return alert(data.error);

        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify({ username: data.username }));
        location.reload();
    } catch {
        alert("Server error");
    }
};

// Logout = clear session
window.logoutUser = function () {
    if (!confirm("Logout?")) return;
    localStorage.clear();
    currentUser = null;
    token = null;
    location.reload();
};

// Feed render with filter
window.renderFeed = async function (filterType) {
    const grid = document.getElementById('feed-grid');
    if (!grid) return;

    try {
        const res = await fetch(`${API_URL}/posts`);
        items = await res.json();
    } catch { items = []; }

    grid.innerHTML = '';

    const filtered = filterType === 'All'
        ? items
        : items.filter(i => i.type === filterType);

    if (!filtered.length) {
        grid.innerHTML = `<div class="col-span-3 text-center text-gray-500 py-10">No items found.</div>`;
        return;
    }

    filtered.forEach(item => {
        const author = item.authorName ? item.authorName.split('@')[0] : "Anonymous";
        const isResolved = item.status === 'Resolved';

        grid.innerHTML += `
        <div class="card ${isResolved ? 'grayscale opacity-60' : ''}">
            <div class="card__img" style="visibility:visible; background-image:url('${item.imageUrl || ''}')"></div>
            <div class="card__info">
                <h3 class="card__title">${item.title}</h3>
                <span class="text-xs text-blue-400 font-bold">${author}</span>
                <button onclick="openDetails('${item._id}')" class="w-full mt-3 text-xs">Details</button>
            </div>
        </div>`;
    });
};

// Claim PIN generation (non-owner)
window.generateClaimPin = async function (id) {
    try {
        const res = await fetch(`${API_URL}/generate-pin/${id}`, {
            method: 'POST',
            headers: authHeaders()
        });

        const data = await res.json();
        if (!res.ok) return alert(data.error);

        document.getElementById('generated-pin-display').innerText = data.pin;
        document.getElementById('pin-result-area').classList.remove('hidden');
    } catch {
        alert("Connection error");
    }
};

// PIN verify by owner
window.verifyTransaction = async function (id) {
    const pin = document.getElementById('verify-pin-input').value.trim();
    if (!pin) return alert("Enter PIN");

    try {
        const res = await fetch(`${API_URL}/verify-pin/${id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...authHeaders() },
            body: JSON.stringify({ pin })
        });

        const data = await res.json();
        if (res.ok && data.success) {
            alert("Verified");
            closeModals();
            renderFeed('All');
        } else alert("Wrong PIN");
    } catch {
        alert("Server error");
    }
};

// Modal close helper
window.closeModals = function () {
    ['modal-report', 'modal-details', 'modal-auth', 'modal-profile']
        .forEach(id => document.getElementById(id)?.classList.add('hidden'));
};

// Mobile menu toggle + animation
window.toggleMobileMenu = function () {
    document.getElementById('mobile-menu').classList.toggle('menu-open');
    document.getElementById('hamburger-btn').classList.toggle('active');
};

// Click outside to close menu
document.addEventListener('click', e => {
    const menu = document.getElementById('mobile-menu');
    const btn = document.getElementById('hamburger-btn');

    if (menu?.classList.contains('menu-open') &&
        !menu.contains(e.target) &&
        !btn.contains(e.target)) {
        menu.classList.remove('menu-open');
        btn.classList.remove('active');
    }
});
