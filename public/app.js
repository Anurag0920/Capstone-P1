// =========================================================================
// THE MISPLACED MANSION - APP.JS
// =========================================================================
const API_URL = window.location.origin;

let items = []; 
let currentUser = null;
let token = null;
let regEmail = '';

function authHeaders() {
    const t = localStorage.getItem('token');
    if (!t) throw new Error("No session");
    return { 'Authorization': t };
}

// --- 1. INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    checkSession();
    renderFeed('All');

    // --- SMART SCROLL LISTENER ---
    window.addEventListener('scroll', () => {
        const nav = document.getElementById('main-nav');
        if(!nav) return;

        // If scrolled down more than 50px
        if (window.scrollY > 50) {
            nav.classList.add('scrolled-mode');
        } else {
            // Back at the top
            nav.classList.remove('scrolled-mode');
            
            // Auto-close the menu if it was open when they scrolled back to top
            const menu = document.getElementById('mobile-menu');
            const btn = document.getElementById('hamburger-btn');
            
            if(menu && menu.classList.contains('menu-open')) {
                menu.classList.remove('menu-open');
                btn.classList.remove('active');
            }
        }
    });

    const reportForm = document.getElementById('form-report');
    if(reportForm) reportForm.addEventListener('submit', handleReportSubmit);
});

// --- 2. AUTHENTICATION ---

window.checkSession = function() {
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
}

window.updateNavUI = function(isLoggedIn) {
    const navAuth = document.getElementById('nav-auth-section');
    const mobileAuth = document.getElementById('mobile-auth-section');
    
    let html = '';
    if (isLoggedIn) {
        const simpleName = currentUser.username.split('@')[0];
        html = `
            <div class="flex items-center gap-3">
                <button onclick="window.openProfileModal()" class="text-sm text-white hover:text-blue-400 font-bold transition hover:underline">
                    <i class="fa-solid fa-user-circle mr-1 text-blue-400"></i> ${simpleName}
                </button>
                <button onclick="window.logoutUser()" class="text-xs border border-red-500 text-red-400 px-3 py-1 rounded hover:bg-red-500 hover:text-white transition">Logout</button>
            </div>
        `;
    } else {
        html = `
            <button onclick="window.openAuthModal('login')" class="text-sm text-gray-300 hover:text-white font-bold mr-4">Login</button>
            <button onclick="window.openAuthModal('register')" class="btn !w-auto !h-9 !px-4 !text-xs !bg-blue-600 shadow-lg shadow-blue-500/30">Register</button>
        `;
    }

    if(navAuth) navAuth.innerHTML = html;
    if(mobileAuth) mobileAuth.innerHTML = html;
}

window.openAuthModal = function(mode) {
    document.getElementById('modal-auth').classList.remove('hidden');
    window.toggleAuthMode(mode);
}

window.toggleAuthMode = function(mode) {
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
}

// REGISTER FLOW
window.sendOtp = async function() {
    const email = document.getElementById('reg-email').value;
    if(!email.endsWith('@gmail.com')) return alert("Please use a valid @gmail.com address");
    
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
            alert("OTP Sent! Check your inbox.");
            document.getElementById('reg-step-1').classList.add('hidden');
            document.getElementById('reg-step-2').classList.remove('hidden');
        } else {
            alert(data.error);
            btn.disabled = false;
            btn.innerText = "Send OTP";
        }
    } catch (e) {
        alert("Something went wrong. Please try again.");
        btn.disabled = false;
    }
}

window.completeRegistration = async function() {
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
            alert("Account Created!");
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify({ username: data.username }));
            window.location.reload();
        } else {
            alert(data.error);
        }
    } catch (e) {
        alert("Registration Failed.");
    }
}

// LOGIN FLOW
window.loginUser = async function() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-pass').value;

    try {
        const res = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: email, password })
        });

        const data = await res.json();

        if (!res.ok) {
            return alert(data.error || "Login Failed");
        }

        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify({ username: data.username }));

        location.reload();
    } catch (err) {
        alert("Server Error");
    }
};

window.logoutUser = function() {
    if (!confirm("Are you sure you want to log out?")) return;

    localStorage.clear(); // important
    currentUser = null;
    token = null;

    location.reload();
};


// --- 3. RENDER FEED ---

window.renderFeed = async function(filterType) {
    const grid = document.getElementById('feed-grid');
    if (!grid) return;
    
    try {
        const res = await fetch(`${API_URL}/posts`);
        items = await res.json();
    } catch (e) { items = []; }

    grid.innerHTML = ''; 

    const filteredItems = filterType === 'All' ? items : items.filter(item => item.type === filterType);

    if (filteredItems.length === 0) {
        grid.innerHTML = `<div class="col-span-3 text-center text-gray-500 py-10">No items found.</div>`;
        return;
    }

    filteredItems.forEach(item => {
        const colorClass = item.type === 'Lost' ? '#f59e0b' : '#10b981';
        let bgStyle = item.imageUrl ? `background-image: url('${item.imageUrl}');` : `background-color: #333;`;
        
        let displayDate = "Just now";
        if (item.createdAt) {
            const d = new Date(item.createdAt);
            displayDate = d.toLocaleDateString();
        } else if (item.date) {
            displayDate = item.date.split('•')[0];
        }

        // Format Author Name
        let authorDisplay = "Anonymous";
        if (item.authorName) {
            authorDisplay = item.authorName.split('@')[0];
        }

        const isResolved = item.status === 'Resolved';
        const resolvedClass = isResolved ? 'grayscale opacity-60' : '';
        const resolvedBadge = isResolved ? '<div class="absolute top-2 right-2 bg-red-600 text-white text-[10px] font-bold px-2 py-1 rounded z-20">RESOLVED</div>' : '';

        const cardHTML = `
        <div class="card group ${resolvedClass}">
            ${resolvedBadge}
            <div class="card__img relative flex items-center justify-center" style="visibility:visible; ${bgStyle}"></div>
            <div class="card__img--hover" style="${bgStyle}"></div>
            <div class="card__info">
                <div class="flex justify-between items-center mb-1">
                    <span class="card__category" style="color:${colorClass}">${item.type}</span>
                    <span class="text-[10px] text-gray-500">${displayDate}</span>
                </div>
                <h3 class="card__title truncate mb-0">${item.title}</h3>
                
                <div class="flex items-center gap-2 mb-3 mt-1">
                    <div class="w-5 h-5 rounded-full bg-slate-700 flex items-center justify-center text-[10px] text-white">
                        <i class="fa-solid fa-user"></i>
                    </div>
                    <span class="text-xs text-blue-400 font-bold">${authorDisplay}</span>
                </div>

                <span class="card__by block mb-3 text-sm">at <span class="card__author text-gray-300">${item.location}</span></span>
                
                <button onclick="window.openDetails('${item._id}')" class="w-full py-2 rounded border border-gray-600 text-xs font-bold text-gray-300 hover:bg-white/10 transition">
                    ${isResolved ? 'View History' : 'More Details'}
                </button>
            </div>
        </div>`;
        grid.innerHTML += cardHTML;
    });

    if(filterType !== 'All') {
        const browse = document.getElementById('browse');
        if(browse) browse.scrollIntoView({ behavior: 'smooth' });
    }
}

// --- 4. DETAILS MODAL ---

window.openDetails = function(id) {
    const item = items.find(i => i._id == id || i.id == id);
    if(!item) return alert("Error loading item.");

    const modal = document.getElementById('modal-details');
    
    document.getElementById('detail-type').innerText = (item.type || "ITEM").toUpperCase() + " ITEM";
    document.getElementById('detail-title').innerText = item.title || "Untitled";
    document.getElementById('detail-loc').innerText = item.location || "Unknown";
    
    const rawDate = item.createdAt || item.date;
    const displayDate = rawDate ? new Date(rawDate).toLocaleString() : "Recently";
    document.getElementById('detail-date').innerText = displayDate;

    // --- Report Author Info ---
    let authorDisplay = "Anonymous";
    if (item.authorName) authorDisplay = item.authorName.split('@')[0];
    
    const descArea = document.getElementById('detail-desc');
    descArea.innerHTML = `
        ${item.description || "No description."}
        <div class="mt-6 pt-4 border-t border-gray-700 flex items-center gap-3">
            <div class="w-10 h-10 rounded-full bg-blue-900/50 flex items-center justify-center text-blue-400">
                <i class="fa-solid fa-user text-lg"></i>
            </div>
            <div>
                <p class="text-[10px] text-gray-500 uppercase font-bold">Reported By</p>
                <p class="text-sm text-white font-bold">${authorDisplay}</p>
            </div>
        </div>
    `;

    // --- MEDIA ---
    const mediaContainer = document.getElementById('detail-media');
    if(item.imageUrl) {
        mediaContainer.innerHTML = `<img src="${item.imageUrl}" class="w-full h-full object-cover">`;
    } else {
        mediaContainer.innerHTML = `<div class="w-full h-full bg-gray-800 flex flex-col items-center justify-center text-gray-500"><i class="fa-solid fa-image text-4xl mb-2"></i><span>No Image</span></div>`;
    }

    // --- ACTION BUTTONS ---
    const btnContainer = document.querySelector('#modal-details .mt-8');
    btnContainer.innerHTML = ''; 

    const currentUsername = currentUser ? currentUser.username : "";
    const isAuthor = currentUsername === item.authorName;

    if (item.status === 'Resolved') {
        btnContainer.innerHTML = `<div class="text-center text-green-500 font-bold text-xl py-4 border-t border-gray-700"><i class="fa-solid fa-check-circle"></i> ITEM RESOLVED</div>`;
    } 
    else if (isAuthor) {
        btnContainer.innerHTML = `
            <div class="bg-gray-800 p-4 rounded-lg mt-4 border border-gray-700">
                <p class="text-gray-400 text-xs uppercase font-bold mb-2">Verify Claimant</p>
                <div class="flex gap-2">
                    <input type="text" id="verify-pin-input" placeholder="Enter PIN" class="w-full bg-black border border-gray-600 rounded p-2 text-white text-center font-bold tracking-widest outline-none focus:border-blue-500">
                    <button onclick="window.verifyTransaction('${item._id}')" class="btn !w-auto bg-green-600 hover:bg-green-500 text-white">Verify</button>
                </div>
            </div>
        `;
    } 
    else {
        btnContainer.innerHTML = `
            <div id="claim-section">
                <button onclick="window.generateClaimPin('${item._id}')" class="btn w-full shadow-lg shadow-indigo-500/30 font-bold">
                    ${item.type === 'Lost' ? 'I Found This!' : 'This is Mine!'}
                </button>
            </div>
            <div id="pin-result-area" class="hidden mt-4 bg-blue-900/30 border border-blue-500/50 p-4 rounded text-center animate-pulse">
                <p class="text-blue-300 text-xs uppercase font-bold">Show this PIN to Owner:</p>
                <h1 id="generated-pin-display" class="text-4xl font-black text-white my-2 tracking-widest">----</h1>
            </div>
        `;
    }

    modal.classList.remove('hidden');
};

window.generateClaimPin = async function(id) {
    const storedToken = localStorage.getItem('token');
    if (!storedToken) {
        alert("Session Expired. Please Login.");
        window.openAuthModal('login');
        return;
    }

    const btn = document.querySelector('#claim-section button');
    if(btn) { btn.innerText = "Processing..."; btn.disabled = true; }

    try {
        const res = await fetch(`${API_URL}/generate-pin/${id}`, {
    method: 'POST',
    headers: authHeaders()
});

        const data = await res.json();
        
        if (res.ok) {
            document.getElementById('claim-section').classList.add('hidden');
            const pinArea = document.getElementById('pin-result-area');
            document.getElementById('generated-pin-display').innerText = data.pin;
            pinArea.classList.remove('hidden');
        } else {
            alert("Error: " + data.error);
            if(btn) btn.disabled = false;
        }
    } catch (e) { alert("Connection Error"); }
};

window.verifyTransaction = async function(id) {
    const storedToken = localStorage.getItem('token');
    const pin = document.getElementById('verify-pin-input').value.trim();
    if (!pin) return alert("Enter PIN");

    try {
        const res = await fetch(`${API_URL}/verify-pin/${id}`, {
            method: 'POST',
           headers: {
    'Content-Type': 'application/json',
    ...authHeaders()
},

            body: JSON.stringify({ pin })
        });
        const data = await res.json();

        if (res.ok && data.success) {
            alert("✅ Verified! Item Resolved.");
            window.closeModals();
            window.renderFeed('All'); 
        } else {
            alert("❌ Incorrect PIN.");
        }
    } catch (e) { alert("Connection Error"); }
};

window.openReportModal = function(preType = 'Lost') {
    if (!currentUser) { alert("Please login."); return window.openAuthModal('login'); }
    document.getElementById('report-type').value = preType;
    document.getElementById('form-report').reset();
    document.getElementById('file-preview-container').classList.add('hidden');
    uploadedFileBase64 = null;
    document.getElementById('modal-report').classList.remove('hidden');
}

window.handleFileSelect = function(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(e) {
        uploadedFileBase64 = e.target.result;
        document.getElementById('file-preview-container').classList.remove('hidden');
        document.getElementById('preview-content').innerHTML = `<img src="${uploadedFileBase64}" class="w-full h-full object-cover">`;
    };
    reader.readAsDataURL(file);
}

async function handleReportSubmit(e) {
    e.preventDefault();
    const storedToken = localStorage.getItem('token');
    
    const newItem = {
        title: document.getElementById('report-title').value,
        type: document.getElementById('report-type').value,
        location: document.getElementById('report-location').value,
        description: document.getElementById('report-desc').value,
        date: document.getElementById('report-date').value + " • " + document.getElementById('report-time').value,
        imageUrl: uploadedFileBase64
    };

    try {
        const res = await fetch(`${API_URL}/posts`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': storedToken },
            body: JSON.stringify(newItem)
        });
        if (res.ok) {
            alert("Reported Successfully!");
            renderFeed('All');
            closeModals();
        } else { alert("Failed to report."); }
    } catch (err) { alert("Server Error."); }
}

// --- 5. MODAL CONTROL ---

window.closeModals = function() {
    document.getElementById('modal-report').classList.add('hidden');
    document.getElementById('modal-details').classList.add('hidden');
    document.getElementById('modal-auth').classList.add('hidden');
    document.getElementById('modal-profile').classList.add('hidden');
}

window.toggleAdmin = function() { 
    if(!currentUser) return alert("Login required"); 
    alert("Admin Panel is Restricted."); 
};

// ==========================================
// NEW: REPUTATION & MEDAL LOGIC
// ==========================================

const RANKS = [
    { min: 0,   name: "NOVICE",    color: "text-gray-400",   medalColor: "text-gray-600", next: 50 },
    { min: 50,  name: "SCOUT",     color: "text-blue-400",   medalColor: "text-amber-700", next: 100 },
    { min: 100, name: "DETECTIVE", color: "text-purple-400", medalColor: "text-slate-300", next: 250 },
    { min: 250, name: "HERO",      color: "text-yellow-400", medalColor: "text-yellow-400", next: 1000 }
];

window.openProfileModal = function() {
    if(!currentUser) return alert("Please login to view reputation.");
    
    const points = currentUser.reputation || 0;
    const userDisplay = currentUser.username.split('@')[0];

    // Find Rank
    let rank = RANKS[0];
    for (let i = 0; i < RANKS.length; i++) {
        if (points >= RANKS[i].min) rank = RANKS[i];
    }

    document.getElementById('profile-username').innerText = userDisplay;
    document.getElementById('profile-points').innerText = points;
    
    const tagEl = document.getElementById('profile-tag');
    tagEl.innerText = rank.name + " INVESTIGATOR";
    tagEl.className = `text-xs uppercase tracking-widest font-bold mb-6 ${rank.color}`;

    document.getElementById('profile-medal').className = `text-6xl drop-shadow-lg transition-transform hover:scale-110 duration-300 ${rank.medalColor}`;

    const nextGoal = rank.next;
    const percent = Math.min(100, (points / nextGoal) * 100);
    document.getElementById('profile-progress').style.width = `${percent}%`;
    document.getElementById('profile-next').innerText = `${nextGoal - points} pts to next rank`;

    document.getElementById('modal-profile').classList.remove('hidden');
};

// ==========================================
// MOBILE MENU & HAMBURGER ANIMATION
// ==========================================

window.toggleMobileMenu = function() {
    const menu = document.getElementById('mobile-menu');
    const btn = document.getElementById('hamburger-btn');
    
    // 1. Toggle the Menu Panel (Slide/Fade in)
    menu.classList.toggle('menu-open');
    
    // 2. Toggle the "Active" class (Triggers the X animation)
    btn.classList.toggle('active');
    
    // Debugging: Check console to see if it works
    console.log("Menu Toggled. Class list:", menu.classList);
}

// Close menu when clicking outside
document.addEventListener('click', function(event) {
    const menu = document.getElementById('mobile-menu');
    const btn = document.getElementById('hamburger-btn');

    // Only check if the menu is currently OPEN
    if (menu && menu.classList.contains('menu-open')) {
        // If the click is NOT inside the menu AND NOT on the button
        if (!menu.contains(event.target) && !btn.contains(event.target)) {
            menu.classList.remove('menu-open');
            btn.classList.remove('active');
        }
    }
});