const notifStyles = `
    .notif-container { position: relative; display: inline-block; margin-right: 15px; vertical-align: middle; }
    .notif-btn {
        background: transparent; border: none; color: #aaa; font-size: 1.2rem; 
        cursor: pointer; position: relative; transition: 0.2s; padding: 5px;
    }
    .notif-btn:hover { color: white; transform: scale(1.1); }

    .notif-badge {
        position: absolute; top: 0; right: 0;
        background: var(--red-main, #ff4444); color: white;
        font-size: 0.6rem; font-weight: bold; padding: 1px 5px;
        border-radius: 10px; display: none; border: 1px solid #14141a;
    }

    .notif-dropdown {
        position: absolute; right: -50px; top: 45px; width: 300px;
        background: rgba(30, 30, 45, 0.95); backdrop-filter: blur(12px);
        border: 1px solid rgba(255,255,255,0.1); border-radius: 12px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.6);
        display: none; z-index: 9999; overflow: hidden; transform-origin: top right;
    }
    .notif-header {
        padding: 15px; border-bottom: 1px solid rgba(255,255,255,0.08);
        font-weight: 600; color: white; display: flex; justify-content: space-between; align-items: center;
        background: rgba(255,255,255,0.02);
    }
    .notif-list { max-height: 350px; overflow-y: auto; }
    .notif-item {
        padding: 15px; border-bottom: 1px solid rgba(255,255,255,0.05);
        font-size: 0.9rem; color: #ccc; cursor: pointer; transition: 0.2s;
        display: block; text-decoration: none; position: relative;
    }
    .notif-item:hover { background: rgba(255,255,255,0.05); color: white; }
    .notif-item.unread { background: rgba(120, 111, 239, 0.08); border-left: 3px solid #786fef; }
    .notif-time { font-size: 0.75rem; color: #777; display: block; margin-top: 5px; }
    .notif-empty { padding: 30px; text-align: center; color: #666; font-style: italic; }
    
    /* Scrollbar for notifs */
    .notif-list::-webkit-scrollbar { width: 6px; }
    .notif-list::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 3px; }
`;

const styleSheet = document.createElement("style");
styleSheet.innerText = notifStyles;
document.head.appendChild(styleSheet);

document.addEventListener("DOMContentLoaded", () => {
    const token = localStorage.getItem('authToken');
    const path = window.location.pathname;
    
    const headerHTML = `
    <header class="header">
        <h2>Math Portal</h2>
        <nav class="nav-links">
            <a href="/" class="nav-item ${path === '/' ? 'active' : ''}">Home</a>
            <a href="/problems" class="nav-item ${path.includes('/problems') ? 'active' : ''}">Problems</a>
            <a href="/leaderboard" class="nav-item ${path.includes('/leaderboard') ? 'active' : ''}">Leaderboard</a>
            <a href="/vcontest" class="nav-item ${path.includes('/vcontest') ? 'active' : ''}">Contest</a>
            <div id="authSection" style="margin-left:20px;"></div>
        </nav>
    </header>`;
    
    document.body.insertAdjacentHTML('afterbegin', headerHTML);

    const authSection = document.getElementById('authSection');

    if (token) {
        checkUserCategory(token).then(cat => {
            let html = '';
            html += `
            <div class="notif-container">
                <button class="notif-btn" onclick="toggleNotifs()">
                    🔔 <span id="notifBadge" class="notif-badge">0</span>
                </button>
                <div id="notifDropdown" class="notif-dropdown">
                    <div class="notif-header">
                        <span>Notifications</span>
                        <span style="font-size:0.75rem; cursor:pointer; color:var(--purple-main);" onclick="markAllRead()">Mark all read</span>
                    </div>
                    <div id="notifList" class="notif-list">
                        <div class="notif-empty">Loading...</div>
                    </div>
                </div>
            </div>`;

            if (parseInt(cat) >= 0) {
                html += `<a href="/academics" class="nav-item ${path === '/academics' ? 'active' : ''}" style="margin-right:20px; color:var(--purple-main);">Academic Dashboard</a>`;
            }
            html += `<a href="/profile" class="nav-item ${path === '/profile' ? 'active' : ''}">👤 Profile</a>`;
            html += `<a href="#" onclick="logout()" class="nav-item" style="color:#ff6b6b; margin-left:15px;">Logout</a>`;
            authSection.innerHTML = html;
            loadNotifications();
        });
    } else {
        authSection.innerHTML = `<button class="btn-primary" onclick="window.location.href='/join'" style="padding:5px 15px; font-size:0.9rem;">Join Us</button>`;
    }
    document.addEventListener('click', (e) => {
        const container = document.querySelector('.notif-container');
        if (container && !container.contains(e.target)) {
            document.getElementById('notifDropdown').style.display = 'none';
        }
    });
});



async function checkUserCategory(token) {
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        return payload.category;
    } catch (e) { return -1; }
}

function logout() {
    localStorage.removeItem('authToken');
    window.location.href = '/join';
}

let isNotifOpen = false;

async function loadNotifications() {
    const token = localStorage.getItem('authToken');
    if(!token) return;

    try {
        const res = await fetch('/api/notifications', { 
            headers: { 'Authorization': `Bearer ${token}` } 
        });
        const data = await res.json();
        
        const badge = document.getElementById('notifBadge');
        if (data.unreadCount > 0) {
            badge.innerText = data.unreadCount > 9 ? '9+' : data.unreadCount;
            badge.style.display = 'block';
        } else {
            badge.style.display = 'none';
        }

        const list = document.getElementById('notifList');
        if (data.notifications.length === 0) {
            list.innerHTML = '<div class="notif-empty">No notifications</div>';
            return;
        }

        list.innerHTML = data.notifications.map(n => `
            <a href="${n.link || '#'}" 
               class="notif-item ${n.is_read ? '' : 'unread'}" 
               onclick="handleNotifClick(event, ${n.notification_id}, '${n.link || ''}')">
                
                <div style="margin-bottom:2px;">${escapeHtml(n.message)}</div>
                <span class="notif-time">${new Date(n.created_at).toLocaleDateString()}</span>
            </a>
        `).join('');

    } catch (e) { console.error("Notif Error", e); }
}

async function handleNotifClick(event, id, link) {
    event.preventDefault();

    const item = event.currentTarget;
    if (item.classList.contains('unread')) {
        item.classList.remove('unread');
        
        const badge = document.getElementById('notifBadge');
        let count = parseInt(badge.innerText) || 0;
        if (count > 0) {
            count--;
            badge.innerText = count > 9 ? '9+' : count;
            if (count === 0) badge.style.display = 'none';
        }
    }
    try {
        const token = localStorage.getItem('authToken');
        await fetch(`/api/notifications/${id}/read`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${token}` }
        });
    } catch (err) { console.error("Failed to mark read", err); }
    if (link && link !== '#') {
        window.location.href = link;
    }
}

function toggleNotifs() {
    const dd = document.getElementById('notifDropdown');
    const computedDisplay = window.getComputedStyle(dd).display;
    
    if (computedDisplay === 'none') {
        dd.style.display = 'block';
    } else {
        dd.style.display = 'none';
    }
}

async function markAllRead() {
    const token = localStorage.getItem('authToken');
    await fetch('/api/notifications/mark-read', { 
        method: 'POST', 
        headers: { 'Authorization': `Bearer ${token}` } 
    });
    
    document.getElementById('notifBadge').style.display = 'none';
    document.querySelectorAll('.notif-item.unread').forEach(el => {
        el.classList.remove('unread');
    });
}

function escapeHtml(text) {
    if (!text) return "";
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}