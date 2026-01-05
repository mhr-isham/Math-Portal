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
            if (parseInt(cat) >= 0) {
                html += `<a href="/academics" class="nav-item ${path === '/academics' ? 'active' : ''}" style="margin-right:20px; color:var(--purple-main);">Academic Dashboard</a>`;
            }
            html += `<a href="/profile" class="nav-item ${path === '/profile' ? 'active' : ''}">👤 Profile</a>`;
            html += `<a href="#" onclick="logout()" class="nav-item" style="color:#ff6b6b; margin-left:15px;">Logout</a>`;
            authSection.innerHTML = html;
        });
    } else {
        authSection.innerHTML = `<button class="btn-primary" onclick="window.location.href='/join'" style="padding:5px 15px; font-size:0.9rem;">Join Us</button>`;
    }
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