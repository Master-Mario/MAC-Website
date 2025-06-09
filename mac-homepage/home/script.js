// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const targetId = this.getAttribute('href');
        // Check if the target is on the current page or another page
        if (targetId.startsWith('#')) { // Target is on the current page
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        } else { // Target is on another page (e.g., smp.html#hash)
            window.location.href = this.href;
        }
    });
});

// Navbar scroll effect
window.addEventListener('scroll', function() {
    const navbar = document.getElementById('navbar');
    if (navbar && window.scrollY > 50) { // Added null check for navbar
        navbar.classList.add('scrolled');
    } else if (navbar) {
        navbar.classList.remove('scrolled');
    }
});

// --- Auth Script Start ---
document.addEventListener('DOMContentLoaded', () => {
    const discordLoginBtn = document.getElementById('discordLoginBtn');
    const userInfoDiv = document.getElementById('userInfo');
    const userAvatarImg = document.getElementById('userAvatar');
    const userNameSpan = document.getElementById('userName');
    const logoutBtn = document.getElementById('logoutBtn');

    // Mobile menu toggle
    const mobileMenuIcon = document.querySelector('.mobile-menu');
    const navLinks = document.querySelector('.nav-links');

    if (mobileMenuIcon && navLinks) {
        mobileMenuIcon.addEventListener('click', function() {
            navLinks.classList.toggle('open'); // Toggle 'open' class
        });
    }
    // End of Mobile menu toggle

    const defaultAvatarUrl = '../logos/favicon-32x32.png'; // Path to your default avatar

    async function checkAuthStatus() {
        try {
            const response = await fetch('/api/auth/status', { // Geändert zu relativem Pfad
                credentials: 'include' // Wichtig für Cookies/Sessions
            });
            if (!response.ok) {
                console.error('Auth status check failed:', response.status);
                displayLoggedOutState();
                return;
            }
            const data = await response.json();
            if (data.loggedIn && data.user) {
                displayLoggedInState(data.user);
            } else {
                displayLoggedOutState();
            }
        } catch (error) {
            console.error('Error checking auth status:', error);
            displayLoggedOutState();
        }
    }

    function displayLoggedInState(user) {
        if (discordLoginBtn) discordLoginBtn.style.display = 'none';
        if (userInfoDiv) userInfoDiv.style.display = 'flex';
        if (userNameSpan) userNameSpan.textContent = user.username;
        if (userAvatarImg) {
            if (user.id && user.avatar) {
                userAvatarImg.src = `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`;
            } else {
                userAvatarImg.src = defaultAvatarUrl;
            }
        }
    }

    function displayLoggedOutState() {
        if (discordLoginBtn) discordLoginBtn.style.display = 'flex';
        if (userInfoDiv) userInfoDiv.style.display = 'none';
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            try {
                const response = await fetch('/logout', { // Geändert zu relativem Pfad
                    method: 'GET',
                    credentials: 'include'
                });
                if (response.ok) {
                    displayLoggedOutState();
                    // Optionally redirect to home or refresh
                    // window.location.href = '/';
                } else {
                    console.error('Logout failed:', response.status);
                    alert('Logout fehlgeschlagen.');
                }
            } catch (error) {
                console.error('Error during logout:', error);
                alert('Fehler beim Logout.');
            }
        });
    }

    // Initial check
    checkAuthStatus();
});
// --- Auth Script End ---
