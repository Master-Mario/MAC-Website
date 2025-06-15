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
            console.log('Mobile menu icon geklickt!'); // Hinzugefügte Zeile für die Diagnose
            navLinks.classList.toggle('open'); // Toggle 'open' class
            console.log('Klassen von navLinks:', navLinks.className); // Hinzugefügte Zeile für die Diagnose
        });
    }
    // End of Mobile menu toggle

    // Logout Modal Elements
    const logoutConfirmationModal = document.getElementById('logoutConfirmationModal');
    const confirmLogoutBtn = document.getElementById('confirmLogoutBtn');
    const cancelLogoutBtn = document.getElementById('cancelLogoutBtn');

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

    function showLogoutModal() {
        if (logoutConfirmationModal) {
            logoutConfirmationModal.classList.add('open');
        }
    }

    function hideLogoutModal() {
        if (logoutConfirmationModal) {
            logoutConfirmationModal.classList.remove('open');
        }
    }

    async function performActualLogout() {
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
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', (event) => {
            event.preventDefault(); // Prevent any default action
            showLogoutModal();
        });
    }

    if (confirmLogoutBtn) {
        confirmLogoutBtn.addEventListener('click', () => {
            hideLogoutModal();
            performActualLogout();
        });
    }

    if (cancelLogoutBtn) {
        cancelLogoutBtn.addEventListener('click', () => {
            hideLogoutModal();
        });
    }

    // Close modal if user clicks on the overlay itself
    if (logoutConfirmationModal) {
        logoutConfirmationModal.addEventListener('click', (event) => {
            if (event.target === logoutConfirmationModal) {
                hideLogoutModal();
            }
        });
    }

    // Initial check
    checkAuthStatus();
});
// --- Auth Script End ---

// --- Stripe Payment Script Start ---
document.addEventListener('DOMContentLoaded', () => {
    const registrationForm = document.getElementById('registrationForm');
    const paymentMessage = document.getElementById('payment-message');
    if (registrationForm) {
        registrationForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            paymentMessage.textContent = ''; // Clear previous messages

            const minecraftUsername = document.getElementById('minecraftUsername').value;
            const email = document.getElementById('email').value;
            const agbChecked = document.getElementById('agb').checked;

            if (!agbChecked) {
                paymentMessage.textContent = 'Bitte stimme den AGB und der Datenschutzerklärung zu.';
                return;
            }

            if (!minecraftUsername || !email) {
                paymentMessage.textContent = 'Bitte fülle alle erforderlichen Felder aus.';
                return;
            }

            try {
                // 1. Create a checkout session on the server
                const response = await fetch('/create-checkout-session', { // Sicherstellen, dass der Pfad korrekt ist
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ minecraftUsername, email }),
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    paymentMessage.textContent = errorData.error || 'Fehler bei der Erstellung der Bezahlseite.';
                    console.error('Server error:', errorData);
                    return;
                }

                const sessionData = await response.json();
                if (!sessionData.url) {
                    paymentMessage.textContent = 'Fehler: Keine URL für die Bezahlseite erhalten.';
                    return;
                }
                // 2. Redirect to the Stripe Checkout page
                window.location.href = sessionData.url;

            } catch (error) {
                paymentMessage.textContent = 'Ein unerwarteter Fehler ist aufgetreten.';
                console.error('Client-side error:', error);
            }
        });
    }

    // Handle payment status messages from URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('payment_success')) {
        paymentMessage.style.color = 'green';
        paymentMessage.textContent = 'Zahlung erfolgreich! Du wirst in Kürze für den Server freigeschaltet.';
    }
    if (urlParams.has('payment_cancelled')) {
        paymentMessage.style.color = 'orange';
        paymentMessage.textContent = 'Die Zahlung wurde abgebrochen. Bitte versuche es erneut.';
    }
});
// --- Stripe Payment Script End ---

// --- Cookie Banner Script ---
document.addEventListener('DOMContentLoaded', function() {
    // Cookie-Banner auf AGB und Datenschutzseite erst nach Login-Klick anzeigen
    const isAGB = window.location.pathname.endsWith('agb.html');
    const isDatenschutz = window.location.pathname.endsWith('datenschutz.html');
    if (isAGB || isDatenschutz) {
        // Cookie-Banner sofort verstecken, falls es im HTML existiert
        const cookieBanner = document.getElementById('cookieBanner');
        if (cookieBanner) {
            cookieBanner.classList.add('hide');
            cookieBanner.style.display = 'none';
        }
        // Login-Button suchen
        const loginBtn = document.getElementById('discordLoginBtn');
        if (loginBtn) {
            loginBtn.addEventListener('click', function() {
                showCookieBanner();
            });
        }
        // Funktion zum Anzeigen des Cookie-Banners
        function showCookieBanner() {
            let banner = document.getElementById('cookieBanner');
            if (!banner) {
                banner = document.createElement('div');
                banner.id = 'cookieBanner';
                banner.className = 'cookie-banner';
                banner.innerHTML = `
                    <div class=\"cookie-banner-overlay\"></div>
                    <div class=\"cookie-banner-center\">
                        <div class=\"cookie-banner-content\">
                            <span class=\"cookie-banner-text\">Diese Website verwendet Cookies für Login und Zahlungsabwicklung. Mehr dazu in der <a href=\"datenschutz.html\" target=\"_blank\">Datenschutzerklärung</a>.</span>
                            <button id=\"acceptCookiesBtn\" class=\"cookie-banner-btn\">Verstanden</button>
                        </div>
                    </div>
                `;
                document.body.appendChild(banner);
            } else {
                banner.style.display = '';
            }
            banner.classList.remove('hide');
            disablePage(true);
            const acceptBtn = document.getElementById('acceptCookiesBtn');
            if (acceptBtn) {
                acceptBtn.addEventListener('click', function() {
                    setCookie('mac_cookies_accepted', '1', 365);
                    banner.classList.add('hide');
                    banner.style.display = 'none';
                    disablePage(false);
                    const overlay = document.querySelector('.cookie-banner-overlay');
                    if (overlay) overlay.style.display = 'none';
                });
            }
        }
        // Hilfsfunktionen (aus Originalskript)
        function setCookie(name, value, days) {
            let expires = '';
            if (days) {
                const date = new Date();
                date.setTime(date.getTime() + (days*24*60*60*1000));
                expires = "; expires=" + date.toUTCString();
            }
            document.cookie = name + "=" + (value || "") + expires + "; path=/; SameSite=Lax";
        }
        function disablePage(disabled) {
            if (disabled) {
                document.body.classList.add('cookies-blocked');
                if (!document.getElementById('cookieBlockerOverlay')) {
                    const overlay = document.createElement('div');
                    overlay.id = 'cookieBlockerOverlay';
                    overlay.style.position = 'fixed';
                    overlay.style.inset = '0';
                    overlay.style.width = '100vw';
                    overlay.style.height = '100vh';
                    overlay.style.zIndex = '2999';
                    overlay.style.background = 'transparent';
                    overlay.style.pointerEvents = 'all';
                    overlay.tabIndex = 0;
                    overlay.setAttribute('aria-hidden', 'true');
                    document.body.appendChild(overlay);
                }
            } else {
                document.body.classList.remove('cookies-blocked');
                const overlay = document.getElementById('cookieBlockerOverlay');
                if (overlay) overlay.remove();
            }
        }
        return; // Restliches Cookie-Banner-Skript nicht ausführen
    }
    // Cookie-Banner dynamisch einfügen, falls noch nicht vorhanden
    if (!document.getElementById('cookieBanner')) {
        const banner = document.createElement('div');
        banner.id = 'cookieBanner';
        banner.className = 'cookie-banner';
        banner.innerHTML = `
            <div class="cookie-banner-overlay"></div>
            <div class="cookie-banner-center">
                <div class="cookie-banner-content">
                    <span class="cookie-banner-text">Diese Website verwendet Cookies für Login und Zahlungsabwicklung. Mehr dazu in der <a href="datenschutz.html" target="_blank">Datenschutzerklärung</a>.</span>
                    <button id="acceptCookiesBtn" class="cookie-banner-btn">Verstanden</button>
                </div>
            </div>
        `;
        document.body.appendChild(banner);
    }
    const cookieBanner = document.getElementById('cookieBanner');
    const acceptBtn = document.getElementById('acceptCookiesBtn');
    // Cookie prüfen
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }
    if (getCookie('mac_cookies_accepted') === '1') {
        cookieBanner.classList.add('hide');
        disablePage(false);
        const overlay = document.querySelector('.cookie-banner-overlay');
        if (overlay) overlay.style.display = 'none';
    } else {
        cookieBanner.classList.remove('hide');
        disablePage(true);
    }
    if (acceptBtn) {
        acceptBtn.addEventListener('click', function() {
            setCookie('mac_cookies_accepted', '1', 365);
            cookieBanner.classList.add('hide');
            disablePage(false);
            const overlay = document.querySelector('.cookie-banner-overlay');
            if (overlay) overlay.style.display = 'none';
        });
    }
});
// --- Cookie Banner Script ---
