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
// Stripe initialisieren
const stripe = Stripe('pk_test_...'); // Dein Stripe-Publishable-Key
let elements, card;

async function setupStripeElements() {
    elements = stripe.elements();
    card = elements.create('card');
    card.mount('#card-element');
    card.on('change', (event) => {
        document.getElementById('card-errors').textContent = event.error ? event.error.message : '';
    });
}

async function handleRegistrationFormSubmit(event) {
    event.preventDefault();

    // Hole die E-Mail vom Formular
    const email = document.getElementById('email').value;

    // SetupIntent vom Server holen
    const response = await fetch('/create-setup-intent', {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email })
    });
    const data = await response.json();

    // SetupIntent bestätigen (Card speichern)
    const { setupIntent, error } = await stripe.confirmCardSetup(
        data.clientSecret, {
            payment_method: {
                card: card,
                billing_details: { email }
            }
        }
    );
    if (error) {
        document.getElementById('card-errors').textContent = error.message;
        return;
    }

    // Jetzt ist die Karte sicher bei Stripe gespeichert!
    // Sende alle Formulardaten + customerId + paymentMethodId an DEIN backend
    const registerBody = {
        minecraftUsername: document.getElementById('minecraftUsername').value,
        email,
        customerId: data.customerId,
        paymentMethodId: setupIntent.payment_method
    };
    await fetch('/final-registration', {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(registerBody)
    });

    // Zeige Erfolg, leite weiter, etc.
    alert('Registrierung erfolgreich! Wir buchen erst am Monatsende ab.');
}

document.addEventListener('DOMContentLoaded', () => {
    setupStripeElements();
    document.getElementById('registrationForm').addEventListener('submit', handleRegistrationFormSubmit);
});
