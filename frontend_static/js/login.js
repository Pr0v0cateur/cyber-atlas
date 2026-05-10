document.addEventListener('DOMContentLoaded', () => {
    initParticles();
    initMatrixRain();
    initLoginForm();
});

/* -------------------------------------------------------------------------- */
/*                               Particle System                              */
/* -------------------------------------------------------------------------- */
function initParticles() {
    const canvas = document.getElementById('particle-canvas');
    const ctx = canvas.getContext('2d');

    let width, height;
    let particles = [];

    // Configuration
    const particleCount = 100;
    const colors = ['#4a9eff', '#06b6d4', '#8b5cf6'];

    function resize() {
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width;
        canvas.height = height;
    }

    class Particle {
        constructor() {
            this.reset();
            // Random start Y to fill screen initially
            this.y = Math.random() * height;
        }

        reset() {
            this.x = Math.random() * width;
            this.y = height + Math.random() * 100; // Start below screen
            this.speed = 0.5 + Math.random() * 1.5;
            this.size = 1 + Math.random() * 2;
            this.color = colors[Math.floor(Math.random() * colors.length)];
            this.alpha = 0.1 + Math.random() * 0.5;
            this.drift = (Math.random() - 0.5) * 0.5;
        }

        update() {
            this.y -= this.speed;
            this.x += this.drift;

            if (this.y < -10) {
                this.reset();
            }
        }

        draw() {
            ctx.globalAlpha = this.alpha;
            ctx.fillStyle = this.color;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    function init() {
        resize();
        particles = [];
        for (let i = 0; i < particleCount; i++) {
            particles.push(new Particle());
        }
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);
        particles.forEach(p => {
            p.update();
            p.draw();
        });
        requestAnimationFrame(animate);
    }

    window.addEventListener('resize', () => {
        resize();
        init();
    });

    init();
    animate();
}

/* -------------------------------------------------------------------------- */
/*                                 Login Logic                                */
/* -------------------------------------------------------------------------- */
function initLoginForm() {
    const form = document.getElementById('login-form');
    const btn = document.getElementById('login-btn');
    const emailInput = document.getElementById('email');
    const passInput = document.getElementById('password');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        // UI Loading State
        const originalText = btn.querySelector('span').innerText;
        btn.querySelector('span').innerText = 'AUTHENTICATING...';
        btn.classList.add('loading');
        btn.disabled = true;

        const email = emailInput.value;
        const password = passInput.value;

        try {
            // Attempt login against our API
            // Assuming the frontend is served on the same origin or we use absolute URL
            // Using relative path assuming proxy or same origin
            const API_URL = 'http://localhost:8000/api';

            const response = await fetch(`${API_URL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    'username': email,
                    'password': password
                })
            });

            if (!response.ok) {
                throw new Error('Invalid credentials');
            }

            const data = await response.json();

            // Store token
            localStorage.setItem('access_token', data.access_token);

            // Success Animation
            btn.querySelector('span').innerText = 'SUCCESS';
            btn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';

            // Redirect
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 800);

        } catch (error) {
            console.error(error);

            // Error State
            btn.querySelector('span').innerText = 'FAILED';
            btn.style.background = 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)';

            // Shake animation on card
            const card = document.querySelector('.login-card');
            card.animate([
                { transform: 'translateX(0)' },
                { transform: 'translateX(-10px)' },
                { transform: 'translateX(10px)' },
                { transform: 'translateX(0)' }
            ], { duration: 400 });

            // Reset button
            setTimeout(() => {
                btn.querySelector('span').innerText = originalText;
                btn.classList.remove('loading');
                btn.disabled = false;
                btn.style.background = ''; // Reset to CSS default
            }, 2000);
        }
    });
}

/* -------------------------------------------------------------------------- */
/*                               Matrix Rain                                 */
/* -------------------------------------------------------------------------- */
function initMatrixRain() {
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) {
        return;
    }

    const ctx = canvas.getContext('2d');
    const chars = ['0', '1'];
    let width = 0;
    let height = 0;
    let fontSize = 16;
    let columns = 0;
    let drops = [];
    let lastFrame = 0;
    const frameInterval = 1000 / 30;

    function resize() {
        const dpr = window.devicePixelRatio || 1;
        width = window.innerWidth;
        height = window.innerHeight;

        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);
        canvas.style.width = `${width}px`;
        canvas.style.height = `${height}px`;

        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        fontSize = 16;
        columns = Math.floor(width / fontSize);
        drops = Array.from({ length: columns }, () => Math.random() * height / fontSize);
        ctx.font = `${fontSize}px Consolas, "Courier New", monospace`;
    }

    function draw(timestamp) {
        if (timestamp - lastFrame < frameInterval) {
            requestAnimationFrame(draw);
            return;
        }
        lastFrame = timestamp;

        ctx.fillStyle = 'rgba(10, 14, 26, 0.08)';
        ctx.fillRect(0, 0, width, height);
        ctx.fillStyle = 'rgba(0, 132, 255, 0.35)';

        for (let i = 0; i < drops.length; i += 1) {
            const char = chars[Math.floor(Math.random() * chars.length)];
            const x = i * fontSize;
            const y = drops[i] * fontSize;
            ctx.fillText(char, x, y);

            if (y > height && Math.random() > 0.985) {
                drops[i] = 0;
            } else {
                drops[i] += 0.6;
            }
        }

        requestAnimationFrame(draw);
    }

    resize();
    window.addEventListener('resize', resize);
    requestAnimationFrame(draw);
}
