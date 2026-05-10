/**
 * Cyber Atlas - Enhanced Sidebar Controller
 * Handles navigation, settings dropdown, theme toggle, and user interactions
 */

class SidebarController {
    constructor() {
        this.sidebar = document.getElementById('sidebar');
        this.settingsDropdown = document.getElementById('settingsDropdown');
        const storedExpanded = localStorage.getItem('sidebarExpanded');
        this.isExpanded = storedExpanded === null ? true : storedExpanded === 'true';
        this.isDarkMode = localStorage.getItem('theme') !== 'light';

        this.init();
    }

    init() {
        this.ensureIconFont();
        // Set initial states
        this.updateSidebarState();
        this.updateTheme();

        // Set active nav item based on current page
        this.setActiveNavItem();

        // Bind events
        this.bindEvents();

        // Update badge counts
        this.updateBadgeCounts();
    }

    ensureIconFont() {
        const hasFontAwesome = document.querySelector('link[href*="font-awesome"], link[href*="fontawesome"]');
        if (hasFontAwesome) {
            return;
        }
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css';
        link.setAttribute('data-font-awesome', 'true');
        document.head.appendChild(link);
    }

    bindEvents() {
        // Toggle sidebar expand/collapse
        const toggleBtn = document.getElementById('sidebarToggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggleSidebar());
        }

        // Settings trigger
        const settingsTrigger = document.getElementById('settingsTrigger');
        if (settingsTrigger) {
            settingsTrigger.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggleSettings();
            });
        }

        // Close settings when clicking outside
        document.addEventListener('click', (e) => {
            if (this.settingsDropdown && !this.settingsDropdown.contains(e.target)) {
                this.closeSettings();
            }
        });

        // Theme toggle
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }

        // Logout button
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.handleLogout());
        }

        // Nav item click effects
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                // Ripple effect
                const ripple = document.createElement('span');
                ripple.className = 'nav-ripple';
                ripple.style.left = e.offsetX + 'px';
                ripple.style.top = e.offsetY + 'px';
                item.appendChild(ripple);
                setTimeout(() => ripple.remove(), 600);
            });
        });

        // Keyboard navigation
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeSettings();
            }
        });
    }

    toggleSidebar() {
        this.isExpanded = !this.isExpanded;
        localStorage.setItem('sidebarExpanded', this.isExpanded);
        this.updateSidebarState();
    }

    updateSidebarState() {
        if (this.sidebar) {
            this.sidebar.classList.toggle('expanded', this.isExpanded);
        }
    }

    toggleSettings() {
        if (this.settingsDropdown) {
            this.settingsDropdown.classList.toggle('show');
        }
    }

    closeSettings() {
        if (this.settingsDropdown) {
            this.settingsDropdown.classList.remove('show');
        }
    }

    toggleTheme() {
        this.isDarkMode = !this.isDarkMode;
        localStorage.setItem('theme', this.isDarkMode ? 'dark' : 'light');
        this.updateTheme();
    }

    updateTheme() {
        document.body.classList.toggle('light-mode', !this.isDarkMode);

        const themeSwitch = document.querySelector('.theme-switch');
        if (themeSwitch) {
            themeSwitch.classList.toggle('dark', this.isDarkMode);
        }

        const themeIcon = document.getElementById('themeIcon');
        if (themeIcon) {
            themeIcon.className = this.isDarkMode ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
        }

        const themeLabel = document.getElementById('themeLabel');
        if (themeLabel) {
            themeLabel.textContent = this.isDarkMode ? 'Dark Mode' : 'Light Mode';
        }
    }

    setActiveNavItem() {
        const currentPath = window.location.pathname;
        const navItems = document.querySelectorAll('.nav-item[data-page]');

        navItems.forEach(item => {
            const page = item.getAttribute('data-page');
            const isActive = currentPath.includes(page) ||
                (page === 'dashboard' && (currentPath === '/' || currentPath.endsWith('dashboard.html')));
            item.classList.toggle('active', isActive);
        });
    }

    async updateBadgeCounts() {
        try {
            // Fetch counts from API
            const response = await fetch(`${getAppBase()}/api/stats/summary`);
            if (response.ok) {
                const data = await response.json();

                // Update badges
                this.setBadge('badge-ips', data.blacklisted_ips || 0);
                this.setBadge('badge-domains', data.blacklisted_domains || 0);
                this.setBadge('badge-cves', data.new_cves || 0);
            }
        } catch (error) {
            console.log('Could not fetch badge counts:', error);
        }
    }

    setBadge(id, count) {
        const badge = document.getElementById(id);
        if (badge) {
            if (count > 0) {
                badge.textContent = count > 999 ? '999+' : count;
                badge.style.display = 'block';
            } else {
                badge.style.display = 'none';
            }
        }
    }

    handleLogout() {
        // Clear tokens
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        sessionStorage.clear();

        // Redirect to login
        window.location.href = `${getAppBase()}/static/index.html`;
    }
}

function getAppBase() {
    if (window.location.origin.includes('localhost:8000') || window.location.origin.includes('127.0.0.1:8000')) {
        return window.location.origin;
    }
    return 'http://localhost:8000';
}

const ICON_SVGS = {
    dashboard: '<path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>',
    threats: '<path d="M12 2l8 4v6c0 5-3.5 9.5-8 12-4.5-2.5-8-7-8-12V6l8-4z"/>',
    search: '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    ips: '<circle cx="5" cy="12" r="3"/><circle cx="19" cy="5" r="3"/><circle cx="19" cy="19" r="3"/><line x1="7.5" y1="11" x2="16.5" y2="6.5"/><line x1="7.5" y1="13" x2="16.5" y2="17.5"/>',
    domains: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 0 20a15.3 15.3 0 0 1 0-20z"/>',
    cves: '<rect x="8" y="6" width="8" height="12" rx="4"/><path d="M12 6V3"/><path d="M9 3h6"/><path d="M5 7l3 2"/><path d="M19 7l-3 2"/><path d="M5 17l3-2"/><path d="M19 17l-3-2"/>',
    breach: '<path d="M12 2l8 4v6c0 5-3.5 9.5-8 12-4.5-2.5-8-7-8-12V6l8-4z"/><path d="M8.5 12.5l2.5 2.5 4.5-4.5"/>',
    mitre: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><line x1="8" y1="7" x2="16" y2="7"/><line x1="7" y1="8" x2="11" y2="16"/><line x1="17" y1="8" x2="13" y2="16"/>',
    reports: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>',
    default: '<circle cx="12" cy="12" r="4"/>'
};

function iconMarkup(name) {
    const svg = ICON_SVGS[name] || ICON_SVGS.default;
    return `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">${svg}</svg>`;
}

// Generate sidebar HTML
function generateSidebarHTML() {
    const appBase = getAppBase();
    const userName = localStorage.getItem('user_name') || 'Admin';
    const userEmail = localStorage.getItem('user_email') || 'admin@cyberatlas.io';
    const userInitial = userName.charAt(0).toUpperCase();

    return `
    <aside class="sidebar" id="sidebar">
        <!-- Logo -->
        <div class="sidebar-logo" onclick="window.location.href='${appBase}/static/dashboard.html'" title="Cyber Atlas">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2L2 7l10 5 10-5-10-5z"/>
                <path d="M2 17l10 5 10-5"/>
                <path d="M2 12l10 5 10-5"/>
            </svg>
        </div>
        
        <!-- Main Navigation -->
        <nav class="nav-section">
            <div class="nav-section-title">Main</div>
            
            <a href="${appBase}/static/dashboard.html" class="nav-item" data-page="dashboard">
                <div class="nav-icon">
                    ${iconMarkup('dashboard')}
                </div>
                <span class="nav-label">Dashboard</span>
                <span class="nav-tooltip">Dashboard</span>
            </a>
            
            <a href="${appBase}/static/threats.html" class="nav-item" data-page="threats">
                <div class="nav-icon threats">
                    ${iconMarkup('threats')}
                </div>
                <span class="nav-label">Threat Intel</span>
                <span class="nav-tooltip">Threat Intelligence</span>
            </a>
            
            <a href="${appBase}/static/search.html" class="nav-item" data-page="search">
                <div class="nav-icon intel">
                    ${iconMarkup('search')}
                </div>
                <span class="nav-label">IOC Search</span>
                <span class="nav-tooltip">Search IOCs</span>
            </a>
        </nav>
        
        <div class="nav-divider"></div>
        
        <!-- Threat Categories -->
        <nav class="nav-section">
            <div class="nav-section-title">Blacklists</div>
            
            <a href="${appBase}/static/blacklist-ips.html" class="nav-item has-update" data-page="blacklist-ips">
                <div class="nav-icon threats">
                    ${iconMarkup('ips')}
                </div>
                <span class="nav-label">Blacklisted IPs</span>
                <span class="nav-badge" id="badge-ips">128</span>
                <span class="nav-tooltip">Blacklisted IPs</span>
            </a>
            
            <a href="${appBase}/static/blacklist-domains.html" class="nav-item" data-page="blacklist-domains">
                <div class="nav-icon threats">
                    ${iconMarkup('domains')}
                </div>
                <span class="nav-label">Malicious Domains</span>
                <span class="nav-badge" id="badge-domains">56</span>
                <span class="nav-tooltip">Malicious Domains</span>
            </a>
            
            <a href="${appBase}/static/cves.html" class="nav-item" data-page="cves">
                <div class="nav-icon intel">
                    ${iconMarkup('cves')}
                </div>
                <span class="nav-label">Latest CVEs</span>
                <span class="nav-badge" id="badge-cves">24</span>
                <span class="nav-tooltip">Latest CVEs</span>
            </a>
        </nav>
        
        <div class="nav-divider"></div>
        
        <!-- Analysis Tools -->
        <nav class="nav-section">
            <div class="nav-section-title">Tools</div>
            
            <a href="${appBase}/static/breach-checker.html" class="nav-item" data-page="breach-checker">
                <div class="nav-icon assets">
                    ${iconMarkup('breach')}
                </div>
                <span class="nav-label">Breach Checker</span>
                <span class="nav-tooltip">Email Breach Checker</span>
            </a>
            
            <a href="${appBase}/static/mitre.html" class="nav-item" data-page="mitre">
                <div class="nav-icon reports">
                    ${iconMarkup('mitre')}
                </div>
                <span class="nav-label">MITRE ATT&CK</span>
                <span class="nav-tooltip">MITRE Framework</span>
            </a>
            
            <a href="${appBase}/static/reports.html" class="nav-item" data-page="reports">
                <div class="nav-icon reports">
                    ${iconMarkup('reports')}
                </div>
                <span class="nav-label">Reports</span>
                <span class="nav-tooltip">Threat Reports</span>
            </a>
        </nav>
        
        <!-- Footer: Settings & User -->
        <div class="sidebar-footer">
            <!-- Toggle Button -->
            <div class="sidebar-toggle" id="sidebarToggle" title="Toggle Sidebar">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M9 18l6-6-6-6"/>
                </svg>
            </div>
            
            <!-- Settings -->
            <div class="settings-container">
                <div class="settings-trigger" id="settingsTrigger">
                    <div class="nav-icon">
                        <i class="fa-solid fa-gear"></i>
                    </div>
                    <span class="nav-label">Settings</span>
                    <span class="nav-tooltip">Settings</span>
                </div>
                
                <div class="settings-dropdown" id="settingsDropdown">
                    <div class="settings-dropdown-header">
                        <h4>Settings</h4>
                        <p>Manage your preferences</p>
                    </div>
                    
                    <div class="theme-toggle" id="themeToggle">
                        <i id="themeIcon" class="fa-solid fa-moon"></i>
                        <span id="themeLabel">Dark Mode</span>
                        <div class="theme-switch dark"></div>
                    </div>
                    
                    <div class="settings-item" onclick="window.location.href='${appBase}/static/dashboard.html#section-search'">
                        <i class="fa-solid fa-user"></i>
                        <span>Account Settings</span>
                    </div>
                    
                    <div class="settings-item" onclick="window.location.href='${appBase}/static/dashboard.html#section-search'">
                        <i class="fa-solid fa-key"></i>
                        <span>Change Password</span>
                    </div>
                    
                    <div class="settings-item" onclick="window.location.href='${appBase}/static/dashboard.html#section-search'">
                        <i class="fa-solid fa-bell"></i>
                        <span>Notifications</span>
                    </div>
                    
                    <div class="settings-item" onclick="window.location.href='${appBase}/static/dashboard.html#section-search'">
                        <i class="fa-solid fa-code"></i>
                        <span>API Keys</span>
                    </div>
                    
                    <div class="nav-divider" style="margin: 8px 0;"></div>
                    
                    <div class="settings-item danger" id="logoutBtn">
                        <i class="fa-solid fa-right-from-bracket"></i>
                        <span>Log Out</span>
                    </div>
                </div>
            </div>
            
            <!-- User Profile -->
            <div class="user-profile" onclick="window.location.href='${appBase}/static/dashboard.html#section-search'">
                <div class="user-avatar">${userInitial}</div>
                <div class="user-info">
                    <div class="user-name">${userName}</div>
                    <div class="user-role">Administrator</div>
                </div>
            </div>
        </div>
    </aside>
    `;
}

// Initialize sidebar
document.addEventListener('DOMContentLoaded', () => {
    // Find sidebar placeholder or existing sidebar
    const existingSidebar = document.querySelector('.sidebar, aside.sidebar');

    if (existingSidebar) {
        // Replace with new sidebar
        existingSidebar.outerHTML = generateSidebarHTML();
    } else {
        // Insert at beginning of app-container
        const appContainer = document.querySelector('.app-container');
        if (appContainer) {
            appContainer.insertAdjacentHTML('afterbegin', generateSidebarHTML());
        }
    }

    // Initialize controller
    window.sidebarController = new SidebarController();
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SidebarController, generateSidebarHTML };
}
