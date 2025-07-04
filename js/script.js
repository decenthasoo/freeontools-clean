function loadHTML(file, placeholderId, callback) {
    console.log(`script.js: Trying to load ${file}`);
    fetch(file, { cache: "no-store" })
        .then(response => {
            console.log(`script.js: ${file} response status: ${response.status}`);
            if (!response.ok) {
                throw new Error(`${file} failed to load with status ${response.status}`);
            }
            return response.text();
        })
        .then(data => {
            console.log(`script.js: ${file} loaded successfully`);
            const placeholder = document.getElementById(placeholderId);
            if (placeholder) {
                placeholder.innerHTML = data;
                console.log(`script.js: Inserted ${file} into ${placeholderId}`);
                if (callback) callback();
                // Trigger auth header update after header load
                if (file === "Header.html") {
                    console.log("script.js: Header.html loaded, scheduling auth header update");
                    triggerAuthHeaderUpdate(1, 30);
                }
            } else {
                console.error(`script.js: Placeholder ${placeholderId} not found`);
            }
        })
        .catch(error => {
            console.error(`script.js: Error loading ${file}: ${error.message}`);
        });
}

function initializeHeaderScripts() {
    console.log("script.js: Setting up header buttons");

    function setupHeader(attempt = 1, maxAttempts = 10) {
        const hamburgerBtn = document.querySelector(".hamburger-btn");
        const hamburgerContent = document.querySelector(".hamburger-content");
        const dropdownBtn = document.querySelector(".dropbtn");
        const dropdown = document.querySelector(".dropdown");
        const languageBtn = document.querySelector(".language-btn");
        const languageContent = document.querySelector(".language");
        const dropdownCloseBtn = document.querySelector(".dropdown .dropdown-content .close-btn");
        const navDropdownBtn = document.querySelector(".nav-has-dropdown .nav-dropdown-btn");
        const navDropdown = document.querySelector(".nav-has-dropdown");
        const navCloseBtn = document.querySelector(".nav-has-dropdown .dropdown-content .close-btn");

        if (!hamburgerBtn || !hamburgerContent || !dropdownBtn || !dropdown || !languageBtn || !languageContent || !dropdownCloseBtn || !navDropdownBtn || !navDropdown || !navCloseBtn) {
            console.error(`script.js: Attempt ${attempt}: Some header elements are missing:`, {
                hamburgerBtn: !!hamburgerBtn,
                hamburgerContent: !!hamburgerContent,
                dropdownBtn: !!dropdownBtn,
                dropdown: !!dropdown,
                languageBtn: !!languageBtn,
                languageContent: !!languageContent,
                dropdownCloseBtn: !!dropdownCloseBtn,
                navDropdownBtn: !!navDropdownBtn,
                navDropdown: !!navDropdown,
                navCloseBtn: !!navCloseBtn
            });
            if (attempt < maxAttempts) {
                setTimeout(() => setupHeader(attempt + 1, maxAttempts), 100);
            } else {
                console.error(`script.js: Failed to initialize header after ${maxAttempts} attempts`);
            }
            return;
        }

        // Toggle dropdown (POPULAR TOOLS)
        const toggleDropdown = () => {
            if (window.innerWidth <= 1280) {
                console.log("script.js: Dropdown button clicked/touched, toggling active class");
                dropdown.classList.toggle("active");
                const dropdownContent = dropdown.querySelector(".dropdown-content");
                dropdownContent.style.display = dropdown.classList.contains("active") ? "flex" : "none";
            }
        };

        // Toggle nav-has-dropdown (Profile, Settings, Logout)
        const toggleNavDropdown = () => {
            if (window.innerWidth <= 834) {
                console.log("script.js: Nav dropdown button clicked/touched, toggling active class");
                navDropdown.classList.toggle("active");
                const navDropdownContent = navDropdown.querySelector(".dropdown-content");
                navDropdownContent.style.display = navDropdown.classList.contains("active") ? "block" : "none";
            }
        };

        // Remove existing listeners to prevent duplicates
        dropdownBtn.removeEventListener("click", toggleDropdown);
        dropdownBtn.removeEventListener("touchstart", toggleDropdown);
        navDropdownBtn.removeEventListener("click", toggleNavDropdown);
        navDropdownBtn.removeEventListener("touchstart", toggleNavDropdown);

        // Add listeners for dropdown
        dropdownBtn.addEventListener("click", toggleDropdown);
        dropdownBtn.addEventListener("touchstart", (e) => {
            e.preventDefault();
            toggleDropdown();
        });

        // Add listeners for nav-has-dropdown
        navDropdownBtn.addEventListener("click", toggleNavDropdown);
        navDropdownBtn.addEventListener("touchstart", (e) => {
            e.preventDefault();
            toggleNavDropdown();
        });

        // Hamburger menu
        hamburgerBtn.addEventListener("click", () => {
            console.log("script.js: Hamburger button clicked");
            hamburgerContent.classList.toggle("active");
        });

        // Language dropdown
        languageBtn.addEventListener("click", () => {
            console.log("script.js: Language button clicked");
            languageContent.classList.toggle("active");
        });

        // Close button for dropdown
        dropdownCloseBtn.addEventListener("click", () => {
            if (window.innerWidth <= 1280) {
                console.log("script.js: Dropdown close button clicked, removing active class");
                dropdown.classList.remove("active");
                const dropdownContent = dropdown.querySelector(".dropdown-content");
                dropdownContent.style.display = "none";
            }
        });

        // Close button for nav-has-dropdown
        navCloseBtn.addEventListener("click", () => {
            if (window.innerWidth <= 834) {
                console.log("script.js: Nav dropdown close button clicked, removing active class");
                navDropdown.classList.remove("active");
                const navDropdownContent = navDropdown.querySelector(".dropdown-content");
                navDropdownContent.style.display = "none";
            }
        });

        // Add immediate navigation for dropdown links
        const dropdownLinks = document.querySelectorAll(".tool-list a");
        dropdownLinks.forEach(link => {
            link.removeEventListener("click", handleLinkClick);
            link.addEventListener("click", handleLinkClick);

            function handleLinkClick(e) {
                e.stopPropagation();
                console.log(`script.js: Navigating to ${link.href}`);
                dropdown.classList.remove("active");
                const dropdownContent = dropdown.querySelector(".dropdown-content");
                dropdownContent.style.display = "none";
                window.location.href = link.href;
            }
        });

        // Add immediate navigation for nav-has-dropdown links
        const navLinks = navDropdown.querySelectorAll(".tool-list a");
        navLinks.forEach(link => {
            link.removeEventListener("click", handleNavLinkClick);
            link.addEventListener("click", handleNavLinkClick);

            function handleNavLinkClick(e) {
                e.stopPropagation();
                console.log(`script.js: Navigating to ${link.href}`);
                navDropdown.classList.remove("active");
                const navDropdownContent = navDropdown.querySelector(".dropdown-content");
                navDropdownContent.style.display = "none";
                window.location.href = link.href;
            }
        });

        // Close dropdowns when clicking outside
        document.addEventListener("click", (event) => {
            if (!hamburgerBtn.contains(event.target) && !hamburgerContent.contains(event.target)) {
                hamburgerContent.classList.remove("active");
            }
            if (!dropdownBtn.contains(event.target) && !dropdown.contains(event.target) && window.innerWidth <= 1280) {
                dropdown.classList.remove("active");
                const dropdownContent = dropdown.querySelector(".dropdown-content");
                dropdownContent.style.display = "none";
            }
            if (!navDropdownBtn.contains(event.target) && !navDropdown.contains(event.target) && window.innerWidth <= 834) {
                navDropdown.classList.remove("active");
                const navDropdownContent = navDropdown.querySelector(".dropdown-content");
                navDropdownContent.style.display = "none";
            }
            if (!languageBtn.contains(event.target) && !languageContent.contains(event.target)) {
                languageContent.classList.remove("active");
            }
        });

        // Handle resize/rotation
        window.addEventListener("resize", () => {
            console.log("script.js: Window resized, rechecking dropdown state");
            if (window.innerWidth > 1280) {
                dropdown.classList.remove("active");
                const dropdownContent = dropdown.querySelector(".dropdown-content");
                dropdownContent.style.display = "none";
            }
            if (window.innerWidth > 834) {
                navDropdown.classList.remove("active");
                const navDropdownContent = navDropdown.querySelector(".dropdown-content");
                navDropdownContent.style.display = "none";
            }
        });

        // Initialize scroll-up button for nav-has-dropdown dropdown-content
        initializeDropdownScrollUp();
    }

    function initializeDropdownScrollUp() {
        const navDropdownContent = document.querySelector(".nav-has-dropdown .dropdown-content");
        const scrollUpBtn = document.querySelector(".nav-has-dropdown .dropdown-content .dropdown-scroll-up-btn");

        if (navDropdownContent && scrollUpBtn) {
            console.log("script.js: Setting up dropdown scroll-up button");
            navDropdownContent.addEventListener("scroll", () => {
                navDropdownContent.classList.toggle("scrolled", navDropdownContent.scrollTop > 100);
            });
            scrollUpBtn.addEventListener("click", () => {
                console.log("script.js: Dropdown scroll-up button clicked");
                navDropdownContent.scrollTo({ top: 0, behavior: "smooth" });
            });
        } else {
            console.error("script.js: Dropdown scroll-up button or content not found");
        }
    }

    setupHeader();
}

function initializeFooterScripts() {
    console.log("script.js: Setting up footer button");
    const scrollUpBtn = document.querySelector(".scroll-up-btn");
    if (!scrollUpBtn) {
        console.error("script.js: Scroll-up button not found");
        return;
    }

    scrollUpBtn.addEventListener("click", () => {
        window.scrollTo({ top: 0, behavior: "smooth" });
    });

    window.addEventListener("scroll", () => {
        if (window.scrollY > 300) {
            scrollUpBtn.style.display = "flex";
        } else {
            scrollUpBtn.style.display = "none";
        }
    });
}

// Load header and footer
console.log("script.js: Script started");
document.addEventListener("DOMContentLoaded", () => {
    console.log("script.js: DOMContentLoaded fired, loading header and footer");
    const headerPath = "Header.html";
    const footerPath = "Footer.html"; // Fixed case to match server.js
    loadHTML(headerPath, "header-placeholder", initializeHeaderScripts);
    loadHTML(footerPath, "footer-placeholder", initializeFooterScripts);
});

// Fallback if DOMContentLoaded doesn't fire
window.addEventListener("load", () => {
    console.log("script.js: Window load fired, checking header and footer");
    if (!document.getElementById("header-placeholder").innerHTML) {
        console.log("script.js: Header not loaded, retrying");
        loadHTML("Header.html", "header-placeholder", initializeHeaderScripts);
    }
    if (!document.getElementById("footer-placeholder").innerHTML) {
        console.log("script.js: Footer not loaded, retrying");
        loadHTML("Footer.html", "footer-placeholder", initializeFooterScripts);
    }
});

// NEW CODE: Apply styles to <h1> and <p> tags following <h1> in tool pages only (non-.html URLs)
document.addEventListener("DOMContentLoaded", () => {
    console.log(`script.js: Checking for tool page to style h1 and h1 + p. URL: ${window.location.href}, Pathname: ${window.location.pathname}`);
    const pathname = window.location.pathname.toLowerCase();
    const isToolsPage = !pathname.endsWith(".html") && 
                        !pathname.includes("/index") && 
                        !pathname.includes("/desktop") &&
                        /^\/[a-z0-9-]+$/i.test(pathname);
    
    if (isToolsPage) {
        console.log("script.js: Confirmed non-.html tool page, applying styles to h1 and h1 + p");
        const headings = document.querySelectorAll("h1");
        if (headings.length > 0) {
            headings.forEach(h => {
                console.log(`script.js: Styling h1 tag: ${h.textContent.substring(0, 30)}...`);
                h.style.fontSize = "24px";
                h.style.marginTop = "0px";
                h.style.marginBottom = "0px";
                h.style.color = "#000";
            });
        } else {
            console.log("script.js: No h1 elements found on this tool page");
        }
        const paragraphs = document.querySelectorAll("h1 + p");
        if (paragraphs.length > 0) {
            paragraphs.forEach(p => {
                console.log(`script.js: Styling p tag after h1: ${p.textContent.substring(0, 30)}...`);
                p.style.fontSize = "16px";
                p.style.marginTop = "0px";
                p.style.marginBottom = "0px";
                p.style.color = "#333";
                p.style.maxWidth = "600px";
                p.style.margin = "0 auto";
            });
        } else {
            console.log("script.js: No h1 + p elements found on this tool page");
        }
    } else {
        console.log("script.js: Not a non-.html tool page, skipping h1 and h1 + p styling. Header path: Header.html");
    }
});

// NEW CODE: Ensure auth.js header updates after DOM load and navigation
document.addEventListener("DOMContentLoaded", () => {
    console.log("script.js: Triggering auth header update after DOM load");
    triggerAuthHeaderUpdate(1, 30);
});

// Re-run auth header update on navigation clicks
document.addEventListener("click", (e) => {
    const link = e.target.closest('a');
    if (link && link.href && !link.href.includes('/logout') && !link.href.includes('#')) {
        console.log(`script.js: Navigation click detected to ${link.href}, scheduling auth header update`);
        setTimeout(() => {
            triggerAuthHeaderUpdate(1, 30);
        }, 200);
    }
});

// Helper function to trigger auth header update with retries
function triggerAuthHeaderUpdate(attempt, maxAttempts) {
    console.log(`script.js: Attempt ${attempt} to call window.updateHeader for ${window.location.pathname}`);
    if (typeof window.updateHeader === "function") {
        console.log(`script.js: Calling window.updateHeader on attempt ${attempt}`);
        window.updateHeader();
        // Extra retries for profile.html
        if (window.location.pathname === '/profile.html' && attempt === 1) {
            console.log('script.js: On profile.html, scheduling additional header update retries');
            setTimeout(() => triggerAuthHeaderUpdate(attempt + 1, maxAttempts), 500);
            setTimeout(() => triggerAuthHeaderUpdate(attempt + 2, maxAttempts), 1000);
        }
    } else {
        console.log(`script.js: window.updateHeader not found on attempt ${attempt}`);
        if (attempt < maxAttempts) {
            setTimeout(() => triggerAuthHeaderUpdate(attempt + 1, maxAttempts), 100);
        } else {
            console.error(`script.js: Failed to find window.updateHeader after ${maxAttempts} attempts`);
        }
    }
}