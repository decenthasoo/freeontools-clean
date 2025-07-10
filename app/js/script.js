function loadHTML(file, placeholderId, callback) {
    console.log(`script.js: Loading ${file}`);
    return fetch(file, { cache: "no-store" })
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
            } else {
                console.error(`script.js: Placeholder ${placeholderId} not found`);
            }
            return data;
        })
        .catch(error => {
            console.error(`script.js: Error loading ${file}: ${error.message}`);
            throw error;
        });
}

function initializeHeaderScripts() {
    console.log("script.js: Setting up header buttons");

    function setupHeader(attempt = 1, maxAttempts = 5) {
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
                setTimeout(() => setupHeader(attempt + 1, maxAttempts), 50);
            } else {
                console.error(`script.js: Failed to initialize header after ${maxAttempts} attempts`);
            }
            return;
        }

        const toggleDropdown = () => {
            if (window.innerWidth <= 1280) {
                console.log("script.js: Dropdown button clicked/touched, toggling active class");
                dropdown.classList.toggle("active");
                const dropdownContent = dropdown.querySelector(".dropdown-content");
                dropdownContent.style.display = dropdown.classList.contains("active") ? "flex" : "none";
            }
        };

        const toggleNavDropdown = () => {
            if (window.innerWidth <= 834) {
                console.log("script.js: Nav dropdown button clicked/touched, toggling active class");
                navDropdown.classList.toggle("active");
                const navDropdownContent = navDropdown.querySelector(".dropdown-content");
                navDropdownContent.style.display = navDropdown.classList.contains("active") ? "block" : "none";
            }
        };

        dropdownBtn.removeEventListener("click", toggleDropdown);
        dropdownBtn.removeEventListener("touchstart", toggleDropdown);
        navDropdownBtn.removeEventListener("click", toggleNavDropdown);
        navDropdownBtn.removeEventListener("touchstart", toggleNavDropdown);

        dropdownBtn.addEventListener("click", toggleDropdown);
        dropdownBtn.addEventListener("touchstart", (e) => {
            e.preventDefault();
            toggleDropdown();
        });

        navDropdownBtn.addEventListener("click", toggleNavDropdown);
        navDropdownBtn.addEventListener("touchstart", (e) => {
            e.preventDefault();
            toggleNavDropdown();
        });

        hamburgerBtn.addEventListener("click", () => {
            console.log("script.js: Hamburger button clicked");
            hamburgerContent.classList.toggle("active");
        });

        languageBtn.addEventListener("click", () => {
            console.log("script.js: Language button clicked");
            languageContent.classList.toggle("active");
        });

        dropdownCloseBtn.addEventListener("click", () => {
            if (window.innerWidth <= 1280) {
                console.log("script.js: Dropdown close button clicked, removing active class");
                dropdown.classList.remove("active");
                const dropdownContent = dropdown.querySelector(".dropdown-content");
                dropdownContent.style.display = "none";
            }
        });

        navCloseBtn.addEventListener("click", () => {
            if (window.innerWidth <= 834) {
                console.log("script.js: Nav dropdown close button clicked, removing active class");
                navDropdown.classList.remove("active");
                const navDropdownContent = navDropdown.querySelector(".dropdown-content");
                navDropdownContent.style.display = "none";
            }
        });

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

        let resizeTimeout;
        window.addEventListener("resize", () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
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
            }, 100);
        });

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

let authStatusPromise = null;

async function checkAuthStatusCached() {
    console.log("script.js: Initiating auth status check");
    if (!authStatusPromise) {
        authStatusPromise = window.checkAuthStatus ? window.checkAuthStatus() : Promise.resolve(false);
    }
    return authStatusPromise;
}

document.addEventListener("DOMContentLoaded", async () => {
    console.log("script.js: DOMContentLoaded fired, loading header, footer, checking auth, and styling content");
    const headerPath = "header.html";
    const footerPath = "footer.html";

    const headerPlaceholder = document.getElementById("header-placeholder");
    const footerPlaceholder = document.getElementById("footer-placeholder");

    const loadPromises = [];

    if (headerPlaceholder && !headerPlaceholder.innerHTML.trim()) {
        loadPromises.push(loadHTML(headerPath, "header-placeholder", initializeHeaderScripts));
    } else {
        console.log("script.js: Header already loaded or placeholder missing");
        initializeHeaderScripts();
    }

    if (footerPlaceholder && !footerPlaceholder.innerHTML.trim()) {
        loadPromises.push(loadHTML(footerPath, "footer-placeholder", initializeFooterScripts));
    } else {
        console.log("script.js: Footer already loaded or placeholder missing");
        initializeFooterScripts();
    }

    loadPromises.push(checkAuthStatusCached());

    const [headerResult, footerResult, isAuthenticated] = await Promise.all(loadPromises.map(p => p.catch(err => {
        console.error("script.js: Load error:", err);
        return null;
    })));

    if (typeof window.updateHeader === "function") {
        console.log("script.js: Header loaded, updating with auth status:", isAuthenticated);
        await window.updateHeader();
    }

    console.log(`script.js: Checking for tool page to style h1 and h1 + p. URL: ${window.location.href}, Pathname: ${window.location.pathname}`);
    const pathname = window.location.pathname.toLowerCase();
    const isToolsPage = !pathname.endsWith(".html") && 
                        !pathname.includes("/index") && 
                        !pathname.includes("/desktop") &&
                        !pathname.includes("/reset-password") &&
                        !pathname.includes("/signup") &&
                        !pathname.includes("/login") &&
                        !pathname.includes("/profile") &&
                        /^\/[a-z0-9-]+$/i.test(pathname);
    
    if (isToolsPage) {
        console.log("script.js: Confirmed non-.html tool page, applying styles to h1 and h1 + p");
        const headings = document.querySelectorAll("h1");
        headings.forEach(h => {
            console.log(`script.js: Styling h1 tag: ${h.textContent.substring(0, 30)}...`);
            h.style.fontSize = "24px";
            h.style.marginTop = "0px";
            h.style.marginBottom = "0px";
            h.style.color = "#000";
        });
        const paragraphs = document.querySelectorAll("h1 + p");
        paragraphs.forEach(p => {
            console.log(`script.js: Styling p tag after h1: ${p.textContent.substring(0, 30)}...`);
            p.style.fontSize = "16px";
            p.style.marginTop = "0px";
            p.style.marginBottom = "0px";
            p.style.color = "#333";
            p.style.maxWidth = "600px";
            p.style.margin = "0 auto";
        });
    }
});