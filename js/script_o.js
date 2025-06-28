function loadHTML(file, placeholderId, callback) {
    console.log("Trying to load " + file);
    fetch(file, { cache: "no-store" })
        .then(response => {
            console.log(file + " response status: " + response.status);
            if (!response.ok) {
                throw new Error(file + " failed to load with status " + response.status);
            }
            return response.text();
        })
        .then(data => {
            console.log(file + " loaded successfully");
            const placeholder = document.getElementById(placeholderId);
            if (placeholder) {
                placeholder.innerHTML = data;
                console.log("Inserted " + file + " into " + placeholderId);
                if (callback) callback();
            } else {
                console.error("Placeholder " + placeholderId + " not found");
            }
        })
        .catch(error => {
            console.error("Error loading " + file + ": " + error.message);
        });
}

function initializeHeaderScripts() {
    console.log("Setting up header buttons");
    const hamburgerBtn = document.querySelector(".hamburger-btn");
    const hamburgerContent = document.querySelector(".hamburger-content");
    const dropdownBtn = document.querySelector(".dropbtn");
    const dropdown = document.querySelector(".dropdown");
    const languageBtn = document.querySelector(".language-btn");
    const languageContent = document.querySelector(".language");

    if (!hamburgerBtn || !hamburgerContent || !dropdownBtn || !dropdown || !languageBtn || !languageContent) {
        console.error("Some header elements are missing:", {
            hamburgerBtn: !!hamburgerBtn,
            hamburgerContent: !!hamburgerContent,
            dropdownBtn: !!dropdownBtn,
            dropdown: !!dropdown,
            languageBtn: !!languageBtn,
            languageContent: !!languageContent
        });
        return;
    }

    hamburgerBtn.addEventListener("click", () => {
        hamburgerContent.classList.toggle("active");
    });

    dropdownBtn.addEventListener("click", () => {
        if (window.innerWidth <= 768) {
            dropdown.classList.toggle("active");
        }
    });

    languageBtn.addEventListener("click", () => {
        languageContent.classList.toggle("active");
    });

    document.addEventListener("click", (event) => {
        if (!hamburgerBtn.contains(event.target) && !hamburgerContent.contains(event.target)) {
            hamburgerContent.classList.remove("active");
        }
        if (!dropdownBtn.contains(event.target) && !dropdown.contains(event.target) && window.innerWidth <= 768) {
            dropdown.classList.remove("active");
        }
        if (!languageBtn.contains(event.target) && !languageContent.contains(event.target)) {
            languageContent.classList.remove("active");
        }
    });
}

function initializeFooterScripts() {
    console.log("Setting up footer button");
    const scrollUpBtn = document.querySelector(".scroll-up-btn");
    if (!scrollUpBtn) {
        console.error("Scroll-up button not found");
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
console.log("Script started");
document.addEventListener("DOMContentLoaded", () => {
    console.log("DOMContentLoaded fired, loading header and footer");
    const isToolsPage = window.location.pathname.includes("/Tools/");
    const headerPath = isToolsPage ? "../Header.html" : "Header.html";
    const footerPath = isToolsPage ? "../footer.html" : "footer.html";

    loadHTML(headerPath, "header-placeholder", initializeHeaderScripts);
    loadHTML(footerPath, "footer-placeholder", initializeFooterScripts);
});

// Fallback if DOMContentLoaded doesn't fire
window.addEventListener("load", () => {
    console.log("Window load fired, checking header and footer");
    if (!document.getElementById("header-placeholder").innerHTML) {
        console.log("Header not loaded, retrying");
        loadHTML("../Header.html", "header-placeholder", initializeHeaderScripts);
    }
    if (!document.getElementById("footer-placeholder").innerHTML) {
        console.log("Footer not loaded, retrying");
        loadHTML("../footer.html", "footer-placeholder", initializeFooterScripts);
    }
});