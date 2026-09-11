// Theme toggle. Reads from localStorage first, falls back to
// prefers-color-scheme. On change, mirrors to a cookie so the server can
// render the right theme on first paint (no FOUC on reload).

(function () {
    const KEY = "mcp-gw-theme";
    const root = document.documentElement;

    function apply(theme) {
        if (theme === "light" || theme === "dark") {
            root.setAttribute("data-theme", theme);
        } else {
            root.removeAttribute("data-theme");
        }
    }

    function store(theme) {
        try { localStorage.setItem(KEY, theme); } catch (_) { /* private mode */ }
        // Cookie: path=/ so /admin and /api share it. SameSite=Lax so it
        // travels on top-level nav but not cross-site iframes.
        document.cookie = `${KEY}=${theme}; path=/; max-age=31536000; SameSite=Lax`;
    }

    function next() {
        const current = root.getAttribute("data-theme")
            || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
        return current === "dark" ? "light" : "dark";
    }

    window.addEventListener("DOMContentLoaded", () => {
        const btn = document.querySelector("[data-theme-toggle]");
        if (btn) {
            btn.addEventListener("click", () => {
                const t = next();
                apply(t);
                store(t);
            });
        }
    });
})();
