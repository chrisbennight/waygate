// Decisions nav badge. Fetches the pending count from the server-side
// cached endpoint (data-badge-src, tenant-prefixed by the layout) and
// reveals the chip only for a non-zero count. Stays hidden on any
// error and with JS off — the badge is a hint, never load-bearing.
(function () {
    document.querySelectorAll("[data-badge-src]").forEach(async (el) => {
        try {
            const r = await fetch(el.dataset.badgeSrc, { headers: { Accept: "text/plain" } });
            if (!r.ok) return;
            const n = (await r.text()).trim();
            if (n && n !== "0") {
                el.textContent = n;
                el.hidden = false;
            }
        } catch (_) {
            /* hint only — never surface fetch errors */
        }
    });
})();
