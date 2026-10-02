// Decisions nav badge. Fetches the pending count from the server-side
// cached endpoint (data-badge-src, tenant-prefixed by the layout) and
// reveals the chip for pending reviews or unavailable review counts.
// Fetch failures retain the last known hint; review pages hold the details.
(function () {
    document.querySelectorAll("[data-badge-src]").forEach((el) => {
        let latest = 0;
        async function refresh() {
            const request = ++latest;
            try {
                const r = await fetch(el.dataset.badgeSrc, { headers: { Accept: "text/plain" } });
                if (!r.ok) return;
                const n = (await r.text()).trim();
                if (request !== latest) return;
                el.textContent = n;
                el.title = n === "?" ? "Tool or skill review counts are unavailable. Open Decisions for details." : "";
                el.hidden = !n || n === "0";
            } catch (_) {
                /* Preserve the last known hint when its refresh fails. */
            }
        }
        document.addEventListener("tool-reviews-changed", refresh);
        refresh();
    });
})();
