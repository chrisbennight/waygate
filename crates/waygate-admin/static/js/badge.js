// Decisions nav badge. Fetches the live pending count (data-badge-src,
// tenant-prefixed by the layout) and reveals the chip for pending work or
// unavailable counts. The queue changes without a page load: agents propose,
// requests expire, and other administrators decide. The badge therefore
// refreshes while the tab is visible and whenever the page is shown again,
// including a back/forward restore that would otherwise show an old count.
// Fetch failures retain the last known hint; review pages hold the details.
// An expired session answers with a redirect to sign-in. The badge must not
// follow it: requesting the sign-in page replaces its login-state cookie,
// which would break a sign-in in progress in another window.
(function () {
    const REFRESH_MS = 30000;
    document.querySelectorAll("[data-badge-src]").forEach((el) => {
        let latest = 0;
        async function refresh() {
            const request = ++latest;
            try {
                const r = await fetch(el.dataset.badgeSrc, {
                    headers: { Accept: "text/plain" },
                    redirect: "manual",
                });
                if (!r.ok) return;
                const n = (await r.text()).trim();
                if (request !== latest) return;
                el.textContent = n;
                el.title = n === "?" ? "Some pending decision counts are unavailable. Open Decisions for details." : "";
                el.hidden = !n || n === "0";
            } catch (_) {
                /* Preserve the last known hint when its refresh fails. */
            }
        }
        document.addEventListener("tool-reviews-changed", refresh);
        document.addEventListener("visibilitychange", () => {
            if (document.visibilityState === "visible") refresh();
        });
        window.addEventListener("pageshow", (event) => {
            if (event.persisted) refresh();
        });
        setInterval(() => {
            if (document.visibilityState === "visible") refresh();
        }, REFRESH_MS);
        refresh();
    });
})();
