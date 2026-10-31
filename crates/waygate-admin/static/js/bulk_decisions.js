// Selection stays on the current page. Reviewed identities are validated by
// the server; newly rendered items never inherit a previous selection.
(function () {
    if (window.waygateBulkDecisions) {
        window.waygateBulkDecisions();
        return;
    }
    const controllers = new WeakMap();
    function initialize() {
        document.querySelectorAll("form[data-bulk-selection]").forEach((form) => {
            if (controllers.has(form)) {
                controllers.get(form)();
                return;
            }
            const items = () => Array.from(document.querySelectorAll("input[data-bulk-item]"))
                .filter((item) => item.form === form && !item.disabled);
            const all = form.querySelector("[data-bulk-select-all]");
            const clear = form.querySelector("[data-bulk-clear]");
            const count = form.querySelector("[data-bulk-count]");
            const hint = form.querySelector("[data-bulk-hint]");
            function refresh() {
                const available = items();
                const selected = available.filter((item) => item.checked);
                const selectedRiskNames = new Set(selected.map((item) => item.dataset.riskName));
                Array.from(form.elements).filter((control) => control.tagName === "SELECT").forEach((control) => {
                    control.required = selectedRiskNames.has(control.name);
                    control.disabled = !control.required;
                });
                all.checked = available.length > 0 && selected.length === available.length;
                all.indeterminate = selected.length > 0 && selected.length < available.length;
                count.textContent = `${selected.length} selected`;
                clear.disabled = selected.length === 0;
                const unavailable = selected.some((item) => item.dataset.approvable !== "true");
                form.querySelectorAll("[data-bulk-submit]").forEach((button) => {
                    button.disabled = selected.length === 0 || (button.hasAttribute("data-bulk-approve") && unavailable);
                });
                hint.textContent = unavailable
                    ? (form.dataset.bulkUnavailableHint || "A selected definition is unavailable. The selection can only be kept blocked.")
                    : "Review the complete selection before confirmation.";
            }
            form.querySelector("[data-bulk-select-all-label]").hidden = false;
            clear.hidden = false;
            all.addEventListener("change", () => {
                items().forEach((item) => { item.checked = all.checked; });
                refresh();
            });
            clear.addEventListener("click", () => {
                items().forEach((item) => { item.checked = false; });
                refresh();
                all.focus();
            });
            controllers.set(form, refresh);
            form.addEventListener("submit", (event) => {
                if (form.dataset.submitting) {
                    event.preventDefault();
                    return;
                }
                form.dataset.submitting = "true";
                // Native submission captures the selected controls before the
                // next task disables them, including the clicked action.
                window.setTimeout(() => {
                    Array.from(form.elements).forEach((control) => { control.disabled = true; });
                }, 0);
            });
            refresh();
        });
    }
    window.waygateBulkDecisions = initialize;
    document.addEventListener("change", (event) => {
        if (event.target.matches("[data-bulk-item]")) controllers.get(event.target.form)?.();
    });
    window.addEventListener("pageshow", (event) => {
        if (!event.persisted) return;
        document.querySelectorAll("form[data-bulk-selection]").forEach((form) => {
            delete form.dataset.submitting;
            Array.from(form.elements).forEach((control) => {
                control.disabled = false;
                if (control.matches("[data-bulk-item]")) control.checked = false;
            });
            controllers.get(form)?.();
        });
    });
    initialize();
    document.addEventListener("htmx:afterSwap", initialize);
})();
