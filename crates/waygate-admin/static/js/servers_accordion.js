// Inline accordion for the Servers table.
//
// Each row's expander button lazy-loads its per-server config panel via htmx
// (hx-get with hx-trigger="click once", so the fetch happens once on first
// open). This script handles only the show/hide of the detail row and the
// chevron/aria state — htmx owns the content load. Event delegation on the
// document keeps it robust across htmx swaps and re-renders.
(function () {
  function onClick(e) {
    var btn = e.target.closest('[data-accordion]');
    if (!btn) return;
    var row = document.getElementById(btn.getAttribute('aria-controls'));
    if (!row) return;
    if (row.hasAttribute('hidden')) {
      row.removeAttribute('hidden');
      btn.setAttribute('aria-expanded', 'true');
    } else {
      row.setAttribute('hidden', '');
      btn.setAttribute('aria-expanded', 'false');
    }
  }
  document.addEventListener('click', onClick);
})();
