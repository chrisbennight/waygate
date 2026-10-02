import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../crates/waygate-admin/static/js/badge.js", import.meta.url), "utf8");

test("catalog refresh updates the badge and an older response cannot erase it", async () => {
    const badge = { dataset: { badgeSrc: "/admin/badge/decisions" }, hidden: true, textContent: "", title: "" };
    const listeners = new Map();
    const pending = [];
    const document = {
        querySelectorAll: () => [badge],
        addEventListener: (name, callback) => listeners.set(name, callback),
    };
    vm.runInNewContext(source, {
        document,
        fetch: () => new Promise(resolve => pending.push(resolve)),
    });
    assert.equal(pending.length, 1, "page load requests the initial count");
    const refresh = listeners.get("tool-reviews-changed");
    assert.equal(typeof refresh, "function", "catalog refresh must update the visible badge");
    refresh();
    assert.equal(pending.length, 2);
    const respond = async (index, value) => {
        pending[index]({ ok: true, text: async () => value });
        await new Promise(resolve => setImmediate(resolve));
    };
    await respond(1, "3");
    assert.equal(badge.hidden, false);
    assert.equal(badge.textContent, "3");
    await respond(0, "0");
    assert.equal(badge.hidden, false, "the older page-load response must not hide pending reviews");
    assert.equal(badge.textContent, "3");
    refresh();
    await respond(2, "0");
    assert.equal(badge.hidden, true, "a completed decision clears the current indication");
    refresh();
    await respond(3, "?");
    assert.equal(badge.hidden, false);
    assert.equal(badge.textContent, "?");
    assert.match(badge.title, /unavailable/);
});
