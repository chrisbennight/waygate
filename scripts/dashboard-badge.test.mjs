import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../crates/waygate-admin/static/js/badge.js", import.meta.url), "utf8");

function load() {
    const badge = { dataset: { badgeSrc: "/admin/badge/decisions" }, hidden: true, textContent: "", title: "" };
    const listeners = new Map();
    const windowListeners = new Map();
    const intervals = [];
    const pending = [];
    const requests = [];
    const document = {
        visibilityState: "visible",
        querySelectorAll: () => [badge],
        addEventListener: (name, callback) => listeners.set(name, callback),
    };
    vm.runInNewContext(source, {
        document,
        window: { addEventListener: (name, callback) => windowListeners.set(name, callback) },
        setInterval: (callback, ms) => intervals.push({ callback, ms }),
        fetch: (url, options) => {
            requests.push({ url, options });
            return new Promise(resolve => pending.push(resolve));
        },
    });
    const respond = async (index, value) => {
        pending[index]({ ok: true, text: async () => value });
        await new Promise(resolve => setImmediate(resolve));
    };
    const respondWith = async (index, response) => {
        pending[index](response);
        await new Promise(resolve => setImmediate(resolve));
    };
    return { badge, document, listeners, windowListeners, intervals, pending, requests, respond, respondWith };
}

test("an expired session's sign-in redirect is not followed and keeps the last count", async () => {
    const { badge, intervals, requests, respond, respondWith } = load();
    await respond(0, "2");
    assert.equal(
        requests[0].options.redirect,
        "manual",
        "following the redirect would request the sign-in page and replace its login-state cookie",
    );
    intervals[0].callback();
    assert.equal(requests[1].options.redirect, "manual", "periodic refreshes must not follow redirects either");
    await respondWith(1, { ok: false, status: 0, type: "opaqueredirect", text: async () => "" });
    assert.equal(badge.hidden, false);
    assert.equal(badge.textContent, "2");
});

test("catalog refresh updates the badge and an older response cannot erase it", async () => {
    const { badge, listeners, pending, respond } = load();
    assert.equal(pending.length, 1, "page load requests the initial count");
    const refresh = listeners.get("tool-reviews-changed");
    assert.equal(typeof refresh, "function", "catalog refresh must update the visible badge");
    refresh();
    assert.equal(pending.length, 2);
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

test("a restored or returning page replaces its old count", async () => {
    const { badge, document, listeners, windowListeners, pending, respond } = load();
    await respond(0, "7");
    assert.equal(badge.textContent, "7");

    const pageshow = windowListeners.get("pageshow");
    assert.equal(typeof pageshow, "function", "a back/forward restore must re-read the count");
    pageshow({ persisted: false });
    assert.equal(pending.length, 1, "a fresh load already fetched its own count");
    pageshow({ persisted: true });
    assert.equal(pending.length, 2);
    await respond(1, "0");
    assert.equal(badge.hidden, true, "work decided elsewhere must not stay on a restored page");

    const visibility = listeners.get("visibilitychange");
    assert.equal(typeof visibility, "function", "returning to the tab must re-read the count");
    document.visibilityState = "hidden";
    visibility();
    assert.equal(pending.length, 2, "a hidden tab does not fetch");
    document.visibilityState = "visible";
    visibility();
    assert.equal(pending.length, 3);
    await respond(2, "2");
    assert.equal(badge.hidden, false);
    assert.equal(badge.textContent, "2");
});

test("an open tab picks up new work while visible", async () => {
    const { badge, document, intervals, pending, respond } = load();
    await respond(0, "0");
    assert.equal(intervals.length, 1, "the badge refreshes on a timer");
    assert.ok(intervals[0].ms > 0 && intervals[0].ms <= 60000, "the refresh interval stays short");

    document.visibilityState = "hidden";
    intervals[0].callback();
    assert.equal(pending.length, 1, "a hidden tab does not poll");

    document.visibilityState = "visible";
    intervals[0].callback();
    assert.equal(pending.length, 2);
    await respond(1, "4");
    assert.equal(badge.hidden, false);
    assert.equal(badge.textContent, "4");
});
