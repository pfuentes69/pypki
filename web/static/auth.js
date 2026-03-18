/**
 * auth.js — JWT authentication helper for PyPKI web UI.
 *
 * - Redirects to login.html when no token is present (except on login page itself).
 * - Monkey-patches window.fetch to attach Bearer token and handle 401 responses.
 * - Exposes logout() for the sidebar Sign Out button.
 * - Populates #sidebarUsername and #sidebarRole on page load.
 */
(function () {
    'use strict';

    const LOGIN_PAGE   = 'login.html';
    const API_BASE     = '/api';
    const onLoginPage  = window.location.pathname.endsWith(LOGIN_PAGE)
                      || window.location.pathname === '/'
                         && window.location.search === ''
                         && window.location.hash   === '';

    // ── Token storage ─────────────────────────────────────────────────────────

    function getToken()     { return sessionStorage.getItem('auth_token'); }
    function setToken(t)    { sessionStorage.setItem('auth_token', t); }
    function clearToken()   { sessionStorage.removeItem('auth_token'); }

    // ── Redirect to login if no token ─────────────────────────────────────────

    if (!onLoginPage && !getToken()) {
        window.location.href = LOGIN_PAGE;
    }

    // ── Monkey-patch fetch ────────────────────────────────────────────────────
    // Automatically adds Authorization header to every fetch call and
    // redirects to login on 401.

    const _origFetch = window.fetch.bind(window);

    window.fetch = function (url, opts) {
        opts = opts ? Object.assign({}, opts) : {};
        const headers = Object.assign({}, opts.headers || {});
        const token = getToken();

        // Only inject the Bearer token when the caller hasn't already set an
        // Authorization header (e.g. EST test page sets Basic auth itself).
        const hasAuth = Object.keys(headers).some(k => k.toLowerCase() === 'authorization');
        if (token && !hasAuth) {
            headers['Authorization'] = 'Bearer ' + token;
        }
        opts.headers = headers;

        // Only redirect to login on 401 for API calls — EST and other
        // endpoints may legitimately return 401 for wrong credentials and
        // the calling page should handle that itself.
        const isApiCall = (typeof url === 'string') && url.startsWith(API_BASE);

        return _origFetch(url, opts).then(function (res) {
            if (res.status === 401 && isApiCall && !onLoginPage) {
                clearToken();
                window.location.href = LOGIN_PAGE;
            }
            return res;
        });
    };

    // ── Logout ────────────────────────────────────────────────────────────────

    window.logout = function () {
        _origFetch(API_BASE + '/auth/logout', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + (getToken() || '') }
        }).finally(function () {
            clearToken();
            window.location.href = LOGIN_PAGE;
        });
    };

    // ── Expose helpers for login page ─────────────────────────────────────────

    function getCurrentUser() {
        const token = getToken();
        if (!token) return null;
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            return { id: parseInt(payload.sub), username: payload.username, role: payload.role };
        } catch (_) { return null; }
    }

    window._auth = { getToken, setToken, clearToken, getCurrentUser, API_BASE };

    // ── Populate sidebar user info ────────────────────────────────────────────

    document.addEventListener('DOMContentLoaded', function () {
        const token = getToken();
        if (!token) return;
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const uEl = document.getElementById('sidebarUsername');
            if (uEl) uEl.textContent = payload.username || '';
            const rEl = document.getElementById('sidebarRole');
            if (rEl) rEl.textContent = payload.role || '';
        } catch (_) {}
    });
})();
