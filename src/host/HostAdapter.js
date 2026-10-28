/**
 * Host adapter: the editor's only way to reach a backend.
 *
 * Every method is optional. The editor checks `has(name)` and hides the
 * matching feature when a method is missing. Methods never parse rules:
 * they send text and return plain data.
 *
 *   validate(language, text)        -> [{ message, severity: 'error'|'warning', line?, column? }]
 *   searchRules(language, query)    -> [{ name, description?, author?, url?, content? }]
 *   getRule(language, name)         -> { name, description?, author?, url?, content? } | null
 *   loadDraft(key) / saveDraft(key, text)
 *
 *   Tests on samples (rulezet-tester behind the host; see docs/testing.md):
 *   testSets(language)              -> { available, sets: [{ id, name, kind, count, description, labels }] }
 *   startTest(language, text, sets) -> run (every sample pending)
 *   testState(runId)                -> run; poll until status is done | failed
 *
 *   Fields panel (the host's metadata for a rule: title, CVE, tags...; docs/fields.md):
 *   ruleFields(language)            -> [{ id, label, type, help?, options?, suggest?, report?, meta? }]
 *   suggest(language, field, query) -> [{ value, label, detail?, color? }]
 *   browse(language, field, path, page) -> { folders: [{ id, label, count? }], items, has_more }
 */
export class HostAdapter {
    constructor() {
        this.name = 'host';
    }

    has(method) {
        return typeof this[method] === 'function' && this[method] !== HostAdapter.prototype[method];
    }
}

/** Keeps drafts in the browser (localStorage). Safe when storage is blocked. */
export class LocalDraftHost extends HostAdapter {
    constructor(prefix = 'rulezet-editor:draft:') {
        super();
        this.name = 'local';
        this.prefix = prefix;
    }

    async loadDraft(key) {
        try {
            const raw = window.localStorage.getItem(this.prefix + key);
            return raw ? JSON.parse(raw) : null;
        } catch {
            return null;
        }
    }

    async saveDraft(key, text) {
        try {
            if (text == null) window.localStorage.removeItem(this.prefix + key);
            else window.localStorage.setItem(this.prefix + key, JSON.stringify({ text, savedAt: Date.now() }));
        } catch {
            /* storage blocked: drafts are a convenience only */
        }
    }
}

/** Base for adapters that talk JSON over HTTP. A 400 answer still carries a body to read. */
export class HttpHost extends LocalDraftHost {
    constructor(options = {}) {
        super(options.draftPrefix);
        this.baseUrl = (options.baseUrl ?? '').replace(/\/+$/, '');
        this.apiKey = options.apiKey || null;
        this.csrfToken = options.csrfToken || null;
        this.fetch = options.fetch || ((...args) => window.fetch(...args));
        this.timeout = options.timeout ?? 15000;
        this.formatMap = options.formatMap || {};      // editor language id -> backend format name
    }

    format(language) {
        return this.formatMap[language] || language;
    }

    _headers(json) {
        const h = { Accept: 'application/json' };
        if (json) h['Content-Type'] = 'application/json';
        if (this.apiKey) h['X-API-KEY'] = this.apiKey;
        if (this.csrfToken) h['X-CSRFToken'] = this.csrfToken;
        return h;
    }

    /**
     * One JSON call. A busy server (restarting, running jobs) must not fail the editor: a GET
     * (nothing changes on the server) is tried again when it times out, cannot be reached or
     * answers 502 / 503 / 504 — after 1 s, 2 s, then 4 s. A POST is sent once.
     * Options: allow (statuses whose body is still read), timeout (ms), retries (GET only).
     */
    async _request(path, init = {}, { allow = [400], timeout = this.timeout, retries = null } = {}) {
        const method = String(init.method || 'GET').toUpperCase();
        const tries = 1 + (retries ?? (method === 'GET' ? 3 : 0));
        let lastError;
        for (let attempt = 0; attempt < tries; attempt++) {
            if (attempt) await new Promise(r => setTimeout(r, 1000 * 2 ** (attempt - 1)));
            try {
                return await this._requestOnce(path, init, allow, timeout);
            } catch (e) {
                lastError = e;
                if (!e.transient) throw e;
            }
        }
        throw lastError;
    }

    async _requestOnce(path, init, allow, timeout) {
        const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
        const timer = ctrl ? setTimeout(() => ctrl.abort(), timeout) : null;
        const fail = (message, extra = {}) => Object.assign(new Error(message), extra);
        try {
            let res;
            try {
                res = await this.fetch(this.baseUrl + path, { ...init, signal: ctrl ? ctrl.signal : undefined });
            } catch (e) {
                if (e && e.name === 'AbortError') throw fail(`${this.name} did not answer within ${Math.round(timeout / 1000)} s (busy?)`, { transient: true });
                throw fail(`${this.name} not reachable: ${e.message || e}`, { transient: true });
            }
            const data = await res.json().catch(() => ({}));
            if (!res.ok && !allow.includes(res.status)) {
                throw fail(data.error || data.message || `HTTP ${res.status}`,
                    { status: res.status, transient: [502, 503, 504].includes(res.status) });
            }
            return data;
        } finally {
            if (timer) clearTimeout(timer);
        }
    }
}
