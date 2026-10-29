/**
 * Host adapter for the editor's own server (server/rulezet_editor, Python).
 * The same adapter works in both modes; only the server side changes:
 *
 *   inside Rulezet   blueprint mounted by Rulezet, answers from its database and compilers
 *   standalone       `rulezet-editor serve`: local compilers, rule lookup on rulezet.org
 *
 *   new EditorServerHost({ baseUrl: '/editor-api', csrfToken })
 *
 *   POST /validate   { format, content }  -> { valid, items }
 *   GET  /rules      ?format=&q=&limit=   -> { results }
 *   GET  /rules/<name>?format=            -> rule | 404
 *   GET  /test/sets?format=               -> { available, sets }      (rulezet-tester)
 *   POST /test/  { format, text, sets }   -> 202 run
 *   GET  /test/<run id>                   -> run
 *   GET  /fields?format=                  -> { fields }               (Fields panel)
 *   GET  /fields/suggest?format=&field=&q= -> { results }
 *   GET  /fields/browse?format=&field=&path=&page= -> { folders, items, has_more }
 *   POST /external-checks { format, text } -> { results: { tool: result } }   (host's extra tools)
 */
import { HttpHost } from './HostAdapter.js';

export class EditorServerHost extends HttpHost {
    constructor(options = {}) {
        super({ ...options, baseUrl: options.baseUrl ?? '/editor-api' });
        this.name = options.name || 'Rulezet';
    }

    async validate(language, text) {
        const data = await this._request('/validate', {
            method: 'POST',
            headers: this._headers(true),
            body: JSON.stringify({ format: this.format(language), content: text }),
        });
        return Array.isArray(data.items) ? data.items : [];
    }

    async searchRules(language, query, { limit = 10 } = {}) {
        const params = new URLSearchParams({ format: this.format(language), q: query, limit: String(limit) });
        const data = await this._request(`/rules?${params}`, { headers: this._headers(false) });
        return data.results || [];
    }

    async ruleFields(language) {
        const params = new URLSearchParams({ format: this.format(language) });
        try {
            return (await this._request(`/fields?${params}`, { headers: this._headers(false) })).fields || [];
        } catch (e) {
            if (e.status === 404) return [];
            throw e;
        }
    }

    async suggest(language, field, query, { limit = 10 } = {}) {
        const params = new URLSearchParams({ format: this.format(language), field, q: query, limit: String(limit) });
        return (await this._request(`/fields/suggest?${params}`, { headers: this._headers(false) })).results || [];
    }

    async browse(language, field, path = [], page = 1) {
        const params = new URLSearchParams({ format: this.format(language), field, page: String(page),
                                             path: path.map(encodeURIComponent).join('/') });
        return this._request(`/fields/browse?${params}`, { headers: this._headers(false) });
    }

    async testSets(language) {
        const params = new URLSearchParams({ format: this.format(language) });
        try {
            return await this._request(`/test/sets?${params}`, { headers: this._headers(false) });
        } catch (e) {
            if (e.status === 404) return { available: false, sets: [] };      // server without tests
            throw e;
        }
    }

    async startTest(language, text, sets) {
        return this._request('/test/', {
            method: 'POST',
            headers: this._headers(true),
            body: JSON.stringify({ format: this.format(language), text, sets }),
        }, { allow: [], timeout: 30000 });     // queues the run: can be slow when the server is busy
    }

    async testState(runId) {
        return this._request(`/test/${encodeURIComponent(runId)}`, { headers: this._headers(false) }, { allow: [] });
    }

    async externalChecks(language, text) {
        try {
            const data = await this._request('/external-checks', {
                method: 'POST',
                headers: this._headers(true),
                body: JSON.stringify({ format: this.format(language), text }),
            }, { allow: [], timeout: 60000 });          // the tools can take a few seconds on a big document
            return data.results || {};
        } catch (e) {
            if (e.status === 404) return {};               // a server without external tools (standalone)
            throw e;
        }
    }

        async getRule(language, name) {
        const params = new URLSearchParams({ format: this.format(language) });
        try {
            return await this._request(`/rules/${encodeURIComponent(name)}?${params}`, { headers: this._headers(false) });
        } catch (e) {
            if (e.status === 404) return null;
            throw e;
        }
    }
}
