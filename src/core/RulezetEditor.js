/**
 * RulezetEditor: the public editor class.
 *
 *   RulezetEditor.registerLanguage(yara);
 *   const editor = new RulezetEditor(element, { language: 'yara', value, host, theme: 'auto' });
 *
 * The core knows no rule format: everything format-specific comes from the
 * language pack (see docs/language-pack.md), everything server-side from the
 * host adapter (see src/host/HostAdapter.js).
 */
import { EditorState, Compartment, StateEffect, StateField, EditorSelection } from '@codemirror/state';
import {
    EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, drawSelection,
    dropCursor, rectangularSelection, crosshairCursor, highlightSpecialChars, hoverTooltip, Decoration,
    ViewPlugin, showPanel, WidgetType,
} from '@codemirror/view';
import {
    StreamLanguage, foldGutter, foldService, indentOnInput, bracketMatching, foldKeymap, indentUnit,
    foldAll, unfoldAll,
} from '@codemirror/language';
import { defaultKeymap, history, historyKeymap, indentWithTab, toggleComment, undo, redo, undoDepth, redoDepth } from '@codemirror/commands';
import {
    autocompletion, completionKeymap, closeBrackets, closeBracketsKeymap, snippetCompletion, startCompletion,
} from '@codemirror/autocomplete';
import { linter, lintGutter, lintKeymap, forceLinting, nextDiagnostic, previousDiagnostic } from '@codemirror/lint';
import { search, searchKeymap, highlightSelectionMatches, openSearchPanel, closeSearchPanel, searchPanelOpen, gotoLine } from '@codemirror/search';

import { registerLanguage, getLanguage, listLanguages, detectLanguage } from './registry.js';
import { TOKEN_TAGS } from './tokens.js';
import { themeExtensions } from './theme.js';
import { translator } from './i18n.js';
import { Emitter } from './events.js';
import { LocalDraftHost } from '../host/HostAdapter.js';
import plain from '../languages/plain/index.js';
import { h, icon } from '../ui/dom.js';
import { renderOutline } from '../ui/outline.js';
import { renderProblems } from '../ui/problems.js';
import { renderTests } from '../ui/tests.js';
import { renderTry } from '../ui/try.js';
import { renderFields } from '../ui/fields.js';
import { resizable } from '../ui/resize.js';
import { Tour } from '../ui/tour.js';
import { emptyValue, fieldStatus, initialState, isEmpty, readField, sameValue, toMetaValue } from './fields.js';
import { CommandPalette } from '../ui/palette.js';

registerLanguage(plain);

const DEFAULTS = {
    language: 'auto',            // pack id or 'auto'
    value: '',
    theme: 'auto',               // auto | light | dark
    locale: 'en',
    readOnly: false,
    height: null,                // CSS height of the whole editor, e.g. '520px'; null = fill the parent
    toolbar: true,
    statusBar: true,
    outline: 'auto',             // true | false | 'auto' (open when the document has 2+ rules)
    problems: false,             // problems panel open at start
    host: null,                  // HostAdapter
    serverValidation: true,      // use host.validate when available
    serverDelay: 1200,           // ms of idle typing before asking the server
    lookupExternalRules: true,   // ask the host about rules used but not defined here
    lint: {},                    // options passed to pack.lint
    format: {},                  // options passed to pack.format
    draftKey: null,              // autosave drafts under this key (host.saveDraft or localStorage)
    author: null,
    buttons: [],                 // host page buttons in the toolbar: [{ id, label, icon?, title?, primary?, disabled?(), run(editor) }]                // default author for authoring actions (e.g. the logged-in user)
    lineWrapping: null,          // null: last choice of this viewer (default off)
    fields: 'auto',              // Fields panel: 'auto' = when the pack has `meta` and the host has ruleFields; false = never
    fieldsReport: true,          // fields written into a rule built from the panel (empty document); a rule already
                                 // in the text never gets fields written into it unless the user ticks them
    tutorial: true,              // a Tutorial button: a guided tour of every feature, with examples
    toast: null,                 // (message, tone) => void: show the editor's messages with the host's own notifications
    lockPasted: false,           // a pasted rule is locked (unlockable): fields can be filled, its text is kept as is
    fieldsOpen: true,            // the Fields panel is open when the editor starts (when it is available)
    tests: 'auto',               // Test panel: 'auto' = when the pack has `test` and the host has startTest; false = never
    testPollMs: 700,             // how often a running test is polled
    placeholder: '',
};

const COMPLETION_TYPES = {
    module: 'namespace', rule: 'class', section: 'keyword', modifier: 'type', snippet: 'text',
    variable: 'variable', property: 'property', function: 'function', keyword: 'keyword', constant: 'constant',
    namespace: 'namespace',
};

const renameEffect = StateEffect.define();
const locksChanged = StateEffect.define();
const refreshLint = StateEffect.define();
const setTestMarks = StateEffect.define();
const DRAFT = '\u0000draft';                      // Fields panel state while the document has no rule      // [{ from, to, active }] or [] : strings a test sample matched

export class RulezetEditor {
    static registerLanguage(pack) { return registerLanguage(pack); }
    static getLanguage(id) { return getLanguage(id); }
    static listLanguages() { return listLanguages(); }

    constructor(element, options = {}) {
        if (typeof element === 'string') element = document.querySelector(element);
        if (!element) throw new Error('rulezet-editor: element not found');
        this.options = { ...DEFAULTS, ...options };
        this.t = translator(this.options.locale);
        this.host = this.options.host || null;
        this.events = new Emitter();
        this.diagnostics = [];
        this._modelCache = { doc: null, pack: null, model: null };
        this._foldCache = new WeakMap();
        this._server = { text: null, items: [], error: null };
        this._annotations = { text: null, diagnostics: [], rules: {} };
        this._locks = new Map();      // rule name -> { label, canUnlock, url }
        this._docs = new Map();       // document id -> saved state of a document not shown (openDocument)
        this._activeDoc = 'main';
        this._serverState = this._serverEnabled() ? 'idle' : 'off';
        this._externals = new Map();
        this._test = { open: false, sets: null, chosen: new Set(), expanded: new Set(), focus: null, query: '', filter: 'all', limits: {}, run: null, error: null, loading: false, starting: false, text: null, stale: false };
        this._try = { open: false, mode: 'text', input: '', rule: null, result: null, error: null };
        this._fields = { open: false, defs: null, loading: false, error: null, byRule: new Map(), picked: null, suggest: null, ui: {} };
        this._timers = {};
        this._destroyed = false;

        const initial = this.options.value || '';
        this.pack = this._resolvePack(this.options.language, initial);

        this.languageConf = new Compartment();
        this.readOnlyConf = new Compartment();
        this.wrapConf = new Compartment();

        this._buildDom(element);
        this._createView(initial);
        this._renderToolbar();          // host buttons can now ask the editor (disabled())
        if (this.options.fieldsOpen && this._fieldsEnabled()) this.toggleFields(true);
        this._applyTheme();
        this._watchTheme();
        this._setOutlineOpen(this.options.outline === true);
        this._setProblemsOpen(!!this.options.problems);
        this._renderStatus();
        if (this.options.draftKey) this._checkDraft(initial);
        queueMicrotask(() => this.events.emit('ready', this));
    }

    // ───────────────────────────────── public API ─────────────────────────────────

    on(event, fn) { this.events.on(event, fn); return this; }
    off(event, fn) { this.events.off(event, fn); return this; }

    getValue() { return this.view.state.doc.toString(); }

    setValue(value, { keepHistory = true } = {}) {
        const state = this.view.state;
        this._locks.clear();
        this.view.dispatch({ changes: { from: 0, to: state.doc.length, insert: value || '' }, userEvent: keepHistory ? 'input.replace' : undefined });
    }

    getLanguage() { return this.pack.id; }

    setLanguage(id) {
        this.pack = this._resolvePack(id, this.getValue());
        this._server = { text: null, items: [], error: null };
        this._externals.clear();
        this._fields = { ...this._fields, defs: null, byRule: new Map(), picked: null, suggest: null };
        if (!this._fieldsEnabled()) this.toggleFields(false);
        else if (this._fields.open) this._loadFieldDefs();
        clearTimeout(this._timers.test);
        this._test = { ...this._test, sets: null, chosen: new Set(), run: null, error: null, stale: false };
        if (!this._testsEnabled()) this.toggleTests(false);
        else if (this._test.open) this._test.loadPromise = this._loadTestSets();
        this.view.dispatch({ effects: this.languageConf.reconfigure(this._languageExtensions()) });
        this._relint();
        this._renderStatus();
        this._renderToolbar();
        this.events.emit('language', this.pack.id);
    }

    getModel() { return this._model(this.view.state); }

    /** One entry per rule: { name, from, to, kind, tags, text, errors, warnings, line } */
    getRules() {
        if (!this.pack.splitRules) return [];
        const model = this.getModel();
        return this.pack.splitRules(model).map(r => this._ruleStatus(r));
    }

    getDiagnostics() { return this.diagnostics.slice(); }

    format() {
        if (!this.pack.format || this.options.readOnly) return null;
        const res = this.pack.format(this.getModel(), this.options.format);
        if (!res || res.text === this.getValue()) {
            this._toast(this.t('formatted', { n: res ? res.formatted : 0 }) + (res && res.skipped.length ? ` · ${this.t('formatSkipped', { n: res.skipped.length })}` : ''), 'success');
            return res;
        }
        const { state } = this.view;
        const line = state.doc.lineAt(state.selection.main.head);
        this.view.dispatch({ changes: { from: 0, to: state.doc.length, insert: res.text }, userEvent: 'format' });
        const doc = this.view.state.doc;
        const target = doc.line(Math.min(line.number, doc.lines));
        this.view.dispatch({ selection: { anchor: target.from }, scrollIntoView: true });
        this._toast(this.t('formatted', { n: res.formatted }) + (res.skipped.length ? ` · ${this.t('formatSkipped', { n: res.skipped.length })}` : ''), 'success');
        this.events.emit('format', res);
        return res;
    }

    /** Ask the server now (skips the typing delay). */
    validate() {
        if (!this._serverEnabled()) { this._relint(); return; }
        this._server = { text: null, items: [], error: null };
        this._runServer(this.getValue());
    }

    focus() { this.view.focus(); }

    goTo(posOrLine, { select = null } = {}) {
        const doc = this.view.state.doc;
        let from = typeof posOrLine === 'object' ? posOrLine.from : posOrLine;
        if (typeof posOrLine === 'object' && posOrLine.line) from = doc.line(Math.min(posOrLine.line, doc.lines)).from;
        from = Math.max(0, Math.min(from, doc.length));
        const to = select != null ? Math.min(select, doc.length) : from;
        this.view.dispatch({ selection: EditorSelection.single(from, to), effects: EditorView.scrollIntoView(from, { y: 'center' }) });
        this.view.focus();
    }

    insertText(text, { at = null } = {}) {
        const sel = this.view.state.selection.main;
        const from = at ?? sel.from;
        const to = at ?? sel.to;
        this.view.dispatch({ changes: { from, to, insert: text }, selection: { anchor: from + text.length }, scrollIntoView: true });
    }

    /** Append a new rule from the pack's first snippet, at the end of the document. */
    newRule() {
        const snippet = (this.pack.snippets || []).find(s => s.snippet && /rule/.test(s.label));
        if (!snippet) return;
        const doc = this.view.state.doc;
        const sep = doc.length === 0 ? '' : doc.toString().endsWith('\n\n') ? '' : doc.toString().endsWith('\n') ? '\n' : '\n\n';
        this.view.dispatch({ changes: { from: doc.length, insert: sep }, selection: { anchor: doc.length + sep.length } });
        const pos = this.view.state.doc.length;
        snippetCompletion(expandSnippetVars(snippet.snippet), { label: snippet.label }).apply(this.view, snippet, pos, pos);
        this.view.dispatch({ scrollIntoView: true });
        this.view.focus();
    }

    setTheme(theme) {
        this.options.theme = theme;
        this._applyTheme();
    }

    setReadOnly(readOnly) {
        this.options.readOnly = !!readOnly;
        this.view.dispatch({ effects: this.readOnlyConf.reconfigure(this._readOnlyExtensions()) });
        this._renderStatus();
    }

    /**
     * Results the host page computed for the current text (e.g. "check before creating"):
     *   diagnostics  [{ from, to } | { line, column? }, severity, message]  -> underlines + problems panel
     *   rules        { ruleName: { badge, tone: ok|info|warning|error, notes: [text], links: [{ label, url }] } }
     *                -> shown on each rule in the rules panel (opened)
     * Both are dropped as soon as the text changes: they describe that exact text.
     */
    setAnnotations({ diagnostics = [], rules = {}, source = '' } = {}, { document = this._activeDoc } = {}) {
        if (document !== this._activeDoc) {
            // a document not shown: kept with it, shown when it is opened (if its text is the same)
            const saved = this._docs.get(document);
            if (saved) saved.annotations = { text: saved.state.doc.toString(), diagnostics, rules, source };
            return;
        }
        this._annotations = { text: this.getValue(), diagnostics, rules, source };
        if (Object.keys(rules).length) this._setOutlineOpen(true);
        this._relint();
    }

    clearAnnotations() {
        if (!this._annotations.text) return;
        this._annotations = { text: null, diagnostics: [], rules: {} };
        this._relint();
    }

    // ── several documents (one per file of a workspace) ──

    /**
     * Shows another document in the editor. Each document keeps its own text, undo history,
     * locks and host results; `text` is only used the first time the id is opened.
     */
    openDocument(id, { text = '' } = {}) {
        if (id === this._activeDoc) return;
        this._docs.set(this._activeDoc, {
            state: this.view.state, locks: this._locks, annotations: this._annotations, server: this._server,
        });
        const saved = this._docs.get(id);
        this._docs.delete(id);
        this._activeDoc = id;
        this._locks = saved ? saved.locks : new Map();
        this._annotations = saved ? saved.annotations : { text: null, diagnostics: [], rules: {} };
        this._server = saved ? saved.server : { text: null, items: [], error: null };
        this.view.setState(saved ? saved.state : EditorState.create({ doc: text, extensions: this._extensions }));
        // settings changed since that state was made (theme, wrap, read-only, language) apply to it too
        this.view.dispatch({ effects: [
            this.languageConf.reconfigure(this._languageExtensions()),
            this.readOnlyConf.reconfigure(this._readOnlyExtensions()),
            this.wrapConf.reconfigure(this.options.lineWrapping ? EditorView.lineWrapping : []),
            locksChanged.of(null),
        ] });
        this._applyTheme();
        this._relint();
        this._renderToolbar();
        this.events.emit('document', id);
    }

    /** Forgets a document that is not shown (the shown one cannot be closed). */
    closeDocument(id) {
        if (id === this._activeDoc) return false;
        return this._docs.delete(id);
    }

    activeDocument() { return this._activeDoc; }

    documentIds() { return [this._activeDoc, ...this._docs.keys()]; }

    getDocumentText(id = this._activeDoc) {
        if (id === this._activeDoc) return this.getValue();
        const saved = this._docs.get(id);
        return saved ? saved.state.doc.toString() : null;
    }

    /** Rules of any open document, as getRules() gives them for the shown one. */
    getRulesOf(id = this._activeDoc) {
        if (id === this._activeDoc) return this.getRules();
        const text = this.getDocumentText(id);
        if (text == null || !this.pack.splitRules) return [];
        try {
            const model = this.pack.parse ? this.pack.parse(text) : { text };
            return this.pack.splitRules(model).map(r => ({ ...r, line: text.slice(0, r.from).split('\n').length }));
        } catch {
            return [];
        }
    }

    /** Model (pack.parse) of any open document. */
    getModelOf(id = this._activeDoc) {
        if (id === this._activeDoc) return this.getModel();
        const text = this.getDocumentText(id);
        try { return this.pack.parse ? this.pack.parse(text || '') : { text }; } catch { return { text }; }
    }

    /** Locks of a document that is not shown (or the shown one). */
    lockRuleIn(id, name, info = {}) {
        if (id === this._activeDoc) return this.lockRule(name, info);
        const saved = this._docs.get(id);
        if (saved) saved.locks.set(name, { label: info.label || (this.host ? this.host.name : ''), canUnlock: !!info.canUnlock, url: info.url || null });
    }

    /**
     * Locks a rule of the document (by name): read-only, with a bar above it. Used for rules
     * inserted from the host: they stay what the host has unless the user unlocks them, which
     * `canUnlock` allows (e.g. the user may edit that rule on the host).
     *   info: { label, canUnlock, url }
     */
    lockRule(name, info = {}) {
        this._locks.set(name, { label: info.label || (this.host ? this.host.name : ''), canUnlock: !!info.canUnlock, url: info.url || null,
                                text: info.text || null, hint: info.hint || null });
        this.view.dispatch({ effects: locksChanged.of(null) });
        this._afterLint(this.getModel());
        this.events.emit('locks', this.getLocks());
    }

    unlockRule(name) {
        if (!this._locks.delete(name)) return;
        this.view.dispatch({ effects: locksChanged.of(null) });
        this._afterLint(this.getModel());
        this.events.emit('locks', this.getLocks());
    }

    isLocked(name) { return this._locks.has(name); }

    getLocks() { return [...this._locks].map(([name, info]) => ({ name, ...info })); }

    /** Short message at the bottom of the editor. */
    notify(message, tone = 'info') { this._toast(message, tone); }

    /** Re-renders the toolbar (host buttons whose disabled() changed). */
    refreshToolbar() { this._renderToolbar(); }

    /** Search bar of the current document: every match is highlighted. Ctrl+F. */
    toggleSearch(force) {
        const open = searchPanelOpen(this.view.state);
        if (force ?? !open) openSearchPanel(this.view);
        else closeSearchPanel(this.view);
    }

    /** Long lines continue on the next visual row; line numbers stay the real ones. */
    setLineWrapping(on) {
        this.options.lineWrapping = !!on;
        try { window.localStorage.setItem(WRAP_KEY, on ? '1' : '0'); } catch { /* storage blocked */ }
        this.view.dispatch({ effects: this.wrapConf.reconfigure(on ? EditorView.lineWrapping : []) });
        this._renderToolbar();
    }

    toggleLineWrapping() { this.setLineWrapping(!this.options.lineWrapping); }

    toggleOutline(force) { this._setOutlineOpen(force ?? !this._outlineOpen); }
    toggleProblems(force) { this._setProblemsOpen(force ?? !this._problemsOpen); }

    // ── Try: one rule on a small sample, in the browser (pack.debug) ──

    /** Open / close the Try panel: a sample typed or pasted, the strings' matches, the condition as a tree. */
    toggleTry(force) {
        const open = !!(force ?? !this._try.open) && !!this.pack.debug;
        this._try.open = open;
        this.tryEl.hidden = !open;
        if (open) this._runTry();
        this._renderToolbar();
    }

    _runTry() {
        const T = this._try;
        if (!T.open || !this.pack.debug) return;
        clearTimeout(this._timers.try);
        T.error = null;
        const input = this.pack.debug.inputBytes(T.input, T.mode);
        const model = this.getModel();
        const names = (model.rules || []).map(r => r.name).filter(Boolean);
        const rule = T.rule && names.includes(T.rule) ? T.rule : this._ruleNameAtCursor() || names[0] || null;
        if (input.error) { T.error = input.error; T.result = null; }
        else {
            try { T.result = rule ? this.pack.debug.evaluate(model, rule, input.bytes) : null; }
            catch (e) { T.result = null; T.error = e.message || String(e); }
        }
        renderTry(this.tryEl, { ...T, rules: names }, {
            t: this.t,
            onClose: () => this.toggleTry(false),
            onMode: (m) => { T.mode = m; this._runTry(); },
            onRule: (n) => { T.rule = n; this._runTry(); },
            onInput: (v) => { T.input = v; clearTimeout(this._timers.try); this._timers.try = setTimeout(() => this._runTry(), 200); },
            onGoto: (pos) => { this.view.dispatch({ selection: { anchor: pos }, scrollIntoView: true }); this.view.focus(); },
        });
    }

    _ruleNameAtCursor() {
        const pos = this.view.state.selection.main.head;
        const r = (this.getModel().rules || []).find(x => pos >= x.from && pos <= x.to);
        return r ? r.name : null;
    }

    // ── tests on samples (host: rulezet-tester) ──

    /** Open / close the Test panel; the sample sets are loaded the first time. */
    toggleTests(force) {
        const open = !!(force ?? !this._test.open) && this._testsEnabled();
        this._test.open = open;
        this.testsEl.hidden = !open;
        if (!open) this._markTestHits([]);
        if (open && !this._test.sets && !this._test.loading) this._test.loadPromise = this._loadTestSets();
        this._renderTests();
        this._renderToolbar();
    }

    /** Run the whole document on the chosen sample sets; results arrive sample by sample. */
    async runTest() {
        if (!this._testsEnabled()) return null;
        if (!this._test.open) this.toggleTests(true);
        if (this._test.loading) await this._test.loadPromise;          // opened just now: sets on their way
        if (!this._test.sets) await this._loadTestSets();
        const T = this._test;
        if (T.starting || (T.run && ['queued', 'running'].includes(T.run.status))) return null;
        if (!T.chosen.size) { T.error = this.t('tChooseSet'); this._renderTests(); return null; }
        const text = this.getValue();
        if (!text.trim()) { T.error = this.t('tNothing'); this._renderTests(); return null; }
        T.starting = true;
        T.error = null;
        T.setsOpen = false;            // the results matter now: the chosen sets fold away (summary kept)
        this._renderTests();
        try {
            const run = await this.host.startTest(this.pack.validateAs || this.pack.id, text, [...T.chosen]);
            Object.assign(T, { run, text, stale: false, expanded: new Set(), focus: null, limits: {} });
            this._markTestHits([]);
            this.events.emit('test', run);
            this._pollTest(run.id);
            return run;
        } catch (e) {
            T.error = e.message || String(e);
            return null;
        } finally {
            T.starting = false;
            this._renderTests();
        }
    }

    getTestRun() { return this._test.run; }

    // ── fields (the host's metadata for each rule, optionally written into it) ──

    toggleFields(force) {
        const open = !!(force ?? !this._fields.open) && this._fieldsEnabled();
        this._fields.open = open;
        this.fieldsEl.hidden = !open;
        if (open && !this._fields.defs && !this._fields.loading) this._loadFieldDefs();
        this._renderFields();
        this._renderToolbar();
    }

    /** The guided tour of the editor's features (Tutorial button). */
    openTutorial(index = 0) {
        if (!this._tour) this._tour = new Tour(this.root, [], this.t, { onStep: () => { if (this.palette && this.palette.close) this.palette.close(); } });
        this._tour.steps = this._tutorialSteps();
        this._tour.start(index);
    }

    _tutorialSteps() {
        const q = (sel) => () => this.root.querySelector(sel);
        const btn = (label) => () => this.root.querySelector(`.rze-toolbar button[aria-label="${label}"]`);
        const t = this.t;
        const pack = this.pack;
        const example = pack.sample || 'rule Example\n{\n    strings:\n        $a = "evil"\n    condition:\n        $a\n}';
        const steps = [
            { title: 'Welcome to the rule editor',
              body: `An editor made for detection rules (${pack.name}): it checks your rules as you type, completes what you write, explains every keyword, and can test the rules on samples.\n\nThis tour shows each feature with an example. Use the arrows (← →) or the buttons; Esc closes it. Open it again any time with the Tutorial button.`,
              try: { label: 'Load an example rule', run: () => { if (!this.getValue().trim()) this.setValue(example); else this.insertText('\n' + example + '\n', { at: this.view.state.doc.length }); } } },
            { title: 'Write a rule', target: q('.cm-content'),
              body: 'Type freely: keywords, strings, modules and rule names are coloured. Suggestions appear as you type; Ctrl+Space shows them at any time. Typing `rule` then Tab inserts a full template; `pe.` lists everything the pe module offers (it also adds `import "pe"` for you).',
              example: 'rule Suspicious_Downloader\n{\n    strings:\n        $url = "http://" ascii wide\n        $api = "URLDownloadToFileA"\n    condition:\n        all of them\n}',
              keys: [['Ctrl+Space', 'suggestions'], ['Tab', 'next placeholder of a template']],
              try: pack.snippets ? { label: 'Insert a new rule', run: () => this.newRule() } : null },
            { title: 'Errors while you type', target: q('.rze-status-counts'),
              body: 'Mistakes are underlined at once (an undefined `$string`, a missing import, a wrong modifier, a string that is never used…). Hover the underline to read why; many come with a quick fix (lightbulb). The counters here open the Problems panel, every problem of the document grouped by rule.',
              example: 'condition:\n    $missing      // ← "undefined string $missing"',
              keys: [['F8 / Shift+F8', 'next / previous problem'], ['Ctrl+Shift+M', 'Problems panel']],
              try: { label: 'Open the Problems panel', run: () => this.toggleProblems(true) } },
            { title: 'Understand and navigate', target: q('.cm-content'),
              body: 'Hover anything to get help: a keyword, a module function and its arguments, a `$string` (its bytes in hex), another rule. F12 or Ctrl+Click jumps to where a string or a rule is defined — even to a rule stored on the host. F2 renames a `$string` or a rule everywhere at once.',
              keys: [['F12 / Ctrl+Click', 'go to definition'], ['F2', 'rename everywhere'], ['Ctrl+/', 'comment / uncomment']] },
        ];
        // the pack's worked example: a good rule built step by step, shown in the document
        const tut = pack.tutorial;
        if (tut && tut.stages) {
            for (const stage of tut.stages) {
                steps.push({ title: stage.title, target: q('.cm-content'), body: stage.body, example: stage.text,
                             try: { label: 'Show it in the editor', run: () => this._showTutorialStage(tut.rule, stage.text) } });
            }
        }
        if (pack.actions) steps.push({ title: 'Rule tools', target: btn(t('ruleTools')),
            body: 'Common edits on the rule under the cursor, in one click: set the author, add today\'s date, an id, a tag, a string, a file-type check (PE, ELF…), and more.',
            keys: [['Ctrl+Shift+R', 'rule tools']],
            try: { label: 'Open the rule tools', run: () => this.openRuleTools() } });
        if (pack.format) steps.push({ title: 'Format', target: btn(t('format')),
            body: 'One clean layout for every rule: indentation, aligned `=` in strings, comments kept. Rules that still have errors are left untouched.',
            keys: [['Shift+Alt+F', 'format the document']],
            try: { label: 'Format the document', run: () => this.format() } });
        if (pack.splitRules) steps.push({ title: 'Several rules: the Rules panel', target: btn(t('outline')),
            body: 'A document can hold many rules. The Rules panel lists them with their status (errors, warnings), their strings and condition; click one to jump to it, filter by name or tag, copy a single rule.\n\nThe lock icon freezes a rule: its text can no longer change until you unlock it.',
            keys: [['Ctrl+Shift+O', 'Rules panel and its filter']],
            try: { label: 'Open the Rules panel', run: () => this.toggleOutline(true) } });
        steps.push({ title: 'Locked rules', target: q('.rze-lockbar') ,
            body: 'Some rules are locked, with a bar above them: a rule you pasted (its text is kept as pasted), a rule inserted from the host, the rules another rule depends on, or a rule you locked yourself. Typing inside is refused. "Unlock to edit" frees it when you are allowed to (your own rules, or as an admin).',
            example: '🔒 Pasted rule: locked — fill its fields on the right, its text stays as pasted   [Unlock to edit]' });
        if (this._fieldsEnabled()) {
            steps.push({ title: 'Fields of the rule', target: btn(t('fields')),
                body: 'The rule\'s metadata on the host: title, description, author, license, version, vulnerabilities, ATT&CK techniques, tags, linked rules. Each field can be written into the rule (a `meta:` key) — tick "Write into the rule" — or kept outside it, so the rule text stays untouched.\n\nValues the rule already holds fill the fields; when they differ you choose: use the rule\'s value, write yours, or keep both different on purpose.',
                example: 'meta:\n    author = "you"            ← Author field (Me button)\n    cve = "CVE-2024-3094"     ← Vulnerabilities field',
                try: { label: 'Open the Fields panel', run: () => this.toggleFields(true) } });
            if (pack.body) steps.push({ title: 'Strings & condition as a form', target: () => this.fieldsEl.querySelector('.rze-body') || btn(t('fields'))(),
                body: 'Below the fields, the strings and the condition can be edited as a form: each string (id, text / hex / regex, value, modifiers), and the condition as clauses joined by `and` / `or`. Ready-made clauses (any of them, PE file, filesize…) are added with one click. The form and the text stay in sync both ways.\n\nWith an empty document, filling the fields builds the rule for you; the title names it.',
                try: { label: 'Show the form', run: () => { this.toggleFields(true); requestAnimationFrame(() => { const b = this.fieldsEl.querySelector('.rze-body'); if (b) b.scrollIntoView({ block: 'nearest' }); }); } } });
        }
        if (this._testsEnabled()) steps.push({ title: 'Test on samples', target: btn(t('tests')),
            body: 'Run the document on sample sets in a sandbox and watch every sample turn into a verdict: detected, missed, false positive, clean. Open a sample to see each match in its surroundings; the strings that matched light up in the rule. Search and filter large runs.',
            keys: [['Ctrl+Shift+Enter', 'run the tests']],
            try: { label: 'Open the Test panel', run: () => this.toggleTests(true) } });
        if (this._serverEnabled()) steps.push({ title: `Checked by ${this.host.name}`, target: q('.rze-status-server'),
            body: `When you stop typing, the whole document is also compiled by ${this.host.name} (the real compiler, with the rules your rules depend on). Its answer shows here and as underlines.`,
            keys: [['Ctrl+Enter', 'check now']],
            try: { label: 'Check now', run: () => this.validate() } });
        steps.push(
            { title: 'Undo, search, commands', target: () => this.undoBtn,
              body: 'Undo and redo any change (also the ones the panels make). Search and replace with regular expressions. The command palette lists every action of the editor with its shortcut.',
              keys: [['Ctrl+Z / Ctrl+Shift+Z', 'undo / redo'], ['Ctrl+F', 'search and replace'], ['Ctrl+Shift+P or F1', 'command palette']],
              try: { label: 'Open the command palette', run: () => this.openPalette() } },
            { title: 'Your workspace', target: btn(t('fullscreen')),
              body: 'Light or dark theme, line wrapping, full screen. Every panel can be resized with the mouse (drag its edge; double-click to reset), and so can the editor itself (drag the bar under it). Your choices are remembered.',
              keys: [['Alt+Z', 'wrap lines'], ['Esc', 'leave full screen']] },
            { title: 'All shortcuts', target: null,
              body: 'That\'s it. The shortcuts below are also in the command palette.',
              keys: [['Ctrl+Space', 'suggestions'], ['F12 / Ctrl+Click', 'definition'], ['F2', 'rename'], ['Shift+Alt+F', 'format'],
                     ['Ctrl+Shift+R', 'rule tools'], ['Ctrl+Shift+O', 'Rules panel'], ['Ctrl+Shift+M', 'Problems'], ['Ctrl+Enter', 'check now'],
                     ['Ctrl+Shift+Enter', 'run the tests'], ['Ctrl+S', 'save (the page decides)'], ['Ctrl+Shift+P', 'commands']] },
        );
        return steps;
    }

    /** A stage of the pack's worked example: replaces the example rule (or adds it); the other rules
     *  of the document are left alone. The stage's imports go to the top when missing. */
    _showTutorialStage(ruleName, text) {
        const lines = text.split('\n');
        const imports = lines.filter(l => /^\s*import\s+"/.test(l)).map(l => l.trim());
        const body = lines.filter(l => !/^\s*import\s+"/.test(l)).join('\n').trim() + '\n';
        if (this._locks.has(ruleName)) this.unlockRule(ruleName);
        const current = this.getValue();
        if (!current.trim()) { this.setValue((imports.length ? imports.join('\n') + '\n\n' : '') + body); this.goTo(0); return; }
        const rule = (this.pack.splitRules ? this.pack.splitRules(this.getModel()) : []).find(r => r.name === ruleName);
        const changes = rule
            ? [{ from: rule.from, to: rule.to, insert: body.trimEnd() }]
            : [{ from: current.length, to: current.length, insert: (current.endsWith('\n') ? '\n' : '\n\n') + body }];
        const missing = imports.filter(i => !current.includes(i));
        if (missing.length) changes.push({ from: 0, to: 0, insert: missing.join('\n') + '\n\n' });
        this.view.dispatch({ changes, userEvent: 'input.tutorial' });
        const placed = (this.pack.splitRules(this.getModel()).find(r => r.name === ruleName) || {}).from;
        if (placed != null) this.goTo(placed);
    }

    /** Shows this rule in the Fields panel (null: the rule under the cursor). */
    pickFieldsRule(name) {
        this._fields.picked = name || null;
        this._renderFields();
    }

    /** The field definitions the host gave (null until loaded). */
    fieldDefinitions() { return this._fields.defs; }

    /** One rule's field values: { values: { id: value }, report: { id: bool }, keep: { id: bool } }. */
    getFieldValues(ruleName) {
        const defs = this._fields.defs;
        if (!defs) return null;
        const s = this._fieldState(ruleName);
        return s ? JSON.parse(JSON.stringify(s)) : null;
    }

    /** Every rule of the document: { ruleName: { values, report, keep } }. */
    getAllFieldValues() {
        const out = {};
        if (!this._fields.defs) return out;
        for (const r of this.getRules()) out[r.name] = this.getFieldValues(r.name);
        return out;
    }

    /** The host sets a rule's values (edit page: what it has stored). report: write them into the rule. */
    setFieldValues(ruleName, values, { report = false } = {}) {
        const defs = this._fields.defs;
        if (!defs) { this._fields.pending = [...(this._fields.pending || []), [ruleName, values, { report }]]; return; }
        const s = this._fieldState(ruleName, { force: true });
        if (!s) return;
        for (const def of defs) {
            if (!(def.id in values)) continue;
            s.values[def.id] = values[def.id] ?? emptyValue(def);
            s.report[def.id] = !!def.meta && report;
            s.keep[def.id] = false;
            if (s.report[def.id]) this._writeField(ruleName, def, s.values[def.id]);
        }
        this._fieldsChanged(ruleName);
    }
    toggleFullscreen(force) {
        const on = force ?? !this.root.classList.contains('rze-fullscreen');
        this.root.classList.toggle('rze-fullscreen', on);
        this._renderToolbar();
        this.view.requestMeasure();
    }

    goToDefinition(pos = this.view.state.selection.main.head) {
        if (!this.pack.definition) return false;
        const def = this.pack.definition(this._ctx(this.view.state, pos));
        if (def) { this.goTo(def.from, { select: def.to }); return true; }
        const ext = this._externalAt(pos);
        if (ext && ext.rule && ext.rule.url) { window.open(ext.rule.url, '_blank', 'noopener'); return true; }
        return false;
    }

    startRename(pos = this.view.state.selection.main.head) {
        if (!this.pack.references || this.options.readOnly) return;
        const refs = this.pack.references(this._ctx(this.view.state, pos));
        if (!refs) { this._toast(this.t('nothingToRename')); return; }
        this.view.dispatch({ effects: renameEffect.of({ pos, name: refs.name, kind: refs.kind }) });
    }

    openPalette() { this.palette.open([...this._commands(), ...this._actionCommands()]); }

    /** Palette with only the pack's authoring actions (add date, tag, id...). */
    openRuleTools() {
        const cmds = this._actionCommands();
        if (!cmds.length) { this._toast(this.t('noRuleHere')); return; }
        this.palette.open(cmds);
    }

    /** Runs a pack action by id; value skips the prompt when the action asks for one. */
    async runAction(id, value) {
        const pos = this.view.state.selection.main.head;
        const ctx = this._ctx(this.view.state, pos, { author: this.options.author });
        const action = this._packActions(ctx).find(a => a.id === id);
        if (!action || this.options.readOnly) return false;
        if (action.input && value === undefined) {
            const def = typeof action.input.value === 'function' ? action.input.value(ctx) : action.input.value;
            value = await this.palette.prompt({ label: action.input.label, placeholder: action.input.placeholder, value: def || '' });
            if (value == null) { this.view.focus(); return false; }
        }
        // the document may have changed while the prompt was open
        const fresh = this._ctx(this.view.state, Math.min(pos, this.view.state.doc.length), { author: this.options.author });
        let res;
        try { res = action.run(fresh, value); } catch (e) { res = { error: e.message }; }
        if (!res || res.error || !res.length) {
            this._toast(res && res.error ? res.error : this.t('nothingToDo'), res && res.error ? 'warning' : 'info');
            this.view.focus();
            return false;
        }
        this.view.dispatch({
            changes: res.map(c => ({ from: c.from, to: c.to, insert: expandSnippetVars(c.insert || '') })),
            userEvent: 'input.action', scrollIntoView: true,
        });
        this.view.focus();
        this.events.emit('action', { id });
        return true;
    }

    _packActions(ctx) {
        if (!this.pack.actions) return [];
        try { return this.pack.actions(ctx) || []; } catch { return []; }
    }

    _actionCommands() {
        const ctx = this._ctx(this.view.state, this.view.state.selection.main.head, { author: this.options.author });
        return this._packActions(ctx).map(a => ({ id: a.id, label: `${cap(this.t('rule'))}: ${a.label}`, run: () => this.runAction(a.id) }));
    }

    execCommand(id) {
        const cmd = [...this._commands(), ...this._actionCommands()].find(c => c.id === id);
        if (cmd) cmd.run();
        return !!cmd;
    }

    clearDraft() {
        if (this.options.draftKey) this._drafts().saveDraft(this.options.draftKey, null);
    }

    destroy() {
        this._destroyed = true;
        Object.values(this._timers).forEach(clearTimeout);
        if (this._themeObserver) this._themeObserver.disconnect();
        if (this._media) this._media.removeEventListener('change', this._onMedia);
        this.view.destroy();
        this.root.remove();
        this.events.clear();
    }

    // ───────────────────────────────── setup ─────────────────────────────────

    _resolvePack(id, text) {
        if (id && id !== 'auto') {
            const pack = getLanguage(id);
            if (pack) return pack;
            console.warn(`rulezet-editor: unknown language "${id}", using plain text`);
            return plain;
        }
        return detectLanguage(text) || plain;
    }

    _buildDom(element) {
        const t = this.t;
        this.root = h('div', { class: 'rze', role: 'group', 'aria-label': 'Rule editor' });
        if (this.options.height) this.root.style.height = this.options.height;

        this.toolbarEl = h('div', { class: 'rze-toolbar', role: 'toolbar' });
        this.bannerEl = h('div', { class: 'rze-banner', hidden: true });
        this.editorEl = h('div', { class: 'rze-editor' });
        this.outlineEl = h('aside', { class: 'rze-outline', 'aria-label': t('outline') });
        this.fieldsEl = h('aside', { class: 'rze-fields', 'aria-label': t('fields'), hidden: true });
        this.problemsEl = h('div', { class: 'rze-problems', 'aria-label': t('problems') });
        this.testsEl = h('div', { class: 'rze-tests', 'aria-label': t('tests'), hidden: true });
        this.tryEl = h('div', { class: 'rze-tests rze-try', 'aria-label': t('try'), hidden: true });
        this.statusEl = h('div', { class: 'rze-status' });
        this.toastEl = h('div', { class: 'rze-toast', role: 'status', 'aria-live': 'polite' });

        const main = h('div', { class: 'rze-main' }, this.editorEl, this.outlineEl, this.fieldsEl);
        this.root.append(
            this.options.toolbar ? this.toolbarEl : '',
            this.bannerEl, main, this.problemsEl, this.tryEl, this.testsEl,
            this.options.statusBar ? this.statusEl : '',
            this.toastEl,
        );
        // the editor may sit inside a host <form> (Rulezet's edit page): Enter in one of its own
        // fields (search, test search, rename, filters) must never submit that form
        this.root.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.target instanceof HTMLInputElement) e.preventDefault();
        });
        this.palette = new CommandPalette(this.root, t);
        element.appendChild(this.root);
        // every panel can be resized with the mouse (sizes remembered per viewer)
        const half = () => this.root.getBoundingClientRect().width * 0.7;
        const tall = () => this.root.getBoundingClientRect().height * 0.8;
        resizable(this.outlineEl, { axis: 'x', key: 'outline', min: 180, max: half });
        resizable(this.fieldsEl, { axis: 'x', key: 'fields', min: 240, max: half });
        resizable(this.problemsEl, { axis: 'y', key: 'problems', min: 80, max: tall });
        resizable(this.testsEl, { axis: 'y', key: 'tests', min: 140, max: tall });
        resizable(this.tryEl, { axis: 'y', key: 'try', min: 140, max: tall });
        resizable(this.root, { axis: 'y', side: 'after', key: 'editor', min: 260, max: () => window.innerHeight * 3,
            onResize: () => this.view && this.view.requestMeasure() });
        this._renderToolbar();
    }

    _createView(doc) {
        const self = this;
        const extensions = [
            lineNumbers(),
            highlightActiveLineGutter(),
            highlightSpecialChars(),
            history(),
            foldGutter({ markerDOM: open => h('span', { class: 'rze-fold', text: open ? '▾' : '▸' }) }),
            drawSelection(),
            dropCursor(),
            EditorState.allowMultipleSelections.of(true),
            indentOnInput(),
            bracketMatching(),
            closeBrackets(),
            autocompletion({
                override: [ctx => this._completionSource(ctx)],
                icons: true,
                activateOnTypingDelay: 60,
                addToOptions: [],
            }),
            rectangularSelection(),
            crosshairCursor(),
            highlightActiveLine(),
            highlightSelectionMatches(),
            search({ top: true }),
            EditorState.phrases.of(SEARCH_PHRASES[this.options.locale] || {}),
            lintGutter(),
            linter(view => this._lintSource(view), {
                delay: 300,
                needsRefresh: u => u.transactions.some(tr => tr.effects.some(e => e.is(refreshLint))),
            }),
            hoverTooltip((view, pos, side) => this._hover(view, pos, side), { hoverTime: 350 }),
            referenceHighlighter(this),
            testHitMarks,
            ruleLocks(this),
            renamePanel(this),
            keymap.of([
                { key: 'F12', run: () => this.goToDefinition() },
                { key: 'F2', run: () => { this.startRename(); return true; } },
                { key: 'Shift-Alt-f', run: () => { this.format(); return true; }, preventDefault: true },
                { key: 'Mod-Shift-p', run: () => { this.openPalette(); return true; }, preventDefault: true },
                { key: 'F1', run: () => { this.openPalette(); return true; } },
                { key: 'Mod-s', run: () => { this.events.emit('save', this.getValue()); return true; }, preventDefault: true },
                { key: 'Mod-Shift-m', run: () => { this.toggleProblems(); return true; }, preventDefault: true },
                { key: 'Mod-Shift-o', run: () => { this.toggleOutline(true); this._focusOutlineFilter(); return true; }, preventDefault: true },
                { key: 'Mod-Enter', run: () => { this.validate(); return true; } },
                { key: 'Mod-Shift-y', run: () => { if (!this.pack.debug) return false; this.toggleTry(); return true; }, preventDefault: true },
                { key: 'Mod-Shift-Enter', run: () => { if (!this._testsEnabled()) return false; this.runTest(); return true; }, preventDefault: true },
                { key: 'Mod-Shift-r', run: () => { this.openRuleTools(); return true; }, preventDefault: true },
                { key: 'Alt-z', run: () => { this.toggleLineWrapping(); return true; }, preventDefault: true },
                { key: 'Escape', run: () => { if (this.root.classList.contains('rze-fullscreen')) { this.toggleFullscreen(false); return true; } return false; } },
                indentWithTab,
                ...closeBracketsKeymap, ...defaultKeymap, ...searchKeymap, ...historyKeymap,
                ...foldKeymap, ...completionKeymap, ...lintKeymap,
            ]),
            this.languageConf.of(this._languageExtensions()),
            this.readOnlyConf.of(this._readOnlyExtensions()),
            this.wrapConf.of(this._initialWrap() ? EditorView.lineWrapping : []),
            themeExtensions,
            EditorView.domEventHandlers({
                mousedown(e, view) {
                    if (!(e.ctrlKey || e.metaKey) || e.button !== 0) return false;
                    const pos = view.posAtCoords({ x: e.clientX, y: e.clientY });
                    if (pos == null) return false;
                    if (self.goToDefinition(pos)) { e.preventDefault(); return true; }
                    return false;
                },
            }),
            EditorView.updateListener.of(update => this._onUpdate(update)),
        ];
        this._extensions = extensions;
        this.view = new EditorView({ state: EditorState.create({ doc, extensions }), parent: this.editorEl });
    }

    _languageExtensions() {
        const pack = this.pack;
        const ext = [indentUnit.of(pack.indentUnit || '    ')];
        if (pack.stream) {
            const s = pack.stream;
            ext.push(StreamLanguage.define({
                name: pack.id,
                startState: () => s.startState(),
                token: (stream, state) => s.token(stream, state),
                copyState: s.copyState ? (st) => s.copyState(st) : undefined,
                blankLine: s.blankLine ? (st, unit) => s.blankLine(st, unit) : undefined,
                indent: s.indent ? (st, textAfter, cx) => s.indent(st, textAfter, cx) : undefined,
                languageData: s.languageData || {},
                tokenTable: TOKEN_TAGS,
            }));
        }
        if (pack.folding) {
            ext.push(foldService.of((state, lineStart, lineEnd) => {
                const ranges = this._folds(state);
                for (const r of ranges) {
                    if (r.from < lineStart || r.from > lineEnd) continue;
                    const line = state.doc.lineAt(r.from);
                    if (r.to > line.to) return { from: line.to, to: r.to };
                }
                return null;
            }));
        }
        return ext;
    }

    _readOnlyExtensions() {
        return this.options.readOnly ? [EditorState.readOnly.of(true), EditorView.editable.of(false)] : [];
    }

    // ───────────────────────────────── model ─────────────────────────────────

    _model(state) {
        const c = this._modelCache;
        if (c.doc === state.doc && c.pack === this.pack) return c.model;
        const text = state.doc.toString();
        let model;
        try {
            model = this.pack.parse ? this.pack.parse(text) : { text };
        } catch (e) {
            console.error('rulezet-editor: parse failed', e);
            model = { text, rules: [], errors: [] };
        }
        this._modelCache = { doc: state.doc, pack: this.pack, model };
        return model;
    }

    _folds(state) {
        const model = this._model(state);
        let ranges = this._foldCache.get(model);
        if (!ranges) {
            ranges = this.pack.folding(model) || [];
            this._foldCache.set(model, ranges);
        }
        return ranges;
    }

    _ctx(state, pos, extra = {}) {
        return { text: state.doc.toString(), pos, parsed: this._model(state), ...extra };
    }

    // ───────────────────────────────── lint ─────────────────────────────────

    _serverEnabled() {
        return !!(this.options.serverValidation && this.host && this.host.has && this.host.has('validate'));
    }

    _lintSource(view) {
        const state = view.state;
        const doc = state.doc;
        const text = doc.toString();
        const pack = this.pack;
        const model = this._model(state);
        let local = [];
        try {
            local = pack.lint ? pack.lint(model, this.options.lint) || [] : [];
        } catch (e) {
            console.error('rulezet-editor: lint failed', e);
        }
        const clamp = (p) => Math.max(0, Math.min(p, doc.length));
        const diags = [];
        const pendingLookups = [];

        for (const d of local) {
            const out = {
                from: clamp(d.from), to: clamp(Math.max(d.to, d.from)), severity: d.severity || 'error',
                message: d.message, source: pack.name, code: d.code, origin: 'local',
                actions: (d.fixes || []).map(fix => ({ name: fix.label, apply: (v, from) => this._applyFix(doc, d, fix, from) })),
            };
            if (d.code === 'external-rule' && this.options.lookupExternalRules && this.host && this.host.has && this.host.has('getRule')) {
                const name = text.slice(d.from, d.to);
                const entry = this._externals.get(name);
                if (!entry) pendingLookups.push(name);
                else if (entry.state === 'found') this._decorateExternal(out, name, entry.rule, model);
                else if (entry.state === 'missing') out.message += ` · ${this.t('notFoundOnHost', { name, host: this.host.name })}`;
            }
            diags.push(out);
        }

        // server diagnostics, only for the exact text they were computed on
        if (this._serverEnabled()) {
            const hasSyntaxErrors = local.some(d => d.severity === 'error' && (d.code === 'syntax' || d.code === 'no-condition'));
            if (this._server.text === text) {
                const localLines = new Set(local.filter(d => d.severity === 'error').map(d => doc.lineAt(clamp(d.from)).number));
                // words a local diagnostic already points at, per line ("undefined identifier X" twice is noise)
                const localWords = new Map();
                for (const d of local) {
                    const n = doc.lineAt(clamp(d.from)).number;
                    const word = text.slice(d.from, d.to);
                    if (word.length >= 3) localWords.set(n, [...(localWords.get(n) || []), word]);
                }
                for (const item of this._server.items) {
                    let from = 0;
                    let to = Math.min(doc.length, doc.line(1).to);
                    if (item.line && item.line <= doc.lines) {
                        if (item.severity === 'error' && localLines.has(item.line)) continue;
                        if ((localWords.get(item.line) || []).some(w => item.message.includes(w))) continue;
                        const line = doc.line(item.line);
                        const indent = line.text.match(/^\s*/)[0].length;
                        from = line.from + (item.column ? Math.min(item.column - 1, line.length) : indent);
                        to = Math.max(from + 1, line.to);
                    }
                    if (!item.line && diags.some(d => d.severity === 'error')) continue;
                    diags.push({ from: clamp(from), to: clamp(to), severity: item.severity, message: item.message, source: this.host.name, origin: 'server' });
                }
            } else if (!hasSyntaxErrors && text.trim()) {
                this._scheduleServer(text);
            } else {
                this._serverState = text.trim() ? 'waiting' : 'idle';
            }
        }

        // host page results, only for the exact text they were computed on
        if (this._annotations.text !== null) {
            if (this._annotations.text === text) {
                for (const item of this._annotations.diagnostics) {
                    let from = item.from;
                    let to = item.to;
                    if (from == null) {
                        const line = doc.line(Math.max(1, Math.min(item.line || 1, doc.lines)));
                        const indent = line.text.match(/^\s*/)[0].length;
                        from = line.from + (item.column ? Math.min(item.column - 1, line.length) : indent);
                        to = Math.max(from + 1, line.to);
                    }
                    if (diags.some(d => d.severity === item.severity && d.message === item.message && doc.lineAt(clamp(d.from)).number === doc.lineAt(clamp(from)).number)) continue;
                    diags.push({ from: clamp(from), to: clamp(Math.max(to, from + 1)), severity: item.severity || 'error', message: item.message, source: this._annotations.source || (this.host ? this.host.name : ''), origin: 'host' });
                }
            } else {
                this._annotations = { text: null, diagnostics: [], rules: {} };
                this.events.emit('annotationsCleared');
            }
        }

        if (pendingLookups.length) this._lookupExternals(pendingLookups);

        diags.sort((a, b) => a.from - b.from || severityRank(a.severity) - severityRank(b.severity));
        this.diagnostics = diags.map(d => {
            const line = doc.lineAt(d.from);
            return { ...d, line: line.number, column: d.from - line.from + 1, actions: d.actions };
        });
        this._afterLint(model);
        return diags;
    }

    /** Run the linters again now (server answer, external lookups, language change). */
    _relint() {
        if (this._destroyed) return;
        this.view.dispatch({ effects: refreshLint.of(null) });
        forceLinting(this.view);
    }

    _applyFix(lintDoc, diag, fix, mappedFrom) {
        const view = this.view;
        let changes = fix.changes;
        if (view.state.doc !== lintDoc) {
            // the document moved since the lint: find the same problem again
            const again = (this.pack.lint(this._model(view.state), this.options.lint) || [])
                .filter(d => d.code === diag.code && d.fixes && d.fixes.some(f => f.label === fix.label))
                .sort((a, b) => Math.abs(a.from - mappedFrom) - Math.abs(b.from - mappedFrom))[0];
            if (!again) return;
            changes = again.fixes.find(f => f.label === fix.label).changes;
        }
        view.dispatch({ changes: changes.map(c => ({ from: c.from, to: c.to, insert: expandSnippetVars(c.insert || '') })), userEvent: 'input.fix', scrollIntoView: true });
        view.focus();
    }

    _scheduleServer(text) {
        clearTimeout(this._timers.server);
        this._serverState = 'pending';
        this._timers.server = setTimeout(() => this._runServer(text), this.options.serverDelay);
    }

    async _runServer(text) {
        if (this._destroyed) return;
        this._serverState = 'checking';
        this._renderStatus();
        const lang = this.pack.validateAs || this.pack.id;
        try {
            const items = await this.host.validate(lang, text);
            this._server = { text, items: items || [], error: null };
            this._serverState = 'ok';
        } catch (e) {
            this._server = { text, items: [], error: e.message || String(e) };
            this._serverState = 'error';
        }
        if (this._destroyed) return;
        if (this.getValue() === text) this._relint();
        this._renderStatus();
        this.events.emit('validated', { text, items: this._server.items, error: this._server.error });
    }

    _lookupExternals(names) {
        const lang = this.pack.validateAs || this.pack.id;
        const fresh = [...new Set(names)].filter(n => !this._externals.has(n)).slice(0, 20);
        if (!fresh.length) return;
        const jobs = fresh.map(name => {
            const entry = { state: 'pending', rule: null };
            this._externals.set(name, entry);
            entry.promise = this.host.getRule(lang, name)
                .then(rule => { entry.state = rule ? 'found' : 'missing'; entry.rule = rule; })
                .catch(() => { entry.state = 'missing'; });
            return entry.promise;
        });
        Promise.all(jobs).then(() => { if (!this._destroyed) this._relint(); });
    }

    _decorateExternal(diag, name, rule, model) {
        const host = this.host.name;
        diag.severity = 'info';
        diag.message = `${this.t('foundOnHost', { name, host })}${rule.author ? ` (${rule.author})` : ''}: not in this document.`;
        diag.actions = [];
        if (rule.content && !this.options.readOnly) {
            diag.actions.push({ name: this.t('insertFromHost', { name, host }), apply: (view, from) => this._insertExternal(rule, from) });
        }
        if (rule.url) diag.actions.push({ name: this.t('openOnHost', { host }), apply: () => window.open(rule.url, '_blank', 'noopener') });
    }

    /** Insert a rule fetched from the host above the rule that uses it; imports go to the top. */
    _insertExternal(rule, usedAt) {
        const model = this.getModel();
        const user = (model.rules || []).find(r => usedAt >= r.from && usedAt <= r.to);
        const at = user ? user.from : 0;
        const lines = rule.content.replace(/\r\n/g, '\n').split('\n');
        const imports = lines.filter(l => /^\s*import\s+"/.test(l)).map(l => l.trim());
        const body = lines.filter(l => !/^\s*import\s+"/.test(l)).join('\n').trim();
        const have = new Set((model.imports || []).map(i => `import "${i.name}"`));
        const missing = imports.filter(i => !have.has(i));
        const changes = [{ from: at, to: at, insert: body + '\n\n' }];
        if (missing.length) {
            const last = (model.imports || [])[model.imports.length - 1];
            const pos = last ? this.view.state.doc.lineAt(last.to).to : 0;
            changes.push({ from: pos, to: pos, insert: last ? '\n' + missing.join('\n') : missing.join('\n') + '\n\n' });
        }
        this.view.dispatch({ changes, userEvent: 'input.insert', scrollIntoView: true });
        this.lockRule(rule.name, { canUnlock: !!rule.can_edit, url: rule.url });
        this._toast(`${rule.name}: inserted`, 'success');
    }

    _externalAt(pos) {
        const text = this.getValue();
        let a = pos, b = pos;
        while (a > 0 && /\w/.test(text[a - 1])) a--;
        while (b < text.length && /\w/.test(text[b])) b++;
        return this._externals.get(text.slice(a, b)) || null;
    }

    _ruleStatus(r) {
        const inRule = this.diagnostics.filter(d => d.from >= r.from && d.from <= r.to);
        return {
            ...r,
            errors: inRule.filter(d => d.severity === 'error').length,
            warnings: inRule.filter(d => d.severity === 'warning').length,
            infos: inRule.filter(d => d.severity === 'info' || d.severity === 'hint').length,
            line: this.view.state.doc.lineAt(Math.min(r.from, this.view.state.doc.length)).number,
            annotation: (this._annotations.rules || {})[r.name] || null,
            locked: this._locks.get(r.name) || null,
        };
    }

    _afterLint(model) {
        const rules = this.pack.splitRules ? this.pack.splitRules(model).map(r => this._ruleStatus(r)) : [];
        this._rules = rules;
        if (this.options.outline === 'auto' && this._outlineAuto !== false && !this._outlineOpen && rules.length >= 2) this._setOutlineOpen(true);
        this._renderOutline();
        this._renderProblems();
        this._renderStatus();
        this._renderFields();
        this.events.emit('diagnostics', this.getDiagnostics());
    }

    // ───────────────────────────────── completion & hover ─────────────────────────────────

    async _completionSource(context) {
        const pack = this.pack;
        if (!pack.complete) return null;
        const res = pack.complete({ ...this._ctx(context.state, context.pos), explicit: context.explicit });
        if (!res || !res.options || !res.options.length) return null;
        const options = res.options.map(o => this._toCompletion(o));
        if (res.remoteRules && this.host && this.host.has && this.host.has('searchRules')) {
            const remote = await this._searchRemote(res.remoteRules);
            if (context.aborted) return null;
            const local = new Set(options.map(o => o.label));
            for (const r of remote) {
                if (local.has(r.name) || !/^[A-Za-z_]\w*$/.test(r.name)) continue;
                options.push({
                    label: r.name, type: 'class', boost: -5,
                    detail: `${this.host.name}${r.author ? ' · ' + r.author : ''}`,
                    info: r.description || undefined,
                });
            }
        }
        return { from: res.from, options, validFor: /^[$#@!]?\w*\*?$/ };
    }

    _toCompletion(o) {
        const base = { label: o.label, detail: o.detail, info: o.info, type: COMPLETION_TYPES[o.type] || o.type, boost: o.boost };
        if (o.snippet) {
            // expanded when applied, so every inserted rule gets its own uuid
            const make = () => snippetCompletion(expandSnippetVars(o.snippet), base);
            return { ...base, apply: (view, completion, from, to) => make().apply(view, completion, from, to) };
        }
        if (o.extraChanges) {
            return {
                ...base,
                apply: (view, completion, from, to) => {
                    const insert = o.apply || o.label;
                    const changes = view.state.changes([{ from, to, insert }, ...o.extraChanges]);
                    view.dispatch({ changes, selection: { anchor: changes.mapPos(to, 1) }, userEvent: 'input.complete' });
                },
            };
        }
        return o.apply ? { ...base, apply: o.apply } : base;
    }

    async _searchRemote(query) {
        this._remoteCache = this._remoteCache || new Map();
        const key = `${this.pack.id}:${query.toLowerCase()}`;
        if (this._remoteCache.has(key)) return this._remoteCache.get(key);
        const lang = this.pack.validateAs || this.pack.id;
        const p = Promise.race([
            this.host.searchRules(lang, query).catch(() => []),
            new Promise(resolve => setTimeout(() => resolve([]), 1500)),
        ]);
        this._remoteCache.set(key, p);
        const out = await p;
        if (!out.length) this._remoteCache.delete(key);
        return out;
    }

    async _hover(view, pos) {
        if (!this.pack.hover) return null;
        let externalName = null;
        const res = this.pack.hover(this._ctx(view.state, pos, {
            externalRule: (name, tok) => { externalName = name; return { from: tok.from, to: tok.to, title: name, external: true }; },
        }));
        if (!res) return null;
        let info = res;
        if (externalName) {
            if (!(this.host && this.host.has && this.host.has('getRule'))) {
                info = { ...res, body: 'Not defined in this document.' };
            } else {
                if (!this._externals.has(externalName)) this._lookupExternals([externalName]);
                const entry = this._externals.get(externalName);
                await Promise.race([entry.promise, new Promise(r => setTimeout(r, 2000))]);
                const rule = entry.rule;
                info = rule
                    ? { ...res, title: `rule ${rule.name}`, body: [rule.description, rule.author && `Author: ${rule.author}`, `From ${this.host.name}, not in this document.`].filter(Boolean).join('\n'), link: rule.url }
                    : { ...res, body: `Not defined in this document, not found on ${this.host.name}.` };
            }
        }
        return {
            pos: info.from, end: info.to, above: true,
            create: () => ({ dom: renderHover(info, this.t) }),
        };
    }

    // ───────────────────────────────── UI ─────────────────────────────────

    _onUpdate(update) {
        if (update.docChanged) {
            this.events.emit('change', update.state.doc.toString());
            const T = this._test;
            if (T.run && !T.stale && T.text !== null && update.state.doc.toString() !== T.text) {
                T.stale = true;           // results stay, but hits no longer point into this text
                queueMicrotask(() => this._markTestHits([]));
                this._renderTests();
            }
            if (this.options.draftKey) {
                clearTimeout(this._timers.draft);
                this._timers.draft = setTimeout(() => this._drafts().saveDraft(this.options.draftKey, this.getValue()), 800);
            }
        }
        if (update.docChanged || update.transactions.length) this._updateHistoryButtons();
        if (update.docChanged && this.options.lockPasted && this.pack.splitRules) {
            const pasted = [];
            for (const tr of update.transactions) {
                if (!tr.isUserEvent('input.paste') && !tr.isUserEvent('input.drop')) continue;
                tr.changes.iterChangedRanges((fromA, toA, fromB, toB) => { if (toB > fromB) pasted.push([fromB, toB]); });
            }
            if (pasted.length) queueMicrotask(() => this._lockPasted(pasted));
        }
        if (update.docChanged && this._try.open) {
            clearTimeout(this._timers.try);
            this._timers.try = setTimeout(() => this._runTry(), 300);
        }
        if (update.selectionSet || update.docChanged) {
            this._renderCursor();
            this._highlightActiveRule();
            if (this._fields.open && !this._fields.picked && update.selectionSet && !update.docChanged) {
                const name = this._fieldRuleName();
                if (name !== this._fields.shown) { this._fields.shown = name; this._renderFields(); }
            }
        }
    }

    /** Host buttons stay disabled until the editor exists; a throwing disabled() disables. */
    /** Every rule a paste brought in (or touched) is locked: its text stays what was pasted until
     *  the user unlocks it; the Fields panel can still fill the rule's fields (stored apart). */
    _lockPasted(ranges) {
        if (this._destroyed) return;
        const rules = this.pack.splitRules(this.getModel());
        for (const r of rules) {
            if (!r.name || r.name === '(unnamed)' || this._locks.has(r.name)) continue;
            if (!ranges.some(([a, b]) => a < r.to && b > r.from)) continue;
            this.lockRule(r.name, { label: this.t('pasted'), canUnlock: true, text: this.t('lockedPasted'), hint: this.t('unlockPastedHint') });
        }
    }

    /** Undo / redo buttons: greyed out when there is nothing to undo / redo. */
    _updateHistoryButtons() {
        if (!this.undoBtn || !this.view) return;
        this.undoBtn.disabled = undoDepth(this.view.state) === 0;
        this.redoBtn.disabled = redoDepth(this.view.state) === 0;
    }

    _hostButtonDisabled(b) {
        if (!this.view) return true;
        if (typeof b.disabled !== 'function') return !!b.disabled;
        try { return !!b.disabled(this); } catch { return true; }
    }

    _initialWrap() {
        if (this.options.lineWrapping == null) {
            let saved = null;
            try { saved = window.localStorage.getItem(WRAP_KEY); } catch { /* storage blocked */ }
            this.options.lineWrapping = saved === '1';
        }
        return this.options.lineWrapping;
    }

    _renderToolbar() {
        if (!this.options.toolbar) return;
        const t = this.t;
        const btn = (name, label, onClick, active = false, title = label) =>
            h('button', { type: 'button', class: `rze-btn${active ? ' rze-btn-active' : ''}`, title, 'aria-label': label, onclick: onClick }, icon(name), h('span', { class: 'rze-btn-label', text: label }));
        const fs = this.root && this.root.classList.contains('rze-fullscreen');
        const dark = this.root && this.root.classList.contains('rze-dark');
        this.undoBtn = h('button', { type: 'button', class: 'rze-btn rze-icon-only', title: `${t('undo')} (Ctrl+Z)`, 'aria-label': t('undo'),
            onclick: () => { undo(this.view); this.view.focus(); } }, icon('undo'));
        this.redoBtn = h('button', { type: 'button', class: 'rze-btn rze-icon-only', title: `${t('redo')} (Ctrl+Shift+Z / Ctrl+Y)`, 'aria-label': t('redo'),
            onclick: () => { redo(this.view); this.view.focus(); } }, icon('redo'));
        this.toolbarEl.replaceChildren(
            h('span', { class: 'rze-toolbar-lang', text: this.pack.name }),
            h('span', { class: 'rze-toolbar-sep' }),
            this.undoBtn, this.redoBtn,
            h('span', { class: 'rze-toolbar-sep' }),
            this.pack.snippets ? btn('plus', 'New rule', () => this.newRule()) : '',
            this.pack.actions ? btn('tools', t('ruleTools'), () => this.openRuleTools(), false, `${t('ruleTools')} (Ctrl+Shift+R)`) : '',
            this.pack.debug ? btn('search', t('try'), () => this.toggleTry(), this._try.open, `${t('tryTitle')} (Ctrl+Shift+Y)`) : '',
            this.pack.format ? btn('format', t('format'), () => this.format(), false, `${t('format')} (Shift+Alt+F)`) : '',
            this.pack.splitRules ? btn('outline', t('outline'), () => this.toggleOutline(), this._outlineOpen, `${t('outline')} (Ctrl+Shift+O)`) : '',
            btn('problems', t('problems'), () => this.toggleProblems(), this._problemsOpen, `${t('problems')} (Ctrl+Shift+M)`),
            this._fieldsEnabled() ? btn('tag', t('fields'), () => this.toggleFields(), this._fields.open, t('fieldsHint')) : '',
            this._testsEnabled() ? btn('play', t('tests'), () => this.toggleTests(), this._test.open, `${t('tests')} (Ctrl+Shift+Enter: ${t('tRun').toLowerCase()})`) : '',
            h('span', { class: 'rze-toolbar-fill' }),
            this.options.tutorial ? btn('help', t('tutorial'), () => this.openTutorial(), false, t('tutorialHint')) : '',
            ...(this.options.buttons || []).map(b => h('button', {
                type: 'button', class: `rze-btn rze-host-btn${b.primary ? ' rze-btn-primary' : ''}`, title: b.title || b.label, 'aria-label': b.label,
                disabled: this._hostButtonDisabled(b),
                onclick: () => b.run(this),
            }, b.icon ? icon(b.icon) : '', h('span', { class: 'rze-btn-label', text: b.label }))),
            (this.options.buttons || []).length ? h('span', { class: 'rze-toolbar-sep' }) : '',
            btn('search', t('search'), () => this.toggleSearch(), false, `${t('search')} (Ctrl+F)`),
            btn('palette', t('palette'), () => this.openPalette(), false, `${t('palette')} (Ctrl+Shift+P / F1)`),
            btn(dark ? 'sun' : 'moon', t('theme'), () => this.setTheme(dark ? 'light' : 'dark')),
            btn('wrap', t('wrap'), () => this.toggleLineWrapping(), !!this.options.lineWrapping, `${t('wrap')} (Alt+Z)`),
            btn(fs ? 'collapse' : 'expand', t('fullscreen'), () => this.toggleFullscreen()),
        );
        this._updateHistoryButtons();
    }

    _renderStatus() {
        if (!this.options.statusBar || !this.view) return;
        const t = this.t;
        const counts = { error: 0, warning: 0, info: 0 };
        for (const d of this.diagnostics) counts[d.severity === 'hint' ? 'info' : d.severity] = (counts[d.severity === 'hint' ? 'info' : d.severity] || 0) + 1;
        const langSelect = h('select', { class: 'rze-status-lang', 'aria-label': 'Language', onchange: e => this.setLanguage(e.target.value) },
            ...listLanguages().map(p => h('option', { value: p.id, selected: p.id === this.pack.id, text: p.name })));
        const rulesCount = this._rules ? this._rules.length : 0;
        const serverLabel = {
            off: '', idle: this.host ? this.host.name : '', pending: `${this.host && this.host.name}: …`,
            waiting: `${this.host && this.host.name}: …`, checking: `${this.host && this.host.name}: ${t('serverChecking')}`,
            ok: `${this.host && this.host.name}: ${t('serverOk')}`, error: `${this.host && this.host.name}: ${t('serverError')}`,
        }[this._serverState] || '';
        this.cursorEl = h('span', { class: 'rze-status-item' });
        this.statusEl.replaceChildren(
            langSelect,
            this.pack.splitRules ? h('span', { class: 'rze-status-item', text: `${rulesCount} ${rulesCount === 1 ? t('rule') : t('rules')}` }) : '',
            serverLabel ? h('button', {
                type: 'button', class: `rze-status-item rze-status-server rze-server-${this._serverState}`,
                title: this._server.error || 'Validate now (Ctrl+Enter)', onclick: () => this.validate(),
            }, icon('cloud'), serverLabel) : '',
            this.options.readOnly ? h('span', { class: 'rze-status-item', text: t('readOnly') }) : '',
            h('span', { class: 'rze-toolbar-fill' }),
            h('button', { type: 'button', class: 'rze-status-item rze-status-counts', title: t('problems'), onclick: () => this.toggleProblems() },
                icon('error', 'rze-sev-error'), String(counts.error),
                icon('warning', 'rze-sev-warning'), String(counts.warning),
                icon('info', 'rze-sev-info'), String(counts.info)),
            this.cursorEl,
        );
        this._renderCursor();
    }

    _renderCursor() {
        if (!this.cursorEl) return;
        const { state } = this.view;
        const head = state.selection.main.head;
        const line = state.doc.lineAt(head);
        const sel = state.selection.main.to - state.selection.main.from;
        this.cursorEl.textContent = `${this.t('line')} ${line.number}, ${this.t('col')} ${head - line.from + 1}${sel ? ` (${sel})` : ''}`;
    }

    _setOutlineOpen(open) {
        if (open !== this._outlineOpen && this._outlineOpen !== undefined) this._outlineAuto = false;
        this._outlineOpen = !!open && !!this.pack.splitRules;
        this.outlineEl.hidden = !this._outlineOpen;
        this._renderOutline();
        this._renderToolbar();
    }

    _fieldsEnabled() {
        return this.options.fields !== false && !!this.pack.meta && !!(this.host && this.host.has && this.host.has('ruleFields'));
    }

    async _loadFieldDefs() {
        const F = this._fields;
        F.loading = true;
        F.error = null;
        this._renderFields();
        try {
            F.defs = (await this.host.ruleFields(this.pack.validateAs || this.pack.id)) || [];
        } catch (e) {
            F.defs = null;
            F.error = e.message || String(e);
        } finally {
            F.loading = false;
        }
        for (const [name, values, opts] of F.pending || []) this.setFieldValues(name, values, opts);
        F.pending = [];
        this._renderFields();
        this.events.emit('fields', this.getAllFieldValues());
    }

    _ruleEntries(name) {
        if (name === DRAFT) return [];
        return this.pack.meta ? this.pack.meta.entries(this.getModel(), name) : null;
    }

    /** First value typed with no rule in the document: the rule is created, named after the title
     *  field when there is one, and every written field goes into it. Returns its name. */
    _createRuleFromFields({ strings = true } = {}) {
        const F = this._fields;
        const meta = this.pack.meta;
        if (!meta || !meta.skeleton) return null;
        const draft = F.byRule.get(DRAFT);
        const titleDef = F.defs.find(d => d.ruleName);
        const fromTitle = titleDef && draft && meta.ruleName ? meta.ruleName(draft.values[titleDef.id]) : null;
        const name = fromTitle || 'new_rule';
        F.namedByPanel = F.namedByPanel || new Set();
        F.namedByPanel.add(name);
        const doc = this.view.state.doc;
        this.view.dispatch({ changes: { from: doc.length, insert: (doc.length ? '\n' : '') + expandSnippetVars(meta.skeleton(name, { strings })) }, userEvent: 'input.fields' });
        F.byRule.delete(DRAFT);
        if (draft) {
            F.byRule.set(name, draft);
            for (const def of F.defs) if (draft.report[def.id] && !isEmpty(def, draft.values[def.id])) this._writeField(name, def, draft.values[def.id]);
        }
        return name;
    }

    /** Strings / condition edited in the panel: written into the rule (created first when there is none). */
    _editBody(name, make) {
        if (!name || !this.pack.body) return;
        let target = name;
        if (name === DRAFT) target = this._createRuleFromFields({ strings: false });   // the form adds the strings itself
        if (!target) return;
        if (this._locks.has(target)) { this._toast(this.t('lockedUnlockFirst', { name: target }), 'warning'); return; }
        const changes = make(this.getModel(), target);
        if (changes && changes.length) this.view.dispatch({ changes, userEvent: 'input.fields' });
        this._renderFields();
    }

    /** The title field names the rule: renaming it keeps its field state. */
    _renameFromTitle(name, title) {
        const meta = this.pack.meta;
        if (!meta || !meta.renameRule || !meta.ruleName || name === DRAFT || this._locks.has(name)) return name;
        const next = meta.ruleName(title);
        if (!next || next === name) return name;
        const changes = meta.renameRule(this.getModel(), name, next);
        if (!changes || changes.error) return name;
        this.view.dispatch({ changes, userEvent: 'input.fields' });
        const F = this._fields;
        F.byRule.set(next, F.byRule.get(name));
        F.byRule.delete(name);
        F.namedByPanel = F.namedByPanel || new Set();
        F.namedByPanel.delete(name);
        F.namedByPanel.add(next);
        if (F.picked === name) F.picked = next;
        return next;
    }

    /** A rule's field state, created from what the rule holds the first time it is asked.
     *  DRAFT: the values typed while the document has no rule yet. */
    _fieldState(name, { force = false } = {}) {
        const F = this._fields;
        if (!F.defs || !name) return null;
        if (name === DRAFT) {
            if (!F.byRule.has(DRAFT)) F.byRule.set(DRAFT, initialState(F.defs, [], this.options.fieldsReport));
            return F.byRule.get(DRAFT);
        }
        if (!F.byRule.has(name)) {
            const entries = this._ruleEntries(name);
            if (!entries && !force) return null;
            // a rule that already exists in the text (pasted, loaded): nothing is written into it by
            // default — the fields are filled from it and only written back where the user ticks
            F.byRule.set(name, initialState(F.defs, entries || [], false, name));
        }
        return F.byRule.get(name);
    }

    /** The rule was edited by hand: fields written into it follow it; a removed key stops being written. */
    _syncFieldsFromRule(name) {
        const s = this._fieldState(name);
        if (!s) return;
        const entries = this._ruleEntries(name);
        for (const def of this._fields.defs) {
            if (!s.report[def.id]) continue;
            const ruleValue = readField(def, entries);
            if (ruleValue === null) {
                if (!isEmpty(def, s.values[def.id]) && !this._fields.writing) s.report[def.id] = false;
            } else if (!sameValue(def, s.values[def.id], ruleValue)) {
                s.values[def.id] = ruleValue;
            }
        }
    }

    _writeField(name, def, value) {
        if (!def.meta || !this.pack.meta) return;
        if (this._locks.has(name)) { this._toast(this.t('lockedUnlockFirst', { name }), 'warning'); return; }
        const model = this.getModel();
        // the key the rule already uses for this field (licence for license...), else the field's own
        const key = this._metaKeyFor(name, def);
        const changes = isEmpty(def, value)
            ? this.pack.meta.remove(model, name, key)
            : this.pack.meta.set(model, name, key, toMetaValue(def, value));
        if (!changes || !changes.length) return;
        this._fields.writing = true;
        try {
            this.view.dispatch({ changes, userEvent: 'input.fields' });
        } finally {
            this._fields.writing = false;
        }
    }

    /** The title renames the rule only while the rule was born in the panel or still has the
     *  default name: a rule pasted with its own name keeps it. */
    _renamesRule(name) {
        const F = this._fields;
        F.namedByPanel = F.namedByPanel || new Set();
        return name === 'new_rule' || F.namedByPanel.has(name);
    }

    /** The key a field is written under in this rule: the one the rule already uses (licence for
     *  license...), else the field's own. */
    _metaKeyFor(name, def) {
        if (!def.meta) return null;
        const names = [def.meta.key, ...(def.meta.aliases || [])].filter(k => !k.startsWith('@')).map(k => k.toLowerCase());
        const used = name && name !== DRAFT ? (this.pack.meta.entries(this.getModel(), name) || []).find(e => names.includes(e.key.toLowerCase())) : null;
        return used ? used.key : def.meta.key;
    }

    _fieldsChanged(name) {
        this._renderFields();
        this.events.emit('fields', { rule: name, ...this.getFieldValues(name) });
    }

    _fieldRuleName() {
        const F = this._fields;
        const rules = this._rules || (this.pack.splitRules ? this.pack.splitRules(this.getModel()) : []);
        if (!rules.length) return DRAFT;
        if (F.picked && rules.some(r => r.name === F.picked)) return F.picked;
        const head = this.view.state.selection.main.head;
        const at = rules.find(r => head >= r.from && head <= r.to);
        return at ? at.name : (rules.length === 1 ? rules[0].name : null);
    }

    _renderFields() {
        const F = this._fields;
        if (!F.open || !this.view) return;
        const name = F.defs ? this._fieldRuleName() : null;
        if (name) this._syncFieldsFromRule(name);
        const state = name ? this._fieldState(name) : null;
        const entries = name ? this._ruleEntries(name) : null;
        const ruleValueOf = (def) => readField(def, entries);
        const set = (fn) => { if (name && state) { fn(state); this._fieldsChanged(name); } };
        renderFields(this.fieldsEl, {
            defs: F.defs || [], rules: (this._rules || []).map(r => r.name), rule: state ? name : null, picked: F.picked,
            docRules: (this._rules || []).map(r => r.name),
            draft: name === DRAFT, me: this.options.author || null,
            body: this.pack.body ? (name === DRAFT ? { strings: [], condition: '' } : (name ? this.pack.body.read(this.getModel(), name) : null)) : null,
            bodyModifiers: this.pack.body ? this.pack.body.modifiers : null,
            splitCondition: this.pack.body && this.pack.body.splitCondition,
            joinCondition: this.pack.body && this.pack.body.joinCondition,
            conditionClauses: this.pack.body && this.pack.body.clauses,
            state, locked: name ? this._locks.has(name) : false, loading: F.loading, error: F.error, suggest: F.suggest, ui: F.ui,
            statusOf: (def) => fieldStatus(def, state, ruleValueOf(def), name === DRAFT ? null : name), ruleValueOf,
            metaKeyOf: (def) => this._metaKeyFor(name, def),
        }, {
            t: this.t,
            onClose: () => this.toggleFields(false),
            onPickRule: (n) => { F.picked = n || null; this._renderFields(); },
            onValue: (def, value) => {
                if (!name || !state) return;
                state.values[def.id] = value;
                state.keep[def.id] = false;
                let target = name;
                if (name === DRAFT) target = this._createRuleFromFields();
                else {
                    if (def.ruleName && this._renamesRule(name)) target = this._renameFromTitle(name, value);
                    if (state.report[def.id]) this._writeField(target, def, value);
                }
                this._fieldsChanged(target || name);
            },
            onReport: (def, on) => set((s) => {
                s.report[def.id] = on;
                s.keep[def.id] = false;
                if (!on) return;
                const ruleValue = ruleValueOf(def);
                if (isEmpty(def, s.values[def.id]) && ruleValue !== null) s.values[def.id] = ruleValue;
                else this._writeField(name, def, s.values[def.id]);
            }),
            onResolve: (def, how) => set((s) => {
                if (how === 'rule') { s.values[def.id] = ruleValueOf(def); s.keep[def.id] = false; }
                else if (how === 'mine') { s.report[def.id] = true; s.keep[def.id] = false; this._writeField(name, def, s.values[def.id]); }
                else if (how === 'keep') { s.keep[def.id] = true; s.report[def.id] = false; }
                else if (how === 'undo') { s.keep[def.id] = false; }
            }),
            onSuggest: (def, query, opts = {}) => {
                this._suggestField(def, query);
                if (opts.focus) {
                    const input = this.fieldsEl.querySelector(`[data-focus-key="${CSS.escape(opts.focus)}"]`);
                    if (input) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
                }
            },
            onString: (index, s) => this._editBody(name, (model, rule) => this.pack.body.setString(model, rule, index, s)),
            onStringRemove: (index) => this._editBody(name, (model, rule) => this.pack.body.removeString(model, rule, index)),
            onCondOp: (op) => { F.ui = { ...F.ui, condOp: op }; this._renderFields(); },
            onCondition: (text) => this._editBody(name, (model, rule) => this.pack.body.setCondition(model, rule, text)),
            onFormats: (def) => { F.ui = { ...F.ui, formats: def ? def.id : null }; this._renderFields(); },
            onSelect: (def, query = '', onlyIf = null) => {
                if (onlyIf && F.ui.select !== onlyIf) return;
                F.ui = { ...F.ui, select: def ? def.id : null, selectQuery: def ? query : '' };
                this._renderFields();
            },
            onBrowse: (def, path, page = 1, label = null, append = false) => this._browseField(def, path, page, label, append),
            canPick: typeof this.options.pickValues === 'function',
            canInsert: !!(this.host && this.host.has && this.host.has('getRule')),
            onInsertItems: (def, items) => this._insertFieldRules(def, items),
            onPick: (def, items) => this._pickValues(def, items),
            onBrowseClose: () => { F.ui = { ...F.ui, browse: null }; this._renderFields(); },
        });
    }

    /** One level of a field's folders (tag namespaces, ATT&CK tactics), from the host. */
    async _browseField(def, path, page, label, append) {
        const F = this._fields;
        if (!(this.host && this.host.has('browse'))) return;
        const prev = F.ui.browse && F.ui.browse.field === def.id ? F.ui.browse : null;
        const labels = (prev ? prev.labels : []).slice(0, path.length);
        if (label && path.length) labels[path.length - 1] = label;
        const b = { field: def.id, path, labels, page, loading: true, error: null,
                    data: append && prev ? prev.data : null };
        F.ui = { ...F.ui, browse: b };
        this._renderFields();
        try {
            const data = await this.host.browse(this.pack.validateAs || this.pack.id, def.id, path, page);
            if (F.ui.browse !== b) return;
            b.data = append && b.data
                ? { folders: [...(b.data.folders || []), ...(data.folders || [])], items: [...(b.data.items || []), ...(data.items || [])], has_more: data.has_more }
                : data;
        } catch (e) {
            b.error = e.message || String(e);
        }
        b.loading = false;
        this._renderFields();
    }

    _suggestField(def, query, { focus = null } = {}) {
        const F = this._fields;
        clearTimeout(this._timers.suggest);
        F.suggest = query ? { field: def.id, query, items: (F.suggest && F.suggest.field === def.id ? F.suggest.items : []) } : null;
        this._renderFields();
        if (!query || !def.suggest || !(this.host && this.host.has('suggest'))) return;
        this._timers.suggest = setTimeout(async () => {
            let items = [];
            try { items = await this.host.suggest(this.pack.validateAs || this.pack.id, def.id, query) || []; } catch { items = []; }
            if (!F.suggest || F.suggest.field !== def.id || F.suggest.query !== query) return;
            F.suggest = { field: def.id, query, items: items.slice(0, 10) };
            this._renderFields();
        }, 200);
    }

    /** "Add to the document" under a field of host rules (Linked rules): each one fetched from the
     * host and inserted locked (unlockable by who may edit it), its imports gathered at the top.
     * Rules of another format, or not found, are skipped with a message. */
    async _insertFieldRules(def, items) {
        // bounded: a field never pulls a whole collection into the document
        const perClick = def.insertMax || 10;
        const room = Math.max(0, (def.insertTotalMax || 30) - this._locks.size);
        const allowed = Math.min(perClick, room);
        if (!allowed) { this._toast(this.t('fInsertFull', { n: def.insertTotalMax || 30 }), 'warning'); return; }
        if (items.length > allowed) this._toast(this.t('fInsertCapped', { n: allowed }), 'warning');
        let added = 0;
        const skipped = [];
        for (const item of items.slice(0, allowed)) {
            const name = String(item.label ?? item.value);
            if ((this.getModel().rules || []).some(r => r.name === name)) continue;
            let rule = null;
            try { rule = await this.host.getRule(this.pack.validateAs || this.pack.id, name); } catch { rule = null; }
            if (!rule || !rule.content) { skipped.push(name); continue; }
            this._insertExternal(rule, -1);
            added += 1;
        }
        if (skipped.length) this._toast(this.t('fInsertSkipped', { names: skipped.join(', ') }), 'warning');
        if (added) this._renderFields();
    }

    /** The host's own picker for a field (options.pickValues(def, items) -> the new list or null):
     * the items the user keeps stay as they were (their relation kind…), new ones get the default.
     * Returns the new list (the Fields panel stores it like a typed value), or null: unchanged. */
    async _pickValues(def, items) {
        let picked = null;
        try { picked = await this.options.pickValues(def, items); } catch { picked = null; }
        if (!Array.isArray(picked)) return null;
        const byValue = new Map(items.map(i => [String(i.value), i]));
        let next = picked.map(p => byValue.get(String(p.value))
            || (def.kinds ? { ...p, kind: p.kind || def.kinds[0].value } : p));
        if (def.max) next = next.slice(0, def.max);
        return next;
    }

    _testsEnabled() {
        return this.options.tests !== false && !!this.pack.test && !!(this.host && this.host.has && this.host.has('startTest'));
    }

    _testSetsKey() { return `rulezet-editor:test-sets:${this.pack.id}`; }

    async _loadTestSets() {
        const T = this._test;
        T.loading = true;
        T.error = null;
        this._renderTests();
        try {
            const data = await this.host.testSets(this.pack.validateAs || this.pack.id);
            T.sets = (data && data.available && data.sets) || [];
            if (data && !data.available) T.error = this.t('tUnavailable', { host: this.host.name });
            let saved = null;
            try { saved = JSON.parse(window.localStorage.getItem(this._testSetsKey()) || 'null'); } catch { /* storage blocked */ }
            const ids = new Set(T.sets.map(s => s.id));
            // the viewer's last choice; the first time, every set
            T.chosen = new Set(Array.isArray(saved) ? saved.filter(id => ids.has(id)) : ids);
        } catch (e) {
            T.sets = [];
            T.error = e.message || String(e);
        } finally {
            T.loading = false;
            this._renderTests();
        }
    }

    _toggleTestSet(id, on) {
        this._toggleTestSets([id], on);
    }

    _toggleTestSets(ids, on) {
        const T = this._test;
        for (const id of ids) { if (on) T.chosen.add(id); else T.chosen.delete(id); }
        try { window.localStorage.setItem(this._testSetsKey(), JSON.stringify([...T.chosen])); } catch { /* storage blocked */ }
        this._renderTests();
    }

    _pollTest(runId) {
        clearTimeout(this._timers.test);
        this._timers.test = setTimeout(async () => {
            if (this._destroyed || !this._test.run || this._test.run.id !== runId) return;
            try {
                const run = await this.host.testState(runId);
                if (!this._test.run || this._test.run.id !== runId) return;
                this._test.run = run;
                this.events.emit('test', run);
                if (run.status === 'queued' || run.status === 'running') this._pollTest(runId);
            } catch (e) {
                this._test.error = e.message || String(e);
                this._test.run = { ...this._test.run, status: 'failed' };
            }
            this._renderTests();
        }, this.options.testPollMs);
    }

    /** Highlights in the rule the strings that matched one sample; `active` is the clicked one. */
    _focusTestSample(sampleId, activeHit = null) {
        const T = this._test;
        const profile = this.pack.test;
        T.focus = sampleId;
        if (T.stale || !profile || !profile.locate || !T.run) { this._markTestHits([]); return null; }
        const smp = T.run.samples.find(s => s.id === sampleId);
        if (!smp) { this._markTestHits([]); return null; }
        const model = this.getModel();
        const seen = new Set();
        const marks = [];
        let active = null;
        for (const hit of smp.hits || []) {
            const key = `${hit.rule}\u0000${hit.item || ''}`;
            if (seen.has(key)) continue;          // one mark per string, however many times it matched
            seen.add(key);
            const isActive = !!activeHit && hit.rule === activeHit.rule && hit.item === activeHit.item;
            const r = profile.locate(model, hit);
            if (!r) continue;
            marks.push({ from: r.from, to: Math.max(r.to, r.from + 1), active: !!isActive });
            if (isActive) active = r;
        }
        this._markTestHits(marks);
        return active;
    }

    _markTestHits(marks) {
        if (!this.view || this._destroyed) return;
        const len = this.view.state.doc.length;
        this.view.dispatch({ effects: setTestMarks.of(marks.filter(m => m.from < len).map(m => ({ ...m, to: Math.min(m.to, len) }))) });
    }

    _testHit(hit, sampleId) {
        if (this._test.stale) return;
        const range = this._focusTestSample(sampleId ?? this._test.focus, hit);
        if (range) this.goTo(range.from, { select: range.to });
        this._renderTests();
    }

    _renderTests() {
        if (!this._test.open) return;
        renderTests(this.testsEl, this._test, {
            t: this.t,
            profile: this.pack.test,
            onToggleSet: (id, on) => this._toggleTestSet(id, on),
            onToggleSets: (ids, on) => this._toggleTestSets(ids, on),
            onSetsOpen: (open) => { this._test.setsOpen = open; this._renderTests(); },
            onSetsQuery: (q) => { this._test.setsQuery = q; this._renderTests(); },
            onToggleSample: (id) => {
                const T = this._test;
                if (T.expanded.has(id)) {
                    T.expanded.delete(id);
                    if (T.focus === id) { T.focus = null; this._markTestHits([]); }
                } else {
                    T.expanded.add(id);
                    this._focusTestSample(id);
                }
                this._renderTests();
            },
            onQuery: (q) => { this._test.query = q; this._renderTests(); },
            onFilter: (f) => { this._test.filter = f; this._renderTests(); },
            onMore: (setId) => { const L = this._test.limits; L[setId] = (L[setId] || 100) + 200; this._renderTests(); },
            onRun: () => this.runTest(),
            onHit: (hit, sampleId) => this._testHit(hit, sampleId),
            onClose: () => this.toggleTests(false),
        });
    }

    _setProblemsOpen(open) {
        this._problemsOpen = !!open;
        this.problemsEl.hidden = !this._problemsOpen;
        this._renderProblems();
        this._renderToolbar();
    }

    _renderOutline() {
        if (!this._outlineOpen || !this.view) return;
        renderOutline(this.outlineEl, this._rules || [], {
            t: this.t,
            filter: this._outlineFilter || '',
            onFilter: (v) => { this._outlineFilter = v; this._renderOutline(); },
            onSelect: (r) => this.goTo(r.from),
            onSelectChild: (c) => this.goTo(c.from),
            onCopy: async (r) => { try { await navigator.clipboard.writeText(r.text); this._toast(this.t('copied'), 'success'); } catch { /* clipboard blocked */ } },
            onToggleLock: (r) => {
                if (!r.name || r.name === '(unnamed)') return;
                if (this._locks.has(r.name)) {
                    if (this._locks.get(r.name).canUnlock) this.unlockRule(r.name);
                    else this._toast(this.t('lockedNoRight', { name: r.name }), 'warning');
                } else {
                    this.lockRule(r.name, { label: this.t('lockedByYou'), canUnlock: true, text: this.t('lockedManual'), hint: this.t('unlockManualHint') });
                }
            },
            onClose: () => this.toggleOutline(false),
            activeFrom: this._activeRuleFrom,
        });
        this._highlightActiveRule();
    }

    _focusOutlineFilter() {
        const input = this.outlineEl.querySelector('input');
        if (input) input.focus();
    }

    _highlightActiveRule() {
        if (!this._outlineOpen || !this._rules) return;
        const head = this.view.state.selection.main.head;
        const active = this._rules.find(r => head >= r.from && head <= r.to);
        const from = active ? active.from : null;
        if (from === this._activeRuleFrom) return;
        this._activeRuleFrom = from;
        this.outlineEl.querySelectorAll('[data-from]').forEach(el => el.classList.toggle('rze-active', Number(el.dataset.from) === from));
    }

    _renderProblems() {
        if (!this._problemsOpen) return;
        renderProblems(this.problemsEl, this.diagnostics, {
            t: this.t,
            rules: this._rules || [],
            onSelect: (d) => this.goTo(d.from, { select: d.to }),
            onFix: (d, a) => a.apply(this.view, d.from, d.to),
            onClose: () => this.toggleProblems(false),
        });
    }

    /** A short message to the user: the host's own notifications when it gives `toast`, else the
     *  editor's. tone: info | success | warning | error. */
    _toast(message, tone = 'info') {
        if (typeof this.options.toast === 'function') {
            try { this.options.toast(message, tone); return; } catch { /* fall back to the editor's own */ }
        }
        this.toastEl.textContent = message;
        this.toastEl.classList.add('rze-toast-show');
        clearTimeout(this._timers.toast);
        this._timers.toast = setTimeout(() => this.toastEl.classList.remove('rze-toast-show'), 2600);
    }

    _commands() {
        const t = this.t;
        const v = this.view;
        const cmds = [
            { id: 'format', label: `${t('format')} document`, key: 'Shift+Alt+F', run: () => this.format(), when: () => !!this.pack.format },
            { id: 'newRule', label: 'Insert a new rule', run: () => this.newRule(), when: () => !!this.pack.snippets },
            { id: 'definition', label: 'Go to definition', key: 'F12 / Ctrl+Click', run: () => this.goToDefinition(), when: () => !!this.pack.definition },
            { id: 'rename', label: 'Rename symbol', key: 'F2', run: () => this.startRename(), when: () => !!this.pack.references },
            { id: 'complete', label: 'Trigger suggestions', key: 'Ctrl+Space', run: () => startCompletion(v) },
            { id: 'validate', label: `Validate on ${this.host ? this.host.name : 'server'} now`, key: 'Ctrl+Enter', run: () => this.validate(), when: () => this._serverEnabled() },
            { id: 'nextProblem', label: 'Next problem', key: 'F8', run: () => nextDiagnostic(v) },
            { id: 'prevProblem', label: 'Previous problem', key: 'Shift+F8', run: () => previousDiagnostic(v) },
            { id: 'fields', label: `Toggle ${t('fields').toLowerCase()} panel`, run: () => this.toggleFields(), when: () => this._fieldsEnabled() },
            { id: 'tests', label: `Toggle ${t('tests').toLowerCase()} panel`, run: () => this.toggleTests(), when: () => this._testsEnabled() },
            { id: 'runTest', label: `${t('tRun')}`, key: 'Ctrl+Shift+Enter', run: () => this.runTest(), when: () => this._testsEnabled() },
            { id: 'problems', label: `Toggle ${t('problems').toLowerCase()} panel`, key: 'Ctrl+Shift+M', run: () => this.toggleProblems() },
            { id: 'outline', label: `Toggle ${t('outline').toLowerCase()} panel`, key: 'Ctrl+Shift+O', run: () => this.toggleOutline(), when: () => !!this.pack.splitRules },
            { id: 'find', label: 'Find / replace', key: 'Ctrl+F', run: () => openSearchPanel(v) },
            { id: 'gotoLine', label: 'Go to line', key: 'Ctrl+Alt+G', run: () => gotoLine(v) },
            { id: 'comment', label: 'Toggle comment', key: 'Ctrl+/', run: () => toggleComment(v) },
            { id: 'foldAll', label: 'Fold all', key: 'Ctrl+Alt+[', run: () => foldAll(v) },
            { id: 'unfoldAll', label: 'Unfold all', key: 'Ctrl+Alt+]', run: () => unfoldAll(v) },
            { id: 'wrap', label: 'Toggle line wrapping', key: 'Alt+Z', run: () => this.toggleLineWrapping() },
            { id: 'theme', label: 'Toggle light / dark theme', run: () => this.setTheme(this.root.classList.contains('rze-dark') ? 'light' : 'dark') },
            { id: 'fullscreen', label: 'Toggle full screen', key: 'Esc to leave', run: () => this.toggleFullscreen() },
            { id: 'undo', label: 'Undo', key: 'Ctrl+Z', run: () => undo(v) },
            { id: 'redo', label: 'Redo', key: 'Ctrl+Shift+Z', run: () => redo(v) },
            { id: 'copyAll', label: 'Copy the whole document', run: async () => { try { await navigator.clipboard.writeText(this.getValue()); this._toast(t('copied'), 'success'); } catch { /* blocked */ } } },
            ...listLanguages().filter(p => p.id !== this.pack.id).map(p => ({ id: `lang:${p.id}`, label: `Change language: ${p.name}`, run: () => this.setLanguage(p.id) })),
        ];
        for (const r of this._rules || []) cmds.push({ id: `rule:${r.from}`, label: `${t('goTo')} ${t('rule')}: ${r.name}`, key: `${t('line')} ${r.line}`, run: () => this.goTo(r.from) });
        return cmds.filter(c => !c.when || c.when());
    }

    // ───────────────────────────────── theme & drafts ─────────────────────────────────

    _isDark() {
        const mode = this.options.theme;
        if (mode === 'dark') return true;
        if (mode === 'light') return false;
        const html = document.documentElement;
        const attr = html.getAttribute('data-bs-theme') || html.getAttribute('data-theme');
        if (attr === 'dark') return true;
        if (attr === 'light') return false;
        if (document.body && document.body.classList.contains('dark-mode')) return true;
        if (document.body && document.body.classList.contains('light-mode')) return false;
        return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    }

    _applyTheme() {
        const dark = this._isDark();
        this.root.classList.toggle('rze-dark', dark);
        this.root.classList.toggle('rze-light', !dark);
        this._renderToolbar();
    }

    _watchTheme() {
        const update = () => { if (this.options.theme === 'auto') this._applyTheme(); };
        if (typeof MutationObserver !== 'undefined') {
            this._themeObserver = new MutationObserver(update);
            this._themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme', 'data-theme', 'class'] });
            if (document.body) this._themeObserver.observe(document.body, { attributes: true, attributeFilter: ['class'] });
        }
        if (window.matchMedia) {
            this._media = window.matchMedia('(prefers-color-scheme: dark)');
            this._onMedia = update;
            this._media.addEventListener('change', this._onMedia);
        }
    }

    _drafts() {
        if (this.host && this.host.has && this.host.has('loadDraft')) return this.host;
        this._localDrafts = this._localDrafts || new LocalDraftHost();
        return this._localDrafts;
    }

    async _checkDraft(initial) {
        const draft = await this._drafts().loadDraft(this.options.draftKey);
        if (!draft || !draft.text || draft.text === initial || this._destroyed) return;
        const t = this.t;
        const time = new Date(draft.savedAt).toLocaleString();
        this.bannerEl.replaceChildren(
            h('span', { text: t('draftFound', { time }) }),
            h('button', { type: 'button', class: 'rze-btn rze-btn-primary', onclick: () => { this.setValue(draft.text); this.bannerEl.hidden = true; } }, t('restore')),
            h('button', { type: 'button', class: 'rze-btn', onclick: () => { this.clearDraft(); this.bannerEl.hidden = true; } }, t('discard')),
        );
        this.bannerEl.hidden = false;
    }
}

function severityRank(s) {
    return { error: 0, warning: 1, info: 2, hint: 3 }[s] ?? 4;
}

/** Hover tooltip DOM: title, optional code block, body with `code` spans, optional link. */
function renderHover(info, t) {
    const body = h('div', { class: 'rze-hover-body' });
    for (const line of String(info.body || '').split('\n')) {
        if (!line) continue;
        const p = h('div');
        line.split(/(`[^`]+`)/).forEach(part => {
            if (part.startsWith('`') && part.endsWith('`')) p.appendChild(h('code', { text: part.slice(1, -1) }));
            else p.appendChild(document.createTextNode(part));
        });
        body.appendChild(p);
    }
    return h('div', { class: 'rze-hover' },
        h('div', { class: 'rze-hover-title', text: info.title || '' }),
        info.code ? h('pre', { class: 'rze-hover-code', text: info.code }) : '',
        body,
        info.link ? h('a', { class: 'rze-hover-link', href: info.link, target: '_blank', rel: 'noopener' }, icon('link'), ' ', t('openOnHost', { host: new URL(info.link, location.href).host })) : '',
    );
}

/**
 * Locked rules (lockRule): edits inside them are refused (with a message), a bar above each one
 * says where it comes from and offers to unlock it. Locks follow the rule by name, so formatting
 * or text moving around keeps them; deleting the whole rule is allowed.
 */
function ruleLocks(editor) {
    const lockedRanges = (state) => {
        if (!editor._locks.size || !editor.pack.splitRules) return [];
        let rules = [];
        try { rules = editor.pack.splitRules(editor._model(state)); } catch { rules = []; }
        return rules.filter(r => editor._locks.has(r.name));
    };

    class LockBar extends WidgetType {
        constructor(name, info) { super(); this.name = name; this.info = info; }
        eq(other) { return other.name === this.name && other.info.canUnlock === this.info.canUnlock && other.info.label === this.info.label && other.info.text === this.info.text; }
        toDOM() {
            const t = editor.t;
            return h('div', { class: 'rze-lockbar' },
                icon('lock'),
                h('span', { text: this.info.text || t('lockedFrom', { host: this.info.label || '' }) }),
                h('span', { class: 'rze-toolbar-fill' }),
                this.info.url ? h('a', { href: this.info.url, target: '_blank', rel: 'noopener', text: t('open') }) : '',
                this.info.canUnlock
                    ? h('button', { type: 'button', class: 'rze-btn rze-lockbar-unlock', title: this.info.hint || t('unlockHint'), onclick: () => editor.unlockRule(this.name) }, icon('unlock'), h('span', { text: t('unlock') }))
                    : h('span', { class: 'rze-lockbar-ro', text: t('lockedReadOnly') }));
        }
        ignoreEvent() { return true; }
    }

    const build = (state) => {
        const marks = [];
        for (const r of lockedRanges(state)) {
            const first = state.doc.lineAt(Math.min(r.from, state.doc.length));
            const last = state.doc.lineAt(Math.min(r.to, state.doc.length));
            marks.push(Decoration.widget({ widget: new LockBar(r.name, editor._locks.get(r.name)), block: true, side: -1 }).range(first.from));
            for (let n = first.number; n <= last.number; n++) marks.push(Decoration.line({ class: 'rze-locked' }).range(state.doc.line(n).from));
        }
        return Decoration.set(marks, true);
    };

    const field = StateField.define({
        create: build,
        update: (value, tr) => (tr.docChanged || tr.effects.some(e => e.is(locksChanged))) ? build(tr.state) : value,
        provide: f => EditorView.decorations.from(f),
    });

    // edits strictly inside a locked rule are refused; the formatter (whitespace only) may pass
    const guard = EditorState.transactionFilter.of(tr => {
        if (!tr.docChanged || tr.isUserEvent('format') || !editor._locks.size) return tr;
        const ranges = lockedRanges(tr.startState);
        if (!ranges.length) return tr;
        let blocked = null;
        tr.changes.iterChangedRanges((fromA, toA) => {
            for (const r of ranges) {
                const wholeRule = fromA <= r.from && toA >= r.to;
                const inside = fromA === toA ? fromA > r.from && fromA < r.to : fromA < r.to && toA > r.from;
                if (inside && !wholeRule) blocked = r;
            }
        });
        if (!blocked) return tr;
        const info = editor._locks.get(blocked.name);
        queueMicrotask(() => editor._toast(editor.t(info && info.canUnlock ? 'lockedUnlockFirst' : 'lockedNoRight', { name: blocked.name }), 'warning'));
        return [];
    });

    return [field, guard];
}

/** Highlights every occurrence of the $string / rule name under the cursor. */
function referenceHighlighter(editor) {
    const refMark = Decoration.mark({ class: 'rze-ref' });
    const defMark = Decoration.mark({ class: 'rze-ref-def' });
    return ViewPlugin.fromClass(class {
        constructor(view) { this.decorations = this.build(view); }
        update(u) { if (u.docChanged || u.selectionSet) this.decorations = this.build(u.view); }
        build(view) {
            const pack = editor.pack;
            const sel = view.state.selection.main;
            if (!pack.references || !sel.empty) return Decoration.none;
            let refs = null;
            try { refs = pack.references(editor._ctx(view.state, sel.head)); } catch { refs = null; }
            if (!refs || refs.ranges.length < 1) return Decoration.none;
            const sorted = refs.ranges.slice().sort((a, b) => a.from - b.from);
            const ranges = [];
            let last = -1;
            sorted.forEach((r, i) => {
                if (r.from < last || r.to <= r.from) return;
                ranges.push((i === 0 && refs.ranges[0] === r ? defMark : refMark).range(r.from, r.to));
                last = r.to;
            });
            return Decoration.set(ranges, true);
        }
    }, { decorations: v => v.decorations });
}

/** Strings of the rule that matched the test sample the user opened (Test panel). */
const testHitMarks = StateField.define({
    create: () => Decoration.none,
    update(value, tr) {
        value = value.map(tr.changes);
        for (const e of tr.effects) {
            if (!e.is(setTestMarks)) continue;
            const marks = e.value
                .filter(m => m.to > m.from)
                .sort((a, b) => a.from - b.from)
                .map(m => Decoration.mark({ class: m.active ? 'rze-test-mark rze-test-mark-active' : 'rze-test-mark' }).range(m.from, m.to));
            value = Decoration.set(marks, true);
        }
        return value;
    },
    provide: f => EditorView.decorations.from(f),
});

/** The rename box (F2), as an editor panel. */
function renamePanel(editor) {
    const field = StateField.define({
        create: () => null,
        update(value, tr) {
            for (const e of tr.effects) if (e.is(renameEffect)) value = e.value;
            return value;
        },
        provide: f => showPanel.from(f, value => value ? (view) => {
            const t = editor.t;
            const input = h('input', { class: 'cm-textfield rze-rename-input', value: value.name, 'aria-label': t('renameTo') });
            const close = () => view.dispatch({ effects: renameEffect.of(null) });
            const apply = () => {
                const res = editor.pack.rename(editor._ctx(view.state, value.pos), input.value.trim());
                if (res.error) { input.setCustomValidity(res.error); input.reportValidity(); return; }
                view.dispatch({ changes: res.changes, effects: renameEffect.of(null), userEvent: 'input.rename' });
                view.focus();
            };
            input.addEventListener('keydown', e => {
                if (e.key === 'Enter') { e.preventDefault(); apply(); }
                if (e.key === 'Escape') { e.preventDefault(); close(); view.focus(); }
            });
            input.addEventListener('input', () => input.setCustomValidity(''));
            const dom = h('div', { class: 'rze-rename' },
                h('label', { text: `${t('renameTo')} (${value.kind === 'string' ? '$' : 'rule '}${value.name})` }),
                input,
                h('button', { type: 'button', class: 'cm-button', onclick: apply }, t('rename')),
                h('button', { type: 'button', class: 'cm-button', onclick: () => { close(); view.focus(); } }, t('cancel')),
            );
            return { dom, top: true, mount: () => { input.focus(); input.select(); } };
        } : null),
    });
    return field;
}

const WRAP_KEY = 'rulezet-editor:wrap';
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// CodeMirror's search bar texts (English is built in)
const SEARCH_PHRASES = {
    fr: {
        'Find': 'Rechercher', 'Replace': 'Remplacer', 'next': 'suivant', 'previous': 'précédent', 'all': 'tout',
        'match case': 'respecter la casse', 'regexp': 'regex', 'by word': 'mot entier', 'replace': 'remplacer',
        'replace all': 'tout remplacer', 'close': 'fermer', 'current match': 'occurrence courante',
        'replaced $ matches': '$ occurrences remplacées', 'replaced match on line $': 'occurrence remplacée ligne $',
        'on line': 'ligne', 'Go to line': 'Aller à la ligne', 'go': 'aller',
    },
};

/** Fresh RFC 4122 v4 uuid, like Rulezet's uuid.uuid4(). */
export function uuid4() {
    const c = globalThis.crypto;
    if (c && typeof c.randomUUID === 'function') return c.randomUUID();
    const b = new Uint8Array(16);
    if (c && c.getRandomValues) c.getRandomValues(b);
    else for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Pack snippets may use {{uuid}} and {{date}}: filled in when the snippet is inserted. */
export function expandSnippetVars(snippet) {
    return snippet
        .replace(/\{\{uuid\}\}/g, () => uuid4())
        .replace(/\{\{date\}\}/g, () => new Date().toISOString().slice(0, 10));
}
