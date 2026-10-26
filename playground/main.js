import { RulezetEditor, RulezetHost, EditorServerHost, listLanguages } from '/dist/rulezet-editor.js';
import { SAMPLES } from '/playground/samples.js';

const $ = (id) => document.getElementById(id);
const settings = { sample: 'Several rules', language: 'yara', host: 'server', theme: 'auto', locale: 'en', readOnly: false };
let editor = null;

for (const name of Object.keys(SAMPLES)) $('pg-sample').append(new Option(name, name));
for (const p of listLanguages()) $('pg-lang').append(new Option(p.name, p.id));
$('pg-lang').value = settings.language;

function log(event, detail) {
    const li = document.createElement('li');
    li.innerHTML = `<time>${new Date().toLocaleTimeString()}</time> <b></b> <span></span>`;
    li.querySelector('b').textContent = event;
    li.querySelector('span').textContent = detail || '';
    const list = $('pg-events');
    list.prepend(li);
    while (list.children.length > 40) list.lastChild.remove();
}

function create(value) {
    if (editor) editor.destroy();
    editor = new RulezetEditor($('editor'), {
        value,
        language: settings.language,
        theme: settings.theme,
        locale: settings.locale,
        readOnly: settings.readOnly,
        host: { server: () => new EditorServerHost({ baseUrl: '/editor-api' }), rulezet: () => new RulezetHost({ baseUrl: '' }) }[settings.host]?.() || null,
        draftKey: 'playground',
    });
    editor.on('ready', () => log('ready', editor.getLanguage()));
    editor.on('diagnostics', d => log('diagnostics', `${d.filter(x => x.severity === 'error').length} errors, ${d.length} total`));
    editor.on('validated', r => log('validated', r.error ? `server error: ${r.error}` : `${r.items.length} server message(s)`));
    editor.on('format', r => log('format', `${r.formatted} formatted, ${r.skipped.length} skipped`));
    editor.on('save', v => log('save', `${v.length} chars (Ctrl+S)`));
    editor.on('language', l => log('language', l));
    editor.on('test', r => log('test', `${r.status}: ${r.summary.done}/${r.summary.total}, ${r.summary.false_positives} false positive(s)`));
    window.editor = editor;
}

$('pg-sample').addEventListener('change', e => { settings.sample = e.target.value; editor.setValue(SAMPLES[settings.sample]); });
$('pg-lang').addEventListener('change', e => { settings.language = e.target.value; editor.setLanguage(settings.language); });
$('pg-host').addEventListener('change', e => { settings.host = e.target.value; create(editor.getValue()); });
$('pg-theme').addEventListener('change', e => { settings.theme = e.target.value; editor.setTheme(settings.theme); document.documentElement.dataset.theme = settings.theme === 'auto' ? '' : settings.theme; });
$('pg-locale').addEventListener('change', e => { settings.locale = e.target.value; create(editor.getValue()); });
$('pg-readonly').addEventListener('change', e => { settings.readOnly = e.target.checked; editor.setReadOnly(settings.readOnly); });

document.querySelectorAll('[data-api]').forEach(btn => btn.addEventListener('click', () => {
    const name = btn.dataset.api;
    let out = editor[name]();
    if (name === 'getRules') out = out.map(({ text, children, ...r }) => ({ ...r, strings: (children || []).length }));
    if (name === 'getDiagnostics') out = out.map(({ actions, ...d }) => ({ ...d, fixes: (actions || []).map(a => a.name) }));
    $('pg-output').textContent = typeof out === 'string' ? out : JSON.stringify(out, null, 2) ?? String(out);
}));

create(SAMPLES[settings.sample]);
