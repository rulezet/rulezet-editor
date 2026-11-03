// Writes the pack's own texts (sample, templates as inserted, tutorial stages, Fields skeleton) for
// build.py: they must be accepted by Rulezet as they are.   node scripts/sigma-oracle/export.mjs
import { writeFileSync } from 'node:fs';
import { EditorState } from '@codemirror/state';
import { snippet } from '@codemirror/autocomplete';
import sigma from '../../src/languages/sigma/index.js';
import { numberSnippetFields } from '../../src/ui/templates.js';

const fill = (s) => s.replace(/\{\{uuid\}\}/g, '929a690e-bef0-4204-a928-ef5e620d6fcc').replace(/\{\{date\}\}/g, '2026-11-03');
function insert(text) {
    const editor = { state: EditorState.create({ doc: '' }), dispatch(tr) { this.state = tr.state; } };
    snippet(numberSnippetFields(fill(text)))(editor, null, 0, 0);
    return editor.state.doc.toString();
}
const out = [
    { name: 'sample', text: sigma.sample, expect: true },
    { name: 'skeleton', text: fill(sigma.meta.skeleton('My new rule')), expect: true },
    ...sigma.templates.map(t => ({ name: `template ${t.id}`, text: insert(t.snippet), expect: true })),
    ...sigma.snippets.map(s => ({ name: `snippet ${s.label}`, text: insert(s.snippet), expect: true })),
    ...sigma.tutorial.stages.slice(2).filter((_, i, a) => i >= 1).map((s, i) => ({ name: `tutorial ${i + 4}`, text: s.text, expect: true })),
];
writeFileSync(new URL('./generated.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`${out.length} texts`);
