// Inserting a template keeps every default value: the text in the document is the preview's
// (score = 70, #s > 3…), fields are numbered in reading order. Runs CodeMirror's own snippet
// code on an EditorState (no DOM needed).
import test from 'node:test';
import assert from 'node:assert/strict';
import { EditorState } from '@codemirror/state';
import { snippet } from '@codemirror/autocomplete';
import { TEMPLATES } from '../src/languages/yara/templates.js';
import { numberSnippetFields, preview } from '../src/ui/templates.js';

function insert(text) {
    const editor = { state: EditorState.create({ doc: '' }), dispatch(tr) { this.state = tr.state; } };
    snippet(text)(editor, null, 0, 0);
    return editor.state.doc.toString();
}

const fixed = (s) => s.replace(/\{\{uuid\}\}/g, 'U').replace(/\{\{date\}\}/g, 'D');

test('every template is inserted with its default values', () => {
    for (const tpl of TEMPLATES) {
        const body = fixed(tpl.snippet);
        assert.equal(insert(numberSnippetFields(body)), preview(body), tpl.id);
    }
});

test('bare numbers keep their value', () => {
    assert.equal(insert(numberSnippetFields('score = ${70}, n > ${3}')), 'score = 70, n > 3');
    assert.equal(numberSnippetFields('${a} ${70} ${a}'), '${1:a} ${2:70} ${3:a}');
});
