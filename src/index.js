/**
 * rulezet-editor public entry point.
 *   import { RulezetEditor, yara, RulezetHost } from 'rulezet-editor';
 * Importing this file registers every bundled language pack.
 */
import { RulezetEditor } from './core/RulezetEditor.js';
import { registerLanguage, getLanguage, listLanguages, detectLanguage, languageForFile } from './core/registry.js';
import { HostAdapter, LocalDraftHost, HttpHost } from './host/HostAdapter.js';
import { RulezetHost } from './host/RulezetHost.js';
import { EditorServerHost } from './host/EditorServerHost.js';
import { createVueComponent } from './wrappers/vue.js';
import { TOKEN_KINDS } from './core/tokens.js';
import yara from './languages/yara/index.js';
import plain from './languages/plain/index.js';

registerLanguage(yara);

export const version = '0.1.0';
export {
    RulezetEditor, registerLanguage, getLanguage, listLanguages, detectLanguage, languageForFile,
    HostAdapter, LocalDraftHost, HttpHost, RulezetHost, EditorServerHost, createVueComponent, TOKEN_KINDS, yara, plain,
};
export default RulezetEditor;
