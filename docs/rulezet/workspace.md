# Editor workspace and bundles

`/editor`: the editor as a full page. Folders and files on the left, tabs, one editor; create
the rules, create a bundle with the same folders and files, or open a bundle, edit it and save it.

## Contract

- Core: several documents in one editor (`openDocument`, `getDocumentText`, `getRulesOf`,
  per-document locks and `setAnnotations(..., { document })`).
- Job: `POST /editor-api/yara/jobs` with, besides `rules` (each with `path` and its file's
  `imports`):
  - `bundle`: `{ mode: 'create', name, description, public }` or `{ mode: 'update', bundle_id }`
  - `tree`: the explorer: `{type:'folder', name, children}`, `{type:'file', name:'x.yar', rules:[names]}`,
    `{type:'file', name:'README.md', content}`.
  An extra step "Bundle" runs after the rules are written; the job state has `bundle: { id, name, url, mode }`.
- `GET /editor-api/bundles/<id>`: a bundle as a workspace (`can_view_bundle`): folders, rule files
  (`content`, `rule: { id, name, can_edit, url }`), text files; `bundle.can_edit`.

## Inside Rulezet

- `app/features/editor/editor_bundle.py`: tree <-> bundle structure, `write_bundle`
  (`create_bundle`, `validate_structure`, `update_bundle_from_structure`, `save_workspace` inside
  `track_bundle_change`), `workspace_from_bundle`.
- Mapping: a YARA file with one rule -> a rule node; with several -> a folder named after the
  file, one rule node per rule; any other file -> a custom file node.
- Rights: create a bundle = any logged-in user, name unique per user (`bundle_name_taken`), checked
  before the job; update = owner or admin (checked before the job and again when writing); open =
  `can_view_bundle` (private bundles: 404). Rules follow the rules of the YARA editor (update when
  the user may edit, proposal otherwise); a bundle's rule the user may not edit opens locked.
- Page: `app/templates/editor/workspace.html`, `app/static/js/editor/EditorWorkspace.js` (explorer =
  `TreeItem` exported by `static/js/bundle/BundleStructureEditor.js`), `static/css/editor/workspace.css`.
- Entry points: "Open in editor" on the bundle page; "Open the full editor" in the create page's tab.
- Draft: browser storage, `rulezet-editor-workspace` (or `-bundle-<id>`).

## Standalone

Not yet (Rulezet page).

## Tests

`tests_new/editor/test_editor_bundle.py`.
