# Tests on samples (Test panel)

A **Test** button in the toolbar opens a panel under the editor: tick sample sets, **Run the tests**
(Ctrl+Shift+Enter), and every sample turns live into *Clean*, *False positive*, *Detected*,
*Missed*, *Match*, *No match* or *Timeout*, with its hits (`$lic at 0x14`). A click on a hit selects
that string in the rule.

Opening a sample shows each match in its surroundings (32 bytes before and after, ASCII and hex,
the match highlighted) and highlights in the editor every string that matched that sample (the
clicked one darker). A search bar (sample name, sha256, `$string`, rule, outcome) and filters
(all / matches / false positives / missed / errors) keep large runs readable; each set shows 100
samples, then "Show more".

The runs themselves come from [rulezet-tester](https://github.com/rulezet/rulezet-tester): one
driver per format, a bubblewrap sandbox, sample sets in folders. The editor only shows them.

## Contract

- Server: `create_blueprint(backend, tests=TestService(...), test_owner=fn)` mounts the tester's
  blueprint on `/test` (`web.py`). Without `tests` there are no `/test` routes and
  `GET /` says `features.test: false`.
- Endpoints: `GET /editor-api/test/sets?format=` → `{ available, sets }`;
  `POST /editor-api/test/` `{ format, text, sets }` → `202` run; `GET /editor-api/test/<id>` → run.
  The run shape is the tester's (see its `docs/design.md` §3.1).
- Browser: `EditorServerHost.testSets()`, `startTest()`, `testState()`. The core shows the Test
  button when the pack has a `test` profile and the host has `startTest` (option `tests: false`
  hides it). Methods `toggleTests()`, `runTest()`, `getTestRun()`; event `test` on every update.
- Pack: `test: { sampleKind, hitLabel(hit), locate(model, hit) }` (YARA: `src/languages/yara/index.js`).
- The chosen sets are remembered per format in the browser (`localStorage`); the first time,
  every set is ticked.
- When the text changes after a run, the results stay but are marked as for an older version, and
  hits no longer move the cursor.

## Inside Rulezet

- `app/features/editor/editor_core.py` → `tests`: `TestService(FolderSampleStore(shipped sets +
  RULE_TESTS_SAMPLES folders), Sandbox(mode=RULE_TESTS_SANDBOX))`; `None` when off or when
  rulezet-tester is not installed.
- `app/features/editor/editor.py`: `create_blueprint(..., tests=EditorModel.tests,
  test_owner=current_user.id)`. Anonymous users get 401 (the blueprint's `before_request`); a run
  is visible only to the user who started it (admins included: it is that user's work in progress).
- Settings (`.env`): `RULE_TESTS_SANDBOX` = `bwrap` (default; needs `apt install bubblewrap`,
  otherwise the button does not show), `process` (development only) or `off`;
  `RULE_TESTS_SAMPLES` = extra folders, `:`-separated. A real benign set from the server's own
  files: `rulezet-tester benign-set /srv/rulezet/samples/benign-linux`, then
  `RULE_TESTS_SAMPLES=/srv/rulezet/samples`. **No real malware on the web server**:
  that waits for a sandbox on a separate machine (`Sandbox(command=...)`).
- Runs are kept in memory (one gunicorn worker): a worker restart drops runs in progress. A
  database registry comes with the Lab.
- Later: "test on Create" (the `samples` step of `editor_jobs`), results stored per rule version.

## Standalone

- `rulezet-editor serve` builds a `TestService` when rulezet-tester is installed
  (`pip install "rulezet-editor[test]"`), with the shipped sets plus `--samples DIR`;
  `--sandbox bwrap|process|off`.
- No rulezet-tester, or no bubblewrap: no Test button.

## Tests

- `server/tests/test_server.py` (`test_tests_are_mounted_from_rulezet_tester`, `test_no_tests_without_a_service`).
- rulezet-tester's own suite (`tests/test_runs.py`): sandbox, store, service, HTTP, CLI.
- Rulezet: `tests_new/editor/test_editor_tests.py` (login, privacy, refused rules).
