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
- Runs are kept in Rulezet's database (`DbRunRegistry`, table `sample_test_run`,
  `app/features/rule_tester/sample_test_core.py`): every gunicorn worker and the job worker see
  the same runs, and they survive a restart.
- "Test on Create": the `samples` step of `editor_jobs` runs the whole document (rules needed from
  Rulezet included) on the sets chosen by the setting `editor.test_on_create` (`kinds`, benign by
  default). False positives are a warning (red step) unless `block_on_false_positives`; nothing is tested
  when every rule of the document is already in Rulezet. Each
  rule written keeps its own share of the run (`rule_sample_result`, per version = sha256 of its
  text): the rule page shows "N samples · X FP" while the text is unchanged.

- Who does what: **rulezet-tester** runs everything (drivers, bubblewrap sandbox, sample sets,
  run states, the lab VM); Rulezet only stores (registry, per-rule results), decides when to run
  (Test button, Create step) and shows the results. Nothing about execution lives in Rulezet.
- Rule page: badge "N samples · X FP" (current version) and a **Samples** tab
  (`/rule/detail_rule/<id>/samples`, `detail_rule_samples.html`, `css/rule/base/detail_rule_samples.css`,
  data from `sample_test_core.rule_sample_details`): verdict, counts, per-set table; "Strings of
  the rule" (sticky, collapsible) = the rule with, next to each string, what it matched in the
  opened sample, and per string the samples it matched / detections / false positives (a string
  that never matched says so); the samples (false positives first, filters, search, 25 per page,
  one open at a time) with every match grouped by string, offset, length and the bytes around it;
  the history of every test of the rule. Sample contents never leave the tester: hashes, labels,
  offsets and at most 64 bytes + 32 bytes of context per hit.

## Standalone

- `rulezet-editor serve` builds a `TestService` when rulezet-tester is installed
  (`pip install "rulezet-editor[test]"`), with the shipped sets plus `--samples DIR`;
  `--sandbox bwrap|process|off`.
- No rulezet-tester, or no bubblewrap: no Test button.

## Tests

- `server/tests/test_server.py` (`test_tests_are_mounted_from_rulezet_tester`, `test_no_tests_without_a_service`).
- rulezet-tester's own suite (`tests/test_runs.py`): sandbox, store, service, HTTP, CLI.
- Rulezet: `tests_new/editor/test_editor_tests.py` (login, privacy, refused rules).
