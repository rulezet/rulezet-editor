# Templates ("New rule from template")

The **Templates** toolbar button (or the palette: "New rule from template…") opens a gallery of
complete rules to start from, grouped by category, with a filter, the description of the selected
template and its full text as a preview. **Insert** puts it at the end of the document; the
imports it needs are added at the top (once); Tab moves from one placeholder to the next.

Categories of the YARA pack (25 templates): Windows (PE malware, DLL with exports / imports, import
hash, packed / UPX with entropy, .NET, shellcode), Linux & other systems (ELF, Mach-O, Android DEX),
Documents (Office macro OLE, OOXML with VBA, PDF with JavaScript, RTF with an embedded object, LNK),
Scripts & web (PowerShell loader, VBS / JS dropper, PHP webshell, ASPX / JSP webshell), Families &
hunting (ransomware note, C2 configuration, hack tool, exploit of a CVE with `meta: cve`, hunting
rule, private helper rule, known file by hash).

Every template follows the [YARA Style Guide](https://neo23x0.github.io/YARA-Style-Guide):

| Part | Convention |
|---|---|
| Name | `CATEGORY_Platform_Family_Detail`: `MAL_`, `HKTL_`, `SUSP_`, `EXPL_`, `WEBSHELL_` |
| Meta | `description` (what and why), `author`, `date`, `reference`, `hash`, `score`, `id` |
| Strings | `$x*` specific (one is enough), `$s*` grouped (several needed), `$a*` file type, `$fp*` false-positive filters |
| Condition | cheap checks first (magic bytes, `filesize`), then strings, then modules |

## Contract

- Pack: `templates` = `TEMPLATES` of `src/languages/yara/templates.js`:
  `{ id, label, category, description, imports?, snippet }`.
- Core: `openTemplates()`, `insertTemplate(tpl)` (emits `template` with the id); gallery
  `src/ui/templates.js`.
- Adding a template: one entry in `TEMPLATES`; `npm test` checks it lints clean and compiles with
  libyara (`test/templates.test.js`, needs yara-python).

## Inside Rulezet

Nothing to wire: the YARA editor tab of the create and edit pages shows the button.

## Standalone

Same.
