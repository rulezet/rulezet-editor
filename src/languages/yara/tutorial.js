/**
 * "A complete example" chapter of the tutorial: a good YARA rule built step by step. Pure data:
 * each stage is the whole rule at that point (the editor puts it in the document, replacing the
 * previous stage), with what to learn from it.
 *
 * The final rule compiles with libyara, has no lint warning, and matches the inert sample
 * synthetic-pe/pe_downloader.exe shipped with rulezet-tester (so "Run the tests" shows a hit).
 */
const NAME = 'MAL_Win_Downloader_Example';

const META = `    meta:
        description = "Small Windows downloader that fetches a second stage over HTTP (tutorial example)"
        author = "Your Name"
        date = "2026-10-26"
        reference = "https://example.org/analysis-report"
        version = "1.0"
        tlp = "clear"
`;

const STRINGS = `    strings:
        $api_dl   = "URLDownloadToFileA" ascii
        $api_exec = "WinExec" ascii
        $ua       = "Mozilla/4.0 (compatible; MSIE 6.0; Win32)" ascii wide
        $url      = /https?:\\/\\/[a-z0-9.\\-]{4,64}\\/[a-z0-9_\\/\\-]{1,64}\\.(bin|dat)/ nocase ascii wide
        $hex_url  = { 68 74 74 70 3A 2F 2F [4-48] 2E 62 69 6E }
`;

const CONDITION = `    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and pe.imports("urlmon.dll", "URLDownloadToFileA")
        and 2 of ($api_*, $ua)
        and ($url or $hex_url)
`;

const rule = (body, imports = false) => `${imports ? 'import "pe"\n\n' : ''}rule ${NAME}\n{\n${body}}\n`;

export const TUTORIAL = {
    title: 'A complete example',
    rule: NAME,
    stages: [
        {
            title: 'Example 1/6 — what we want to detect',
            body: 'Goal: a small Windows downloader. It imports URLDownloadToFileA, starts what it downloaded with WinExec, and fetches a ".bin" or ".dat" over HTTP.\n\nStart with a clear name: `CATEGORY_Platform_Family_Detail` (MAL_ for malware, SUSP_ for suspicious, HKTL_ for hack tools). Letters, digits and `_` only. A rule that only says `condition: true` matches everything: never publish it.',
            text: rule('    condition:\n        true\n'),
        },
        {
            title: 'Example 2/6 — meta: describe the rule',
            body: 'The `meta:` section is for people and for Rulezet: `description` (what and why), `author`, `date` (YYYY-MM-DD), `reference` (the report or sample), `version`, `tlp`. Rulezet reads them into the rule\'s fields (title, description, author, version…): fill them here or in the Fields panel.\n\nA good description says what the rule catches, not how ("Downloader fetching a second stage", not "matches 3 strings").',
            text: rule(META + '    condition:\n        true\n'),
        },
        {
            title: 'Example 3/6 — strings: what is unique',
            body: 'Pick strings that are specific to the threat and long enough (4+ distinctive bytes): API names, a user agent, a URL pattern. Avoid common words ("http", "error", "kernel32"): they make the rule slow and noisy.\n\nModifiers say how to search: `ascii wide` for both encodings, `nocase` only when the case really varies. A hex string with a bounded jump `[4-48]` matches "http://" followed by up to 48 bytes then ".bin". A regex should always be bounded (`{4,64}`, never `.*`).',
            text: rule(META + STRINGS + '    condition:\n        any of them\n'),
        },
        {
            title: 'Example 4/6 — condition: cheap checks first',
            body: 'Put the cheapest tests first so YARA can stop early: the file type (`uint16(0) == 0x5A4D` = "MZ", a Windows executable), then `filesize`, then the module check, then the strings.\n\nAvoid `any of them` on its own: one common string would be enough to fire. Here `2 of ($api_*, $ua)` needs two of the three behaviours, and `($url or $hex_url)` needs the download target. `pe.imports(…)` uses the pe module: its `import "pe"` goes at the top of the file.',
            text: rule(META + STRINGS + CONDITION, true),
        },
        {
            title: 'Example 5/6 — check it',
            body: 'No underline and 0 errors in the status bar: the rule is valid for the editor. When the host checks it too (status bar, Ctrl+Enter), the real compiler agrees.\n\nHover `pe.imports` or `$hex_url` to read what they do; F12 on `$api_dl` in the condition jumps to its definition; Format (Shift+Alt+F) keeps the layout clean.',
            text: rule(META + STRINGS + CONDITION, true),
        },
        {
            title: 'Example 6/6 — test it, then publish',
            body: 'Before publishing, test: the rule should catch what it targets and nothing else. With a Test panel, run it: in "Synthetic — Windows PE" it matches pe_downloader.exe (the inert downloader sample), and it must stay "Clean" on every benign set (a false positive means the rule is too broad: add a stronger string or a tighter condition).\n\nThen fill the remaining fields (tags, ATT&CK T1105 "Ingress Tool Transfer", vulnerabilities) and create the rule. Keep the example? Rename it first: `MAL_Win_Downloader_Example` is only a sample.',
            text: rule(META + STRINGS + CONDITION, true),
        },
    ],
};
