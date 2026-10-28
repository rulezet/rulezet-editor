/** Credits of the YARA language pack (Markdown, shown in the editor's Credits & licences page). */
export const CREDITS = `# YARA

## The language

| Project | Used for | Licence |
|---|---|---|
| [YARA](https://virustotal.github.io/yara/) by VirusTotal (Victor M. Alvarez and contributors) | the language itself; the module structure (fields, types, functions) is generated from libyara 4.5.4; the lint is checked against libyara's verdicts | BSD-3-Clause |
| [YARA documentation](https://yara.readthedocs.io/) | the help shown on hover and in completion is written after it | BSD-3-Clause |
| [yara-python](https://github.com/VirusTotal/yara-python) | server-side validation of \`rulezet-editor serve\`, and the template tests | Apache-2.0 |

## Templates and good practice

The rule templates ("New rule from template") follow the conventions of the
[YARA Style Guide](https://neo23x0.github.io/YARA-Style-Guide) by Florian Roth (Neo23x0): rule
names (MAL_, HKTL_, SUSP_…), meta fields, string prefixes ($x, $s, $a, $fp) and cheap checks first.
The templates are written for this editor; no rule of the guide is copied.

## Try panel

The strings and conditions of the Try panel are evaluated by the editor's own code, in the browser,
following YARA's documented semantics; regular expressions run with the browser's JavaScript engine.
It is a reading aid: the reference remains libyara (the Test panel runs it).
`;
