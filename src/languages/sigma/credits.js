/** Credits of the Sigma language pack (Markdown, shown in the editor's Credits & licences page). */
export const CREDITS = `# Sigma

## The language

| Project | Used for | Licence |
|---|---|---|
| [Sigma specification](https://github.com/SigmaHQ/sigma-specification) by SigmaHQ (Florian Roth, Thomas Patzke and contributors) | the rule format; the help shown on hover and in completion (keys, modifiers, condition, tags, log sources) is written after it | Detection Rule License (DRL) 1.1 / see the repository |
| [pySigma](https://github.com/SigmaHQ/pySigma) by Thomas Patzke and contributors | the validation the lint follows (modifiers, conditions, HIGH checks), and server-side validation of \`rulezet-editor serve\` when installed | LGPL-2.1 |
| [SigmaHQ rules](https://github.com/SigmaHQ/sigma) | naming conventions (selection_*, filter_main_*, filter_optional_*) and the common field names offered by completion | DRL 1.1 |

## Templates

The rule templates ("New rule from template") follow the SigmaHQ conventions (title, status, filters,
\`all of selection_* and not 1 of filter_*\`). They are written for this editor; no SigmaHQ rule is copied.

## YAML

The editor reads Sigma rules with its own small YAML reader (positions of every key and value); it
is checked against PyYAML on real rules.
`;
