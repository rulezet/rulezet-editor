/**
 * Credits & licences of the editor itself (Markdown, rendered by ui/markdown.js). Each language
 * pack adds its own section (pack.credits) and the host page may add one (options.credits).
 * Keep it true: list what the editor really ships or uses, with its licence.
 */
export const CORE_CREDITS = `# rulezet-editor

A standalone, pluggable editor for detection rules, made at [CIRCL](https://www.circl.lu/) for the
[Rulezet](https://rulezet.org) project. Licence: **AGPL-3.0-only**.
Source: [github.com/rulezet/rulezet-editor](https://github.com/rulezet/rulezet-editor).

## Built with

| Project | Used for | Licence |
|---|---|---|
| [CodeMirror 6](https://codemirror.net/) (Marijn Haverbeke and contributors) | the editing engine: view, state, completion, lint, search, commands | MIT |
| [Lezer](https://lezer.codemirror.net/) highlight | syntax highlighting tags | MIT |
| [esbuild](https://esbuild.github.io/) | building the editor bundle (not shipped) | MIT |

## Funding

Rulezet is co-funded by CIRCL and by the European Union under the
[FETTA](https://www.circl.lu/pub/press/20240131/) project (Federated European Team for Threat Analysis).
`;
