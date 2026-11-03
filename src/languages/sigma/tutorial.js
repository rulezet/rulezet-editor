/**
 * "A complete example" chapter of the tutorial for Sigma: a good rule built step by step. Each
 * stage is the whole rule at that point; the final one is accepted by Rulezet's validation
 * (JSON schema + pySigma) with no lint warning.
 */
const TITLE = 'Certutil Used To Download A File';

const HEAD = `title: ${TITLE}
id: 6f0b2b8a-0f0e-4c63-9a5c-3d6b1c2e4f10
status: experimental
description: Certutil, a Windows certificate tool, downloading a file from the Internet (a "living off the land" download, tutorial example)
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
author: Your Name
date: 2026-11-03
tags:
    - attack.command-and-control
    - attack.t1105
`;

const LOGSOURCE = `logsource:
    category: process_creation
    product: windows
`;

const SELECTION = `detection:
    selection_img:
        - Image|endswith: '\\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_cli:
        CommandLine|contains:
            - 'urlcache'
            - 'verifyctl'
`;

const FILTER = `    filter_optional_localhost:
        CommandLine|contains: 'http://127.0.0.1'
`;

const TAIL = `falsepositives:
    - Administrators downloading certificates with certutil
level: high
`;

export const TUTORIAL = {
    title: 'A complete example',
    rule: TITLE,
    stages: [
        {
            title: 'Example 1/6 — what we want to detect',
            body: 'Goal: certutil.exe, a legitimate Windows tool, used to download a payload (`certutil -urlcache -f http://… payload.exe`). Attackers like it because it is signed and always there.\n\nA Sigma rule is YAML: one `key: value` per line, indentation with spaces. It starts with a `title` that says what is detected, and an `id` (a UUID) so the rule is recognised when it is updated.',
            text: `title: ${TITLE}\nid: 6f0b2b8a-0f0e-4c63-9a5c-3d6b1c2e4f10\n`,
        },
        {
            title: 'Example 2/6 — describe it',
            body: '`status` (experimental for a new rule), `description` (what and why), `references`, `author`, `date` (YYYY-MM-DD) and `tags`. Tags are namespaced and lower case: `attack.t1105` is the ATT&CK technique "Ingress Tool Transfer", `attack.command-and-control` its tactic. Rulezet reads them into the rule\'s fields (ATT&CK, vulnerabilities…).',
            text: HEAD,
        },
        {
            title: 'Example 3/6 — logsource: which logs',
            body: '`logsource` says where the events come from. Prefer a generic `category` (`process_creation`: every new process, whatever the tool that logs it — Sysmon EventID 1, Security 4688…) with the `product` (`windows`). Rulezet refuses `service: sysmon` + `EventID: 1` because the category exists.',
            text: HEAD + LOGSOURCE,
        },
        {
            title: 'Example 4/6 — detection: what to look for',
            body: 'Each key under `detection` is a search identifier. Inside one, every field must match (AND); a list of values means any of them (OR). `selection_img` is a list of two mappings: the image name OR the original file name (renamed copies). Modifiers change how a value matches: `|endswith`, `|contains`, `|all`.\n\nThe `condition` combines them: `all of selection_*` = every identifier starting with selection_. Hover a modifier to read what it does.',
            text: HEAD + LOGSOURCE + SELECTION + '    condition: all of selection_*\n',
        },
        {
            title: 'Example 5/6 — exclude the benign',
            body: 'A filter removes known benign activity: `filter_optional_localhost` (a download from the machine itself). The condition becomes `all of selection_* and not 1 of filter_optional_*`. Every search identifier must be used in the condition: Rulezet refuses one that is not (the lint underlines it and offers to add it).',
            text: HEAD + LOGSOURCE + SELECTION + FILTER + '    condition: all of selection_* and not 1 of filter_optional_*\n',
        },
        {
            title: 'Example 6/6 — level, then publish',
            body: '`falsepositives` tells analysts when a hit may be benign; `level` how urgent it is (`high`: review quickly). No underline and 0 errors: the rule is valid for the editor, and the server check (status bar, Ctrl+Enter) runs Rulezet\'s own validation (schema + pySigma).\n\nThen fill the remaining fields and create the rule. Keep the example? Give it your own title and a new id first (Rule tools, Ctrl+Shift+R).',
            text: HEAD + LOGSOURCE + SELECTION + FILTER + '    condition: all of selection_* and not 1 of filter_optional_*\n' + TAIL,
        },
    ],
};
