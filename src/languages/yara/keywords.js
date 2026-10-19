/** YARA vocabulary with short docs (hover + completion). */

export const RULE_KEYWORDS = {
    rule: 'Starts a rule: `rule name : tags { meta: strings: condition: }`.',
    private: 'Private rule: can be used by other rules but never reported as a match.',
    global: 'Global rule: every other rule in the file only matches if this one matches.',
    import: 'Loads a module: `import "pe"`.',
    include: 'Includes another rule file: `include "other.yar"`.',
};

export const SECTIONS = {
    meta: 'Free metadata: `key = "string" | number | true/false`. Not used for matching.',
    strings: 'Patterns to look for: text `"..."`, hex `{ ... }` or regex `/.../`.',
    condition: 'Boolean expression deciding if the rule matches. Required.',
};

export const CONDITION_KEYWORDS = {
    and: 'Logical AND.',
    or: 'Logical OR.',
    not: 'Logical NOT.',
    all: '`all of (...)`: every string of the set must match.',
    any: '`any of (...)`: at least one string of the set must match.',
    none: '`none of (...)`: no string of the set may match.',
    of: '`N of ($a, $b, ...)` or `N of them`.',
    them: 'All the strings of the rule.',
    for: '`for any i in (1..#a) : ( @a[i] < 100 )` / `for all of them : ( # > 2 )`.',
    in: '`$a in (0..100)`: string found inside the offset range.',
    at: '`$a at 0`: string found at this exact offset.',
    filesize: 'Size of the scanned file, in bytes. Use with KB / MB: `filesize < 2MB`.',
    entrypoint: 'Deprecated: use `pe.entry_point` or `elf.entry_point`.',
    true: 'Boolean true.',
    false: 'Boolean false.',
    contains: '`string contains "x"`: substring test, case sensitive.',
    icontains: 'Case-insensitive `contains`.',
    startswith: 'Prefix test, case sensitive.',
    istartswith: 'Case-insensitive `startswith`.',
    endswith: 'Suffix test, case sensitive.',
    iendswith: 'Case-insensitive `endswith`.',
    iequals: 'Case-insensitive equality.',
    matches: '`string matches /regex/`.',
    defined: '`defined expr`: true if the expression is not undefined.',
    int8: 'Signed 8-bit integer at an offset: `int8(0)`.',
    int16: 'Signed 16-bit little-endian integer at an offset.',
    int32: 'Signed 32-bit little-endian integer at an offset.',
    uint8: 'Unsigned 8-bit integer at an offset: `uint8(0) == 0x4D`.',
    uint16: 'Unsigned 16-bit little-endian integer: `uint16(0) == 0x5A4D` (MZ).',
    uint32: 'Unsigned 32-bit little-endian integer: `uint32(uint32(0x3C)) == 0x00004550` (PE).',
    int8be: 'Signed 8-bit big-endian integer.',
    int16be: 'Signed 16-bit big-endian integer.',
    int32be: 'Signed 32-bit big-endian integer.',
    uint8be: 'Unsigned 8-bit big-endian integer.',
    uint16be: 'Unsigned 16-bit big-endian integer.',
    uint32be: 'Unsigned 32-bit big-endian integer.',
};

/** Modifiers, with the string kinds they apply to. */
export const MODIFIERS = {
    nocase: { kinds: ['text', 'regex'], doc: 'Case-insensitive match.' },
    wide: { kinds: ['text', 'regex'], doc: 'UTF-16LE (two bytes per char). Add `ascii` to also match the plain form.' },
    ascii: { kinds: ['text', 'regex'], doc: 'Plain one-byte form (default; useful together with `wide`).' },
    fullword: { kinds: ['text', 'regex'], doc: 'Only match when delimited by non-alphanumeric characters.' },
    private: { kinds: ['text', 'hex', 'regex'], doc: 'Matches are not reported in the output.' },
    xor: { kinds: ['text'], doc: 'Single-byte XOR with every key, or `xor(0x01-0xff)`.' },
    base64: { kinds: ['text'], doc: 'Match the base64 forms of the string. Optional custom alphabet: `base64("...")`.' },
    base64wide: { kinds: ['text'], doc: 'Like `base64`, then UTF-16LE.' },
};

/** Pairs YARA refuses on the same string. */
export const MODIFIER_CONFLICTS = [
    ['nocase', 'xor'], ['nocase', 'base64'], ['nocase', 'base64wide'],
    ['xor', 'base64'], ['xor', 'base64wide'],
    ['fullword', 'base64'], ['fullword', 'base64wide'],
];

/** Usual meta keys, offered in the meta section. */
export const META_KEYS = {
    author: 'Who wrote the rule.',
    description: 'What the rule detects.',
    date: 'Creation date, YYYY-MM-DD.',
    modified: 'Last change, YYYY-MM-DD.',
    reference: 'Link to the report / sample source.',
    hash: 'Hash of a sample the rule matches.',
    version: 'Rule version.',
    id: 'Stable identifier (UUID).',
    license: 'Licence of the rule (e.g. Detection Rule License 1.1).',
    tlp: 'Traffic Light Protocol level.',
    score: 'Confidence / severity score.',
    malware_family: 'Detected family.',
    mitre_attack: 'ATT&CK technique id, e.g. T1059.',
};

export const RESERVED = new Set([
    ...Object.keys(RULE_KEYWORDS), ...Object.keys(SECTIONS), ...Object.keys(CONDITION_KEYWORDS),
    ...Object.keys(MODIFIERS),
]);
