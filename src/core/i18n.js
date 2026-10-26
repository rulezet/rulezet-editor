/** UI strings. Add a locale by adding a key; missing entries fall back to English. */
const STRINGS = {
    en: {
        undo: 'Undo', redo: 'Redo', tutorial: 'Tutorial', tutorialHint: 'A guided tour of every feature, with examples',
        tourNext: 'Next', tourBack: 'Back', tourDone: 'Done', tourClose: 'Close the tour', pasted: 'pasted', lockRule: 'Lock', lockRuleHint: 'Lock this rule: its text can no longer be changed (until you unlock it)',
        unlockRule: 'Unlock this rule', lockedByYou: 'you', lockedManual: 'Locked by you — its text is kept as is', unlockManualHint: 'Edit this rule again',
        lockedPasted: 'Pasted rule: locked — fill its fields on the right, its text stays as pasted',
        unlockPastedHint: 'Edit the rule text itself (and let the Fields panel write into it)', format: 'Format', outline: 'Rules', problems: 'Problems', palette: 'Commands', theme: 'Theme',
        fullscreen: 'Full screen', wrap: 'Wrap lines', search: 'Search', ruleTools: 'Rule tools', noRuleHere: 'Put the cursor inside a rule', nothingToDo: 'Nothing to change', noProblems: 'No problems', rules: 'rules', rule: 'rule',
        line: 'Ln', col: 'Col', filterRules: 'Filter rules', filterCommands: 'Type a command',
        noRules: 'No rule in this document', renameTo: 'Rename to', rename: 'Rename', cancel: 'Cancel',
        draftFound: 'An unsaved draft from {time} was found.', restore: 'Restore', discard: 'Discard',
        serverOff: 'offline', serverChecking: 'checking', serverOk: 'checked', serverError: 'unreachable',
        formatted: 'Formatted {n} rule(s)', formatSkipped: '{n} rule(s) with errors left as is',
        copy: 'Copy', copied: 'Copied', select: 'Select', goTo: 'Go to', insertFromHost: 'Insert "{name}" from {host}', lockedFrom: 'Rule from {host}: locked', unlock: 'Unlock to edit', unlockHint: 'Edit this rule here: creating will update it on the host', lockedReadOnly: 'Read-only: you may not edit this rule', lockedUnlockFirst: '"{name}" is locked: unlock it to edit', lockedNoRight: '"{name}" is read-only: you may not edit it', open: 'Open',
        foundOnHost: '"{name}" exists on {host}', notFoundOnHost: '"{name}" was not found on {host} either',
        openOnHost: 'Open on {host}', errors: 'errors', warnings: 'warnings', infos: 'infos', readOnly: 'read only',
        nothingToRename: 'Nothing to rename here', dependencies: 'Needs',
        tests: 'Test', tRun: 'Run the tests', tRunning: 'Running…', tLoading: 'Loading the sample sets…', tSets: 'Sample sets',
        tNoSets: 'No sample set for this format', tUnavailable: 'Tests are not available on {host}', tChooseSet: 'Choose at least one sample set',
        tNothing: 'Nothing to test', tStale: 'The rules changed since this run: run the tests again',
        tDetected: 'Detected', tClean: 'Clean', tMissed: 'Missed', tFalsePositive: 'False positive', tMatched: 'Match', tNotMatched: 'No match',
        tTimeout: 'Timeout', tError: 'Error', tFalsePositives: 'false positives', tFalsePositiveOne: 'false positive', tMissedPlural: 'missed', tDetectedPlural: 'detected', tTimeouts: 'timeouts',
        tBenign: 'benign', tMalicious: 'malicious', tSynthetic: 'synthetic', tPending: 'Pending',
        tShowInRule: 'Show in the rule', tSize: 'Size', tHits: 'Matches', tHitsShown: '{shown} shown of {total}', tExpected: 'Expected',
        tExpectMatch: 'should match', tExpectNoMatch: 'should not match', tCondition: 'condition', tHitOne: 'match', tHitMany: 'matches',
        tWhere: 'Offset', tLength: 'Length', tBytes: 'Matched bytes', tInContext: 'Match in its surroundings',
        tSearch: 'Search a sample, a sha256, a string ($a), an outcome…', tAll: 'All', tWithMatches: 'Matches', tProblems: 'Errors / timeouts',
        tErrors: 'errors', tShown: '{n} shown', tShowMore: 'Show {n} more ({total} left)', tNoResult: 'No sample matches the search',
        tHighlightLegend: 'strings that matched this sample are highlighted in the rule', tConditionOnly: 'Matched by its condition alone (no string)',
        tFpHint: 'Benign samples the rules matched: they should not', tMissedHint: 'Malicious samples the rules should catch and did not',
        tDetectedHint: 'Malicious samples caught',
        fields: 'Fields', fieldsHint: 'Fields of the rule (title, CVE, tags…), written into the rule or not',
        fLoading: 'Loading the fields…', fUnderCursor: 'Rule under the cursor', fConflicts: '{n} to decide',
        fLocked: 'This rule is locked: its fields can be read, not written into it.',
        fSynced: 'in the rule', fNamed: 'the rule name', fRenamed: 'differs from the rule name', fSame: 'same as the rule', fKept: 'differs on purpose', fConflict: 'differs from the rule',
        fHostOnly: 'not in the rule', fFromRule: 'in the rule only', fReport: 'Write into the rule as', fHostField: 'Stored outside the rule',
        fReportHint: 'Checked: the value is written into the rule ({key}). Unchecked: it is only stored with the rule, the rule text is left untouched (keeps automatic updates, e.g. from GitHub).',
        fRuleSays: 'The rule says', fUseRule: "Use the rule's value", fWriteMine: 'Write mine into the rule', fKeepDifferent: 'Keep different',
        fKeepHint: 'Keep different: the rule text is not changed (automatic updates, e.g. from GitHub, keep working) and this value is stored apart.',
        fReconsider: 'reconsider', fAdd: 'Add…', fInvalidItem: 'Not a valid value for this field',
        fSearchOption: 'Search or type…', fUseTyped: 'Use', fNotInList: 'Not in the list: kept as typed', fNoMatch: 'Nothing matches', fFormat: 'Format', fMaxReached: 'At most {n}', fBrowse: 'Browse',
        fMe: 'Me', fMeHint: 'Fill with your name: {name}', fKind: 'Relation',
        fBody: 'Strings & condition', fBodyHint: 'written into the rule as you edit', fStrings: 'Strings', fCondition: 'Condition',
        fAddString: 'Add a string', fWhen: 'when', fRemoveClause: 'Remove this clause', fAlwaysTrue: 'always true',
        fAddWith: 'Add a clause with', fAddFirst: 'Add a clause', fClausePlaceholder: 'type a clause, Enter (or pick one below)',
        fAddClause: 'Add: {text}', fRemoveString: 'Remove this string', fAndString: 'Add "and {id}" to the condition',
        fKind_text: 'Text', fKind_hex: 'Hex', fKind_regex: 'Regex',
        fDraft: 'No rule yet: fill the fields, the rule is written in the editor as you go (the title names it).', fValid: '✓ Format correct', fInvalidFor: '✗ Invalid format for {what}', fMore: 'Load more',
    },
    fr: {
        format: 'Formater', outline: 'Règles', problems: 'Problèmes', palette: 'Commandes', theme: 'Thème',
        fullscreen: 'Plein écran', wrap: 'Retour à la ligne', search: 'Rechercher', ruleTools: 'Outils de règle', noRuleHere: 'Placez le curseur dans une règle', nothingToDo: 'Rien à modifier', noProblems: 'Aucun problème', rules: 'règles', rule: 'règle',
        line: 'Ln', col: 'Col', filterRules: 'Filtrer les règles', filterCommands: 'Tapez une commande',
        noRules: 'Aucune règle dans ce document', renameTo: 'Renommer en', rename: 'Renommer', cancel: 'Annuler',
        draftFound: 'Un brouillon non enregistré du {time} a été trouvé.', restore: 'Restaurer', discard: 'Ignorer',
        serverOff: 'hors ligne', serverChecking: 'vérification', serverOk: 'vérifié', serverError: 'injoignable',
        formatted: '{n} règle(s) formatée(s)', formatSkipped: '{n} règle(s) en erreur laissée(s) telle(s) quelle(s)',
        copy: 'Copier', copied: 'Copié', select: 'Sélectionner', goTo: 'Aller à', insertFromHost: 'Insérer « {name} » depuis {host}', lockedFrom: 'Règle de {host} : verrouillée', unlock: 'Déverrouiller', unlockHint: 'Modifier cette règle ici : la création la mettra à jour', lockedReadOnly: 'Lecture seule : vous ne pouvez pas modifier cette règle', lockedUnlockFirst: '« {name} » est verrouillée : déverrouillez-la pour la modifier', lockedNoRight: '« {name} » est en lecture seule : vous ne pouvez pas la modifier', open: 'Ouvrir',
        foundOnHost: '« {name} » existe sur {host}', notFoundOnHost: '« {name} » est introuvable sur {host} aussi',
        openOnHost: 'Ouvrir sur {host}', errors: 'erreurs', warnings: 'avertissements', infos: 'infos', readOnly: 'lecture seule',
        nothingToRename: 'Rien à renommer ici', dependencies: 'Dépend de',
    },
};

export function translator(locale) {
    const table = STRINGS[locale] || STRINGS.en;
    return (key, vars = {}) => {
        let s = table[key] ?? STRINGS.en[key] ?? key;
        for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, v);
        return s;
    };
}

export const LOCALES = Object.keys(STRINGS);
