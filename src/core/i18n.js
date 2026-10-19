/** UI strings. Add a locale by adding a key; missing entries fall back to English. */
const STRINGS = {
    en: {
        format: 'Format', outline: 'Rules', problems: 'Problems', palette: 'Commands', theme: 'Theme',
        fullscreen: 'Full screen', wrap: 'Wrap lines', search: 'Search', ruleTools: 'Rule tools', noRuleHere: 'Put the cursor inside a rule', nothingToDo: 'Nothing to change', noProblems: 'No problems', rules: 'rules', rule: 'rule',
        line: 'Ln', col: 'Col', filterRules: 'Filter rules', filterCommands: 'Type a command',
        noRules: 'No rule in this document', renameTo: 'Rename to', rename: 'Rename', cancel: 'Cancel',
        draftFound: 'An unsaved draft from {time} was found.', restore: 'Restore', discard: 'Discard',
        serverOff: 'offline', serverChecking: 'checking', serverOk: 'checked', serverError: 'unreachable',
        formatted: 'Formatted {n} rule(s)', formatSkipped: '{n} rule(s) with errors left as is',
        copy: 'Copy', copied: 'Copied', select: 'Select', goTo: 'Go to', insertFromHost: 'Insert "{name}" from {host}',
        foundOnHost: '"{name}" exists on {host}', notFoundOnHost: '"{name}" was not found on {host} either',
        openOnHost: 'Open on {host}', errors: 'errors', warnings: 'warnings', infos: 'infos', readOnly: 'read only',
        nothingToRename: 'Nothing to rename here', dependencies: 'Needs',
    },
    fr: {
        format: 'Formater', outline: 'Règles', problems: 'Problèmes', palette: 'Commandes', theme: 'Thème',
        fullscreen: 'Plein écran', wrap: 'Retour à la ligne', search: 'Rechercher', ruleTools: 'Outils de règle', noRuleHere: 'Placez le curseur dans une règle', nothingToDo: 'Rien à modifier', noProblems: 'Aucun problème', rules: 'règles', rule: 'règle',
        line: 'Ln', col: 'Col', filterRules: 'Filtrer les règles', filterCommands: 'Tapez une commande',
        noRules: 'Aucune règle dans ce document', renameTo: 'Renommer en', rename: 'Renommer', cancel: 'Annuler',
        draftFound: 'Un brouillon non enregistré du {time} a été trouvé.', restore: 'Restaurer', discard: 'Ignorer',
        serverOff: 'hors ligne', serverChecking: 'vérification', serverOk: 'vérifié', serverError: 'injoignable',
        formatted: '{n} règle(s) formatée(s)', formatSkipped: '{n} règle(s) en erreur laissée(s) telle(s) quelle(s)',
        copy: 'Copier', copied: 'Copié', select: 'Sélectionner', goTo: 'Aller à', insertFromHost: 'Insérer « {name} » depuis {host}',
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
