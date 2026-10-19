/**
 * Token kinds a language pack's tokenizer may return, mapped to highlight tags.
 * Packs only use these names, never engine types.
 */
import { tags as t, Tag } from '@lezer/highlight';

export const hexTag = Tag.define();
export const hexJumpTag = Tag.define();
export const hexWildcardTag = Tag.define();
export const sectionTag = Tag.define();

export const TOKEN_TAGS = {
    keyword: t.keyword,
    section: sectionTag,
    string: t.string,
    regexp: t.regexp,
    escape: t.escape,
    number: t.number,
    atom: t.bool,
    comment: t.comment,
    variable: t.special(t.variableName),
    name: t.variableName,
    definition: t.definition(t.variableName),
    property: t.propertyName,
    function: t.function(t.variableName),
    module: t.namespace,
    modifier: t.modifier,
    type: t.typeName,
    tag: t.tagName,
    operator: t.operator,
    bracket: t.bracket,
    punctuation: t.punctuation,
    hex: hexTag,
    hexJump: hexJumpTag,
    hexWildcard: hexWildcardTag,
    invalid: t.invalid,
    meta: t.meta,
    heading: t.heading,
};

export const TOKEN_KINDS = Object.keys(TOKEN_TAGS);
