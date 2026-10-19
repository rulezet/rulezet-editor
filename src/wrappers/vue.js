/**
 * Vue 3 wrapper, no build step needed:
 *
 *   const RuleEditor = createVueComponent(Vue);
 *   app.component('rule-editor', RuleEditor);
 *   <rule-editor v-model="content" language="yara" :host="host" height="480px"></rule-editor>
 *
 * Every RulezetEditor option can be passed through the `options` prop.
 */
import { RulezetEditor } from '../core/RulezetEditor.js';

export function createVueComponent(Vue) {
    const { h, ref, onMounted, onBeforeUnmount, watch, markRaw } = Vue;
    return {
        name: 'RulezetEditor',
        props: {
            modelValue: { type: String, default: '' },
            language: { type: String, default: 'auto' },
            theme: { type: String, default: 'auto' },
            readOnly: { type: Boolean, default: false },
            height: { type: String, default: '480px' },
            host: { type: Object, default: null },
            options: { type: Object, default: () => ({}) },
        },
        emits: ['update:modelValue', 'diagnostics', 'save', 'ready'],
        setup(props, { emit, expose }) {
            const el = ref(null);
            let editor = null;
            let lastEmitted = props.modelValue;

            onMounted(() => {
                editor = markRaw(new RulezetEditor(el.value, {
                    ...props.options,
                    value: props.modelValue,
                    language: props.language,
                    theme: props.theme,
                    readOnly: props.readOnly,
                    host: props.host,
                    height: props.height,
                }));
                editor.on('change', (v) => { lastEmitted = v; emit('update:modelValue', v); });
                editor.on('diagnostics', (d) => emit('diagnostics', d));
                editor.on('save', (v) => emit('save', v));
                emit('ready', editor);
            });
            onBeforeUnmount(() => { if (editor) editor.destroy(); });

            watch(() => props.modelValue, (v) => { if (editor && v !== lastEmitted && v !== editor.getValue()) editor.setValue(v); });
            watch(() => props.language, (v) => editor && editor.setLanguage(v));
            watch(() => props.theme, (v) => editor && editor.setTheme(v));
            watch(() => props.readOnly, (v) => editor && editor.setReadOnly(v));

            expose({ getEditor: () => editor });
            return () => h('div', { ref: el, class: 'rze-vue', style: { height: props.height } });
        },
    };
}
