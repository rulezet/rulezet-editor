/** Minimal event emitter. */
export class Emitter {
    constructor() { this.handlers = new Map(); }

    on(event, fn) {
        if (!this.handlers.has(event)) this.handlers.set(event, new Set());
        this.handlers.get(event).add(fn);
    }

    off(event, fn) {
        const set = this.handlers.get(event);
        if (set) set.delete(fn);
    }

    emit(event, payload) {
        const set = this.handlers.get(event);
        if (!set) return;
        for (const fn of [...set]) {
            try { fn(payload); } catch (e) { console.error(`rulezet-editor: "${event}" handler failed`, e); }
        }
    }

    clear() { this.handlers.clear(); }
}
