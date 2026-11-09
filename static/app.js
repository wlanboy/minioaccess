"use strict";

// ---------------------------------------------------------------------------
// DOM-Helfer
// ---------------------------------------------------------------------------

/** Erzeugt ein Element. Texte werden immer als Textknoten eingefügt (kein innerHTML). */
function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs ?? {})) {
        if (value == null || value === false) continue;
        if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
        else if (key === "class") el.className = value;
        else el.setAttribute(key, value === true ? "" : value);
    }
    el.append(...children.flat(Infinity).filter((c) => c != null && c !== false));
    return el;
}

const ICONS = {
    plus: '<path d="M12 5v14M5 12h14"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6"/>',
    key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
    power: '<path d="M12 2v10M18.36 6.64a9 9 0 1 1-12.73 0"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>',
    bucket: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    arrowLeft: '<path d="M19 12H5M12 19l-7-7 7-7"/>',
    chevron: '<path d="m9 18 6-6-6-6"/>',
    unlink: '<path d="M18.84 12.25 20.6 10.5a5 5 0 0 0-7.07-7.07l-1.77 1.76M5.17 11.75 3.4 13.5a5 5 0 0 0 7.07 7.07l1.76-1.76M8 2v3M2 8h3M16 22v-3M22 16h-3"/>',
    dice: '<rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8.5" cy="8.5" r="1.2" fill="currentColor"/><circle cx="15.5" cy="15.5" r="1.2" fill="currentColor"/><circle cx="15.5" cy="8.5" r="1.2" fill="currentColor"/><circle cx="8.5" cy="15.5" r="1.2" fill="currentColor"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    refresh: '<path d="M21 12a9 9 0 1 1-2.64-6.36L21 8M21 3v5h-5"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    alert: '<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>',
};

/** Nur feste SVG-Strings aus ICONS landen in innerHTML. */
function icon(name) {
    const span = h("span", { class: "icon", "aria-hidden": "true" });
    span.innerHTML = `<svg viewBox="0 0 24 24">${ICONS[name]}</svg>`;
    return span;
}

function button(label, { variant = "", iconName, onclick, type = "button", title } = {}) {
    return h("button", { type, class: `btn ${variant}`.trim(), onclick, title, "aria-label": title },
        iconName && icon(iconName), label && h("span", null, label));
}

/** Sperrt den Button während einer Aktion und zeigt einen Spinner. */
async function busy(btn, fn) {
    btn.disabled = true;
    btn.classList.add("loading");
    try {
        return await fn();
    } finally {
        btn.disabled = false;
        btn.classList.remove("loading");
    }
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

const enc = encodeURIComponent;

async function api(method, path, body) {
    const headers = { "X-Requested-With": "minioaccess" }; // CSRF-Schutz, siehe main.py
    if (body) headers["Content-Type"] = "application/json";
    const res = await fetch(`/api${path}`, {
        method,
        headers,
        credentials: "same-origin",
        body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
        let detail = data?.detail ?? `${res.status} ${res.statusText}`;
        if (Array.isArray(detail)) detail = detail.map((d) => d.msg).join(", ");
        throw new Error(detail);
    }
    return data;
}

/** Führt eine schreibende Aktion aus, zeigt das Ergebnis als Toast und lädt die Ansicht neu. */
async function mutate(btn, method, path, body) {
    try {
        const data = await busy(btn, () => api(method, path, body));
        toast(data.message, "success");
        await render();
        return true;
    } catch (err) {
        toast(err.message, "error");
        return false;
    }
}

// ---------------------------------------------------------------------------
// Toasts & Dialog
// ---------------------------------------------------------------------------

function toast(message, type = "info") {
    const el = h("div", { class: `toast toast-${type}` },
        icon(type === "error" ? "alert" : "check"), h("span", null, message));
    document.getElementById("toasts").append(el);
    const remove = () => {
        el.classList.add("leaving");
        el.addEventListener("animationend", () => el.remove(), { once: true });
    };
    el.addEventListener("click", remove);
    setTimeout(remove, type === "error" ? 8000 : 4000);
}

/**
 * Modaler Dialog. Mit `input` wird ein Eingabefeld angezeigt und dessen Wert zurückgegeben,
 * sonst `true`. Abbruch ergibt `null`.
 */
function openDialog({ title, text, confirmLabel = "Bestätigen", danger = false, input }) {
    const dialog = document.getElementById("dialog");
    const field = input && h("input", {
        type: input.type ?? "text",
        placeholder: input.placeholder,
        minlength: input.minlength,
        required: true,
        autocomplete: "new-password",
    });

    dialog.replaceChildren(h("form", { method: "dialog" },
        h("h3", null, title),
        text && h("p", null, text),
        field && passwordField(field),
        h("div", { class: "dialog-actions" },
            h("button", { value: "cancel", class: "btn btn-ghost", formnovalidate: true }, "Abbrechen"),
            h("button", { value: "ok", class: `btn ${danger ? "btn-danger" : "btn-primary"}` }, confirmLabel),
        ),
    ));

    return new Promise((resolve) => {
        dialog.addEventListener("close", () => {
            if (dialog.returnValue !== "ok") resolve(null);
            else resolve(field ? field.value : true);
        }, { once: true });
        dialog.returnValue = "";
        dialog.showModal();
        (field ?? dialog.querySelector(".btn-ghost")).focus();
    });
}

// ---------------------------------------------------------------------------
// Bausteine
// ---------------------------------------------------------------------------

function pageHeader(title, subtitle, ...actions) {
    return h("header", { class: "page-header" },
        h("div", null, h("h1", null, title), subtitle && h("p", { class: "muted" }, subtitle)),
        h("div", { class: "page-actions" }, actions,
            button("", { variant: "btn-ghost btn-icon", iconName: "refresh", title: "Neu laden", onclick: () => render() })),
    );
}

function card(title, ...children) {
    return h("section", { class: "card" }, title && h("h2", { class: "card-title" }, title), children);
}

function emptyState(iconName, text) {
    return h("div", { class: "empty" }, icon(iconName), h("p", null, text));
}

function badge(text, variant) {
    return h("span", { class: `badge badge-${variant}` }, text);
}

function searchInput(placeholder, onInput) {
    return h("label", { class: "search" }, icon("search"),
        h("input", { type: "search", placeholder, oninput: (e) => onInput(e.target.value.trim().toLowerCase()) }));
}

/** Passwortfeld mit Anzeigen- und Generieren-Button. */
/**
 * Rückfrage vor dem Löschen eines Buckets. Standard: nur leere Buckets (mc rb).
 * Mit Häkchen wird der Inhalt mitgelöscht (rb --force); dann muss der Name
 * eingetippt werden. Ergibt `{ force }` oder bei Abbruch `null`.
 */
function confirmBucketDelete(bucket) {
    const dialog = document.getElementById("dialog");
    const force = h("input", { type: "checkbox" });
    const nameField = h("input", { placeholder: bucket, autocomplete: "off", spellcheck: "false" });
    const nameRow = h("label", { class: "dialog-field", hidden: true },
        h("span", null, "Zur Bestätigung den Bucket-Namen eingeben:"), nameField);
    const ok = h("button", { value: "ok", class: "btn btn-danger" }, "Löschen");

    const update = () => {
        nameRow.hidden = !force.checked;
        ok.disabled = force.checked && nameField.value !== bucket;
    };
    force.addEventListener("change", () => { update(); if (force.checked) nameField.focus(); });
    nameField.addEventListener("input", update);

    dialog.replaceChildren(h("form", { method: "dialog" },
        h("h3", null, "Bucket löschen?"),
        h("p", null, `„${bucket}“ wird nur gelöscht, wenn er leer ist.`),
        h("label", { class: "dialog-check" }, force,
            h("span", null, "Inhalt mitlöschen (alle Objekte, nicht rückgängig zu machen)")),
        nameRow,
        h("div", { class: "dialog-actions" },
            h("button", { value: "cancel", class: "btn btn-ghost", formnovalidate: true }, "Abbrechen"),
            ok,
        ),
    ));

    return new Promise((resolve) => {
        dialog.addEventListener("close", () => {
            resolve(dialog.returnValue === "ok" ? { force: force.checked } : null);
        }, { once: true });
        dialog.returnValue = "";
        dialog.showModal();
        dialog.querySelector(".btn-ghost").focus();
    });
}

function passwordField(input) {
    const toggle = button("", {
        variant: "btn-ghost btn-icon", iconName: "eye", title: "Anzeigen",
        onclick: () => { input.type = input.type === "password" ? "text" : "password"; },
    });
    const generate = button("", {
        variant: "btn-ghost btn-icon", iconName: "dice", title: "Zufälliges Passwort erzeugen",
        onclick: () => { input.value = randomSecret(); input.type = "text"; input.focus(); },
    });
    return h("div", { class: "input-group" }, input, toggle, generate);
}

function randomSecret(length = 24) {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const bytes = crypto.getRandomValues(new Uint32Array(length));
    return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

/**
 * Tabelle mit Suchfeld. `columns`: [{ label, render(row), class }].
 * `match(row)` liefert den durchsuchbaren Text einer Zeile.
 */
function dataTable({ title, columns, rows, empty, emptyIcon, match }) {
    const tbody = h("tbody");
    const fill = (query) => {
        const visible = rows.filter((r) => !query || match(r).toLowerCase().includes(query));
        tbody.replaceChildren(...visible.map((row) =>
            h("tr", null, columns.map((c) => h("td", { class: c.class, "data-label": c.label }, c.render(row))))));
        if (!visible.length) {
            tbody.append(h("tr", null, h("td", { colspan: columns.length, class: "no-match" }, "Keine Treffer.")));
        }
    };
    fill("");

    const head = h("div", { class: "card-head" },
        h("h2", { class: "card-title" }, title, h("span", { class: "count" }, rows.length)),
        rows.length > 0 && searchInput("Suchen …", fill));

    if (!rows.length) return h("section", { class: "card" }, head, emptyState(emptyIcon, empty));

    return h("section", { class: "card" }, head,
        h("div", { class: "table-wrap" },
            h("table", null,
                h("thead", null, h("tr", null, columns.map((c) => h("th", { class: c.class }, c.label)))),
                tbody)));
}

function skeleton() {
    return h("div", { class: "skeleton-wrap" },
        h("div", { class: "skeleton skeleton-title" }),
        h("div", { class: "skeleton skeleton-card" }),
        h("div", { class: "skeleton skeleton-card tall" }));
}

// ---------------------------------------------------------------------------
// Ansichten
// ---------------------------------------------------------------------------

async function usersView() {
    const users = await api("GET", "/users");
    const active = users.filter((u) => u.enabled).length;

    const name = h("input", { name: "access_key", placeholder: "Benutzername", required: true, autocomplete: "off" });
    const secret = h("input", {
        name: "secret_key", type: "password", placeholder: "Passwort (min. 12 Zeichen)",
        required: true, minlength: 12, autocomplete: "new-password",
    });
    const submit = button("Erstellen", { variant: "btn-primary", iconName: "plus", type: "submit" });
    const form = h("form", {
        class: "inline-form",
        onsubmit: async (e) => {
            e.preventDefault();
            await mutate(submit, "POST", "/users", { access_key: name.value, secret_key: secret.value });
        },
    }, name, passwordField(secret), submit);

    return [
        pageHeader("Benutzer", `${users.length} Benutzer · ${active} aktiv`),
        card("Neuer Benutzer", form),
        dataTable({
            title: "Vorhandene Benutzer",
            rows: users,
            empty: "Noch keine Benutzer angelegt.",
            emptyIcon: "key",
            match: (u) => u.name,
            columns: [
                { label: "Name", render: (u) => h("span", { class: "mono strong" }, u.name) },
                {
                    label: "Status",
                    render: (u) => u.enabled ? badge("aktiv", "success") : badge("deaktiviert", "warning"),
                },
                {
                    label: "", class: "actions",
                    render: (u) => {
                        const path = `/users/${enc(u.name)}`;
                        const toggle = u.enabled
                            ? button("Deaktivieren", { variant: "btn-ghost", iconName: "power",
                                onclick: () => mutate(toggle, "POST", `${path}/disable`) })
                            : button("Aktivieren", { variant: "btn-ghost", iconName: "power",
                                onclick: () => mutate(toggle, "POST", `${path}/enable`) });
                        const pw = button("", {
                            variant: "btn-ghost btn-icon", iconName: "key", title: "Passwort ändern",
                            onclick: async () => {
                                const value = await openDialog({
                                    title: "Passwort ändern",
                                    text: `Neues Passwort für „${u.name}“.`,
                                    confirmLabel: "Speichern",
                                    input: { type: "password", placeholder: "Neues Passwort (min. 12 Zeichen)", minlength: 12 },
                                });
                                if (value) await mutate(pw, "PUT", `${path}/password`, { secret_key: value });
                            },
                        });
                        const del = button("", {
                            variant: "btn-ghost btn-icon danger", iconName: "trash", title: "Löschen",
                            onclick: async () => {
                                const ok = await openDialog({
                                    title: "Benutzer löschen?",
                                    text: `„${u.name}“ wird endgültig entfernt.`,
                                    confirmLabel: "Löschen", danger: true,
                                });
                                if (ok) await mutate(del, "DELETE", path);
                            },
                        });
                        return [toggle, pw, del];
                    },
                },
            ],
        }),
    ];
}

async function bucketsView() {
    const buckets = await api("GET", "/buckets");

    const name = h("input", {
        name: "name", placeholder: "bucket-name", required: true, autocomplete: "off",
        pattern: "[a-z0-9][a-z0-9.\\-]{1,61}[a-z0-9]",
        title: "3–63 Zeichen: Kleinbuchstaben, Ziffern, Punkt und Bindestrich",
    });
    const submit = button("Erstellen", { variant: "btn-primary", iconName: "plus", type: "submit" });
    const form = h("form", {
        class: "inline-form",
        onsubmit: async (e) => {
            e.preventDefault();
            await mutate(submit, "POST", "/buckets", { name: name.value });
        },
    }, name, submit);

    const grid = h("div", { class: "bucket-grid" });
    const fill = (query) => {
        const visible = buckets.filter((b) => !query || b.toLowerCase().includes(query));
        grid.replaceChildren(...visible.map((b) => {
            const del = button("", {
                variant: "btn-ghost btn-icon danger", iconName: "trash", title: "Löschen",
                onclick: async (e) => {
                    e.preventDefault();
                    const choice = await confirmBucketDelete(b);
                    if (choice) {
                        const query = choice.force ? "?force=true" : "";
                        await mutate(del, "DELETE", `/buckets/${enc(b)}${query}`);
                    }
                },
            });
            return h("div", { class: "bucket-tile" },
                h("a", { href: `#/bucket/${enc(b)}`, class: "bucket-link" },
                    h("span", { class: "bucket-icon" }, icon("bucket")),
                    h("span", { class: "bucket-name mono" }, b),
                    icon("chevron")),
                del);
        }));
        if (!visible.length) grid.append(h("p", { class: "no-match" }, "Keine Treffer."));
    };
    fill("");

    return [
        pageHeader("Buckets", `${buckets.length} Buckets`),
        card("Neuer Bucket", form),
        h("section", { class: "card" },
            h("div", { class: "card-head" },
                h("h2", { class: "card-title" }, "Vorhandene Buckets", h("span", { class: "count" }, buckets.length)),
                buckets.length > 0 && searchInput("Suchen …", fill)),
            buckets.length ? grid : emptyState("bucket", "Noch keine Buckets vorhanden.")),
    ];
}

const POLICY_TYPES = [
    { value: "readonly", label: "Lesen", hint: "GetObject, ListBucket" },
    { value: "readwrite", label: "Lesen & Schreiben", hint: "s3:*" },
    { value: "writeonly", label: "Schreiben", hint: "PutObject" },
];

async function bucketView(bucket) {
    const [policies, users] = await Promise.all([
        api("GET", `/buckets/${enc(bucket)}/policies`),
        api("GET", "/users"),
    ]);

    const userSelect = h("select", { name: "user", required: true },
        h("option", { value: "", disabled: true, selected: true }, "Benutzer wählen …"),
        users.map((u) => h("option", { value: u.name }, u.name)));

    const segmented = h("div", { class: "segmented", role: "radiogroup" },
        POLICY_TYPES.map((t, i) => h("label", null,
            h("input", { type: "radio", name: "policy_type", value: t.value, checked: i === 0 }),
            h("span", null, h("strong", null, t.label), h("small", null, t.hint)))));

    const submit = button("Berechtigung setzen", { variant: "btn-primary", iconName: "plus", type: "submit" });
    const form = h("form", {
        class: "stack-form",
        onsubmit: async (e) => {
            e.preventDefault();
            const policyType = new FormData(form).get("policy_type");
            await mutate(submit, "POST", `/buckets/${enc(bucket)}/policies`,
                { user: userSelect.value, policy_type: policyType });
        },
    },
    h("div", { class: "field" }, h("span", { class: "label" }, "Benutzer"), userSelect),
    h("div", { class: "field" }, h("span", { class: "label" }, "Zugriff"), segmented),
    h("div", null, submit));

    const policyBadge = (policy) => {
        const type = policy.slice(bucket.length + 1);
        const variant = { readonly: "info", readwrite: "accent", writeonly: "warning" }[type] ?? "neutral";
        return h("span", { class: "policy-cell" }, badge(type || policy, variant), h("span", { class: "mono muted" }, policy));
    };

    return [
        h("a", { href: "#/buckets", class: "back" }, icon("arrowLeft"), "Buckets"),
        pageHeader(bucket, "Bucket-Berechtigungen"),
        dataTable({
            title: "Aktuelle Berechtigungen",
            rows: policies,
            empty: "Für diesen Bucket sind keine Berechtigungen vergeben.",
            emptyIcon: "shield",
            match: (p) => `${p.user} ${p.policy}`,
            columns: [
                { label: "Benutzer", render: (p) => h("span", { class: "mono strong" }, p.user) },
                { label: "Policy", render: (p) => policyBadge(p.policy) },
                {
                    label: "", class: "actions",
                    render: (p) => {
                        const btn = button("Entfernen", {
                            variant: "btn-ghost danger", iconName: "unlink",
                            onclick: async () => {
                                const ok = await openDialog({
                                    title: "Berechtigung entfernen?",
                                    text: `Policy „${p.policy}“ wird von „${p.user}“ gelöst.`,
                                    confirmLabel: "Entfernen", danger: true,
                                });
                                if (ok) {
                                    await mutate(btn, "DELETE",
                                        `/buckets/${enc(bucket)}/policies/${enc(p.policy)}/users/${enc(p.user)}`);
                                }
                            },
                        });
                        return btn;
                    },
                },
            ],
        }),
        card("Neue Berechtigung",
            users.length ? form : emptyState("key", "Lege zuerst einen Benutzer an.")),
    ];
}

/** Von MinIO mitgelieferte Policies, die sich nicht löschen lassen. */
const BUILTIN_POLICIES = new Set(["consoleAdmin", "diagnostics", "readonly", "readwrite", "writeonly"]);

function chips(values, className) {
    if (!values?.length) return h("span", { class: "muted" }, "–");
    return h("div", { class: "chips" }, values.map((v) => h("span", { class: `chip ${className}` }, v)));
}

async function policiesView() {
    const policies = await api("GET", "/policies");

    return [
        pageHeader("Policies", `${policies.length} Policies`),
        dataTable({
            title: "Alle Policies",
            rows: policies,
            empty: "Keine Policies gefunden.",
            emptyIcon: "shield",
            match: (p) => [p.name, ...p.actions, ...p.resources].join(" "),
            columns: [
                {
                    label: "Name",
                    render: (p) => h("span", { class: "policy-cell" },
                        h("span", { class: "mono strong" }, p.name),
                        BUILTIN_POLICIES.has(p.name) && badge("System", "neutral")),
                },
                { label: "Actions", render: (p) => chips(p.actions, "chip-action") },
                { label: "Resources", render: (p) => chips(p.resources, "chip-resource") },
                {
                    label: "", class: "actions",
                    render: (p) => {
                        if (BUILTIN_POLICIES.has(p.name)) return null;
                        const del = button("", {
                            variant: "btn-ghost btn-icon danger", iconName: "trash", title: "Löschen",
                            onclick: async () => {
                                const ok = await openDialog({
                                    title: "Policy löschen?",
                                    text: `„${p.name}“ wird entfernt.`,
                                    confirmLabel: "Löschen", danger: true,
                                });
                                if (ok) await mutate(del, "DELETE", `/policies/${enc(p.name)}`);
                            },
                        });
                        return del;
                    },
                },
            ],
        }),
    ];
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

function parseRoute() {
    const [, section = "users", ...rest] = location.hash.replace(/^#/, "").split("/");
    const param = rest.length ? decodeURIComponent(rest.join("/")) : null;
    switch (section) {
        case "buckets": return { nav: "buckets", view: bucketsView };
        case "bucket": return param ? { nav: "buckets", view: () => bucketView(param) } : { nav: "buckets", view: bucketsView };
        case "policies": return { nav: "policies", view: policiesView };
        default: return { nav: "users", view: usersView };
    }
}

let renderToken = 0;

async function render() {
    const token = ++renderToken;
    const route = parseRoute();
    const main = document.getElementById("view");

    for (const link of document.querySelectorAll(".nav a")) {
        link.classList.toggle("active", link.dataset.route === route.nav);
    }

    // Skelett nur beim Seitenwechsel, nicht beim Neuladen nach einer Aktion
    if (main.dataset.route !== location.hash) {
        main.dataset.route = location.hash;
        main.replaceChildren(skeleton());
    }

    try {
        const content = await route.view();
        if (token !== renderToken) return;
        main.replaceChildren(...content);
    } catch (err) {
        if (token !== renderToken) return;
        main.replaceChildren(h("div", { class: "card error-card" },
            icon("alert"),
            h("div", null, h("h2", null, "Laden fehlgeschlagen"), h("p", { class: "muted" }, err.message)),
            button("Erneut versuchen", { variant: "btn-primary", iconName: "refresh", onclick: () => render() })));
    }
}

window.addEventListener("hashchange", render);
render();
