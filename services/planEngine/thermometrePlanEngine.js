/**
 * Thermomètre des tensions — Plan Engine (v12)
 *
 * BREAKING CHANGE v11→v12 :
 *  - Nouveau système de coloration per-signal (vert / orange / rouge).
 *  - `computeSignalColor(signalId, f, a)` remplace `computeSignalIntensityLevel` pour la couleur.
 *  - `computeSignalIntensityLevel` est conservé pour la compatibilité ascendante (do_now layering).
 *  - Règles encodées signal par signal depuis le référentiel S1→S7 + S8 red-flags.
 *  - Cohérence F/A : F1 plafonne automatiquement l'ancienneté à A2.
 *  - Couleur d'une priorité = pire couleur de ses signaux.
 *  - Couleur globale = pire couleur des priorités.
 *  - S8 (red flags) → rouge urgence direct.
 *
 * Paliers
 *  Fréquence  F1=Isolé  F2=Répété  F3=Fréquent  F4=Très fréquent
 *  Ancienneté A1=Récent A2=Confirmé A3=Installé  A4=Ancré
 *
 */

"use strict";

// ─── Utilitaires ────────────────────────────────────────────────────────────

function toNumLevel(code, defaultValue = 1) {
    if (!code || typeof code !== "string") return defaultValue;
    const n = parseInt(code.slice(1), 10);
    return Number.isFinite(n) ? n : defaultValue;
}

/**
 * F1 = événement unique → ancienneté NON PERTINENTE.
 * Si F=1, on force A=1. L'UI désactive le select ancienneté en conséquence.
 */
function normalizeFA(frequencyCode, seniorityCode) {
    const f = toNumLevel(frequencyCode, 1);
    const a = toNumLevel(seniorityCode, 1);
    if (f === 1) return { f: 1, a: 1 };
    return { f, a };
}

/** Niveau legacy pour le do_now layering (inchangé). */
function computeSignalIntensityLevel(frequencyCode, seniorityCode) {
    const { f, a } = normalizeFA(frequencyCode, seniorityCode);
    if (f <= 2 && a <= 2) return 1;
    if (f === 4 || (f >= 3 && a >= 3)) return 3;
    return 2;
}

// ─── Grilles exactes par signal ─────────────────────────────────────────────
//
// SIGNAL_GRILLE[signalId][f-1][a-1] → 'V' | 'O' | 'R'
// Lignes = F1..F4, colonnes = A1..A4.
// Règle F1 : toute la ligne F1 est uniforme (V ou O).
//   F1=VVVV → friction/organisation/climat
//   F1=OOOO → alerte même isolée (humiliation, exclusion, isolement, départ, réaction forte)
//   S8      → RRRR partout

const SIGNAL_GRILLE = {
    // ── S1 Communication et Respect ─────────────────────────────────────────
    "s1-1": [["V", "V", "V", "V"], ["V", "V", "O", "O"], ["O", "O", "O", "R"], ["O", "R", "R", "R"]],
    "s1-2": [["V", "V", "V", "V"], ["O", "O", "O", "R"], ["O", "O", "R", "R"], ["R", "R", "R", "R"]],
    "s1-3": [["V", "V", "V", "V"], ["O", "O", "O", "R"], ["O", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s1-4": [["V", "V", "V", "V"], ["O", "O", "O", "R"], ["O", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s1-5": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "O", "R"], ["O", "R", "R", "R"]],
    "s1-6": [["V", "V", "V", "V"], ["V", "V", "O", "O"], ["O", "O", "O", "R"], ["O", "R", "R", "R"]],
    "s1-7": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s1-8": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "O", "R"], ["O", "O", "R", "R"]],
    // ── S2 Relationnel et Cohésion ───────────────────────────────────────────
    "s2-1": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s2-2": [["V", "V", "V", "V"], ["O", "O", "O", "O"], ["O", "R", "R", "R"], ["O", "R", "R", "R"]],
    "s2-3": [["V", "V", "V", "V"], ["V", "V", "O", "O"], ["O", "O", "O", "R"], ["O", "R", "R", "R"]],
    "s2-4": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "O", "R"], ["O", "O", "R", "R"]],
    "s2-5": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s2-6": [["V", "V", "V", "V"], ["O", "O", "O", "R"], ["O", "R", "R", "R"], ["R", "R", "R", "R"]],
    // ── S3 Organisation et Charge ────────────────────────────────────────────
    "s3-1": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s3-2": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "R", "R"], ["R", "R", "R", "R"]],
    "s3-3": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s3-4": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "R", "R"], ["O", "O", "R", "R"]],
    "s3-5": [["V", "V", "V", "V"], ["V", "V", "O", "O"], ["O", "O", "O", "R"], ["O", "R", "R", "R"]],
    "s3-6": [["V", "V", "V", "V"], ["V", "V", "O", "O"], ["O", "O", "O", "R"], ["O", "R", "R", "R"]],
    "s3-7": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s3-8": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    // ── S4 Management et Équité ──────────────────────────────────────────────
    "s4-1": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s4-2": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s4-3": [["V", "V", "V", "V"], ["V", "V", "O", "O"], ["O", "O", "O", "R"], ["O", "O", "R", "R"]],
    "s4-4": [["O", "O", "O", "O"], ["O", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s4-5": [["V", "V", "V", "V"], ["V", "V", "O", "O"], ["O", "O", "O", "R"], ["O", "O", "R", "R"]],
    "s4-6": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "O", "R"], ["O", "R", "R", "R"]],
    // ── S5 Engagement et Performance ─────────────────────────────────────────
    "s5-1": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s5-2": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s5-3": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s5-4": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s5-5": [["O", "O", "O", "O"], ["O", "O", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s5-6": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    // ── S6 Santé et Fatigue ──────────────────────────────────────────────────
    "s6-1": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s6-2": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s6-3": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s6-4": [["O", "O", "O", "O"], ["O", "R", "R", "R"], ["O", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s6-5": [["O", "O", "O", "O"], ["O", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s6-6": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    // ── S7 Interactions Externes ─────────────────────────────────────────────
    "s7-1": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s7-2": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s7-3": [["V", "V", "V", "V"], ["V", "O", "O", "O"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    "s7-4": [["V", "V", "V", "V"], ["V", "O", "O", "R"], ["O", "O", "R", "R"], ["O", "R", "R", "R"]],
    // ── S8 Signaux d'alerte graves ───────────────────────────────────────────
    "s8-1": [["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s8-2": [["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s8-3": [["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s8-4": [["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"]],
    "s8-5": [["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"], ["R", "R", "R", "R"]],
};

/**
 * Calcule la couleur d'un signal via sa grille exacte.
 * @param {string} signalId       ex: "s1-3"
 * @param {string} frequencyCode  ex: "F2"
 * @param {string} seniorityCode  ex: "A3"
 * @returns {"vert"|"orange"|"rouge"}
 */
function computeSignalColor(signalId, frequencyCode, seniorityCode) {
    const grille = SIGNAL_GRILLE[signalId];
    if (!grille) return "vert";
    const { f, a } = normalizeFA(frequencyCode, seniorityCode);
    const fi = Math.min(Math.max(f, 1), 4) - 1;
    const ai = Math.min(Math.max(a, 1), 4) - 1;
    const cell = grille[fi][ai];
    if (cell === "R") return "rouge";
    if (cell === "O") return "orange";
    return "vert";
}

/**
 * Pire couleur d'une liste de couleurs.
 * rouge > orange > vert
 */
function worstColor(colors) {
    if (colors.includes("rouge")) return "rouge";
    if (colors.includes("orange")) return "orange";
    return "vert";
}

// ─── Déduplication ──────────────────────────────────────────────────────────

function dedupePush(list, item, keyFn) {
    const key = keyFn(item);
    if (!key) return;
    if (!list._seen) list._seen = new Set();
    if (list._seen.has(key)) return;
    list._seen.add(key);
    list.push(item);
}

function normalizeTextItem(signalId, text) {
    if (!text) return null;
    if (typeof text === "string") return { signalId, text };
    if (typeof text === "object") {
        return { signalId, text: text.text || text.title || JSON.stringify(text) };
    }
    return { signalId, text: String(text) };
}

// ─── Moteur principal ────────────────────────────────────────────────────────

function buildThermometrePlan(payload, library) {
    const lib = library || {};
    const recos = lib.recommendations_model || {};

    const microItems = recos.signal_micro_recos?.items || {};
    const playbooksByType = recos.playbooks_by_type || {};

    // Signaux prioritaires (max 3)
    const prioritySignalsRaw = Array.isArray(payload?.prioritySignals)
        ? payload.prioritySignals.slice(0, 3)
        : [];

    // Red flags
    const selectedRedFlags = Array.isArray(payload?.redFlags) ? payload.redFlags : [];
    const hasRedFlags =
        Boolean(payload?.hasRedFlags) ||
        selectedRedFlags.length > 0 ||
        prioritySignalsRaw.some((s) => microItems?.[s.signalId]?.force_escalation === true) ||
        prioritySignalsRaw.some((s) => s.signalId?.startsWith("s8-"));

    // Enrichir chaque signal : couleur + intensité legacy + playbook_key
    const prioritySignals = prioritySignalsRaw.map((s) => {
        const item = microItems?.[s.signalId];
        const playbookKey = item?.playbook_key || item?.type || null;
        const color = computeSignalColor(s.signalId, s.frequency, s.seniority);
        return {
            ...s,
            color,
            intensityLevel: computeSignalIntensityLevel(s.frequency, s.seniority),
            playbook_key: playbookKey,
        };
    });

    // Couleurs agrégées
    const signalColors = prioritySignals.map((s) => s.color);
    const globalColor = hasRedFlags ? "rouge" : worstColor(signalColors);

    // ── 1) signal_micro_recos ─────────────────────────────────────────────────
    const signal_micro_recos = {};

    for (const s of prioritySignals) {
        const item = microItems?.[s.signalId];
        if (!item) continue;

        const base = Array.isArray(item.do_now_base) ? item.do_now_base : [];
        const standard = Array.isArray(item.do_now_standard) ? item.do_now_standard : [];
        const renforce = Array.isArray(item.do_now_renforce) ? item.do_now_renforce : [];
        const legacy = Array.isArray(item.do_now) ? item.do_now : [];

        const doNow = legacy.length
            ? legacy
            : [
                ...base,
                ...(s.intensityLevel === 2 ? standard : []),
                ...(s.intensityLevel === 3 ? renforce : []),
            ];

        // Niveau du playbook (compatibilité ascendante)
        const levelKey = s.intensityLevel === 1 ? "level1"
            : s.intensityLevel === 3 ? "level3"
                : "level2";

        const pb = s.playbook_key ? playbooksByType[s.playbook_key] : null;
        const lvl = pb?.by_intensity?.[levelKey] || pb?.by_intensity?.level2 || {};

        signal_micro_recos[s.signalId] = {
            signalId: s.signalId,
            title: item.title || s.label || s.signalId,
            impact: item.impact || "",
            objective: item.objective || "",
            do_now_base: base,
            do_now_standard: standard,
            do_now_renforce: renforce,
            do_now: doNow,
            avoid: item.avoid || "",
            link_family: item.link_family || s.family || null,
            playbook_key: s.playbook_key || null,
            frequency: s.frequency,
            seniority: s.seniority,
            intensity_level: String(s.intensityLevel),
            color: s.color,                   // ← nouveau
            bons_reflexes: Array.isArray(lvl.bons_reflexes) ? lvl.bons_reflexes : [],
            follow_up: Array.isArray(lvl.follow_up) ? lvl.follow_up : [],
            escalate_if: Array.isArray(lvl.escalate_if) ? lvl.escalate_if : [],
        };
    }

    // ── 2) Agrégation cross-signaux (dédup) ───────────────────────────────────
    const aggregated = {
        do_now: [],
        bons_reflexes: [],
        follow_up: [],
        avoid: [],
        escalate_if: [],
    };

    for (const [signalId, micro] of Object.entries(signal_micro_recos)) {
        for (const x of micro.do_now || []) {
            const item = normalizeTextItem(signalId, x);
            if (!item) continue;
            dedupePush(aggregated.do_now, item, (i) => `${i.signalId}::do_now::${i.text}`);
        }
        for (const x of micro.bons_reflexes || []) {
            const item = normalizeTextItem(signalId, x);
            if (!item) continue;
            dedupePush(aggregated.bons_reflexes, item, (i) => `${i.signalId}::bons_reflexes::${i.text}`);
        }
        for (const x of micro.follow_up || []) {
            const item = normalizeTextItem(signalId, x);
            if (!item) continue;
            dedupePush(aggregated.follow_up, item, (i) => `${i.signalId}::follow_up::${i.text}`);
        }
        if (micro.avoid) {
            const item = normalizeTextItem(signalId, micro.avoid);
            if (item) dedupePush(aggregated.avoid, item, (i) => `${i.signalId}::avoid::${i.text}`);
        }
        for (const x of micro.escalate_if || []) {
            const item = normalizeTextItem(signalId, x);
            if (!item) continue;
            dedupePush(aggregated.escalate_if, item, (i) => `${i.signalId}::escalate_if::${i.text}`);
        }
    }

    // Red-flag : escalade immédiate
    if (hasRedFlags) {
        dedupePush(
            aggregated.escalate_if,
            { signalId: "red-flag", text: "Signal d'alerte grave : escalade RH/Direction immédiate (sécurisation + traçabilité des faits)." },
            (i) => `red-flag::${i.text}`
        );
    }

    // ── 3) Meta ───────────────────────────────────────────────────────────────
    const meta = {
        libraryVersion: lib.schema_version || "unknown",
        hasRedFlags,
        globalColor,                           // ← nouveau
        notes: {
            signals_note: payload?.notes?.signals || payload?.signalsNote || "",
            priorities_note: payload?.notes?.priorities || payload?.prioritiesNote || "",
            triggers_note: payload?.notes?.triggers || payload?.triggersNote || "",
            actions_note: payload?.notes?.actions || payload?.actionsNote || "",
        },
        triggers: Array.isArray(payload?.triggers) ? payload.triggers : [],
        actions_done: Array.isArray(payload?.actionsDone) ? payload.actionsDone : [],
        prioritySignals: prioritySignals.map((s) => ({
            signalId: s.signalId,
            label: s.label,
            family: s.family,
            frequency: s.frequency,
            seniority: s.seniority,
            intensity_level: String(s.intensityLevel),
            color: s.color,                    // ← nouveau
            playbook_key: s.playbook_key || null,
        })),
    };

    // Nettoyage marqueurs dédup
    ["do_now", "bons_reflexes", "follow_up", "avoid", "escalate_if"].forEach(
        (k) => delete aggregated[k]._seen
    );

    return { meta, signal_micro_recos, aggregated };
}

module.exports = { buildThermometrePlan, computeSignalColor, worstColor, normalizeFA };
