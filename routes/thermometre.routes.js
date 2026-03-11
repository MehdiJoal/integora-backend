const express = require("express");
const router = express.Router();

const { thermometreSituations, VERSION, fullPath } = require("../services/libraries/thermometreSituations.store");
const { buildThermometrePlan } = require("../services/planEngine/thermometrePlanEngine");

// ✅ GET /api/outils/thermometre/health
router.get("/health", (req, res) => {
    return res.json({
        ok: true,
        storeVersion: VERSION,
        file: fullPath,
        schema_version: thermometreSituations?.schema_version || null,
        familiesCount:
            thermometreSituations?.recommendations_model?.family_playbooks?.families
                ? Object.keys(thermometreSituations.recommendations_model.family_playbooks.families).length
                : 0,
    });
});

// ✅ POST /api/outils/thermometre/generate
router.post("/generate", (req, res) => {
    try {
        const payload = req.body || {};

        const priorities = Array.isArray(payload.priorities) ? payload.priorities.slice(0, 3) : [];
        const frequencyLevel = Number(payload.frequencyLevel ?? 1);
        const ageLevel = Number(payload.ageLevel ?? 1);

        const plan = buildThermometrePlan(
            { ...payload, priorities, frequencyLevel, ageLevel },
            thermometreSituations
        );

        return res.json({ ok: true, plan });
    } catch (err) {
        console.error("[thermometre] generate failed:", err);
        return res.status(500).json({
            ok: false,
            error: "THERMOMETRE_GENERATE_FAILED",
            message: err?.message || String(err),
        });
    }
});

module.exports = router;