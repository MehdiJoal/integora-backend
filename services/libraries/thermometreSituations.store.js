// services/libraries/thermometreTensions.store.js
const fs = require("fs");
const path = require("path");

const ROOT = path.join(
    __dirname,
    "..",
    "..",
    "data",
    "libraries",
    "appui_managerial",
    "thermometre_des_situations"
);

// ✅ plus de .vX => stable en local + prod
const VERSION = "v1";
const FILE = "thermometre_des_situations.json";

const fullPath = path.join(ROOT, FILE);
const thermometreSituations = JSON.parse(fs.readFileSync(fullPath, "utf8"));

module.exports = { thermometreSituations, VERSION, fullPath };