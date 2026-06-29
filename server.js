//server//

require('dotenv').config();

// ==========================
// 🔧 LOGS (SERVER)
// ==========================
const IS_PROD = process.env.NODE_ENV === "production";

const FRONTEND_URL =
  process.env.FRONTEND_URL || (IS_PROD ? "https://integora.fr" : "http://localhost:3000");

function setNoStore(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}


function devOnly(req, res, next) {
  if (IS_PROD) return res.status(404).send("Not found");
  return next();
}

// ✅ Autorise l’expo de liens sensibles uniquement en DEV (optionnellement protégé par secret)
function devToolsAllowed(req) {
  if (IS_PROD) return false;

  // Si tu n’as pas de secret configuré => autorisé en dev
  const expected = process.env.DEV_TOOLS_SECRET;
  if (!expected) return true;

  const got = String(req.headers["x-dev-secret"] || "");
  return got === expected;
}

// ✅ Détails d'erreur visibles seulement en DEV (jamais en PROD)
function safeDetails(err) {
  if (IS_PROD) return undefined;
  return err?.raw?.message || err?.message || String(err);
}



// (optionnel) petit helper pour ne jamais log d’email
const safeUserTag = (u) => (u?.id ? `user_id=${u.id}` : "user_id=unknown");

// Niveau: error | warn | info | debug
const LOG_LEVEL = (process.env.LOG_LEVEL || (IS_PROD ? "warn" : "debug")).toLowerCase();
const rank = { error: 0, warn: 1, info: 2, debug: 3 };
const can = (lvl) => (rank[lvl] ?? 99) <= (rank[LOG_LEVEL] ?? 1);

const log = {
  error: (...a) => console.error(...a),
  warn: (...a) => { if (can("warn")) console.warn(...a); },
  info: (...a) => { if (can("info")) console.log(...a); },
  debug: (...a) => { if (can("debug")) console.log(...a); },
};

function safeError(e) {
  return {
    name: e?.name,
    message: e?.message,
    code: e?.code,
    status: e?.status,
  };
}



// Vérification CRITIQUE - doit être fait immédiatement
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  log.error("❌ ERREUR CRITIQUE: Variables Supabase manquantes !");
  log.error("   SUPABASE_URL:", process.env.SUPABASE_URL ? "✅ Définie" : "❌ MANQUANTE");
  log.error("   SUPABASE_SERVICE_ROLE_KEY:", process.env.SUPABASE_SERVICE_ROLE_KEY ? "✅ Définie" : "❌ MANQUANTE");
  log.error("💡 Vérifie que ton fichier .env est dans le même dossier que server.js");
  process.exit(1);
}




log.info(`[BOOT] env=${process.env.NODE_ENV} (LOG_LEVEL=${LOG_LEVEL})`);


const express = require("express");
const app = express();
app.disable("x-powered-by");


// ==================== CORS (TOUT EN HAUT) ====================
const ALLOWED_ORIGINS = new Set([
  "https://integora.fr",
  "https://www.integora.fr",
  // (optionnel) temps migration
  "http://localhost:3000",
  "http://localhost:5173",
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  const isVercelPreview =
    !IS_PROD && origin && /^https:\/\/integora-frontend-.*\.vercel\.app$/.test(origin);

  if (origin && (ALLOWED_ORIGINS.has(origin) || isVercelPreview)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
  }

  // ✅ Répondre aux preflights AVANT tout le reste
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  next();
});


// ==========================================
// 📦 IMPORTS DES MODULES
// ==========================================
const path = require('path');
const fs = require('fs');
// FIX B16 — bodyParser supprimé (inutilisé, express.json() fait le travail)
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require("compression");


// ==========================================
// 📧 RESEND 
// ==========================================
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM = process.env.RESEND_FROM || "INTEGORA <noreply@integora.fr>";

async function sendResendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY manquante : email non envoyé.");
  }

  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: RESEND_FROM,
      to: Array.isArray(to) ? to : [to],
      subject,
      html,
    }),
  });

  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const msg = data?.message || data?.error || JSON.stringify(data);
    throw new Error(`Resend error: ${resp.status} ${msg}`);
  }
  return data;
}

// [15 mai 2026] Notification interne (Mehdi + contact@) a chaque nouvelle inscription
// soumise via le formulaire (trial OU paid). Non-bloquante : si l'envoi echoue,
// on log et on continue le flow normal (l'inscription du user n'est pas affectee).
//
// Destinataires fixes :
//   - contact@integora.fr (boite generique)
//   - mehdi.joalland@integora.fr (perso)
//
// Format : email court avec resume des infos d'inscription.
async function sendAdminSignupNotification({
  first_name,
  last_name,
  email,
  company_name,
  company_size,
  desired_plan,
}) {
  try {
    // [16 mai 2026] Destinataires internes : uniquement mehdi.joalland pour l'instant
    // (compte solo). A elargir avec contact@integora.fr si une equipe rejoint plus tard.
    const RECIPIENTS = ["mehdi.joalland@integora.fr"];

    const planLabel = desired_plan === "trial"
      ? "Essai gratuit 7 jours"
      : desired_plan === "paid"
        ? `Abonnement annuel${company_size ? ` - ${company_size} collaborateurs` : ""}`
        : `Plan ${desired_plan || "inconnu"}`;

    const fullName = `${first_name || ""} ${last_name || ""}`.trim() || "Anonyme";
    const subject = `Nouvelle inscription INTEGORA - ${fullName}`;

    const now = new Date().toLocaleString("fr-FR", {
      day: "2-digit", month: "2-digit", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });

    const html = `<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8" /></head>
<body style="margin:0; padding:0; background:#ffffff; color:#2d3748; font-family:Arial,sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#ffffff; padding:24px 12px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;">
        <tr><td style="background:#ffffff; border:1px solid #e2e8f0; border-radius:16px; overflow:hidden;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
            <tr><td align="center" style="padding:22px 20px 12px 20px;">
              <div style="font-size:18px; font-weight:700; color:#0b132b;">Nouvelle inscription INTEGORA</div>
              <div style="margin-top:6px; font-size:13px; color:#718096;">Notification interne</div>
            </td></tr>
            <tr><td style="padding:0 20px;"><div style="height:1px; background:#e2e8f0;"></div></td></tr>
            <tr><td style="padding:16px 22px;">
              <div style="font-size:14px; line-height:1.8; color:#2d3748;">
                <div><strong>Nom :</strong> ${escapeHtml(fullName)}</div>
                <div><strong>Email :</strong> ${escapeHtml(email || "—")}</div>
                <div><strong>Entreprise :</strong> ${escapeHtml(company_name || "—")}</div>
                <div><strong>Palier :</strong> ${escapeHtml(company_size || "—")}</div>
                <div><strong>Formule :</strong> ${escapeHtml(planLabel)}</div>
              </div>
              <div style="margin-top:14px; font-size:12px; color:#718096;">
                Soumis le ${escapeHtml(now)}
              </div>
            </td></tr>
          </table>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

    await sendResendEmail({ to: RECIPIENTS, subject, html });
    log.debug("📧 Admin signup notif sent", { email, plan: desired_plan });
  } catch (e) {
    // Non-bloquant : on n'echoue pas l'inscription du user si la notif admin foire
    log.warn("⚠️ Admin signup notif failed (non-bloquant):", safeError(e));
  }
}

function escapeHtml(s = "") {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


// ==========================================
// ⚙️ CONFIGURATION
// ==========================================
const isProduction = process.env.NODE_ENV === 'production';

// ⚠️ DÉCLARATION GLOBALE DE SUPABASE
let supabase;

const SUBSCRIPTION_TYPES = {
  TRIAL: 'trial',
  PAID: 'paid',
};



// ==========================================
// 🗄️ INITIALISATION SUPABASE
// ==========================================

try {
  // ⚠️ CE DOIT ÊTRE LA SERVICE_ROLE_KEY
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false
      }
    }
  );
} catch (error) {
  process.exit(1);
}


// ==========================================
// 🗄️ DEUX CLIENTS SUPABASE
// ==========================================
// ==========================================
// 🗄️ DEUX CLIENTS SUPABASE - SOLUTION DÉFINITIVE
// ==========================================


// 1. CLIENT AUTH (pour l'authentification Supabase) - ANON_KEY
const supabaseAuth = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    }
  }
);

// 2. CLIENT ADMIN (pour tes tables) - SERVICE_ROLE_KEY
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  }
);






// 🔄 SYSTÈME DE RÉESSAI EXPONENTIEL
async function withRetry(fn, { retries = 3, baseDelayMs = 500 } = {}) {
  let lastErr;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt === retries) break;

      const sleep = baseDelayMs * attempt; // 500ms, 1s, 1.5s...
      await new Promise(r => setTimeout(r, sleep));
    }
  }

  throw lastErr;
}

// ✅ HEALTH-CHECK SIMPLE (pas avec auth.getUser())
app.get('/api/health/supabase', async (req, res) => {
  try {
    // ✅ Test simple: lister les buckets
    const { data, error } = await supabase.storage.listBuckets();


    if (error) {
      log.error("❌ Health check Supabase error:", safeError(error));
      return res.status(500).json({ ok: false, error: "SUPABASE_UNAVAILABLE" });
    }


    res.json({
      ok: true,
      buckets: data.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    log.error('🔴 Health check Supabase KO:', safeError(error));

    if (IS_PROD) {
      return res.status(500).json({ ok: false, error: "SUPABASE_UNAVAILABLE" });
    }

    return res.status(500).json({
      ok: false,
      error: "Supabase indisponible",
      details: safeDetails(error),
    });
  }

});


// Deploiement Vercel voir la vrai IP
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), fullscreen=(self)"
  );
  next();
});

// JWT secret : obligatoire en prod, fallback random seulement en dev
const SECRET_KEY = (() => {
  const env = (process.env.NODE_ENV || "development").toLowerCase();
  const fromEnv = process.env.JWT_SECRET;

  if (IS_PROD && !fromEnv) {
    console.error("❌ JWT_SECRET manquant en production. Ajoute la variable d'environnement JWT_SECRET.");
    process.exit(1);
  }
  return fromEnv || crypto.randomBytes(64).toString("hex");
})();


// 🔥 GZIP - Compression des réponses (60-70% de bande passante en moins)
app.use(compression());

// 🔥 HELMET - Headers de sécurité complets
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-hashes'",
        "https://js.stripe.com",
        "https://cdn.jsdelivr.net"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://fonts.googleapis.com"
      ],
      fontSrc: [
        "'self'",
        "data:",
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/",
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts/",
        "https://fonts.gstatic.com"
      ],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      mediaSrc: [
        "'self'",
        "data:",
        "blob:",
        "https://iugkvzstqwmjfzuuhwao.supabase.co",
        "https://*.supabase.co"
      ],
      connectSrc: [
        "'self'",
        // Supabase
        "https://iugkvzstqwmjfzuuhwao.supabase.co",
        "wss://iugkvzstqwmjfzuuhwao.supabase.co",
        // Stripe
        "https://api.stripe.com",
        "https://m.stripe.network",
        "https://r.stripe.com",
        // Resend
        "https://api.resend.com",
        "https://api.integora.fr",

      ],
      frameSrc: [
        "'self'",
        // Stripe Checkout & Payment Links
        "https://js.stripe.com",
        "https://hooks.stripe.com",
        "https://checkout.stripe.com",
        "https://buy.stripe.com"
      ],
      objectSrc: ["'none'"],
      workerSrc: ["'self'", "blob:"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// 🔥 RATE LIMITING AGGRESSIF (auth)
const { ipKeyGenerator } = require("express-rate-limit");

const authLimiter = rateLimit({
  windowMs: 2 * 60 * 1000,
  max: 10,
  message: { error: "Trop de tentatives. Réessayez dans 2 minutes." },
  standardHeaders: true,
  legacyHeaders: false,

  skip: (req) => req.method === "OPTIONS",

  keyGenerator: (req, res) => {
    const email = (req.body?.email || "").toString().trim().toLowerCase();
    return `${ipKeyGenerator(req, res)}:${email}`;
  },

  // ✅ AJOUT: réponse UX propre quand limite dépassée
  handler: (req, res, next, options) => {
    const accept = req.headers.accept || "";
    const wantsHtml = accept.includes("text/html");

    // (optionnel) aide navigateur + front à gérer le retry
    res.setHeader("Retry-After", "120");

    // Toujours 429
    res.status(429);

    // Si c'est une navigation web -> page HTML stylée
    if (wantsHtml) {
      return res.redirect(302, "/429.html");
      // alternative: return res.sendFile(path.join(__dirname, "../frontend/429.html"));
    }

    // Sinon (fetch/ajax) -> JSON propre
    return res.json(options.message || { error: "Trop de tentatives. Réessayez dans 2 minutes." });
  },
});


// rate limite formulaire contact
const supportLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, res) => {
    const uid = req.user?.id || "anon";
    return `${uid}:${ipKeyGenerator(req, res)}`;
  },
});



const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,

  // ✅ IMPORTANT: ne pas limiter les pages d'erreur + les assets statiques
  skip: (req) => {
    if (req.method === "OPTIONS") return true;

    // Ne JAMAIS limiter les pages d'erreur (sinon boucle infinie sur /429.html)
    const errorPages = new Set([
      "/401.html",
      "/403.html",
      "/404.html",
      "/429.html",
      "/500.html",
      "/subscription-expired.html",
    ]);
    if (errorPages.has(req.path)) return true;

    // Ne pas limiter les assets statiques (sinon tu atteins vite la limite juste en chargeant une page)
    if (
      req.path.startsWith("/app/css") ||
      req.path.startsWith("/app/js") ||
      req.path.startsWith("/app/images") ||
      req.path.startsWith("/app/assets") ||
      req.path.startsWith("/app/fonts") ||
      req.path.startsWith("/app/videos")
    ) {
      return true;
    }

    return false;
  },

  handler: (req, res) => {
    const accept = req.headers.accept || "";
    const wantsHtml = accept.includes("text/html");

    // Optionnel : utile pour afficher un compte à rebours propre côté client
    res.setHeader("Retry-After", "30");

    res.status(429);

    if (wantsHtml) {
      return res.sendFile(path.join(FRONTEND_DIR, "429.html"));
    }

    return res.json({
      error: "Trop de requêtes. Réessayez dans une minute.",
      code: "RATE_LIMIT_EXCEEDED",
    });
  },
});



// 🔥 PROTECTION CONTRE LES ATTACKS CONNUES
app.use(cookieParser());
// Limite taille JSON : 10 ko par défaut (sécurité). Exception : les routes de
// synchronisation "document" (collaborateurs / journal) envoient la LISTE COMPLÈTE,
// donc 512 ko. La taille de CHAQUE document reste bornée DANS ces routes (défense en profondeur).
const PILOTAGE_LARGE_JSON_PATHS = new Set([
  '/api/pilotage/collaborators/sync',
  '/api/pilotage/journal/sync',
]);
const _jsonSmall = express.json({ limit: '10kb' });
const _jsonLarge = express.json({ limit: '512kb' });
app.use((req, res, next) => (PILOTAGE_LARGE_JSON_PATHS.has(req.path) ? _jsonLarge : _jsonSmall)(req, res, next));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));


// Appliquer les limiteurs
app.use(globalLimiter);
app.use('/login', authLimiter);
app.use('/inscription', authLimiter);
app.use('/api/verify-token', authLimiter);
app.use('/api/start-trial-invite', authLimiter);
app.use('/api/start-paid-checkout', authLimiter);
// [15 mai 2026] Rate-limit du set initial password (anti-bruteforce)
app.use('/api/auth/set-initial-password', authLimiter);
app.use('/api/resend-activation', authLimiter);
app.use('/api/direct-activate', authLimiter);



// ======================================================
// 🔒 PROD MODE : API ONLY (frontend servi par Vercel)
// ======================================================
if (IS_PROD) {
  app.get("*", (req, res, next) => {
    // ✅ Autoriser les routes API
    if (req.path.startsWith("/api")) return next();

    // ✅ Autoriser config.js si utilisé par le frontend
    if (req.path === "/config.js") return next();

    // ✅ Autoriser uploads / assets si besoin
    if (req.path.startsWith("/uploads")) return next();

    // ❌ Tout le reste = frontend → redirection vers Vercel
    return res.redirect(302, `${FRONTEND_URL}${req.originalUrl}`);
  });
}


// ==================== STATIC PUBLIC / STATIC APP (PROPRE) ====================
const APP_VERSION = "1.1.1"; // ← incrémenter à chaque déploiement
const FRONTEND_DIR = path.join(__dirname, "../frontend");
const APP_DIR = path.join(FRONTEND_DIR, "app");

// ✅ [ADMIN] Liste auto de toutes les pages réelles de l'app (scan 1x, mis en cache).
// page = nom du fichier sans .html (= exactement ce que le mouchard enregistre).
// On garde le dossier (univers) pour regrouper joliment à l'écran. Pages admin exclues (c'est toi).
let _appPagesCache = null;
function getAppPages() {
  if (_appPagesCache) return _appPagesCache;
  const pages = [];
  const walk = (dir, folder) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (e) { return; } // dossier absent (ex: backend API-only sur Render, frontend sur Vercel) → on ignore
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        // on ignore les dossiers techniques (pas des pages)
        if (["css", "js", "images", "assets", "fonts", "videos"].includes(entry.name)) continue;
        walk(full, folder ? `${folder}/${entry.name}` : entry.name);
      } else if (entry.isFile() && entry.name.endsWith(".html")) {
        const name = entry.name.replace(".html", "");
        if (name.startsWith("admin")) continue; // pages admin exclues
        pages.push({ page: name, folder: folder || null });
      }
    }
  };
  walk(APP_DIR, "");
  // Fallback : si le scan disque est vide (backend API-only sur Render, frontend sur Vercel),
  // on lit la liste figée livrée avec le backend (app-pages.json, généré depuis le frontend).
  if (pages.length === 0) {
    try {
      const bundled = JSON.parse(fs.readFileSync(path.join(__dirname, "app-pages.json"), "utf8"));
      if (Array.isArray(bundled) && bundled.length) { _appPagesCache = bundled; return bundled; }
    } catch (e) { /* pas de fallback disponible */ }
  }
  _appPagesCache = pages;
  return pages;
}


// ==================== STATIC VITE "public/" (LOCAL) ====================
const PUBLIC_DIR = path.join(FRONTEND_DIR, "public");

// Sert /assets/* (images, vidéos, etc.) comme Vite/Vercel
app.use(
  "/assets",
  express.static(path.join(PUBLIC_DIR, "assets"), {
    etag: true,
    maxAge: 0, // en dev on évite les caches
  })
);

// (optionnel mais utile) favicon
app.get("/favicon.ico", (req, res) => {
  const fav = path.join(PUBLIC_DIR, "favicon.ico");
  return res.sendFile(fav);
});



// ✅ Public: tout le frontend SAUF /app/*
const publicStatic = express.static(FRONTEND_DIR, { index: false });

app.use((req, res, next) => {
  if (req.path === "/app" || req.path.startsWith("/app/")) return next();
  return publicStatic(req, res, next);
});

// ✅ Assets /app/* (css/js/images/fonts/videos) — CACHE LONG uniquement pour le LOGO
const ONE_YEAR_MS = 1000 * 60 * 60 * 24 * 365;

// CSS/JS outils (entretiens RH, etc.) — sous-dossiers des pages outils
app.use("/app/appui_managerial/outils/css", express.static(path.join(APP_DIR, "appui_managerial", "outils", "css"), { maxAge: IS_PROD ? "7d" : "0", etag: true }));
app.use("/app/appui_managerial/outils/js", express.static(path.join(APP_DIR, "appui_managerial", "outils", "js"), { maxAge: IS_PROD ? "7d" : "0", etag: true }));

// CSS/JS : cache modéré (pas oublier modifier "const APP_VERSION" après un deploiement pour vider cache prod)
app.use("/app/css", express.static(path.join(APP_DIR, "css"), { maxAge: IS_PROD ? "7d" : "0", etag: true }));
app.use("/app/js", express.static(path.join(APP_DIR, "js"), {
  maxAge: IS_PROD ? "7d" : "0",
  etag: true,
  setHeaders(res) {
    res.setHeader("X-App-Version", APP_VERSION);
  }
}));

// ✅ Injecte ?v= sur JS/CSS dans tous les HTML /app/*
app.use("/app", async (req, res, next) => {
  if (!req.path.endsWith(".html")) return next();

  // 🛡️ Anti path traversal : s'assurer que le chemin résolu reste dans APP_DIR
  const filePath = path.join(APP_DIR, req.path);
  const resolved = path.resolve(filePath);
  const appDirResolved = path.resolve(APP_DIR);
  if (resolved !== appDirResolved && !resolved.startsWith(appDirResolved + path.sep)) {
    return res.status(403).send("Forbidden");
  }

  // 🔒 [INVISIBILITÉ ADMIN] /app/admin*.html n'existe (404) QUE pour les non-admins.
  //    Seuls les emails de ADMIN_EMAILS (vérifiés via le cookie) peuvent charger ces pages.
  //    Pour un curieux : page "introuvable" → il ne peut même pas savoir que l'espace admin existe.
  if (/^\/admin[\w-]*\.html$/.test(req.path)) {
    let email = "";
    try {
      const u = await resolveUserFromCookie(req);
      email = String(u?.email || "").trim().toLowerCase();
    } catch (_) { /* pas de session → traité comme non-admin */ }
    if (!email || !ADMIN_EMAILS.has(email)) {
      return res.status(404).sendFile(path.join(FRONTEND_DIR, "404.html"));
    }
  }

  if (!fs.existsSync(resolved)) return next();

  let html = fs.readFileSync(resolved, "utf8");

  html = html.replace(
    /(src|href)="(\/app\/(js|css)\/[^"]+\.(js|css))(\?[^"]*)?">/g,
    (match, attr, url) => {
      const cleanUrl = url.split("?")[0];
      return `${attr}="${cleanUrl}?v=${APP_VERSION}">`;
    }
  );

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.send(html);
});

// Images "générales" (hors assets) : cache 1 mois
app.use(
  "/app/images",
  express.static(path.join(APP_DIR, "images"), {
    etag: true,
    maxAge: IS_PROD ? "30d" : "0",
  })
);

// ✅ Logo : cache 1 mois
app.use(
  "/app/assets/logo",
  express.static(path.join(APP_DIR, "assets", "logo"), {
    etag: true,
    maxAge: IS_PROD ? "30d" : "0",
  })
);

// ✅ Le reste de /app/assets (jeux, illustrations, etc.) : cache 1 mois
app.use(
  "/app/assets",
  express.static(path.join(APP_DIR, "assets"), {
    etag: true,
    maxAge: IS_PROD ? "30d" : "0",
  })
);


// Fonts : cache long OK (elles changent rarement)
app.use(
  "/app/fonts",
  express.static(path.join(APP_DIR, "fonts"), {
    maxAge: ONE_YEAR_MS,
    immutable: true,
    etag: true,
  }),
);

app.use("/app/videos", express.static(path.join(APP_DIR, "videos"), { maxAge: "30d", etag: true }));


// ==================== CGUV (PDF) ====================
const CURRENT_TERMS_VERSION = "14_05_2026"; // <-- mets TA date
const CGUV_FILENAME = `CGUV_INTEGORA_v1.0_${CURRENT_TERMS_VERSION}.pdf`;

app.get("/legal/cguv", (req, res) => {
  // PDF stocké dans: frontend/app/assets/pages_publiques/
  const filePath = path.join(APP_DIR, "..", "public", "legal", CGUV_FILENAME);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send("CGUV introuvables");
  }

  // Important: éviter le cache si tu remplaces un doc
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  return res.sendFile(filePath);
});


// ==================== PAGE-LEVEL ACCESS (SERVER) ====================

// Rank des plans (simple et robuste)
const __planRank = { trial: 0, paid: 1 };

// Pages qui demandent un plan minimal (clé = nom du fichier sans .html)
const PAGE_MIN_PLAN = {
  //connaissance_des_collegues_irl
  "le_pantheon_des_talents": "paid",


  //creativite_irl
  "le_labo_bizarre": "paid",

  //manager autrement
  "carte_rh_express": "paid",
  "30_defis_pour_mieux_manager": "paid",

  //bien_etre_irl
  "instant_zen": "paid",
  "quiz_bien_etre": "paid",

  //competition_amicale
  "challenge_des_tribus": "paid",





  //connaissance_des_collegues_irl
  "qui_est_qui": "paid",
  "si_j_etais": "paid",
  "c_est_moi_ou_pas": "paid",


  //creativite_irl
  "conference_absurde": "trial",
  "histoire_impossible": "paid",
  "a_vous_de_continuer": "paid",
  "7_secondes_chrono": "paid",


  //manager autrement
  "un_mot_pour_avancer": "trial",
  "la_boussole_en_main": "paid",
  "ce_qu_on_ne_dit_pas_assez": "paid",


  //bien_etre_irl
  "chasse_au_bonheur": "paid",


  //collaboration_irl
  "le_relai_des_mimes": "paid",
  "switch": "trial",


  // RECRUTEMENT
  "fiche_de_poste": "trial",
  "fiche_de_poste_outil": "trial",
  "rediger_offre_recrutement": "trial",
  "guide_recrutement": "trial",
  "recrutement_collectif": "paid",
  "communication_candidat": "paid",


  // INTEGRAION
  "livret_accueil": "paid",
  "processus_integration": "trial",
  "parrain_marraine": "paid",
  "tableau_pilotage_des_formations": "paid",
  "intineraire_de_professionnalisation": "paid",




};


// Convertit un chemin /app/.../*.html en "nom de page" (sans dossier, sans .html, sans query/hash)
// Exemple: "/manager_autrement/carte_rh_express.html?x=1#top" -> "carte_rh_express"
function getPageNameFromAppPath(appPath) {
  const clean = (appPath || "").split("?")[0].split("#")[0];
  const parts = clean.split("/").filter(Boolean);
  const last = parts[parts.length - 1] || "";
  return last.replace(/\.html$/i, "");
}

function canAccessPageServer(user, pageName) {
  const required = PAGE_MIN_PLAN[pageName];
  if (!required) return true; // page non listée => autorisée

  const userPlan = user?.subscription_type || "trial";
  const userRank = __planRank[userPlan] ?? 0;
  const reqRank = __planRank[required] ?? 999;

  return userRank >= reqRank;
}


function hasAnyAuthToken(req) {
  const authHeader = String(req.headers.authorization || "");
  if (authHeader.toLowerCase().startsWith("bearer ")) return true;

  const cookie = String(req.headers.cookie || "");
  // Mets ici les noms de cookies que TON backend utilise réellement :
  // (tu peux en laisser plusieurs, ça ne casse rien)
  return (
    cookie.includes("auth_token=") ||
    cookie.includes("token=") ||
    cookie.includes("access_token=") ||
    cookie.includes("sb-access-token=") ||
    cookie.includes("sb:token=")
  );

}



// ✅ Gate /app : protège UNIQUEMENT les pages HTML + contrôle plan (server-side)
app.use("/app", (req, res, next) => {
  const isAsset = /\.[a-z0-9]+$/i.test(req.path) && !req.path.endsWith(".html");
  if (isAsset) return next(); // les assets passent

  return authenticateToken(req, res, () => {
    // ✅ Profil accessible même avec abonnement expiré (pour renouveler)
    const pageName = getPageNameFromAppPath(req.path);
    const exemptPages = ["profile"];

    // 0) Compte suspendu par un admin -> bloqué partout (avant tout le reste, même profile)
    if (req.user?.suspended) {
      return res.status(403).sendFile(path.join(FRONTEND_DIR, "account-suspended.html"));
    }

    // 1) Abonnement actif requis pour tout /app (sauf pages exemptées)
    if (!req.user?.has_active_subscription && !exemptPages.includes(pageName)) {
      return res.status(403).sendFile(path.join(FRONTEND_DIR, "subscription-expired.html"));
    }

    // 2) Contrôle plan par page
    if (!canAccessPageServer(req.user, pageName)) {
      // ✅ Si le user n'a pas le plan requis pour cette page, on redirige vers 403
      return res.redirect(302, "/403.html");
    }

    return next();
  });
});


// ✅ Pages /app (sert les .html après gate)
app.get("/app/*", (req, res) => {
  const fullPath = req.params[0] || "";

  // si quelqu’un demande un asset et qu’il arrive ici => 404 (évite fallback html)
  if (/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|webm)$/i.test(fullPath)) {
    return res.status(404).end();
  }

  // racine /app => page d’accueil app
  if (fullPath === "" || fullPath === "/" || fullPath === "index" || fullPath === "index.html") {
    return res.sendFile(path.join(APP_DIR, "choix_irl_digital.html"));
  }

  // candidates
  const candidates = [
    path.join(APP_DIR, fullPath),
    path.join(APP_DIR, fullPath + ".html"),
    path.join(APP_DIR, fullPath, fullPath + ".html"),
  ];

  for (const p of candidates) {
    if (fs.existsSync(p)) return res.sendFile(p);
  }

  // ✅ FIX B22 — Vraie 404 au lieu de servir silencieusement la page d'accueil
  return res.status(404).sendFile(path.join(APP_DIR, "..", "404.html"));
});

//middleware empechant POST PUT, ect site externe

function enforceSameSiteForMutations(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();

  // ✅ Exempter les endpoints cron (appels serveur-à-serveur depuis Supabase pg_net, pas d'Origin)
  if (req.path.startsWith("/api/cron/")) return next();

  const origin = req.headers.origin || "";
  const referer = req.headers.referer || "";

  const allowed = (o) =>
    ALLOWED_ORIGINS.has(o) ||
    (!IS_PROD && /^https:\/\/integora-frontend-.*\.vercel\.app$/.test(o));


  // si origin est présent => on le valide
  if (origin) {
    if (!allowed(origin)) return res.status(403).json({ error: "Origin interdit" });
    return next();
  }

  // fallback referer (certains navigateurs / cas)
  if (referer) {
    try {
      const refOrigin = new URL(referer).origin;
      if (!allowed(refOrigin)) return res.status(403).json({ error: "Referer interdit" });
      return next();
    } catch {
      return res.status(403).json({ error: "Referer invalide" });
    }
  }

  // ✅ FIX B7 — En prod, bloquer les mutations sans Origin ni Referer
  if (IS_PROD) return res.status(403).json({ error: "Origin requis" });

  return next();
}

app.use(enforceSameSiteForMutations);

function requireJson(req, res, next) {
  // On ne force pas le JSON sur les méthodes non mutantes
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();

  // Seulement pour l'API
  if (!req.path.startsWith("/api/")) return next();

  // ✅ Autoriser les uploads multipart (avatar, support, etc.)
  if (req.is("multipart/form-data")) return next();

  // ✅ Autoriser JSON normal
  if (req.is("application/json")) return next();

  // ✅ Autoriser body vide (certains DELETE/POST sans body)
  const len = Number(req.headers["content-length"] || 0);
  if (!len) return next();

  return res.status(415).json({
    error: "Content-Type application/json ou multipart/form-data requis",
  });
}

app.use(requireJson);







// -------------------------------------------------------
// 🔒 CSRF sécurisé (double-submit cookie)
// -------------------------------------------------------

// 🛡️ Comparaison en temps constant (protège des timing attacks)
function safeEqual(a, b) {
  const ba = Buffer.from(String(a ?? ""), "utf8");
  const bb = Buffer.from(String(b ?? ""), "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}


// → 1. S'assurer qu'un token existe en cookie lisible


// → 2. Vérifier le token pour les méthodes mutantes
function validateCSRF(req, res, next) {
  // On protège uniquement les méthodes qui modifient
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  // ✅ SAFE: req.path peut être undefined selon le contexte (proxy, libs, tests)
  const p =
    typeof req.path === "string"
      ? req.path
      : (typeof req.originalUrl === "string"
        ? req.originalUrl.split("?")[0]
        : "");

  if (!p.startsWith("/api/")) return next();

  log.debug("🧪 CSRF CHECK", {
    method: req.method,
    path: p,
    url: req.url,
    originalUrl: req.originalUrl,
  });


  // ✅ Routes publiques (signup / paiement) : pas de CSRF, sinon blocage
  const exempt = new Set([
    '/login',
    '/inscription',
    '/verify-token',
    '/api/verify-token',

    // ✅ nouveau flow
    '/api/start-paid-checkout',
    '/api/complete-signup',
    '/api/start-trial-invite',
    '/api/resend-activation',
    '/api/finalize-pending',
    '/api/direct-activate',

    // ✅ [15 mai 2026] Set du mdp initial via API admin (evite l'email "Password changed"
    //    de Supabase pour la creation initiale). Authentifie via access_token Supabase.
    '/api/auth/set-initial-password',

    // ✅ PUBLIC CONTACT
    '/api/contact/ticket',

    // ✅ CRON (appelé par Supabase pg_cron, pas de cookies/CSRF)
    '/api/cron/expiration-reminders',

  ]);

  // ✅ Important : exempt doit être testé sur p (déjà nettoyé)
  if (exempt.has(p)) return next();

  // ✅ Pour debug (tu peux retirer plus tard)
  log.debug("🛡️ CSRF protected route", { p, method: req.method });

  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies['XSRF-TOKEN'];

  if (!headerToken || !cookieToken || !safeEqual(headerToken, cookieToken)) {
    log.warn("🚨 CSRF Token invalide", {
      method: req.method,
      path: req.path,
      headerToken: headerToken ? "present" : "missing",
      cookieToken: cookieToken ? "present" : "missing",
    });
    return res.status(403).json({ error: "Token CSRF invalide" });
  }

  // ✅ SÉCURITÉ : vérifier que le HMAC correspond à la session actuelle
  const sessionToken = req.cookies?.auth_token || "";
  const parts = headerToken.split(".");
  if (parts.length === 2) {
    const expectedHmac = crypto.createHmac("sha256", process.env.JWT_SECRET)
      .update(parts[0] + sessionToken)
      .digest("hex");
    if (!safeEqual(expectedHmac, parts[1])) {
      log.warn("🚨 CSRF HMAC invalide (session mismatch)");
      return res.status(403).json({ error: "Token CSRF invalide" });
    }
  }


  next();
}


function ensureCsrfToken(req, res, next) {
  try {
    const sessionToken = req.cookies?.auth_token || "";

    // Régénérer si absent OU si la session a changé (le HMAC ne matchera plus)
    const existingCsrf = req.cookies?.["XSRF-TOKEN"];
    if (existingCsrf && sessionToken) {
      // Vérifie que le token existant est encore valide pour cette session
      const parts = existingCsrf.split(".");
      if (parts.length === 2) {
        const expectedHmac = crypto.createHmac("sha256", process.env.JWT_SECRET)
          .update(parts[0] + sessionToken)
          .digest("hex");
        if (safeEqual(expectedHmac, parts[1])) return next(); // token encore valide
      }
    }

    // Générer un nouveau token CSRF lié à la session
    const randomPart = crypto.randomBytes(32).toString("hex");
    const hmac = crypto.createHmac("sha256", process.env.JWT_SECRET)
      .update(randomPart + sessionToken)
      .digest("hex");
    const token = randomPart + "." + hmac;

    res.cookie("XSRF-TOKEN", token, {
      httpOnly: false,
      secure: IS_PROD,
      sameSite: IS_PROD ? "none" : "lax",
      path: "/"
    });

    return next();
  } catch (e) {
    log.error("❌ ensureCsrfToken error:", safeError(e));
    return next();
  }
}

function requireCsrf(req, res, next) {
  const headerToken = req.headers["x-csrf-token"];
  const cookieToken = req.cookies?.["XSRF-TOKEN"];

  if (!headerToken || !cookieToken || !safeEqual(headerToken, cookieToken)) {
    return res.status(403).json({ error: "Token CSRF invalide", code: "CSRF_INVALID" });
  }

  // ✅ SÉCURITÉ : vérifier le HMAC lié à la session
  const sessionToken = req.cookies?.auth_token || "";
  const parts = headerToken.split(".");
  if (parts.length === 2) {
    const expectedHmac = crypto.createHmac("sha256", process.env.JWT_SECRET)
      .update(parts[0] + sessionToken)
      .digest("hex");
    if (!safeEqual(expectedHmac, parts[1])) {
      return res.status(403).json({ error: "Token CSRF invalide", code: "CSRF_INVALID" });
    }
  }

  return next();
}


// ➕ Monte-les AVANT tes routes protégées
app.use(ensureCsrfToken);
app.use(validateCSRF);


// API profil
//const profileRoutes = require('./routes/profile');
//app.use('/api', profileRoutes);


// Routes principales
const FRONT = FRONTEND_URL;

if (process.env.NODE_ENV === "production") {
  // En prod: backend => redirect vers le vrai front (Vercel)
  app.get("/", (req, res) => res.redirect(FRONT));
  app.get("/login", (req, res) => res.redirect(`${FRONT}/login.html`));
  app.get("/inscription", (req, res) => res.redirect(`${FRONT}/inscription.html`));
} else {
  // En local: on sert les pages depuis ../frontend
  app.get("/", (req, res) => res.sendFile(path.join(FRONTEND_DIR, "index.html")));
  app.get("/login", (req, res) => res.sendFile(path.join(FRONTEND_DIR, "login.html")));
  app.get("/inscription", (req, res) => res.sendFile(path.join(FRONTEND_DIR, "inscription.html")));
}

if (process.env.NODE_ENV !== "production") {
  app.get("/dev/recovery-link", devOnly, async (req, res) => {
    try {
      const email = String(req.query.email || "").trim().toLowerCase();
      if (!email) return res.status(400).json({ error: "email manquant" });

      // ⚠️ Optionnel mais recommandé : un secret pour éviter qu’un voisin sur le réseau l’utilise
      const secret = req.headers["x-dev-secret"];
      if (process.env.DEV_TOOLS_SECRET && secret !== process.env.DEV_TOOLS_SECRET) {
        return res.status(403).json({ error: "forbidden" });
      }

      const redirectTo = "http://localhost:3000/reset-password.html";

      const { data, error } = await supabase.auth.admin.generateLink({
        type: "recovery",
        email,
        options: { redirectTo }
      });

      if (error) throw error;

      // data.properties.action_link = lien magique complet
      return res.json({ action_link: data.properties.action_link });
    } catch (e) {
      return res.status(500).json({ error: e?.message || "error" });
    }
  });
}





// Gérer les erreurs CORS
app.use((error, req, res, next) => {
  if (error.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS non autorisé' });
  }
  next(error);
});


// ✅ CONFIG FRONT (prod-safe)
app.get("/config.js", (req, res) => {
  const SUPABASE_URL = process.env.SUPABASE_URL || "";
  const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";

  // Autorise uniquement ton front + local
  const allowedOrigins = [
    "https://integora.fr",
    "https://www.integora.fr",
  ];

  if (!IS_PROD) {
    allowedOrigins.push("http://localhost:3000", "http://localhost:5173");
  }



  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  } else {
    // Si pas d'Origin (ex: curl) => on ne met PAS ACAO:*
    // et si origin inconnu => pas de cross-origin
  }

  res.setHeader("Content-Type", "application/javascript; charset=utf-8");
  res.setHeader("Cache-Control", "no-store, max-age=0");

  // Optionnel : évite certains blocages, ok à garder
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");

  res.send(`
    window.APP_CONFIG = {
      SUPABASE_URL: ${JSON.stringify(SUPABASE_URL)},
      SUPABASE_ANON_KEY: ${JSON.stringify(SUPABASE_ANON_KEY)}
    };
  `);
});



// ==================== ROUTES PROPRES (SLUG -> FICHIER) ====================
// - public:true  => fichier dans /frontend (pas besoin de compte)
// - public:false => fichier dans /frontend/app (compte + abonnement requis)

const ROUTES_PROPRES = {
  // ==================== PUBLIC (frontend/) ====================
  "accueil": { fichier: "index", public: true },
  "produit": { fichier: "produit", public: true },
  "tarifs": { fichier: "tarif", public: true },
  "contact": { fichier: "contact", public: true },
  "faq": { fichier: "faq", public: true },
  "mentions-legales": { fichier: "mentions_legales", public: true },
  "politique-de-confidentialite": { fichier: "politique_de_confidentialite", public: true },
  "valeurs": { fichier: "valeur_adn", public: true },
  "statut": { fichier: "status", public: true },
  "bienvenue": { fichier: "welcome", public: true },

  // Auth publiques
  "connexion": { fichier: "login", public: true },
  "inscription": { fichier: "inscription", public: true },
  "mot-de-passe-oublie": { fichier: "forgot-password", public: true },
  "reinitialiser-mdp": { fichier: "reset-password", public: true },
  "creer-mot-de-passe": { fichier: "create-password", public: true },

  // Pages système utiles en public (OK)
  "email-envoye": { fichier: "email-sent", public: true },
  "email-envoye-paiement": { fichier: "email-sent-paiement", public: true },
  "paiement-redirect": { fichier: "paiement-redirect", public: true },
  "abonnement-expire": { fichier: "subscription-expired", public: true },

  // ⚠️ On NE mappe PAS les pages d'erreur (elles restent accessibles via /403.html etc.)
  // 401.html / 403.html / 404.html / 429.html / 500.html


  // ==================== PRIVE (frontend/app/) ====================
  // ⭐ Alias marketing (recommandés)
  "espace": { fichier: "choix_irl_digital", public: false },     // ton "accueil app"
  "jeu-irl": { fichier: "jeu_irl", public: false },
  "profil": { fichier: "profile", public: false },
  "support": { fichier: "support", public: false },

  // --- Hubs / catégories
  "bien-etre": { fichier: "bien_etre_irl/bien_etre_irl", public: false },
  "collaboration": { fichier: "collaboration_irl/collaboration_irl", public: false },
  "competition-amicale": { fichier: "competition_amicale/competition_amicale", public: false },
  "connaissance-collegues": { fichier: "connaissance_des_collegues_irl/connaissance_des_collegues_irl", public: false },
  "creativite": { fichier: "creativite_irl/creativite_irl", public: false },
  "integration": { fichier: "integration/page_integration", public: false },
  "recrutement": { fichier: "recrutement/page_recrutement", public: false },
  "outils-manager": { fichier: "appui_managerial/page_appui_managerial", public: false },
  "manager": { fichier: "manager_autrement/manager_autrement", public: false },

  // --- Bien-être IRL (pages)
  "chasse-au-bonheur": { fichier: "bien_etre_irl/chasse_au_bonheur", public: false },
  "instant-zen": { fichier: "bien_etre_irl/instant_zen", public: false },
  "quiz-bien-etre": { fichier: "bien_etre_irl/quiz_bien_etre", public: false },

  // --- Collaboration IRL
  "le-relai-des-mimes": { fichier: "collaboration_irl/le_relai_des_mimes", public: false },
  "switch": { fichier: "collaboration_irl/switch", public: false },

  // --- Compétition amicale
  "challenge-des-tribus": { fichier: "competition_amicale/challenge_des_tribus", public: false },

  // --- Connaissance collègues IRL
  "c-est-moi-ou-pas": { fichier: "connaissance_des_collegues_irl/c_est_moi_ou_pas", public: false },
  "ile-deserte-corporate": { fichier: "connaissance_des_collegues_irl/ile_deserte_corporate", public: false },
  "le-pantheon-des-talents": { fichier: "connaissance_des_collegues_irl/le_pantheon_des_talents", public: false },
  "photo-de-voyage": { fichier: "connaissance_des_collegues_irl/photo_de_voyage", public: false },
  "qui-est-qui": { fichier: "connaissance_des_collegues_irl/qui_est_qui", public: false },
  "si-j-etais": { fichier: "connaissance_des_collegues_irl/si_j_etais", public: false },

  // --- Créativité IRL
  "7-secondes-chrono": { fichier: "creativite_irl/7_secondes_chrono", public: false },
  "a-vous-de-continuer": { fichier: "creativite_irl/a_vous_de_continuer", public: false },
  "conference-absurde": { fichier: "creativite_irl/conference_absurde", public: false },
  "histoire-impossible": { fichier: "creativite_irl/histoire_impossible", public: false },
  "invento": { fichier: "creativite_irl/invento", public: false },
  "le-labo-bizarre": { fichier: "creativite_irl/le_labo_bizarre", public: false },

  // --- Intégration
  "livret-accueil": { fichier: "integration/livret_accueil", public: false },
  "processus-integration": { fichier: "integration/processus_integration", public: false },
  "parrain-marraine": { fichier: "integration/parrain_marraine", public: false },
  "tableau-pilotage-formations": { fichier: "integration/tableau_pilotage_des_formations", public: false },
  "itineraire-professionnalisation": { fichier: "integration/intineraire_de_professionnalisation", public: false },
  "rapport-etonnement": { fichier: "integration/rapport_etonnement", public: false },

  // --- Manager autrement
  "30-defis-manager": { fichier: "manager_autrement/30_defis_pour_mieux_manager", public: false },
  "cartes-rh-express": { fichier: "manager_autrement/carte_rh_express", public: false },
  "ce-qu-on-ne-dit-pas-assez": { fichier: "manager_autrement/ce_qu_on_ne_dit_pas_assez", public: false },
  "la-boussole-en-main": { fichier: "manager_autrement/la_boussole_en_main", public: false },
  "thermometre-semaine": { fichier: "manager_autrement/le_thermometre_de_la_semaine", public: false },
  "un-mot-pour-avancer": { fichier: "manager_autrement/un_mot_pour_avancer", public: false },

  // --- Recrutement
  "fiche-de-poste": { fichier: "recrutement/fiche_de_poste", public: false },
  "fiche-de-poste-outil": { fichier: "recrutement/fiche_de_poste_outil", public: false },
  "rediger-offre-recrutement": { fichier: "recrutement/rediger_offre_recrutement", public: false },
  "guide-recrutement": { fichier: "recrutement/guide_recrutement", public: false },
  "recrutement-collectif": { fichier: "recrutement/recrutement_collectif", public: false },
  "communication-candidat": { fichier: "recrutement/communication_candidat", public: false },
  "grille-entretien": { fichier: "recrutement/grille_entretien", public: false },

  // --- Outils manager
  "thermometre-tensions-outil": {
    fichier: "appui_managerial/outils/thermometre_des_situations",
    public: false
  },
  "thermometre-tensions-fiche": {
    fichier: "appui_managerial/fiches/thermometre_des_situations_guide",
    public: false
  },



  // ==================== ALIAS "compat" (optionnel) ====================
  // Tu peux les garder le temps de mettre à jour tes liens
  "choix-irl-digital": { fichier: "choix_irl_digital", public: false },
  "profile": { fichier: "profile", public: false },
};




// ==================== ROUTE UNIVERSELLE (SLUG) ====================
// Sert soit /frontend/<fichier>.html (public)
// soit /frontend/app/<fichier>.html (privé)
// Sécurité privés : login requis + abonnement actif + PAGE_MIN_PLAN (plan par page)

app.get("/:page", async (req, res) => {
  try {
    log.debug("ROUTE_SLUG_OK =>", req.path);

    const slug = String(req.params.page || "").replace(".html", "").toLowerCase();
    const config = ROUTES_PROPRES[slug];
    const RESERVED = new Set(["api", "app", "stripe", "health"]);
    if (RESERVED.has(slug)) return res.status(404).sendFile(path.join(__dirname, "../frontend/404.html"));


    // 1) slug inconnu => 404
    if (!config) {
      return res.status(404).sendFile(path.join(__dirname, "../frontend/404.html"));
    }

    const { fichier, public: estPublique } = config;

    // 2) Pages publiques => accès direct frontend/
    if (estPublique) {
      const filePath = path.join(__dirname, `../frontend/${fichier}.html`);
      return fs.existsSync(filePath)
        ? res.sendFile(filePath)
        : res.status(404).sendFile(path.join(__dirname, "../frontend/404.html"));
    }

    // 3) Pages privées => auth requise
    // Si pas de token du tout => redirection UX vers login (au lieu d'un 401 JSON)
    if (!hasAnyAuthToken(req)) {
      log.warn(`🚨 Accès non authentifié (aucun token): ${slug}`);
      return res.redirect(`/login?next=/${slug}`);
    }

    return authenticateToken(req, res, () => {
      if (!req.user) {
        log.warn(`🚨 Accès non authentifié (token invalide/expiré): ${slug}`);
        return res.redirect(`/login?next=/${slug}`);
      }

      // 4) Abonnement actif requis
      if (!req.user.has_active_subscription) {
        log.warn(`🚨 Abonnement inactif: ${slug} (${safeUserTag(req.user)})`);
        return res.status(403).sendFile(path.join(__dirname, "../frontend/subscription-expired.html"));
      }

      // 5) Contrôle plan (PAGE_MIN_PLAN)
      const pageName = String(fichier).split("/").pop();
      if (!canAccessPageServer(req.user, pageName)) {
        return res.redirect(302, "/403.html");
      }

      // 6) Serve page privée
      const filePathPriv = path.join(__dirname, `../frontend/app/${fichier}.html`);
      if (!fs.existsSync(filePathPriv)) {
        return res.status(404).sendFile(path.join(__dirname, "../frontend/404.html"));
      }

      return res.sendFile(filePathPriv);
    });


  } catch (error) {
    log.error("💥 Erreur route universelle:", safeError(error));
    return res.status(500).sendFile(path.join(__dirname, "../frontend/500.html"));
  }
});



// ---------------------------
// FONCTIONS UTILITAIRES
// ---------------------------
//Helper 1 — texte “strict” (entreprise, fonction)
function cleanTextStrict(v, { max, allowEmpty = false } = {}) {
  if (typeof v !== "string") return allowEmpty ? null : "";
  const s = v.trim();
  if (!s) return allowEmpty ? null : "";
  if (s.length > max) return s.slice(0, max);

  if (/[<>]/.test(s) || /[\r\n\t]/.test(s)) return "";
  if (/(https?:\/\/|www\.)/i.test(s)) return "";

  const ok = /^[A-Za-zÀ-ÖØ-öø-ÿ0-9][A-Za-zÀ-ÖØ-öø-ÿ0-9\s.,&'()\/-]*$/.test(s);
  return ok ? s : "";
}


function rejectIfBadChars(s) {
  if (typeof s !== "string") return "";
  if (/[<>"']/.test(s)) return "";          // bloque < > " '
  if (/[\r\n\t]/.test(s)) return "";        // bloque retours ligne / tabs
  if (/(https?:\/\/|www\.)/i.test(s)) return ""; // bloque URLs
  return s;
}

function cleanDigitsStrict(v, { min, max, allowEmpty = true } = {}) {
  if (typeof v !== "string") return allowEmpty ? null : "";
  let s = v.trim();
  if (!s) return allowEmpty ? null : "";
  s = rejectIfBadChars(s);
  if (!s) return ""; // rejet
  if (!/^\d+$/.test(s)) return ""; // que des chiffres
  if (min && s.length < min) return "";
  if (max && s.length > max) return "";
  return s;
}

// Lettres (accents OK) + espaces + tirets + apostrophes + points
function cleanNameLike(v, { min = 0, max = 64, allowEmpty = true } = {}) {
  if (typeof v !== "string") return allowEmpty ? null : "";
  let s = v.trim();
  if (!s) return allowEmpty ? null : "";
  s = rejectIfBadChars(s);
  if (!s) return "";
  if (s.length > max) s = s.slice(0, max);

  const re = /^[\p{L}][\p{L}\p{M}\s\-'.]{0,}$/u;
  if (!re.test(s)) return "";
  if (min && s.length < min) return "";
  return s;
}


/** ✅ Pays : ISO2 strict (FR, BE, ...).
 *  Accepte aussi "France" / "FRANCE" etc (compat anciennes valeurs) => FR
 *  Retourne null si invalide
 */
function normalizeCountryISO2(input) {
  const v = String(input ?? "").trim();
  if (!v) return null;

  const up = v.toUpperCase();
  if (/^[A-Z]{2}$/.test(up)) return up;

  const normalized = v
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim();

  const map = {
    "france": "FR",
    "belgique": "BE",
    "luxembourg": "LU",
    "suisse": "CH",
    "allemagne": "DE",
    "espagne": "ES",
    "italie": "IT",
    "royaume-uni": "GB",
    "royaume uni": "GB",
    "pays-bas": "NL",
    "pays bas": "NL",
  };

  return map[normalized] || null;
}



// ==================== SYNC FACTURATION (Supabase -> Stripe Customer) ====================
// Ne touche qu'au Customer Stripe (affichage facture), pas aux abonnements.
async function syncStripeCustomerBillingFromDb({ userId, stripeCustomerId, requireComplete = true }) {
  // 1) Lire profil + entreprise
  const { data: prof, error: profErr } = await supabaseAdmin
    .from("profiles")
    .select(`
      first_name,
      last_name,
      company_id,
      companies:company_id (
        legal_name,
        display_name,
        company_siret,
        billing_street,
        billing_postal_code,
        billing_city,
        billing_country
      )
    `)
    .eq("user_id", userId)
    .maybeSingle();

  if (profErr) {
    log.warn("⚠️ syncStripeCustomerBillingFromDb: profiles read error:", profErr);
    if (requireComplete) throw new Error("Erreur lecture profil/entreprise");
    return { ok: false, reason: "db_read_error" };
  }

  let company = prof?.companies || null;

  // [15 mai 2026] Fallback owner_id : pour les comptes legacy ou les cas
  // ou profile.company_id n'a jamais ete lie a la company (alors qu'elle
  // existe via companies.owner_id), on tente une 2eme requete avant de
  // declarer les infos manquantes. Meme correctif que pour le devis 50+.
  if (!company) {
    const { data: companyByOwner, error: ownerErr } = await supabaseAdmin
      .from("companies")
      .select(`
        legal_name,
        display_name,
        company_siret,
        billing_street,
        billing_postal_code,
        billing_city,
        billing_country
      `)
      .eq("owner_id", userId)
      .maybeSingle();
    if (ownerErr) {
      log.warn("⚠️ syncStripeCustomerBillingFromDb: companies(owner_id) read error:", ownerErr);
    } else if (companyByOwner) {
      company = companyByOwner;
      log.debug("ℹ️ syncStripeCustomerBillingFromDb: company resolved via owner_id fallback", { userId });
    }
  }

  const legalName = company?.legal_name || null;
  const displayName = company?.display_name || null;
  const siretRaw = company?.company_siret || null;

  const street = company?.billing_street || null;
  const postal = company?.billing_postal_code || null;
  const city = company?.billing_city || null;
  const country = company?.billing_country || null;

  // 2) Normalisations strictes
  const siret = siretRaw ? String(siretRaw).replace(/\s+/g, "") : null;
  const siren = siret && siret.length >= 9 ? siret.slice(0, 9) : null;

  const countryIso2 = country ? normalizeCountryISO2(country) : null;

  // 3) Si requireComplete: on fail-hard (utile pour trial -> paiement / upgrade / prépay)
  if (requireComplete) {
    const missing = [];
    if (!legalName) missing.push("raison sociale");
    if (!siret || siret.length !== 14) missing.push("SIRET (14 chiffres)");
    if (!street) missing.push("adresse");
    if (!postal) missing.push("code postal");
    if (!city) missing.push("ville");
    if (!countryIso2) missing.push("pays");

    if (missing.length) {
      const msg = `Informations légales/facturation manquantes: ${missing.join(", ")}.`;
      const err = new Error(msg);
      err.code = "BILLING_INCOMPLETE";
      throw err;
    }
  }

  // 4) Construire le "name" Customer (raison sociale en priorité)
  const customerName =
    displayName ||
    legalName ||
    `${prof?.first_name || ""} ${prof?.last_name || ""}`.trim() ||
    "Client";

  // 5) Update Stripe customer (facture)
  await stripe.customers.update(stripeCustomerId, {
    name: customerName,
    preferred_locales: ["fr"],
    address: {
      line1: street || undefined,
      postal_code: postal || undefined,
      city: city || undefined,
      country: countryIso2 || undefined,
    },
    invoice_settings: {
      custom_fields: [
        ...(legalName ? [{ name: "Raison sociale", value: String(legalName).slice(0, 120) }] : []),
        ...(siret ? [{ name: "SIRET", value: siret }] : []),
        ...(siren ? [{ name: "SIREN", value: siren }] : []),
        ...(((prof?.first_name || prof?.last_name) ? [{
          name: "Contact",
          value: `${prof?.first_name || ""} ${prof?.last_name || ""}`.trim().slice(0, 120),
        }] : [])),
      ].slice(0, 4), // ⚠️ Stripe max 4 custom fields
    },

    metadata: {
      source: "integora_profile_billing",
      user_id: userId,
      company_id: prof?.company_id || "",
      company_siret: siret || "",
      company_legal_name: legalName || "",
    },
  });

  return { ok: true };
}


// Adresse : autorise lettres/chiffres/espaces/virgule/point/tiret/apostrophe/#/()
function cleanAddress(v, { min = 0, max = 140, allowEmpty = true } = {}) {
  if (typeof v !== "string") return allowEmpty ? null : "";
  let s = v.trim();
  if (!s) return allowEmpty ? null : "";
  s = rejectIfBadChars(s);
  if (!s) return "";
  if (s.length > max) s = s.slice(0, max);

  // autorise : lettres, chiffres, espaces, , . - ' # / ( )
  const re = /^[\p{L}\p{M}\d\s,.\-'/#()]+$/u;
  if (!re.test(s)) return "";
  if (min && s.length < min) return "";
  return s;
}


//Helper 2 — nom/prénom (lettres + tiret)
function cleanPersonName(v, { max } = {}) {
  if (typeof v !== "string") return "";
  const s = v.trim();
  if (!s) return "";
  if (s.length > max) return s.slice(0, max);

  const ok = /^[A-Za-zÀ-ÖØ-öø-ÿ-]+$/.test(s);
  return ok ? s : "";
}

//Helper 3 — message (libre mais safe)
function cleanMessage(v, { max } = {}) {
  if (typeof v !== "string") return "";
  // ✅ FIX B10 — Retirer les balises HTML (protection XSS stocké)
  const s = v.trim().replace(/<[^>]*>/g, "");
  if (!s) return "";
  return s.length > max ? s.slice(0, max) : s;
}



// server.js - AJOUTE CE MIDDLEWARE CORS COMPLET


function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function decodeJwtPayload(token) {
  try {
    const payload = token.split(".")[1];
    const json = Buffer.from(payload, "base64url").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}


// Vérifie si un abonnement est actif et valide
async function getActiveSubscription(userId) {

  const { data: sub, error } = await supabase
    .from('subscriptions')
    .select('plan, status, started_at, created_at, current_period_end, trial_end, access_locked, access_locked_reason')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  if (error || !sub) {
    return {
      plan: 'trial',
      hasActiveSubscription: false,
      status: 'inactive'
    };
  }

  const now = new Date();
  const plan = String(sub.plan || 'trial').toLowerCase();
  const status = String(sub.status || '').toLowerCase();



  const paidPlans = ['paid'];

  // Calcul de la date de début (started_at prime sur created_at)
  const startedAt = sub.started_at ? new Date(sub.started_at) :
    sub.created_at ? new Date(sub.created_at) : null;


  // ✅ FIN CALCULÉE POUR PLANS PAYANTS : N+1 an
  const derivedPaidEnd = (() => {
    if (!startedAt) {
      return null;
    }
    const d = new Date(startedAt);
    d.setFullYear(d.getFullYear() + 1); // N+1 (1 an)
    return d;
  })();

  // current_period_end prime, sinon on utilise N+1
  const paidEnd = sub.current_period_end ? new Date(sub.current_period_end) : derivedPaidEnd;


  // ✅ PLANS PAYANTS : Active si statut valide ET (pas de date de fin OU date non dépassée)
  const isPaidActive =
    paidPlans.includes(plan) &&
    ['active', 'past_due', 'trialing'].includes(status) &&
    (paidEnd === null || paidEnd >= now); // ✅ Accepte paidEnd NULL


  // ✅ TRIAL : Active seulement si trial_end défini ET non expiré
  const trialEnd = sub.trial_end ? new Date(sub.trial_end) : null;
  const isTrialActive =
    plan === 'trial' &&
    status === 'trialing' &&
    trialEnd && trialEnd >= now; // ❌ trial_end NULL = trial inactif


  // ✅ Suspension ADMIN uniquement (on ne bloque PAS les impayés "past_due" qui gardent leur grâce)
  const suspended = sub.access_locked === true
    && String(sub.access_locked_reason || '').toLowerCase() === 'admin_suspended';

  const result = {
    plan,
    status,
    hasActiveSubscription: isPaidActive || isTrialActive,
    suspended,
    started_at: sub.started_at,
    current_period_end: sub.current_period_end,
    trial_end: sub.trial_end,
    derived_paid_end: derivedPaidEnd?.toISOString() // Pour debug
  };

  return result;
}

// Automatisation expiration abonnement verification si il est renouvelé 
async function applyPendingPrepaymentIfNeeded(userId) {
  try {
    const { data, error } = await supabaseAdmin.rpc("apply_pending_prepayment", {
      p_user_id: userId,
    });

    if (error) {
      log.warn("⚠️ apply_pending_prepayment error:", error.message);
      return { ok: false, reason: "rpc_error" };
    }

    if (data?.ok) {
    }

    return data ?? { ok: false, reason: "no_data" };
  } catch (e) {
    log.warn("⚠️ applyPendingPrepaymentIfNeeded exception:", e);
    return { ok: false, reason: "exception" };
  }
}

// [SUPPRIME 15 mai 2026] getContactNameFromProfiles : helper orphelin
// (etait utilise uniquement par les routes /api/change-plan et /api/prepay-next-year/session
//  qui ont ete supprimees)


// ✅ OPTIM PERF: throttle du RPC + cache court verify-token
const __prepayCooldown = global.__prepayCooldown || (global.__prepayCooldown = new Map());
const __authCache = global.__authCache || (global.__authCache = new Map());

function shouldRunPrepay(userId, ms = 60000) {
  const now = Date.now();
  const last = __prepayCooldown.get(userId) || 0;
  if (now - last < ms) return false;
  __prepayCooldown.set(userId, now);
  return true;
}

function cacheGet(key) {
  const hit = __authCache.get(key);
  if (!hit) return null;
  if (hit.expiresAt < Date.now()) {
    __authCache.delete(key);
    return null;
  }
  return hit.value;
}

function cacheSet(key, value, ttlMs = 4000) {
  __authCache.set(key, { value, expiresAt: Date.now() + ttlMs });
}

// ✅ FIX B9 — Ménage automatique des caches toutes les 5 min (évite fuite mémoire)
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of __authCache) {
    if (v.expiresAt < now) __authCache.delete(k);
  }
  for (const [k, v] of __prepayCooldown) {
    if (now - v > 120000) __prepayCooldown.delete(k);
  }
}, 300000);

// Middleware d'authentification
// server.js - NOUVELLE VERSION authenticateToken
async function resolveUserFromCookie(req) {
  const token = req.cookies?.auth_token;
  if (!token) throw new Error("NO_TOKEN");

  // 1) JWT — forcer HS256 uniquement (défense contre "alg:none" et confusion HS/RS)
  const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });

  // ✅ RPC prépayment: non bloquant + throttle
  if (shouldRunPrepay(decoded.id, 60000)) {
    applyPendingPrepaymentIfNeeded(decoded.id).catch(() => { });
  }

  // 2) Session DB
  const tokenHash = hashToken(token);

  // ✅ Cache court (évite rafales)
  const cacheKey = `${decoded.id}:${tokenHash}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  // ✅ IMPORTANT: on garde EXACTEMENT tes filtres stricts
  const { data: session, error: sessionError } = await supabaseAdmin
    .from("token_sessions")
    .select("user_id, expires_at, is_active, revoked_at")
    .eq("token_hash", tokenHash)
    .eq("user_id", decoded.id)
    .eq("is_active", true)
    .is("revoked_at", null)
    .maybeSingle(); // ✅ pas de throw si 0 ligne

  if (sessionError || !session) {
    // ✅ Vérifier si la session a été révoquée (connexion depuis un autre appareil)
    const { data: revoked } = await supabaseAdmin
      .from("token_sessions")
      .select("revoked_at")
      .eq("token_hash", tokenHash)
      .eq("user_id", decoded.id)
      .eq("is_active", false)
      .not("revoked_at", "is", null)
      .maybeSingle();

    if (revoked) {
      log.warn("🔒 SESSION_REVOKED (connexion concurrente)", { user_id: decoded.id });
      throw new Error("SESSION_REVOKED");
    }

    log.warn("❌ INVALID_SESSION", {
      sessionError: sessionError?.message,
      user_id: decoded.id,
    });
    throw new Error("INVALID_SESSION");
  }

  // ✅ expires_at : si null => on ne bloque pas ici
  if (session.expires_at) {
    const expiresMs = Date.parse(session.expires_at);
    if (Number.isFinite(expiresMs) && expiresMs < Date.now()) {
      log.warn("⏳ Session expirée (token_sessions)", { expires_at: session.expires_at });
      throw new Error("INVALID_SESSION");
    }
  }


  // tracking (non bloquant)
  supabaseAdmin
    .from("token_sessions")
    .update({ last_seen_at: new Date().toISOString() })
    .eq("token_hash", tokenHash)
    .eq("user_id", decoded.id)
    .then(() => { })
    .catch(() => { });

  // 3) Profil + abo (parallèle)
  const [profileResult, ownSubscription] = await Promise.all([
    supabaseAdmin
      .from("profiles")
      .select("user_id, first_name, last_name, company_id, avatar_url, terms_accepted_at, terms_version, role, archived_at, companies:company_id ( display_name, legal_name )")
      .eq("user_id", decoded.id)
      .maybeSingle(),
    getActiveSubscription(decoded.id),
  ]);


  if (profileResult.error || !profileResult.data) {
    log.warn("❌ PROFILE_NOT_FOUND", {
      error: profileResult.error?.message,
      user_id: decoded.id,
    });
    throw new Error("PROFILE_NOT_FOUND");
  }

  // ✅ Accès retiré (membre archivé par l'admin) -> on refuse l'accès.
  //    handleAuthenticationError nettoie le cookie et redirige : déconnexion propre.
  if (profileResult.data.archived_at) {
    log.warn("🚫 ACCOUNT_ARCHIVED (accès retiré)", { user_id: decoded.id });
    throw new Error("ACCOUNT_ARCHIVED");
  }

  // ✅ Rôle dans l'entreprise (admin = payeur/propriétaire, membre = invité)
  const role = String(profileResult.data.role || 'admin').toLowerCase();

  // ✅ ACCÈS HÉRITÉ : un membre n'a pas d'abonnement propre.
  // Son accès dépend de l'abonnement de l'ADMIN de son entreprise (companies.owner_id).
  let subscriptionResult = ownSubscription;
  if (role === 'membre' && profileResult.data.company_id) {
    const { data: company } = await supabaseAdmin
      .from("companies")
      .select("owner_id")
      .eq("id", profileResult.data.company_id)
      .maybeSingle();
    if (company?.owner_id) {
      subscriptionResult = await getActiveSubscription(company.owner_id);
    }
  }

  // ✅ Date d'expiration unifiée (trial_end pour trial, current_period_end ou dérivée pour payant)
  const subscriptionEndDate = subscriptionResult.plan === 'trial'
    ? (subscriptionResult.trial_end || null)
    : (subscriptionResult.current_period_end || subscriptionResult.derived_paid_end || null);

  const user = {
    id: decoded.id,
    email: decoded.email,
    first_name: profileResult.data.first_name,
    last_name: profileResult.data.last_name,
    company_id: profileResult.data.company_id,
    company_name: profileResult.data.companies?.display_name || profileResult.data.companies?.legal_name || null,
    role,
    avatar_url: profileResult.data.avatar_url,
    subscription_type: subscriptionResult.plan,
    has_active_subscription: subscriptionResult.hasActiveSubscription,
    suspended: subscriptionResult.suspended === true,
    subscription_end_date: subscriptionEndDate,
  };

  cacheSet(cacheKey, user, 15000);
  return user;
}


async function authenticateToken(req, res, next) {
  try {
    req.user = await resolveUserFromCookie(req);

    // ✅ SAFE: req.path peut être undefined selon le contexte
    const p = typeof req.path === "string"
      ? req.path
      : (typeof req.originalUrl === "string" ? req.originalUrl : "");

    if (p.startsWith("/api/")) {
      setNoStore(res);
    }

    next();
  } catch (error) {
    handleAuthenticationError(req, res, error);
  }
}


// ✅ Liste blanche des emails admin (variable d'env ADMIN_EMAILS, séparés par des virgules)
const ADMIN_EMAILS = new Set(
  String(process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
);

// ✅ Middleware : réserve une route aux admins. À placer APRÈS authenticateToken.
function requireAdmin(req, res, next) {
  const email = String(req.user?.email || "").trim().toLowerCase();
  if (email && ADMIN_EMAILS.has(email)) {
    return next();
  }
  log.warn("🚫 Accès admin refusé:", { email: email || "(inconnu)", path: req.path });
  return res.status(403).json({ error: "Accès réservé à l'administrateur", code: "ADMIN_ONLY" });
}


// ✅ [ADMIN] Journalise une action admin (qui / quoi / quand / pourquoi). Fire-and-forget, non bloquant.
function logAdminAction({ targetUserId, adminEmail, action, detail, motif }) {
  supabaseAdmin.from('admin_audit_log').insert({
    target_user_id: /^[0-9a-f-]{36}$/i.test(String(targetUserId || '')) ? targetUserId : null,
    admin_email: String(adminEmail || '').slice(0, 254),
    action: String(action || '').slice(0, 64),
    detail: detail ? String(detail).slice(0, 500) : null,
    motif: (motif && String(motif).trim()) ? String(motif).trim().slice(0, 500) : null,
  }).then(() => { }).catch((e) => { log.warn('⚠️ admin_audit_log insert skipped:', e?.message); });
}

// Journal technique d'entreprise (actions équipe/accès) — métadonnées only, AUCUN contenu métier.
//   acteur = compte INTEGORA ayant fait l'action (JAMAIS le collaborateur suivi). Best-effort (fire-and-forget).
function logTechAction({ companyId, teamId, actorUserId, action }) {
  if (!/^[0-9a-f-]{36}$/i.test(String(companyId || ''))) return;
  supabaseAdmin.from('pilotage_tech_log').insert({
    company_id: companyId,
    team_id: /^[0-9a-f-]{36}$/i.test(String(teamId || '')) ? teamId : null,
    actor_user_id: /^[0-9a-f-]{36}$/i.test(String(actorUserId || '')) ? actorUserId : null,
    action: String(action || '').slice(0, 64),
  }).then(() => { }).catch((e) => { log.warn('⚠️ pilotage_tech_log insert skipped:', e?.message); });
}



// Fonctions utilitaires
function handleUnauthorized(req, res) {
  const wantsHtml = req.headers.accept && req.headers.accept.includes('text/html');
  const isAppRoute = req.path.startsWith('/app/');

  if (wantsHtml && isAppRoute) {
    const redirectUrl = '/login.html?next=' + encodeURIComponent(req.originalUrl);
    return res.redirect(redirectUrl);
  }

  return res.status(401).json({
    error: "Token d'authentification manquant",
    code: "MISSING_TOKEN"
  });
}


function handleAuthenticationError(req, res, error) {
  res.clearCookie("auth_token", {
    path: "/",
    secure: IS_PROD,
    sameSite: IS_PROD ? "none" : "lax",

  });

  const isRevoked = error?.message === "SESSION_REVOKED";
  const accept = req.headers.accept || "";
  const wantsHtml = accept.includes("text/html");

  if (wantsHtml) {
    const reason = isRevoked ? "&reason=concurrent" : "";
    return res.redirect("/401.html?next=" + encodeURIComponent(req.originalUrl) + reason);
  }

  if (isRevoked) {
    return res.status(401).json({
      error: "Une autre session est active sur ce compte.",
      code: "SESSION_REVOKED",
    });
  }

  return res.status(401).json({
    error: "Session expirée, reconnectez-vous.",
    code: "SESSION_EXPIRED",
  });
}





function generateCSRFToken() {
  return require('crypto').randomBytes(32).toString('hex');
}


// Middleware de vérification d'abonnement
function requireSubscription(allowedPlans) {
  return async (req, res, next) => {
    const userPlan = req.user.subscription_type;
    const hasActiveSub = req.user.has_active_subscription;

    if (!hasActiveSub) {
      return res.status(403).json({
        error: "Abonnement inactif ou expiré",
        code: "SUBSCRIPTION_INACTIVE",
        required: allowedPlans,
        current: userPlan,
        hasActiveSubscription: false
      });
    }

    if (!allowedPlans.includes(userPlan)) {
      return res.status(403).json({
        error: "Accès non autorisé pour votre type d'abonnement",
        code: "SUBSCRIPTION_REQUIRED",
        required: allowedPlans,
        current: userPlan,
        hasActiveSubscription: true
      });
    }

    next();
  };
}


// ==================== OUTILS MANAGER : THERMOMETRE (API) ====================
const thermometreRoutes = require("./routes/thermometre.routes");

// ✅ ROUTE PROD-LIKE (AUTH + ABONNEMENT + CSRF)
app.use(
  "/api/outils/thermometre",
  authenticateToken,                          // ✅ c'est TON middleware auth côté backend
  requireSubscription(["trial", "paid"]), // tous les plans autorises pour le thermometre
  thermometreRoutes
);




// ==================== STRIPE CONFIG (TEST/LIVE) ====================
const STRIPE_MODE = (process.env.STRIPE_MODE ?? (process.env.NODE_ENV === "production" ? "live" : "test")).toLowerCase();

const STRIPE_SECRET_KEY =
  STRIPE_MODE === "live"
    ? (process.env.STRIPE_SECRET_KEY_LIVE || process.env.STRIPE_SECRET_KEY)
    : (process.env.STRIPE_SECRET_KEY_TEST || process.env.STRIPE_SECRET_KEY);

// [SUPPRIME 15 mai 2026] Constantes legacy STRIPE_PRICE_STANDARD,
// STRIPE_PRICE_PREMIUM, STANDARD_PREPAY_PRICE_ID, PREMIUM_PREPAY_PRICE_ID
// retirees apres passage au modele plan unique "paid" + 9 paliers d'effectif.


// ==================== NOUVEAUX TARIFS PAR PALIER (plan 'paid') ====================
// Mapping palier d'effectif -> Stripe Price ID, selon le mode TEST/LIVE
const STRIPE_PRICE_BY_TIER = STRIPE_MODE === "live"
  ? {
      "5-9":   process.env.STRIPE_PRICE_TIER_5_9_LIVE   || "",
      "10-14": process.env.STRIPE_PRICE_TIER_10_14_LIVE || "",
      "15-19": process.env.STRIPE_PRICE_TIER_15_19_LIVE || "",
      "20-24": process.env.STRIPE_PRICE_TIER_20_24_LIVE || "",
      "25-29": process.env.STRIPE_PRICE_TIER_25_29_LIVE || "",
      "30-34": process.env.STRIPE_PRICE_TIER_30_34_LIVE || "",
      "35-39": process.env.STRIPE_PRICE_TIER_35_39_LIVE || "",
      "40-44": process.env.STRIPE_PRICE_TIER_40_44_LIVE || "",
      "45-49": process.env.STRIPE_PRICE_TIER_45_49_LIVE || "",
    }
  : {
      "5-9":   process.env.STRIPE_PRICE_TIER_5_9_TEST   || "",
      "10-14": process.env.STRIPE_PRICE_TIER_10_14_TEST || "",
      "15-19": process.env.STRIPE_PRICE_TIER_15_19_TEST || "",
      "20-24": process.env.STRIPE_PRICE_TIER_20_24_TEST || "",
      "25-29": process.env.STRIPE_PRICE_TIER_25_29_TEST || "",
      "30-34": process.env.STRIPE_PRICE_TIER_30_34_TEST || "",
      "35-39": process.env.STRIPE_PRICE_TIER_35_39_TEST || "",
      "40-44": process.env.STRIPE_PRICE_TIER_40_44_TEST || "",
      "45-49": process.env.STRIPE_PRICE_TIER_45_49_TEST || "",
    };

// Verification au demarrage : alerter si un tier n'a pas de prix configure
for (const [tier, priceId] of Object.entries(STRIPE_PRICE_BY_TIER)) {
  if (!priceId) log.error(`❌ Missing STRIPE price for tier ${tier} (mode ${STRIPE_MODE})`);
}

// Helper: reverse lookup price_id -> tier (utile pour les webhooks et le frontend)
function tierFromPriceId(priceId) {
  if (!priceId) return null;
  for (const [tier, id] of Object.entries(STRIPE_PRICE_BY_TIER)) {
    if (id === priceId) return tier;
  }
  return null;
}


if (!STRIPE_SECRET_KEY) log.error("❌ Missing STRIPE secret key (resolved)");

const stripe = require("stripe")(STRIPE_SECRET_KEY);



// ✅ ROUTE POUR RÉCUPÉRER L'ABONNEMENT UTILISATEUR
app.get('/api/my-subscription', authenticateToken, async (req, res) => {
  try {

    const userId = req.user.id;

    // Utiliser Supabase avec service role (pas de RLS)
    const { data: subscription, error } = await supabaseAdmin
      .from('subscriptions')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (error) {
      if (error.code === 'PGRST116') { // Aucune ligne trouvée
        return res.status(404).json({
          error: 'Aucun abonnement trouvé',
          user_id: userId
        });
      }
      log.error('❌ [SERVER] Erreur Supabase:', safeError(error));
      return res.status(500).json({ error: 'Erreur base de données' });
    }



    // ✅ info prépaiement (année suivante)
    const { data: prepaid, error: prepaidErr } = await supabaseAdmin
      .from("subscription_prepayments")
      .select("amount, currency, plan, created_at, checkout_session_id, effective_period_start, effective_period_end")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();


    if (prepaidErr) log.warn("⚠️ prepaid query:", prepaidErr);

    const period_end = subscription.current_period_end || subscription.trial_end || null;

    // ============================================================
    // [14 mai 2026] Distinction tier actuel (facture en cours) vs
    // tier programme (prochain renouvellement).
    //
    //   subscriptions.current_paid_tier = ce que l'utilisateur paie en cours
    //                                     (mis a jour UNIQUEMENT au renouvellement via webhook invoice.paid)
    //   subscriptions.tier              = ce qui sera facture au prochain renouvellement
    //                                     (mis a jour immediatement par /api/subscription/change-tier)
    //
    // Si current_paid_tier est NULL (compte legacy avant migration), on
    // tombe en fallback sur subscription.tier (= aucun changement detecte).
    // ============================================================
    const current_tier = subscription.current_paid_tier ?? subscription.tier ?? null;
    const scheduled_tier = subscription.tier ?? null;
    const tier_change_pending =
      !!current_tier &&
      !!scheduled_tier &&
      current_tier !== scheduled_tier;


    return res.json({
      ...subscription,
      period_end,
      // NOUVEAU : tier actuellement facture (current) vs tier prevu au prochain renouvellement (scheduled)
      current_tier,
      scheduled_tier,
      tier_change_pending,
      hasPrepaidNextPeriod: !!prepaid,
      prepaid: prepaid ? {
        amount: prepaid.amount,
        currency: prepaid.currency,
        plan: prepaid.plan,
        paidAt: prepaid.created_at,
        checkoutSessionId: prepaid.checkout_session_id,
        startsAt: prepaid.effective_period_start,
        endsAt: prepaid.effective_period_end ?? null

      } : null
    });

  } catch (error) {
    log.error('❌ [SERVER] Erreur récupération abonnement:', safeError(error));
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// ==========================================
// 💳 STATUS MOYEN DE PAIEMENT (Stripe Truth)
// Retourne hasPaymentMethod true/false
// ==========================================
app.get("/api/payment-method/status", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const { data: sub, error } = await supabaseAdmin
      .from("subscriptions")
      .select("stripe_customer_id, stripe_subscription_id")
      .eq("user_id", userId)
      .single();

    if (error || !sub?.stripe_customer_id) {
      return res.status(404).json({
        hasPaymentMethod: false,
        reason: "no_customer",
      });
    }

    // Stripe truth
    const ensured = await ensureStripeCustomer({
      userId,
      email: req.user?.email ?? null,
      existingCustomerId: sub.stripe_customer_id,
    });

    const customer = await stripe.customers.retrieve(ensured.customerId);
    // Optionnel : regarde aussi la subscription (certaines configs mettent default PM au niveau subscription)
    let subscriptionDefaultPm = null;
    if (sub.stripe_subscription_id) {
      const stripeSub = await stripe.subscriptions.retrieve(sub.stripe_subscription_id, {
        expand: ["default_payment_method"],
      });
      subscriptionDefaultPm = stripeSub.default_payment_method ? true : false;
    }

    const customerDefaultPm =
      customer?.invoice_settings?.default_payment_method ? true : false;

    const hasPaymentMethod = customerDefaultPm || subscriptionDefaultPm;

    return res.json({
      hasPaymentMethod,
      customerDefaultPm,
      subscriptionDefaultPm,
    });
  } catch (e) {
    log.error("❌ /api/payment-method/status:", safeError(e));
    return res.status(500).json({ error: "Erreur status paiement" });
  }
});





// ✅ SUPPRESSION DE COMPTE — désactivé le 26 mars 2026
// La suppression se fait désormais via le support (conformité RGPD + traçabilité)
// Les anciennes routes /api/request-account-deletion et /api/confirm-account-deletion ont été retirées


// ==========================================
// ✅ Validation serveur stricte
// ==========================================
// ✅ Whitelist stricte (doit matcher inscription.html)
const ALLOWED_COMPANY_SIZES = new Set([
  "5-9", "10-14", "15-19", "20-24", "25-29",
  "30-34", "35-39", "40-44", "45-49", "50+"
]);
const ALLOWED_PLANS = new Set(["trial", "paid"]);

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());
}

// Verifier si un compte (auth.users) existe deja pour cet email - utilise a l'inscription
async function authEmailExists(emailNorm) {
  const target = String(emailNorm || "").toLowerCase().trim();
  if (!target) return false;

  // 1 seul appel HTTP à l'API GoTrue au lieu de scanner 20 000 users
  const url = `${process.env.SUPABASE_URL}/auth/v1/admin/users?page=1&per_page=1&filter=${encodeURIComponent(target)}`;
  const resp = await fetch(url, {
    headers: {
      "Authorization": `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
      "apikey": process.env.SUPABASE_SERVICE_ROLE_KEY,
    },
  });

  if (!resp.ok) {
    const errBody = await resp.text().catch(() => "");
    throw new Error(`authEmailExists HTTP ${resp.status}: ${errBody}`);
  }

  const body = await resp.json();
  const users = body?.users || [];
  return users.some(u => String(u?.email || "").toLowerCase().trim() === target);
}







// [SUPPRIME 15 mai 2026] retrieveProrationPreview : helper orphelin
// (etait utilise uniquement par /api/change-plan pour calculer le prorata
//  d'un upgrade Standard -> Premium, route supprimee).


async function ensureStripeCustomer({ userId, email, existingCustomerId }) {
  if (existingCustomerId) {
    try {
      const c = await stripe.customers.retrieve(existingCustomerId);
      if (c && !c.deleted) return { customerId: existingCustomerId, created: false };
    } catch (err) {
      const isMissing =
        err?.code === "resource_missing" ||
        err?.raw?.code === "resource_missing" ||
        err?.type === "StripeInvalidRequestError";
      if (!isMissing) throw err;
      log.warn("⚠️ Stripe customer introuvable dans ce mode, on recrée", {
        userId,
        existingCustomerId,
      });
    }

  }

  const created = await stripe.customers.create({
    email: email || undefined,
    preferred_locales: ["fr"],
    metadata: { user_id: userId, source: "ensureStripeCustomer" },
  });

  await supabaseAdmin
    .from("subscriptions")
    .update({ stripe_customer_id: created.id })
    .eq("user_id", userId);

  return { customerId: created.id, created: true };
}




// ==========================================
// [SUPPRIME 15 mai 2026] Routes legacy retirees :
//   - /api/change-plan : upgrade Standard -> Premium avec prorata
//   - /api/prepay-next-year/session : pre-paiement annee suivante
//
// Raison : passage au modele 1 plan unique "paid" + 9 paliers d'effectif.
// Les changements de palier se font via /api/subscription/change-tier
// (sans prorata, applique au prochain renouvellement).
//
// Si du code legacy quelque part appelle encore /api/change-plan ou
// /api/prepay-next-year/session, l'appel renverra 404 (route inexistante).
// ==========================================







// ==========================================
// 🔁 TOGGLE RENOUVELLEMENT (cancel_at_period_end)
// ==========================================
app.post('/api/subscription/toggle-renewal', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { autoRenew } = req.body; // boolean

    const { data: sub, error } = await supabaseAdmin
      .from('subscriptions')
      .select('stripe_subscription_id, status, plan')
      .eq('user_id', userId)
      .single();

    if (error || !sub?.stripe_subscription_id) {
      return res.status(400).json({ error: "Aucun abonnement Stripe actif" });
    }

    // [15 mai 2026] Protection defensive : refuser proprement si la sub
    // est deja terminee. Stripe refuserait l'update avec une erreur 500
    // peu claire. On renvoie un 400 avec un message clair a la place.
    if (sub.status === "canceled") {
      return res.status(400).json({
        error: "Votre abonnement est terminé. Reprenez d'abord un abonnement pour modifier votre renouvellement."
      });
    }
    if (sub.plan === "trial") {
      return res.status(400).json({
        error: "Le renouvellement automatique ne s'applique pas à un essai gratuit."
      });
    }

    // On verifie aussi cote Stripe (defense in depth en cas de desync DB <-> Stripe)
    const current = await stripe.subscriptions.retrieve(sub.stripe_subscription_id);
    if (current.status === "canceled" || current.status === "incomplete_expired") {
      return res.status(400).json({
        error: "Votre abonnement Stripe est déjà terminé. Reprenez d'abord un abonnement."
      });
    }

    const updated = await stripe.subscriptions.update(sub.stripe_subscription_id, {
      cancel_at_period_end: autoRenew ? false : true,
      metadata: {
        ...(current.metadata || {}),
        renewal_mode: autoRenew ? "auto" : "manual",
      }
    });


    // après: const updated = await stripe.subscriptions.update(...)

    const cancelAtIso = updated.cancel_at ? new Date(updated.cancel_at * 1000).toISOString() : null;

    await supabaseAdmin
      .from("subscriptions")
      .update({
        cancel_at: cancelAtIso,
        updated_at: new Date().toISOString(),
      })
      .eq("user_id", userId);


    return res.json({
      success: true,
      cancel_at_period_end: updated.cancel_at_period_end,
      cancel_at: updated.cancel_at ? new Date(updated.cancel_at * 1000).toISOString() : null
    });

  } catch (err) {
    log.error("❌ toggle-renewal error:", safeError(err));
    res.status(500).json({ error: "Erreur renouvellement" });
  }
});


// ==========================================
// 💳 BILLING PORTAL — Gerer moyens de paiement, factures, infos facturation
// Cree une session du Customer Portal Stripe (page hosted par Stripe).
// Le client est redirige sur cette page pour mettre a jour sa CB, voir ses
// factures, etc. PCI compliance assuree par Stripe.
// IMPORTANT : configurer le portail dans Stripe Dashboard avant utilisation
// (Settings > Billing > Customer portal). Desactiver "Cancel subscription"
// pour conserver notre flow custom de resiliation.
// ==========================================
app.post("/api/billing-portal", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // 1) Recuperer le stripe_customer_id de l'utilisateur
    const { data: sub, error: subErr } = await supabaseAdmin
      .from("subscriptions")
      .select("stripe_customer_id, plan")
      .eq("user_id", userId)
      .maybeSingle();

    if (subErr) {
      log.error("❌ billing-portal DB error:", safeError(subErr));
      return res.status(500).json({ error: "Erreur base de donnees" });
    }

    if (!sub?.stripe_customer_id) {
      return res.status(400).json({
        error: "Aucun customer Stripe associe a votre compte.",
        code: "NO_STRIPE_CUSTOMER",
      });
    }

    // 2) Trial users : pas de portail (pas de paiement)
    if (sub.plan === "trial") {
      return res.status(400).json({
        error: "Le portail de facturation est reserve aux abonnements payants.",
        code: "TRIAL_NO_BILLING",
      });
    }

    // 3) Creer la session du portail
    const FRONTEND_URL = process.env.FRONTEND_URL || (IS_PROD ? "https://integora.fr" : "http://localhost:3000");
    const returnUrl = `${FRONTEND_URL}/app/profile.html?portal=returned`;

    const portalSession = await stripe.billingPortal.sessions.create({
      customer: sub.stripe_customer_id,
      return_url: returnUrl,
      locale: "fr",
    });

    log.debug("✅ BILLING-PORTAL session created", {
      userId,
      stripeCustomerId: sub.stripe_customer_id,
      sessionId: portalSession.id,
    });

    return res.json({ url: portalSession.url });

  } catch (e) {
    log.error("❌ /api/billing-portal:", safeError(e));
    return res.status(500).json({
      error: "Erreur creation session portail. Reessayez plus tard.",
      details: safeDetails(e),
    });
  }
});


// ==========================================
// 🔄 CHANGEMENT DE PALIER (sans prorata, applique au prochain renouvellement)
// Decision Mehdi 12 mai 2026 : tout changement de palier s'applique
// uniquement a la prochaine echeance. Pas de facturation intermediaire.
// Stripe : proration_behavior = 'none'
// ==========================================
app.post("/api/subscription/change-tier", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const newTier = String(req.body?.tier ?? "").trim();

    // 1) Validation du tier
    if (newTier === "50+") {
      return res.status(400).json({
        error: "Le palier 50+ necessite un devis. Veuillez contacter le support."
      });
    }
    if (!STRIPE_PRICE_BY_TIER[newTier]) {
      return res.status(400).json({ error: "Palier invalide" });
    }
    const newPriceId = STRIPE_PRICE_BY_TIER[newTier];

    // 2) Recuperer la subscription en DB
    const { data: sub, error: subErr } = await supabaseAdmin
      .from("subscriptions")
      .select("stripe_subscription_id, plan, tier, cancel_at, status")
      .eq("user_id", userId)
      .single();

    if (subErr || !sub?.stripe_subscription_id) {
      return res.status(400).json({ error: "Aucun abonnement Stripe actif" });
    }
    if (sub.plan === "trial") {
      return res.status(400).json({
        error: "Vous devez d'abord souscrire un abonnement payant."
      });
    }

    // [14 mai 2026] Defense in depth : refuser le change-tier si le
    // renouvellement est annule (cancel_at rempli OU status canceled).
    // Modifier le palier n'a aucun sens tant qu'il n'y aura pas de
    // prochain renouvellement. Le frontend doit normalement bloquer
    // l'UI, mais on protege aussi cote backend.
    if (sub.status === "canceled") {
      return res.status(400).json({
        error: "Votre abonnement est terminé. Reprenez d'abord un abonnement pour modifier votre palier."
      });
    }
    if (sub.cancel_at) {
      return res.status(400).json({
        error: "Le renouvellement de votre abonnement est arrêté. Réactivez-le d'abord avant de modifier votre palier."
      });
    }

    // 3) Recuperer la subscription Stripe pour l'item_id
    const stripeSub = await stripe.subscriptions.retrieve(sub.stripe_subscription_id);
    const itemId = stripeSub?.items?.data?.[0]?.id;
    if (!itemId) {
      return res.status(500).json({ error: "Subscription Stripe invalide (item manquant)" });
    }

    // 4) Mettre a jour la subscription Stripe SANS prorata
    //    Le nouveau prix sera applique au prochain renouvellement, sans facture intermediaire.
    await stripe.subscriptions.update(sub.stripe_subscription_id, {
      items: [{ id: itemId, price: newPriceId }],
      proration_behavior: "none",
      metadata: {
        ...(stripeSub.metadata || {}),
        plan: "paid",
        tier: newTier,
        last_tier_change_at: new Date().toISOString(),
      },
    });

    // 5) Mettre a jour la DB
    // [14 mai 2026] IMPORTANT : on ne touche QUE 'tier' et 'stripe_price_id'
    // (= ce qui sera facture au prochain renouvellement).
    // 'current_paid_tier' reste inchangee : elle represente le palier
    // actuellement facture, et ne sera mise a jour qu'au prochain renouvellement
    // par le webhook invoice.paid (subscription_cycle).
    const { error: updateErr } = await supabaseAdmin
      .from("subscriptions")
      .update({
        plan: "paid",
        tier: newTier,
        stripe_price_id: newPriceId,
        updated_at: new Date().toISOString(),
      })
      .eq("user_id", userId);

    if (updateErr) {
      log.error("❌ change-tier DB update error:", safeError(updateErr));
      return res.status(500).json({ error: "Erreur mise a jour de la base de donnees" });
    }

    log.debug("✅ TIER CHANGED", {
      userId,
      oldTier: sub.tier,
      newTier,
      stripeSubId: sub.stripe_subscription_id,
    });

    return res.json({
      success: true,
      tier: newTier,
      stripe_price_id: newPriceId,
      message: "Palier mis a jour. Le nouveau tarif sera applique au prochain renouvellement.",
    });

  } catch (e) {
    log.error("❌ /api/subscription/change-tier:", safeError(e));
    return res.status(500).json({ error: "Erreur changement de palier" });
  }
});


// ==========================================
// 🔐 HELPERS TOKEN SIGNE pour actions admin one-click via email
// ==========================================
// Permet de generer/verifier un token URL-safe qui prouve qu'un lien
// (genre "Marquer comme traite" dans un email) est legitime.
// Signe avec CRON_SECRET (HMAC-SHA256). Expire apres ttlSeconds.
function _b64urlEncode(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function _b64urlDecode(str) {
  let s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64").toString("utf8");
}
// Whitelist des tables autorisees pour le mark-closed via lien email signe
const TICKET_CLOSE_ALLOWED_TABLES = new Set(["contact_tickets", "support_tickets"]);

function generateCloseTicketToken(ticketId, tableName, ttlSeconds = 90 * 24 * 3600) {
  const secret = process.env.CRON_SECRET;
  if (!secret) throw new Error("CRON_SECRET non defini pour signer le token");
  if (!TICKET_CLOSE_ALLOWED_TABLES.has(tableName)) {
    throw new Error(`Table non autorisee pour token close: ${tableName}`);
  }
  const payload = {
    tid: String(ticketId),
    table: tableName,
    exp: Math.floor(Date.now() / 1000) + ttlSeconds,
  };
  const payloadB64 = _b64urlEncode(JSON.stringify(payload));
  const sig = require("crypto")
    .createHmac("sha256", secret).update(payloadB64).digest("base64")
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${payloadB64}.${sig}`;
}
function verifyCloseTicketToken(token) {
  try {
    const secret = process.env.CRON_SECRET;
    if (!secret) return { valid: false, error: "secret_missing" };
    if (!token || typeof token !== "string") return { valid: false, error: "no_token" };
    const parts = token.split(".");
    if (parts.length !== 2) return { valid: false, error: "bad_format" };
    const [payloadB64, sig] = parts;
    const expectedSig = require("crypto")
      .createHmac("sha256", secret).update(payloadB64).digest("base64")
      .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    if (sig.length !== expectedSig.length) return { valid: false, error: "bad_signature" };
    if (!require("crypto").timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
      return { valid: false, error: "bad_signature" };
    }
    const payload = JSON.parse(_b64urlDecode(payloadB64));
    if (!payload.tid) return { valid: false, error: "missing_tid" };
    if (!payload.table || !TICKET_CLOSE_ALLOWED_TABLES.has(payload.table)) {
      return { valid: false, error: "bad_table" };
    }
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
      return { valid: false, error: "expired" };
    }
    return { valid: true, ticketId: payload.tid, tableName: payload.table };
  } catch (e) {
    return { valid: false, error: "decode_failed" };
  }
}


// ==========================================
// 📞 DEMANDE DE DEVIS 50+ COLLABORATEURS
// ==========================================
// Permet a un client connecte (sur profile.html) de declarer que son
// effectif a depasse 50 collaborateurs et qu'il souhaite un devis
// personnalise. Cree un ticket dans contact_tickets + envoie un email
// interne a contact@integora.fr + mehdi.joalland@integora.fr +
// un accuse de reception au client.
// L'abonnement actuel continue normalement (pas de blocage).
app.post("/api/subscription/request-quote-50plus", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const userEmail = req.user.email;

    if (!userEmail) {
      return res.status(400).json({ error: "Email utilisateur introuvable" });
    }

    const { data: profile, error: profErr } = await supabaseAdmin
      .from("profiles")
      .select(`
        user_id, first_name, last_name,
        companies:company_id (
          id, legal_name, display_name, company_siret
        )
      `)
      .eq("user_id", userId)
      .maybeSingle();

    if (profErr) {
      log.error("❌ quote-50plus profil read error:", safeError(profErr));
      return res.status(500).json({ error: "Erreur lecture profil" });
    }

    const { data: sub } = await supabaseAdmin
      .from("subscriptions")
      .select("plan, tier, current_period_end")
      .eq("user_id", userId)
      .maybeSingle();

    // Fallback : si profile.companies est vide (lien profile.company_id null),
    // chercher la company directement via owner_id. Couvre les comptes legacy.
    let company = profile?.companies || null;
    if (!company) {
      const { data: ownedCompany } = await supabaseAdmin
        .from("companies")
        .select("id, legal_name, display_name, company_siret")
        .eq("owner_id", userId)
        .maybeSingle();
      company = ownedCompany || {};
    }

    // Tronquage defensif aligne sur les contraintes SQL de contact_tickets
    // (au cas ou un compte legacy aurait des valeurs depassant les limites en DB)
    const firstName = String(profile?.first_name || "").slice(0, 30);
    const lastName = String(profile?.last_name || "").slice(0, 40);
    const companyNameRaw = company.legal_name || company.display_name || "—";
    const companyName = String(companyNameRaw).slice(0, 60);
    const companySiret = company.company_siret || null;
    const currentTier = sub?.tier || "—";
    const currentPlan = sub?.plan || "—";
    const endIso = sub?.current_period_end || null;
    const endDateFR = endIso ? new Date(endIso).toLocaleDateString("fr-FR") : "—";

    const { data: existing } = await supabaseAdmin
      .from("contact_tickets")
      .select("id, created_at")
      .eq("email", userEmail)
      .eq("subject", "quote_50_plus")
      .eq("status", "open")
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (existing?.id) {
      return res.json({
        ok: true,
        already_pending: true,
        requested_at: existing.created_at,
        ticket_id: existing.id,
        message: "Une demande de devis est deja en cours pour ce compte.",
      });
    }

    const messageText = `Demande de devis pour palier 50+ collaborateurs.

Client connecte depuis profile.html.
Palier actuel souscrit : ${currentTier}
Plan actuel : ${currentPlan}
Renouvellement actuel prevu le : ${endDateFR}
${companySiret ? `SIRET : ${companySiret}\n` : ""}
Merci de contacter ce client pour preparer un devis personnalise pour son nouvel effectif.`;

    const { data: ticket, error: ticketErr } = await supabaseAdmin
      .from("contact_tickets")
      .insert({
        subject: "quote_50_plus",
        message: messageText,
        page_url: "/app/profile.html",
        first_name: firstName,
        last_name: lastName,
        email: userEmail,
        company_name: companyName,
        position: null,
        phone: null,
        status: "open",
      })
      .select("*")
      .single();

    if (ticketErr) {
      log.error("❌ quote_50_plus ticket insert error:", safeError(ticketErr));
      return res.status(500).json({ error: "Erreur creation ticket" });
    }

    // [16 mai 2026] Destinataires internes : uniquement mehdi.joalland (compte solo).
    const internalRecipients = ["mehdi.joalland@integora.fr"];
    const subjectMail = `Demande devis 50+ — ${companyName} (#${String(ticket.id).slice(0, 8)})`;

    // Generer le lien "Marquer comme traite" (token signe HMAC, expire 90 jours)
    const FRONT_URL = process.env.FRONTEND_URL || "https://integora.fr";
    let markClosedUrl = null;
    try {
      const closeToken = generateCloseTicketToken(ticket.id, "contact_tickets");
      markClosedUrl = `${FRONT_URL}/api/admin/ticket-mark-closed?token=${closeToken}`;
    } catch (e) {
      log.warn("⚠️ quote_50_plus: impossible de generer le token close:", safeError(e));
    }

    const htmlInternal = `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#1a1a1a;font-size:15px;line-height:1.6;">
        <h2 style="margin:0 0 16px 0;font-size:18px;font-weight:700;">Nouvelle demande de devis 50+ collaborateurs</h2>
        <p>Un client a declare avoir depasse le palier 50 collaborateurs et demande un devis personnalise.</p>
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:16px 0;">
          <p style="margin:0 0 6px 0;"><strong>Client :</strong> ${escapeHtml(firstName)} ${escapeHtml(lastName)}</p>
          <p style="margin:0 0 6px 0;"><strong>Email :</strong> ${escapeHtml(userEmail)}</p>
          <p style="margin:0 0 6px 0;"><strong>Entreprise :</strong> ${escapeHtml(companyName)}</p>
          ${companySiret ? `<p style="margin:0 0 6px 0;"><strong>SIRET :</strong> ${escapeHtml(companySiret)}</p>` : ""}
          <p style="margin:0 0 6px 0;"><strong>Palier actuel souscrit :</strong> ${escapeHtml(currentTier)}</p>
          <p style="margin:0 0 6px 0;"><strong>Plan :</strong> ${escapeHtml(currentPlan)}</p>
          <p style="margin:0;"><strong>Renouvellement prevu le :</strong> ${endDateFR}</p>
        </div>
        <p>Action : contacter ce client pour preparer un devis personnalise.</p>
        ${markClosedUrl ? `
        <div style="text-align:center;margin:28px 0 20px 0;">
          <a href="${markClosedUrl}"
             style="display:inline-block;background:#16a34a;color:#ffffff;text-decoration:none;padding:13px 28px;border-radius:8px;font-weight:700;font-size:14px;">
            ✓ Marquer ce ticket comme traite
          </a>
          <div style="font-size:12px;color:#64748b;margin-top:8px;">
            Une fois le client contacte, cliquez ici pour cloturer la demande.
          </div>
        </div>
        ` : ""}
        <p style="font-size:13px;color:#64748b;margin-top:24px;">
          Ticket ID : <code>${ticket.id}</code><br/>
          Recu le ${new Date(ticket.created_at).toLocaleString("fr-FR")}
        </p>
      </div>
    `;

    try {
      await sendResendEmail({ to: internalRecipients, subject: subjectMail, html: htmlInternal });
    } catch (emailErr) {
      log.error("❌ quote_50_plus internal email failed:", safeError(emailErr));
    }

    const ackSubject = "Votre demande de devis INTEGORA est bien recue";
    const ackHtml = `
      <div style="font-family:Arial,sans-serif;max-width:560px;padding:32px 16px;color:#1a1a1a;font-size:15px;line-height:1.6;">
        <p>Bonjour ${escapeHtml(firstName)},</p>
        <p>Nous avons bien recu votre demande de devis pour un effectif de 50 collaborateurs ou plus.</p>
        <p>Notre equipe va vous contacter rapidement pour preparer une proposition adaptee a votre nouvelle situation.</p>
        <p>En attendant, votre abonnement actuel continue normalement et votre acces a INTEGORA n'est pas modifie.</p>
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:32px 0 16px;" />
        <p style="font-size:13px;color:#64748b;line-height:1.6;margin:0;">
          L'equipe <strong>Integora</strong><br/>
          <a href="https://integora.fr" style="color:#64748b;text-decoration:none;">integora.fr</a>
          ·
          <a href="mailto:contact@integora.fr" style="color:#64748b;text-decoration:none;">contact@integora.fr</a>
        </p>
      </div>
    `;

    try {
      await sendResendEmail({ to: userEmail, subject: ackSubject, html: ackHtml });
    } catch (emailErr) {
      log.error("❌ quote_50_plus ack email failed:", safeError(emailErr));
    }

    return res.json({
      ok: true,
      already_pending: false,
      requested_at: ticket.created_at,
      ticket_id: ticket.id,
    });

  } catch (err) {
    log.error("❌ request-quote-50plus error:", safeError(err));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});


// ==========================================
// 📞 STATUT DE LA DEMANDE DE DEVIS 50+
// ==========================================
// Indique au frontend si une demande de devis 50+ est deja en cours
// pour le user connecte. Permet d'afficher "Demande envoyee le X"
// au lieu du bouton "Demander un devis".
app.get("/api/subscription/quote-50plus-status", authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email;
    if (!userEmail) {
      return res.json({ pending: false });
    }

    const { data: existing, error } = await supabaseAdmin
      .from("contact_tickets")
      .select("id, created_at")
      .eq("email", userEmail)
      .eq("subject", "quote_50_plus")
      .eq("status", "open")
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) {
      log.error("❌ quote-50plus-status read error:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture statut" });
    }

    if (existing?.id) {
      return res.json({
        pending: true,
        requested_at: existing.created_at,
        ticket_id: existing.id,
      });
    }

    return res.json({ pending: false });

  } catch (err) {
    log.error("❌ quote-50plus-status error:", safeError(err));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});


// ==========================================
// ✅ MARQUER UN TICKET COMME TRAITE (action one-click via email)
// ==========================================
// Route GET non-authentifiee mais protegee par un TOKEN SIGNE (HMAC).
// Cliquable depuis l'email envoye a contact@integora.fr / mehdi.joalland@integora.fr / support.
// Generique : fonctionne pour contact_tickets ET support_tickets (whitelist).
// Le token expire apres 90 jours. Renvoie une page HTML simple de confirmation.
app.get("/api/admin/ticket-mark-closed", async (req, res) => {
  const pageHtml = (title, color, heading, body) => {
    // Detection du type d'etat pour adapter l'icone et le fond
    const isSuccess = color === "#16a34a";
    const isInfo = color === "#0891b2";
    // Icone SVG selon l'etat (check / info / warning)
    const iconSvg = isSuccess
      ? `<svg xmlns="http://www.w3.org/2000/svg" width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`
      : isInfo
      ? `<svg xmlns="http://www.w3.org/2000/svg" width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`
      : `<svg xmlns="http://www.w3.org/2000/svg" width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    const bgGradient = isSuccess
      ? "linear-gradient(135deg, #ecfdf5 0%, #f0fdf4 50%, #f7fee7 100%)"
      : isInfo
      ? "linear-gradient(135deg, #ecfeff 0%, #f0fdfa 50%, #eff6ff 100%)"
      : "linear-gradient(135deg, #fef2f2 0%, #fff1f2 50%, #fef3f2 100%)";
    // Heading propre sans emoji (l'icone SVG s'en charge)
    const cleanHeading = String(heading).replace(/^[✅❌ℹ️\s]+/, "").trim();

    return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} — INTEGORA</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      padding: 24px 16px;
      background: ${bgGradient};
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      color: #0f172a;
      display: flex;
      align-items: center;
      justify-content: center;
      -webkit-font-smoothing: antialiased;
    }
    .card {
      max-width: 480px;
      width: 100%;
      background: #ffffff;
      border-radius: 20px;
      padding: 48px 32px 32px;
      box-shadow: 0 12px 40px rgba(15, 23, 42, 0.08), 0 2px 6px rgba(15, 23, 42, 0.04);
      text-align: center;
      animation: fadeIn 0.45s cubic-bezier(0.2, 0.8, 0.2, 1);
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(12px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .icon-circle {
      width: 84px;
      height: 84px;
      border-radius: 50%;
      background: ${color};
      margin: 0 auto 24px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 10px 28px ${color}40;
    }
    h1 {
      color: ${color};
      font-size: 24px;
      font-weight: 700;
      margin: 0 0 14px;
      letter-spacing: -0.01em;
      line-height: 1.25;
    }
    p {
      color: #475569;
      font-size: 15px;
      line-height: 1.6;
      margin: 0 0 12px;
    }
    p:last-of-type { margin-bottom: 0; }
    code {
      background: #f1f5f9;
      color: #334155;
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 13px;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      letter-spacing: -0.01em;
    }
    .meta {
      margin-top: 28px;
      padding-top: 20px;
      border-top: 1px solid #e2e8f0;
      color: #94a3b8;
      font-size: 12px;
      letter-spacing: 0.01em;
    }
    .brand {
      margin-top: 14px;
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.05em;
    }
    .brand a {
      color: #1e293b;
      text-decoration: none;
      border-bottom: 1px solid transparent;
      transition: border-color .2s;
    }
    .brand a:hover { border-bottom-color: #1e293b; }
    @media (max-width: 480px) {
      .card { padding: 36px 22px 28px; border-radius: 16px; }
      .icon-circle { width: 72px; height: 72px; }
      h1 { font-size: 20px; }
    }
  </style>
</head>
<body>
  <main class="card" role="status" aria-live="polite">
    <div class="icon-circle" aria-hidden="true">${iconSvg}</div>
    <h1>${escapeHtml(cleanHeading)}</h1>
    ${body}
    <div class="meta">Vous pouvez fermer cette page en toute sécurité.</div>
    <div class="brand"><a href="https://integora.fr" target="_blank" rel="noopener">INTEGORA</a></div>
  </main>
</body>
</html>`;
  };

  try {
    const token = String(req.query.token || "");
    const v = verifyCloseTicketToken(token);

    if (!v.valid) {
      return res.status(400).type("html").send(pageHtml(
        "Lien invalide",
        "#dc2626",
        "❌ Lien invalide ou expire",
        `<p>Ce lien ne peut plus etre utilise (${escapeHtml(v.error || "inconnu")}).</p>
         <p style="color:#64748b;">Si besoin, fermez le ticket directement dans Supabase.</p>`
      ));
    }

    const ticketId = v.ticketId;
    const tableName = v.tableName;

    // Choix de la colonne email selon la table (les schemas different)
    const emailCol = tableName === "support_tickets" ? "user_email" : "email";

    const { data: ticket, error: readErr } = await supabaseAdmin
      .from(tableName)
      .select(`id, status, subject, ${emailCol}, created_at`)
      .eq("id", ticketId)
      .maybeSingle();

    if (readErr) {
      log.error("❌ mark-closed read error:", safeError(readErr));
      return res.status(500).type("html").send(pageHtml(
        "Erreur",
        "#dc2626",
        "❌ Erreur serveur",
        `<p>Impossible de lire le ticket. Reessayez plus tard.</p>`
      ));
    }

    if (!ticket) {
      return res.status(404).type("html").send(pageHtml(
        "Ticket introuvable",
        "#dc2626",
        "❌ Ticket introuvable",
        `<p>Ce ticket n'existe plus en base.</p>`
      ));
    }

    if (ticket.status === "closed") {
      return res.type("html").send(pageHtml(
        "Deja traite",
        "#0891b2",
        "ℹ️ Ce ticket etait deja cloture",
        `<p>Le ticket <code>#${escapeHtml(String(ticket.id).slice(0, 8))}</code> a deja ete marque comme traite.</p>
         <p style="color:#64748b;">Aucune action supplementaire necessaire.</p>`
      ));
    }

    const { error: updateErr } = await supabaseAdmin
      .from(tableName)
      .update({ status: "closed" })
      .eq("id", ticketId);

    if (updateErr) {
      log.error("❌ mark-closed update error:", safeError(updateErr));
      return res.status(500).type("html").send(pageHtml(
        "Erreur",
        "#dc2626",
        "❌ Erreur lors de la cloture",
        `<p>${escapeHtml(updateErr.message || "Erreur inconnue")}</p>`
      ));
    }

    log.info(`✅ Ticket marque comme traite via email: ${tableName} ${ticketId}`);

    const ticketEmail = ticket[emailCol] || "—";

    return res.type("html").send(pageHtml(
      "Ticket traite",
      "#16a34a",
      "✅ Ticket marque comme traite",
      `<p>Le ticket <code>#${escapeHtml(String(ticket.id).slice(0, 8))}</code> (${escapeHtml(ticketEmail)}) est maintenant cloture.</p>
       <p style="color:#64748b;">Table : <code>${escapeHtml(tableName)}</code></p>`
    ));

  } catch (err) {
    log.error("❌ quote-50plus-mark-closed error:", safeError(err));
    return res.status(500).type("html").send(pageHtml(
      "Erreur",
      "#dc2626",
      "❌ Erreur serveur",
      `<p>Une erreur inattendue s'est produite.</p>`
    ));
  }
});


// ==========================================
// ✅ TRIAL -> PAID : créer une nouvelle subscription Stripe via Checkout
// ==========================================
app.post("/api/subscribe/session", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const desiredTier = req.body?.tier;     // "5-9" | "10-14" | ... | "45-49"

    // ----- Resolution du price_id selon le palier d'effectif -----
    let priceId = null;
    let planForMetadata = null;  // sera lu par le webhook pour ecrire en DB
    let tierForMetadata = null;

    if (!desiredTier) {
      return res.status(400).json({
        error: "Body invalide. Envoyez { tier: '5-9' } (ou autre palier 5-9 a 45-49)."
      });
    }
    if (desiredTier === "50+") {
      return res.status(400).json({
        error: "Le palier 50+ necessite un devis. Veuillez contacter le support."
      });
    }
    if (!STRIPE_PRICE_BY_TIER[desiredTier]) {
      return res.status(400).json({ error: "Palier invalide" });
    }
    priceId = STRIPE_PRICE_BY_TIER[desiredTier];
    planForMetadata = "paid";
    tierForMetadata = desiredTier;

    if (!priceId) {
      return res.status(500).json({ error: "PriceId Stripe manquant pour ce palier/plan" });
    }

    // 1) récupérer infos locales (customer existant ?)
    const { data: subRow } = await supabaseAdmin
      .from("subscriptions")
      .select("stripe_customer_id, stripe_subscription_id, plan, status")
      .eq("user_id", userId)
      .maybeSingle();

    // ✅ Si déjà une subscription Stripe ACTIVE -> on ne passe pas ici
    //    (mais on AUTORISE le cas status='canceled' = sub morte, le user
    //    veut souscrire a nouveau, on creera une nouvelle subscription
    //    qui remplacera l'ancienne dans subscriptions via le webhook)
    if (subRow?.stripe_subscription_id && subRow?.status !== 'canceled') {
      return res.status(400).json({
        error: "Abonnement Stripe déjà actif, utilise change-plan."
      });
    }

    const FRONT = process.env.FRONTEND_URL || "https://integora.fr";

    // 3) s'assurer d'avoir un customer Stripe
    let customerId = subRow?.stripe_customer_id || null;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: req.user.email,
        metadata: { user_id: userId }
      });
      customerId = customer.id;

      await supabaseAdmin
        .from("subscriptions")
        .upsert({ user_id: userId, stripe_customer_id: customerId }, { onConflict: "user_id" });
    }


    // ✅ Synchronise la facturation Stripe avec les infos companies/profiles AVANT de créer la session
    try {
      await syncStripeCustomerBillingFromDb({
        userId,
        stripeCustomerId: customerId,
        requireComplete: true,
      });
    } catch (e) {
      if (e?.code === "BILLING_INCOMPLETE") {
        return res.status(400).json({
          ok: false,
          error: e.message,
          code: "BILLING_INCOMPLETE",
        });
      }
      log.error("❌ sync billing (subscribe/session) error:", safeError(e));
      return res.status(500).json({ ok: false, error: "Erreur sync facturation (Stripe)" });
    }


    // 🧪 DEBUG
    log.debug("🧪 SUBSCRIBE DEBUG (/api/subscribe/session)", {
      desiredTier,
      planForMetadata,
      tierForMetadata,
      priceId,
      customerId,
      userId,
    });





    // 4) créer Checkout Session subscription (PARAMS STRIPE VALIDES)
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      locale: "fr",

      // ✅ TVA auto (Stripe Tax)
      automatic_tax: { enabled: true },
      billing_address_collection: "required",

      tax_id_collection: { enabled: true },
      customer_update: { name: "auto", address: "auto" },




      line_items: [{ price: priceId, quantity: 1 }],

      success_url: `${FRONTEND_URL}/app/profile.html?checkout=success`,
      cancel_url: `${FRONTEND_URL}/app/profile.html?checkout=cancel`,

      metadata: {
        action: "subscribe_paid",
        user_id: userId,
        plan: planForMetadata,
        ...(tierForMetadata ? { tier: tierForMetadata } : {}),
      },

      subscription_data: {
        metadata: {
          action: "subscribe_paid",
          user_id: userId,
          plan: planForMetadata,
          // [15 mai 2026] IMPORTANT : on declare explicitement renewal_mode = "auto"
          // pour que le webhook (enforceRenewalModeOnStripeSubscription) ne force pas
          // cancel_at_period_end = true par defaut sur cette nouvelle subscription.
          // Sans ca, la sub se cree puis se met en "non reconductible" automatiquement
          // car le code considere une absence de renewal_mode comme "manual".
          renewal_mode: "auto",
          ...(tierForMetadata ? { tier: tierForMetadata } : {}),
        },

      },

      // ✅ si tu veux forcer la saisie d’un moyen de paiement à l’achat
      payment_method_collection: "always",

    });

    return res.json({ url: session.url });

  } catch (e) {
    log.error("❌ /api/subscribe/session:", e?.raw?.message || safeError(e));
    return res.status(500).json({
      error: "Erreur création session Stripe",
      details: safeDetails(e)
    });
  }
});










// ✅ VÉRIFICATION SERVEUR RENFORCÉE
function extractPageName(fullPath) {
  const fileName = fullPath.split('/').pop() || 'index';
  return fileName.replace('.html', '');
}


// ---------------------------
// ROUTES D'AUTHENTIFICATION
// ---------------------------

app.post("/login", async (req, res) => {
  const GENERIC_AUTH_ERROR =
    "Identifiants invalides. Réessayez ou réinitialisez votre mot de passe.";

  try {
    const { email, password, device_id } = req.body || {};

    // ✅ 0) Input minimal (mais réponse opaque)
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: GENERIC_AUTH_ERROR,
      });
    }

    if (!isProduction) {
    }

    // ✅ 1) AUTHENTIFICATION avec client AUTH
    const { data: authData, error: authError } =
      await supabaseAuth.auth.signInWithPassword({
        email,
        password,
      });

    // 🚫 Toujours opaque : jamais renvoyer authError.message
    if (authError || !authData?.user) {
      if (!isProduction) {
      }
      return res.status(401).json({
        success: false,
        error: GENERIC_AUTH_ERROR,
      });
    }

    const user_id = authData.user.id;

    // ✅ 2) PROFIL avec client ADMIN (non bloquant)
    const { data: profile } = await supabaseAdmin
      .from("profiles")
      .select("first_name, last_name, company_id, archived_at")
      .eq("user_id", user_id)
      .single();

    // 🚫 Accès retiré (membre archivé par l'admin) : on n'ouvre pas de session.
    if (profile?.archived_at) {
      return res.status(403).json({
        success: false,
        error: "Votre accès à cet espace a été retiré. Contactez l'administrateur de votre entreprise.",
        code: "ACCESS_REVOKED",
      });
    }

    // 🔐 2FA : si ce compte a la 2FA activée, on N'OUVRE PAS la session ici.
    //    On renvoie un "challenge" court (5 min) ; le code sera vérifié par POST /login/2fa.
    {
      const { data: mfaRow } = await supabaseAdmin
        .from("user_mfa").select("enabled").eq("user_id", user_id).maybeSingle();
      if (mfaRow && mfaRow.enabled) {
        const challenge = jwt.sign(
          {
            id: user_id,
            email: authData.user.email,
            first_name: profile?.first_name || "Utilisateur",
            last_name: profile?.last_name || "",
            company_id: profile?.company_id || null,
            mfa_pending: true,
          },
          SECRET_KEY,
          { expiresIn: "5m" }
        );
        return res.json({ success: false, mfaRequired: true, challenge: challenge });
      }
    }

    // ✅ 3) Fermer anciennes sessions (non bloquant)
    await supabaseAdmin
      .from("token_sessions")
      .update({
        is_active: false,
        revoked_at: new Date().toISOString(),
      })
      .eq("user_id", user_id)
      .eq("is_active", true);

    // ✅ 4) CRÉATION JWT + session DB
    const token = jwt.sign(
      {
        id: user_id,
        email: authData.user.email,
        first_name: profile?.first_name || "Utilisateur",
        last_name: profile?.last_name || "",
      },
      SECRET_KEY,
      { expiresIn: "24h" }
    );

    const tokenHash = hashToken(token);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);

    await supabaseAdmin.from("token_sessions").insert([
      {
        user_id: user_id,
        token_hash: tokenHash,
        device_id: device_id || "web",
        user_agent: req.headers["user-agent"],
        ip: req.ip,
        expires_at: expiresAt.toISOString(),
        is_active: true,
      },
    ]);

    // ✅ 5) COOKIE
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: IS_PROD ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000,
      path: "/",
    });

    // ✅ 6) RÉPONSE OK
    return res.json({
      success: true,
      redirect: "/app/choix_irl_digital.html",
      user: {
        id: user_id,
        first_name: profile?.first_name || "Utilisateur",
        last_name: profile?.last_name || "",
        email: authData.user.email,
        company_id: profile?.company_id || null,
      },
    });
  } catch (error) {
    log.error("💥 Erreur login:", safeError(error));
    return res.status(500).json({
      success: false,
      error: "Erreur serveur lors de la connexion.",
    });
  }
});


// 🔐 [2FA] Vérifie le code à 6 chiffres (ou un code de secours) puis ouvre la session.
//    Reçoit le "challenge" émis par /login (jwt court). Rate-limité par app.use('/login', authLimiter).
app.post("/login/2fa", async (req, res) => {
  const GENERIC = "Code invalide. Réessayez.";
  try {
    const { challenge, code } = req.body || {};
    if (!challenge || !code) return res.status(400).json({ success: false, error: GENERIC });

    let payload;
    try { payload = jwt.verify(challenge, SECRET_KEY); }
    catch (_) { return res.status(401).json({ success: false, error: "Session expirée. Reconnecte-toi." }); }
    if (!payload || !payload.mfa_pending || !payload.id) {
      return res.status(401).json({ success: false, error: GENERIC });
    }
    const user_id = payload.id;

    const { data: mfaRow } = await supabaseAdmin
      .from("user_mfa").select("secret, enabled, recovery_codes").eq("user_id", user_id).maybeSingle();
    if (!mfaRow || !mfaRow.enabled || !mfaRow.secret) {
      return res.status(401).json({ success: false, error: GENERIC });
    }

    const { authenticator } = require("otplib");
    const clean = String(code).trim();
    let ok = false, usedRecovery = false, remaining = null;

    // 1) Code TOTP (6 chiffres)
    if (/^\d{6}$/.test(clean.replace(/\s/g, ""))) {
      ok = authenticator.verify({ token: clean.replace(/\s/g, ""), secret: mfaRow.secret });
    }
    // 2) Sinon, code de secours (usage unique)
    if (!ok) {
      const bcrypt = require("bcryptjs");
      const codes = Array.isArray(mfaRow.recovery_codes) ? mfaRow.recovery_codes : [];
      const idx = codes.findIndex((h) => { try { return bcrypt.compareSync(clean.toUpperCase(), h); } catch (_) { return false; } });
      if (idx !== -1) { ok = true; usedRecovery = true; remaining = codes.filter((_, i) => i !== idx); }
    }
    if (!ok) return res.status(401).json({ success: false, error: GENERIC });

    // Code de secours consommé → on le retire (usage unique)
    if (usedRecovery && remaining) {
      await supabaseAdmin.from("user_mfa").update({ recovery_codes: remaining, updated_at: new Date().toISOString() }).eq("user_id", user_id);
    }

    // ✅ Tout est bon → on ouvre la session (mêmes étapes que /login)
    await supabaseAdmin.from("token_sessions")
      .update({ is_active: false, revoked_at: new Date().toISOString() })
      .eq("user_id", user_id).eq("is_active", true);

    const token = jwt.sign(
      { id: user_id, email: payload.email, first_name: payload.first_name, last_name: payload.last_name },
      SECRET_KEY, { expiresIn: "24h" }
    );
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await supabaseAdmin.from("token_sessions").insert([{
      user_id: user_id, token_hash: tokenHash, device_id: "web",
      user_agent: req.headers["user-agent"], ip: req.ip,
      expires_at: expiresAt.toISOString(), is_active: true,
    }]);
    res.cookie("auth_token", token, {
      httpOnly: true, secure: IS_PROD, sameSite: IS_PROD ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000, path: "/",
    });

    logAdminAction({
      targetUserId: user_id, adminEmail: payload.email,
      action: usedRecovery ? "login_2fa_recovery" : "login_2fa",
      detail: usedRecovery ? "Connexion via un code de secours" : "Connexion validée par 2FA",
    });

    return res.json({
      success: true, redirect: "/app/choix_irl_digital.html",
      user: { id: user_id, email: payload.email, first_name: payload.first_name, last_name: payload.last_name, company_id: payload.company_id || null },
    });
  } catch (error) {
    log.error("💥 /login/2fa:", safeError(error));
    return res.status(500).json({ success: false, error: "Erreur serveur." });
  }
});


// 🧪 ROUTE DE TEST - À ajouter temporairement
app.post("/test-supabase", devOnly, async (req, res) => {

  const { email, password } = req.body;

  try {


    // Test 2: Tester l'authentification
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email || "test@test.com",
      password: password || "test123"
    });



    // Test 3: Vérifier si l'utilisateur existe dans auth.users
    if (email) {
      // Note: On ne peut pas directement query auth.users, donc on teste avec signIn
    }

    res.json({
      supabase_config: {
        url_defined: !!process.env.SUPABASE_URL,
        key_defined: !!process.env.SUPABASE_SERVICE_ROLE_KEY
      },
      auth_test: {
        success: !error,
        error: error?.message,
        user_id: data?.user?.id
      }
    });

  } catch (error) {
    log.error("❌ Erreur serveur:", safeError(error));
    if (IS_PROD) return res.status(500).json({ error: "SERVER_ERROR" });
    return res.status(500).json({ error: error.message });
  }
});




// 📌 VÉRIFICATION DU TOKEN
// server.js - NOUVELLE VERSION /verify-token
app.post("/verify-token", async (req, res) => {
  try {
    const user = await resolveUserFromCookie(req);
    return res.json({ valid: true, user });
  } catch (error) {
    // ✅ Connexion concurrente : on le signale au frontend
    if (error.message === "SESSION_REVOKED") {
      res.clearCookie("auth_token", {
        path: "/",
        secure: IS_PROD,
        sameSite: IS_PROD ? "none" : "lax",
      });
      return res.json({ valid: false, code: "SESSION_REVOKED" });
    }
    return res.json({ valid: false });
  }
});


// 🧪 TEST SERVICE ROLE
app.get("/api/test-service-role", devOnly, async (req, res) => {
  try {
    // Test 1: Lecture simple
    const { data: testData, error: testError } = await supabase
      .from('token_sessions')
      .select('count')
      .limit(1);


    // Test 2: Écriture
    const { error: insertError } = await supabase
      .from('token_sessions')
      .insert({
        user_id: '00000000-0000-0000-0000-000000000000', // UUID fictif pour test
        token_hash: 'test_hash',
        expires_at: new Date().toISOString(),
        is_active: true
      });


    res.json({
      read: testError ? testError.message : 'OK',
      write: insertError ? insertError.message : 'OK'
    });

  } catch (error) {
    log.error("❌ Erreur serveur:", safeError(error));
    if (IS_PROD) return res.status(500).json({ error: "SERVER_ERROR" });
    return res.status(500).json({ error: error.message });
  }
});


// ---------------------------
// ROUTES PROTÉGÉES AVEC ABONNEMENTS
// ---------------------------

app.get("/test-supabase", devOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.auth.getUser();
    res.json({
      status: "OK",
      user: data.user,
      error: error?.message
    });
  } catch (error) {
    log.error("❌ Erreur serveur:", safeError(error));
    if (IS_PROD) return res.status(500).json({ error: "SERVER_ERROR" });
    return res.status(500).json({ error: error.message });
  }
});


// ==================== ROUTES API PROFIL INLINE ====================

// ✅ Route de santé pour debug
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    scope: 'server.js-inline',
    timestamp: new Date().toISOString()
  });
});


// ✅ ROUTE MY-PROFILE - VÉRIFIEZ QU'ELLE RETOURNE avatar_url
app.get('/api/my-profile', authenticateToken, async (req, res) => {

  try {
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('first_name, last_name, phone, company_id, avatar_url')
      .eq('user_id', req.user.id)
      .single();



    if (error || !profile) {
      return res.status(404).json({ error: 'Profil non trouvé' });
    }

    // ✅ BIEN retourner avatar_url
    const responseData = {
      id: req.user.id,
      email: req.user.email,
      first_name: profile.first_name,
      last_name: profile.last_name,
      phone: profile.phone,
      company_id: profile.company_id,
      avatar_url: profile.avatar_url,  // ⚠️ CRITIQUE : toujours inclure
      // ✅ Rôle + accès (déjà résolus sur req.user, aucune requête en plus) :
      // sert à la page profil pour afficher les bons onglets (équipe / abonnement).
      role: req.user.role,
      subscription_type: req.user.subscription_type,
      has_active_subscription: req.user.has_active_subscription
    };

    res.json(responseData);

  } catch (error) {
    log.error('💥 [API My-Profile] Exception:', safeError(error));
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// ✅ Lecture des infos entreprise (companies) -> auto-remplissage profile.html
app.get("/api/my-company", authenticateToken, async (req, res) => {

  try {
    const { data: company, error } = await supabase
      .from("companies")
      .select(
        "id, legal_name, display_name, company_size, company_siret, billing_street, billing_postal_code, billing_city, billing_country",
      )
      .eq("owner_id", req.user.id)
      .maybeSingle();

    if (error) {
      log.error("❌ [API My-Company] Supabase error:", safeError(error));
      return res.status(400).json({ ok: false, error: "Erreur serveur" });
    }

    // Si pas encore de company : on renvoie un objet vide (pas une 404)
    return res.json(company || {});
  } catch (e) {
    log.error("💥 [API My-Company] Exception:", safeError(e));
    return res.status(500).json({ ok: false, error: "Erreur serveur my-company" });
  }
});


// ✅ Mise à jour du profil (POST au lieu de PUT pour CSRF)
app.post('/api/update-profile', authenticateToken, requireCsrf, async (req, res) => {

  try {
    const { firstName, lastName, phone, companyId } = req.body;

    // Nettoyage des données
    const cleanPhone = (phone || '').replace(/[.\s-]/g, '').trim() || null;

    const updateData = {
      first_name: (firstName || '').trim() || null,
      last_name: (lastName || '').trim() || null,
      phone: cleanPhone,
      company_id: companyId || null,
      updated_at: new Date().toISOString()
    };


    const { data, error } = await supabase
      .from('profiles')
      .update(updateData)
      .eq('user_id', req.user.id)
      .select() // Retourne les données mises à jour
      .single();

    if (error) {
      log.error('❌ [API Update-Profile] Erreur Supabase:', safeError(error));
      return res.status(400).json({
        ok: false,
        error: 'Échec de la mise à jour: ' + error.message
      });
    }

    res.json({
      ok: true,
      message: 'Profil mis à jour avec succès',
      user: {
        firstName: data.first_name,
        lastName: data.last_name,
        phone: data.phone,
        companyId: data.company_id
      }
    });

  } catch (error) {
    log.error('💥 [API Update-Profile] Exception:', safeError(error));
    res.status(500).json({
      ok: false,
      error: 'Erreur serveur lors de la mise à jour du profil'
    });
  }
});


// ✅ Suivi d'usage (analytics) — enregistre l'ouverture d'une page.
//    Ne stocke QUE : qui (via le cookie), quelle page, quand. Jamais de contenu.
app.post('/api/track', authenticateToken, requireCsrf, async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(204).end();

    // Nom de page reçu du front : on borne et on nettoie (défensif)
    const page = String(req.body?.page || '').trim().slice(0, 120);
    if (!page) return res.status(204).end();

    // Insertion "fire-and-forget"
    await supabaseAdmin
      .from('activity_log')
      .insert({ user_id: userId, page });

    return res.status(204).end();
  } catch (e) {
    // ⚠️ Un échec de tracking ne doit JAMAIS gêner l'utilisateur
    log.warn('⚠️ /api/track insert failed:', e?.message);
    return res.status(204).end();
  }
});


// ✅ [ADMIN] Vérifie que l'appelant est admin (gate de la future page admin)
app.get('/api/admin/check', authenticateToken, requireAdmin, (req, res) => {
  return res.json({ ok: true, email: req.user?.email || null });
});


// ✅ [ADMIN] Renvoie les stats d'usage (pages via vues + emails via API admin)
app.get('/api/admin/analytics', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [pagesRes, actRes, usersList, profsRes, compsRes] = await Promise.all([
      supabaseAdmin
        .from('v_admin_pages_stats')
        .select('*')
        .order('opens', { ascending: false }),
      supabaseAdmin
        .from('v_admin_user_activity')
        .select('*'),
      supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 }),
      supabaseAdmin.from('profiles').select('user_id, company_id'),
      supabaseAdmin.from('companies').select('id, owner_id, display_name, legal_name'),
    ]);

    if (pagesRes.error) throw pagesRes.error;
    if (actRes.error) throw actRes.error;
    if (usersList.error) throw usersList.error;
    if (profsRes.error) throw profsRes.error;
    if (compsRes.error) throw compsRes.error;

    // Map user_id -> activité (depuis la vue, ne lit que activity_log)
    const actMap = new Map((actRes.data || []).map((r) => [r.user_id, r]));

    // Entreprise : 2 chemins (lien direct company_id OU propriétaire owner_id pour les vieux comptes)
    const profMap     = new Map((profsRes.data || []).map((p) => [p.user_id, p]));
    const compById    = new Map((compsRes.data || []).map((c) => [c.id, c]));
    const compByOwner = new Map((compsRes.data || []).map((c) => [c.owner_id, c]));

    // Emails via l'API admin (lecture sûre de auth.users) + on inclut TOUS les comptes (même inactifs)
    const users = (usersList.data?.users || [])
      .map((u) => {
        const a = actMap.get(u.id);
        const p = profMap.get(u.id) || {};
        const comp = compById.get(p.company_id) || compByOwner.get(u.id) || null;
        const company = comp ? (comp.display_name || comp.legal_name || null) : null;
        return { user_id: u.id, email: u.email || null, company, opens: a?.opens || 0, last_seen: a?.last_seen || null };
      })
      .sort((x, y) => {
        if (!x.last_seen && !y.last_seen) return 0;
        if (!x.last_seen) return 1;
        if (!y.last_seen) return -1;
        return String(y.last_seen).localeCompare(String(x.last_seen));
      });

    return res.json({ ok: true, pages: pagesRes.data || [], users });
  } catch (e) {
    log.error('❌ /api/admin/analytics:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur analytics' });
  }
});


// ===== [ADMIN] Statistiques d'usage avancées (temps actif ESTIMÉ + sessions) =====
// Tout est calculé en Node à partir de activity_log (qui / page / quand) : AUCUNE nouvelle table SQL.
// Règles d'estimation : session coupée après 30 min d'inactivité ; temps d'une page = écart jusqu'à
// la suivante de la session, plafonné à 5 min ; dernière page d'une session = 1 min forfaitaire.
const USAGE_SESSION_GAP_MS = 30 * 60 * 1000;
const USAGE_PAGE_CAP_MS    = 5 * 60 * 1000;
const USAGE_LAST_PAGE_MS   = 60 * 1000;

// Catégorie d'une page (alignée sur les 3 modes INTEGORA + Admin / Compte / Parcours / Plateforme).
function usageCategory(page, folder) {
  if (!page) return 'Autre';
  if (String(page).startsWith('admin')) return 'Admin';
  if (!folder) {
    if (page === 'profile' || page === 'support') return 'Compte';
    if (page === 'choix_irl_digital') return 'Parcours';
    if (page === 'tableau_de_pilotage') return 'Plateforme';
    if (page === 'jeu_irl') return "Activités d'équipe";
    return 'Autre';
  }
  const root = String(folder).split('/')[0];
  if (['bien_etre_irl', 'collaboration_irl', 'competition_amicale', 'connaissance_des_collegues_irl', 'creativite_irl'].includes(root)) return "Activités d'équipe";
  if (['recrutement', 'integration', 'manager_autrement'].includes(root)) return 'Supports RH';
  if (root === 'appui_managerial') return String(folder).includes('/outils') ? 'Outils interactifs' : 'Supports RH';
  return 'Autre';
}

// Date de début ISO selon la période demandée (null = depuis le début).
function usageSince(period) {
  const now = Date.now();
  switch (period) {
    case '7d':  return new Date(now - 7 * 86400000).toISOString();
    case '30d': return new Date(now - 30 * 86400000).toISOString();
    case 'month': { const d = new Date(); return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1)).toISOString(); }
    case '3m':  return new Date(now - 90 * 86400000).toISOString();
    case 'year': return new Date(now - 365 * 86400000).toISOString();
    case 'all': default: return null;
  }
}

app.get('/api/admin/usage', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const scope = ['admin', 'all'].includes(req.query?.scope) ? req.query.scope : 'client';
    const period = String(req.query?.period || '30d');
    const sinceIso = usageSince(period);

    // 0) Comptes : emails + entreprises (servent au filtrage des comptes internes ET à l'affichage)
    const [usersList, profsRes, compsRes] = await Promise.all([
      supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 }),
      supabaseAdmin.from('profiles').select('user_id, company_id'),
      supabaseAdmin.from('companies').select('id, owner_id, display_name, legal_name'),
    ]);
    const emailOf = new Map((usersList.data?.users || []).map((u) => [u.id, u.email || null]));
    const profMap = new Map((profsRes.data || []).map((p) => [p.user_id, p]));
    const compById = new Map((compsRes.data || []).map((c) => [c.id, c]));
    const compByOwner = new Map((compsRes.data || []).map((c) => [c.owner_id, c]));
    const companyOf = (uid) => {
      const p = profMap.get(uid) || {};
      const c = compById.get(p.company_id) || compByOwner.get(uid) || null;
      return c ? (c.display_name || c.legal_name || null) : null;
    };
    // Comptes internes INTEGORA (admin / support) repérés par le domaine email → exclus de l'usage CLIENT.
    const internalSet = new Set();
    (usersList.data?.users || []).forEach((u) => { if ((u.email || '').toLowerCase().endsWith('@integora.fr')) internalSet.add(u.id); });

    // 1) Lecture des événements (paginée, garde-fou à 100k lignes)
    const rows = [];
    const PAGE = 1000;
    for (let from = 0; ; from += PAGE) {
      let q = supabaseAdmin.from('activity_log')
        .select('user_id, page, created_at')
        .order('created_at', { ascending: true })
        .range(from, from + PAGE - 1);
      if (sinceIso) q = q.gte('created_at', sinceIso);
      const { data, error } = await q;
      if (error) throw error;
      rows.push(...(data || []));
      if (!data || data.length < PAGE || rows.length >= 100000) break;
    }

    // 2) Dossier de chaque page (pour la catégorie). Pages admin exclues de getAppPages → repérées par préfixe.
    const folderOf = new Map(getAppPages().map((p) => [p.page, p.folder]));

    // 3) Filtre périmètre + regroupement par compte (ordre chronologique conservé)
    const byUser = new Map();
    for (const e of rows) {
      // « Utilisation client » : on exclut entièrement les comptes internes (admin/support).
      if (scope === 'client' && internalSet.has(e.user_id)) continue;
      const cat = usageCategory(e.page, folderOf.get(e.page) || null);
      if (scope === 'client' && cat === 'Admin') continue;
      if (scope === 'admin' && cat !== 'Admin') continue;
      e._cat = cat;
      if (!byUser.has(e.user_id)) byUser.set(e.user_id, []);
      byUser.get(e.user_id).push(e);
    }

    // 4) Agrégation : temps actif estimé + sessions, par page ET par compte
    const pageAgg = new Map();
    const accountsRaw = [];
    let totalSessions = 0;
    for (const [uid, evs] of byUser) {
      let sessions = 0, userTime = 0, lastSeen = 0;
      const distinct = new Set();
      for (let i = 0; i < evs.length; i++) {
        const t = new Date(evs[i].created_at).getTime();
        const prevT = i > 0 ? new Date(evs[i - 1].created_at).getTime() : null;
        const nextT = i < evs.length - 1 ? new Date(evs[i + 1].created_at).getTime() : null;
        if (i === 0 || (t - prevT) > USAGE_SESSION_GAP_MS) sessions++;
        const sessionEnd = (nextT === null) || ((nextT - t) > USAGE_SESSION_GAP_MS);
        const dur = sessionEnd ? USAGE_LAST_PAGE_MS : Math.min(nextT - t, USAGE_PAGE_CAP_MS);
        userTime += dur;
        distinct.add(evs[i].page);
        if (t > lastSeen) lastSeen = t;
        let pa = pageAgg.get(evs[i].page);
        if (!pa) {
          pa = { page: evs[i].page, folder: folderOf.get(evs[i].page) || null, category: evs[i]._cat, opens: 0, users: new Set(), timeMs: 0, lastOpen: 0 };
          pageAgg.set(evs[i].page, pa);
        }
        pa.opens++; pa.users.add(uid); pa.timeMs += dur; if (t > pa.lastOpen) pa.lastOpen = t;
      }
      totalSessions += sessions;
      accountsRaw.push({ user_id: uid, opens: evs.length, distinctPages: distinct.size, sessions, activeTimeMs: userTime, last_seen: lastSeen ? new Date(lastSeen).toISOString() : null });
    }

    // 5) Comptes enrichis (emails + entreprises calculés à l'étape 0)
    const accounts = accountsRaw
      .map((a) => ({ ...a, email: emailOf.get(a.user_id) || null, company: companyOf(a.user_id) }))
      .sort((x, y) => (y.activeTimeMs - x.activeTimeMs));

    // 6) Pages triées (par ouvertures) + KPI globaux
    const pages = Array.from(pageAgg.values()).map((p) => ({
      page: p.page, folder: p.folder, category: p.category, opens: p.opens, users: p.users.size,
      timeMs: p.timeMs, avgTimeMs: p.opens ? Math.round(p.timeMs / p.opens) : 0,
      last_open: p.lastOpen ? new Date(p.lastOpen).toISOString() : null,
    })).sort((a, b) => b.opens - a.opens);

    const pageViews = pages.reduce((s, p) => s + p.opens, 0);
    const activeTimeMs = accounts.reduce((s, a) => s + a.activeTimeMs, 0);
    const top = pages[0] || null;
    const kpis = {
      pageViews,
      activeAccounts: accounts.length,
      activeTimeMs,
      totalSessions,
      avgSessionMs: totalSessions ? Math.round(activeTimeMs / totalSessions) : 0,
      topPage: top ? { page: top.page, opens: top.opens } : null,
    };

    // Détail d'UN compte (optionnel) : ses pages consultées avec temps actif estimé, dans le périmètre demandé.
    let userPages = null;
    const reqUserId = String(req.query?.userId || '').trim();
    if (/^[0-9a-f-]{36}$/i.test(reqUserId) && byUser.has(reqUserId)) {
      const evs = byUser.get(reqUserId);
      const upm = new Map();
      for (let i = 0; i < evs.length; i++) {
        const t = new Date(evs[i].created_at).getTime();
        const nextT = i < evs.length - 1 ? new Date(evs[i + 1].created_at).getTime() : null;
        const sessionEnd = (nextT === null) || ((nextT - t) > USAGE_SESSION_GAP_MS);
        const dur = sessionEnd ? USAGE_LAST_PAGE_MS : Math.min(nextT - t, USAGE_PAGE_CAP_MS);
        let up = upm.get(evs[i].page);
        if (!up) { up = { page: evs[i].page, folder: folderOf.get(evs[i].page) || null, category: evs[i]._cat, opens: 0, timeMs: 0, lastOpen: 0 }; upm.set(evs[i].page, up); }
        up.opens++; up.timeMs += dur; if (t > up.lastOpen) up.lastOpen = t;
      }
      userPages = Array.from(upm.values()).map((u) => ({
        page: u.page, folder: u.folder, category: u.category, opens: u.opens, timeMs: u.timeMs,
        last_open: u.lastOpen ? new Date(u.lastOpen).toISOString() : null,
      })).sort((a, b) => b.opens - a.opens);
    }

    return res.json({ ok: true, scope, period, kpis, pages, accounts, userPages });
  } catch (e) {
    log.error('❌ /api/admin/usage:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur statistiques' });
  }
});


// ✅ [ADMIN] Détail d'activité d'UN compte : pages lues + TOUTES les pages jamais ouvertes.
// Lecture seule, à la demande (1 compte à la fois). Liste des pages = automatique (scan app/).
app.get('/api/admin/user-activity', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = String(req.query?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }

    // 3 lectures en parallèle : pages (regroupées) + frise semaines + frise mois
    const [pageRes, weekRes, monthRes] = await Promise.all([
      supabaseAdmin.rpc('admin_user_page_activity', { uid: userId }),
      supabaseAdmin.rpc('admin_user_weekly_activity', { uid: userId }),
      supabaseAdmin.rpc('admin_user_monthly_activity', { uid: userId }),
    ]);
    if (pageRes.error) throw pageRes.error;
    if (weekRes.error) throw weekRes.error;
    if (monthRes.error) throw monthRes.error;
    const data = pageRes.data;

    const allPages = getAppPages();                       // [{ page, folder }]
    const folderOf = new Map(allPages.map((p) => [p.page, p.folder]));

    // Pages lues (on rattache le dossier pour le regroupement à l'écran)
    const activity = (data || []).map((r) => ({
      page: r.page,
      opens: Number(r.opens) || 0,
      last_open: r.last_open || null,
      folder: folderOf.has(r.page) ? folderOf.get(r.page) : null,
    }));

    // Pages jamais ouvertes = toutes les pages connues - celles qu'il a ouvertes
    const openedSet = new Set(activity.map((r) => r.page));
    const neverOpened = allPages.filter((p) => !openedSet.has(p.page));

    // Frise des 12 dernières semaines (semaines à 0 incluses pour voir le décrochage)
    const weekly = (weekRes.data || []).map((w) => ({
      year: w.iso_year,
      week: w.iso_week,
      week_start: w.week_start,
      opens: Number(w.opens) || 0,
    }));

    // Frise des 12 derniers mois (mois à 0 inclus)
    const monthly = (monthRes.data || []).map((m) => ({
      year: m.yr,
      month: m.mon,
      month_start: m.month_start,
      opens: Number(m.opens) || 0,
    }));

    return res.json({ ok: true, activity, neverOpened, weekly, monthly, totalPages: allPages.length });
  } catch (e) {
    log.error('❌ /api/admin/user-activity:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur activité compte' });
  }
});


// ✅ [ADMIN] Pages ouvertes par UN compte pendant UNE semaine ISO précise (clic sur une barre de la frise).
app.get('/api/admin/user-activity-week', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = String(req.query?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }
    const year = parseInt(req.query?.year, 10);
    const week = parseInt(req.query?.week, 10);
    if (!Number.isInteger(year) || year < 2020 || year > 2100) {
      return res.status(400).json({ ok: false, error: 'année invalide' });
    }
    if (!Number.isInteger(week) || week < 1 || week > 53) {
      return res.status(400).json({ ok: false, error: 'semaine invalide' });
    }

    const { data, error } = await supabaseAdmin.rpc('admin_user_page_activity_week', { uid: userId, y: year, w: week });
    if (error) throw error;

    const folderOf = new Map(getAppPages().map((p) => [p.page, p.folder]));
    const activity = (data || []).map((r) => ({
      page: r.page,
      opens: Number(r.opens) || 0,
      last_open: r.last_open || null,
      folder: folderOf.has(r.page) ? folderOf.get(r.page) : null,
    }));

    return res.json({ ok: true, activity, year, week });
  } catch (e) {
    log.error('❌ /api/admin/user-activity-week:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur activité semaine' });
  }
});


// ✅ [ADMIN] Pages ouvertes par UN compte pendant UN mois précis (clic sur une barre de la frise mois).
app.get('/api/admin/user-activity-month', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = String(req.query?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }
    const year = parseInt(req.query?.year, 10);
    const month = parseInt(req.query?.month, 10);
    if (!Number.isInteger(year) || year < 2020 || year > 2100) {
      return res.status(400).json({ ok: false, error: 'année invalide' });
    }
    if (!Number.isInteger(month) || month < 1 || month > 12) {
      return res.status(400).json({ ok: false, error: 'mois invalide' });
    }

    const { data, error } = await supabaseAdmin.rpc('admin_user_page_activity_month', { uid: userId, y: year, mo: month });
    if (error) throw error;

    const folderOf = new Map(getAppPages().map((p) => [p.page, p.folder]));
    const activity = (data || []).map((r) => ({
      page: r.page,
      opens: Number(r.opens) || 0,
      last_open: r.last_open || null,
      folder: folderOf.has(r.page) ? folderOf.get(r.page) : null,
    }));

    return res.json({ ok: true, activity, year, month });
  } catch (e) {
    log.error('❌ /api/admin/user-activity-month:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur activité mois' });
  }
});


// ✅ [ADMIN] Tendance globale de l'app : total des visites + comptes actifs, mois par mois (14 derniers mois).
app.get('/api/admin/global-monthly', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin.rpc('admin_global_monthly');
    if (error) throw error;
    const months = (data || []).map((m) => ({
      year: m.yr, month: m.mon, month_start: m.month_start,
      opens: Number(m.opens) || 0, active_users: Number(m.active_users) || 0,
    }));
    return res.json({ ok: true, months });
  } catch (e) {
    log.error('❌ /api/admin/global-monthly:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur tendance mensuelle' });
  }
});


// ✅ [ADMIN] Pages les plus ouvertes pendant UN mois précis (clic sur un mois de la tendance).
app.get('/api/admin/global-month', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const year = parseInt(req.query?.year, 10);
    const month = parseInt(req.query?.month, 10);
    if (!Number.isInteger(year) || year < 2020 || year > 2100) {
      return res.status(400).json({ ok: false, error: 'année invalide' });
    }
    if (!Number.isInteger(month) || month < 1 || month > 12) {
      return res.status(400).json({ ok: false, error: 'mois invalide' });
    }
    const { data, error } = await supabaseAdmin.rpc('admin_global_month_pages', { y: year, mo: month });
    if (error) throw error;
    const folderOf = new Map(getAppPages().map((p) => [p.page, p.folder]));
    const pages = (data || []).map((r) => ({
      page: r.page, opens: Number(r.opens) || 0, users: Number(r.users) || 0,
      folder: folderOf.has(r.page) ? folderOf.get(r.page) : null,
    }));
    return res.json({ ok: true, pages, year, month });
  } catch (e) {
    log.error('❌ /api/admin/global-month:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur pages du mois' });
  }
});


// ✅ [ADMIN] Liste des comptes avec infos profil + abonnement
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [usersList, profsRes, subsRes, compsRes, actRes] = await Promise.all([
      supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 }),
      supabaseAdmin.from('profiles').select('user_id, first_name, last_name, phone, company_id'),
      supabaseAdmin.from('subscriptions').select('user_id, plan, status, tier, current_paid_tier, current_period_end, trial_end, cancel_at, started_at, stripe_subscription_id, access_locked, access_locked_reason'),
      supabaseAdmin.from('companies').select('id, owner_id, display_name, legal_name'),
      supabaseAdmin.from('v_admin_user_activity').select('user_id, last_seen'),
    ]);
    if (usersList.error) throw usersList.error;
    if (profsRes.error) throw profsRes.error;
    if (subsRes.error) throw subsRes.error;
    if (compsRes.error) throw compsRes.error;
    if (actRes.error) throw actRes.error;

    const profMap = new Map((profsRes.data || []).map((p) => [p.user_id, p]));
    const subMap  = new Map((subsRes.data  || []).map((s) => [s.user_id, s]));
    // Entreprise : lien direct (company_id) OU propriétaire (owner_id) pour les vieux comptes
    const compById    = new Map((compsRes.data || []).map((c) => [c.id, c]));
    const compByOwner = new Map((compsRes.data || []).map((c) => [c.owner_id, c]));
    // Dernière activité (depuis activity_log via la vue)
    const actMap = new Map((actRes.data || []).map((a) => [a.user_id, a]));

    const users = (usersList.data?.users || []).map((u) => {
      const p = profMap.get(u.id) || {};
      const s = subMap.get(u.id) || {};
      const comp = compById.get(p.company_id) || compByOwner.get(u.id) || null;
      const company = comp ? (comp.display_name || comp.legal_name || null) : null;
      return {
        user_id: u.id,
        email: u.email || null,
        company,
        first_name: p.first_name || null,
        last_name: p.last_name || null,
        phone: p.phone || null,
        plan: s.plan || null,
        status: s.status || null,
        tier: s.tier || null,
        current_paid_tier: s.current_paid_tier || null,
        current_period_end: s.current_period_end || null,
        trial_end: s.trial_end || null,
        cancel_at: s.cancel_at || null,
        started_at: s.started_at || null,
        has_stripe: !!s.stripe_subscription_id,
        suspended: s.access_locked === true && String(s.access_locked_reason || '').toLowerCase() === 'admin_suspended',
        payment_failed: s.access_locked === true && String(s.access_locked_reason || '').toLowerCase() === 'payment_failed',
        last_seen: (actMap.get(u.id) || {}).last_seen || null,
      };
    }).sort((a, b) => String(a.email || '').localeCompare(String(b.email || '')));

    return res.json({ ok: true, users });
  } catch (e) {
    log.error('❌ /api/admin/users:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur liste comptes' });
  }
});


// ✅ [ADMIN] Liste des entreprises — vue multi-tenant, LECTURE SEULE.
//    Résumé par entreprise : nom, taille (palier d'abonnement du propriétaire),
//    nb de comptes, nb d'équipes, abonnement, dernière activité.
//    Aucun contenu métier — uniquement structure + compteurs (RGPD).
app.get('/api/admin/companies', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [compsRes, profsRes, subsRes, teamsRes, actRes, tmRes, collabListRes] = await Promise.all([
      supabaseAdmin.from('companies').select('id, owner_id, display_name, legal_name'),
      supabaseAdmin.from('profiles').select('user_id, company_id, role, archived_at'),
      supabaseAdmin.from('subscriptions').select('user_id, plan, status, tier, current_paid_tier, current_period_end, trial_end'),
      supabaseAdmin.from('teams').select('id, company_id, archived_at'),
      supabaseAdmin.from('v_admin_user_activity').select('user_id, last_seen'),
      supabaseAdmin.from('team_members').select('user_id, team_id'),
      supabaseAdmin.from('pilotage_collaborators').select('company_id, team_id'),
    ]);
    for (const r of [compsRes, profsRes, subsRes, teamsRes, actRes, tmRes, collabListRes]) if (r.error) throw r.error;

    const subMap = new Map((subsRes.data || []).map((s) => [s.user_id, s]));
    const actMap = new Map((actRes.data || []).map((a) => [a.user_id, a]));

    // Comptes (non archivés) regroupés par entreprise
    const accountsByCompany = new Map();   // company_id -> Set(user_id)
    for (const p of (profsRes.data || [])) {
      if (!p.company_id || p.archived_at) continue;
      if (!accountsByCompany.has(p.company_id)) accountsByCompany.set(p.company_id, new Set());
      accountsByCompany.get(p.company_id).add(p.user_id);
    }
    // Équipes actives par entreprise
    const teamsByCompany = new Map();
    for (const t of (teamsRes.data || [])) {
      if (!t.company_id || t.archived_at) continue;
      teamsByCompany.set(t.company_id, (teamsByCompany.get(t.company_id) || 0) + 1);
    }

    // --- Diagnostic léger par entreprise (Niveau 1 : OK / Attention / Bloquant) ---
    const teamSetsByCompany = new Map();   // company_id -> { all:Set, archived:Set }
    for (const t of (teamsRes.data || [])) {
      if (!t.company_id) continue;
      if (!teamSetsByCompany.has(t.company_id)) teamSetsByCompany.set(t.company_id, { all: new Set(), archived: new Set() });
      const e = teamSetsByCompany.get(t.company_id);
      e.all.add(t.id); if (t.archived_at) e.archived.add(t.id);
    }
    const tmByUser = new Map();             // user_id -> [team_id...]
    for (const l of (tmRes.data || [])) {
      if (!tmByUser.has(l.user_id)) tmByUser.set(l.user_id, []);
      tmByUser.get(l.user_id).push(l.team_id);
    }
    const profsByCompany = new Map();
    for (const p of (profsRes.data || [])) {
      if (!p.company_id) continue;
      if (!profsByCompany.has(p.company_id)) profsByCompany.set(p.company_id, []);
      profsByCompany.get(p.company_id).push(p);
    }
    const collabByCompany = new Map();      // company_id -> [team_id...]
    for (const c of (collabListRes.data || [])) {
      if (!c.company_id) continue;
      if (!collabByCompany.has(c.company_id)) collabByCompany.set(c.company_id, []);
      collabByCompany.get(c.company_id).push(c.team_id);
    }
    function diagFor(companyId) {
      const tinfo = teamSetsByCompany.get(companyId) || { all: new Set(), archived: new Set() };
      let blocked = false, warn = false;
      for (const p of (profsByCompany.get(companyId) || [])) {
        const assigned = tmByUser.get(p.user_id) || [];
        if (p.archived_at) { if (assigned.length) blocked = true; continue; }   // archivé avec accès résiduel
        if ((p.role || 'membre') === 'membre') {
          const act = assigned.filter(id => tinfo.all.has(id) && !tinfo.archived.has(id));
          if (act.length === 0) warn = true;                                    // membre actif sans équipe
        }
      }
      for (const tid of (collabByCompany.get(companyId) || [])) {
        if (!tid || !tinfo.all.has(tid) || tinfo.archived.has(tid)) blocked = true;   // donnée orpheline / équipe archivée
      }
      return blocked ? 'blocked' : (warn ? 'warn' : 'ok');
    }

    const companies = (compsRes.data || []).map((c) => {
      const ids = accountsByCompany.get(c.id) || new Set();
      if (c.owner_id) ids.add(c.owner_id);          // le propriétaire compte toujours
      const ownerSub = subMap.get(c.owner_id) || {};
      let lastActivity = null;
      for (const id of ids) {
        const ls = (actMap.get(id) || {}).last_seen;
        if (ls && (!lastActivity || ls > lastActivity)) lastActivity = ls;
      }
      return {
        id: c.id,
        name: c.display_name || c.legal_name || '—',
        size: ownerSub.current_paid_tier || ownerSub.tier || null,
        accounts: ids.size,
        teams: teamsByCompany.get(c.id) || 0,
        plan: ownerSub.plan || null,
        status: ownerSub.status || null,
        current_period_end: ownerSub.current_period_end || null,
        trial_end: ownerSub.trial_end || null,
        last_activity: lastActivity,
        diagnostic: diagFor(c.id),
      };
    }).sort((a, b) => String(a.name).localeCompare(String(b.name)));

    return res.json({ ok: true, companies });
  } catch (e) {
    log.error('❌ /api/admin/companies:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur liste entreprises' });
  }
});


// ✅ [ADMIN] Fiche détaillée d'une entreprise — LECTURE SEULE.
//    Comptes (propriétaire + membres + état), équipes, abonnement, et INDICATEURS
//    DE SANTÉ (compteurs uniquement, jamais le contenu métier — RGPD).
app.get('/api/admin/companies/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const companyId = String(req.params.id || '');
    if (!/^[0-9a-f-]{36}$/i.test(companyId)) {
      return res.status(400).json({ ok: false, error: 'Identifiant entreprise invalide' });
    }

    // 1) L'entreprise
    const { data: company, error: cErr } = await supabaseAdmin
      .from('companies').select('id, owner_id, display_name, legal_name, created_at')
      .eq('id', companyId).maybeSingle();
    if (cErr) throw cErr;
    if (!company) return res.status(404).json({ ok: false, error: 'Entreprise introuvable' });

    // 2) Comptes rattachés (profiles) + le propriétaire
    const { data: profs, error: pErr } = await supabaseAdmin
      .from('profiles').select('user_id, first_name, last_name, role, phone, archived_at')
      .eq('company_id', companyId);
    if (pErr) throw pErr;
    const idSet = new Set((profs || []).filter(p => !p.archived_at).map(p => p.user_id));
    if (company.owner_id) idSet.add(company.owner_id);
    const idList = Array.from(idSet);
    const SAFE = idList.length ? idList : ['00000000-0000-0000-0000-000000000000'];

    // 3) Données liées (parallèle) : emails, abos, activité, 2FA, équipes, membres + santé pilotage
    const [usersList, subsRes, actRes, mfaRes, teamsRes, tmRes,
           collabRes, kpiRes, journalRes, thermoRes, goalsRes, auditRes, techRes] = await Promise.all([
      supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 }),
      supabaseAdmin.from('subscriptions').select('user_id, plan, status, tier, current_paid_tier, current_period_end, trial_end, cancel_at, stripe_subscription_id, access_locked, access_locked_reason').in('user_id', SAFE),
      supabaseAdmin.from('v_admin_user_activity').select('user_id, last_seen').in('user_id', SAFE),
      supabaseAdmin.from('user_mfa').select('user_id, enabled').in('user_id', SAFE),
      supabaseAdmin.from('teams').select('id, name, archived_at').eq('company_id', companyId),
      supabaseAdmin.from('team_members').select('team_id, user_id').eq('company_id', companyId),
      supabaseAdmin.from('pilotage_collaborators').select('team_id, data, updated_at').eq('company_id', companyId),
      supabaseAdmin.from('pilotage_monthly_kpis').select('team_id').eq('company_id', companyId),
      supabaseAdmin.from('pilotage_journal').select('team_id, data').eq('company_id', companyId),
      supabaseAdmin.from('pilotage_thermometres').select('team_id').eq('company_id', companyId),
      supabaseAdmin.from('pilotage_goals').select('team_id').eq('company_id', companyId),
      supabaseAdmin.from('admin_audit_log').select('action, admin_email, created_at').in('target_user_id', SAFE).order('created_at', { ascending: false }).limit(50),
      supabaseAdmin.from('pilotage_tech_log').select('team_id, actor_user_id, action, created_at').eq('company_id', companyId).order('created_at', { ascending: false }).limit(50),
    ]);
    if (usersList.error) throw usersList.error;
    for (const r of [subsRes, actRes, mfaRes, teamsRes, tmRes, collabRes, kpiRes, journalRes, thermoRes, goalsRes]) {
      if (r.error) throw r.error;
    }

    const emailById = new Map((usersList.data?.users || []).map(u => [u.id, u.email]));
    const initById  = new Map((usersList.data?.users || []).map(u => [u.id, !!u.user_metadata?.password_initialized]));
    const subById   = new Map((subsRes.data || []).map(s => [s.user_id, s]));
    const seenById  = new Map((actRes.data  || []).map(a => [a.user_id, a.last_seen]));
    const mfaById   = new Map((mfaRes.data  || []).map(m => [m.user_id, !!m.enabled]));
    const profById  = new Map((profs || []).map(p => [p.user_id, p]));

    // Comptes : propriétaire en tête, puis membres
    const accounts = idList.map((uid) => {
      const p = profById.get(uid) || {};
      const s = subById.get(uid) || {};
      const suspended = s.access_locked === true && String(s.access_locked_reason || '').toLowerCase() === 'admin_suspended';
      return {
        user_id: uid,
        email: emailById.get(uid) || null,
        first_name: p.first_name || null,
        last_name: p.last_name || null,
        role: (uid === company.owner_id) ? 'propriétaire' : (p.role || 'membre'),
        is_owner: uid === company.owner_id,
        suspended,
        twofa: mfaById.get(uid) || false,
        last_seen: seenById.get(uid) || null,
      };
    }).sort((a, b) => Number(b.is_owner) - Number(a.is_owner) || String(a.email || '').localeCompare(String(b.email || '')));

    // Équipes actives + nb de membres (actifs) + index des accès par utilisateur
    const teamsByUser = new Map();                 // user_id -> [team_id...]
    const membersByTeam = new Map();
    for (const tm of (tmRes.data || [])) {
      if (!teamsByUser.has(tm.user_id)) teamsByUser.set(tm.user_id, []);
      teamsByUser.get(tm.user_id).push(tm.team_id);
      if (idSet.has(tm.user_id)) membersByTeam.set(tm.team_id, (membersByTeam.get(tm.team_id) || 0) + 1);
    }
    const teamMeta = new Map((teamsRes.data || []).map(t => [t.id, { name: t.name || '—', archived: !!t.archived_at }]));
    const activeTeamCount = (teamsRes.data || []).filter(t => !t.archived_at).length;
    const teams = (teamsRes.data || []).filter(t => !t.archived_at).map(t => ({
      id: t.id, name: t.name || '—', members: membersByTeam.get(t.id) || 0,
    })).sort((a, b) => String(a.name).localeCompare(String(b.name)));

    // --- DIAGNOSTIC Bloc 1 : accès aux équipes (état OK / Attention / Bloqué) ---
    function accessRow(uid, email, name, role, isOwner, archived, suspended) {
      const assigned = teamsByUser.get(uid) || [];
      const issues = []; let state = 'ok'; let teamNames = [], teamIds = [];
      const isAdmin = isOwner || role === 'admin' || role === 'propriétaire';
      if (!isAdmin) {
        const act = assigned.filter(id => teamMeta.get(id) && !teamMeta.get(id).archived);
        const arch = assigned.filter(id => teamMeta.get(id) && teamMeta.get(id).archived);
        const unknown = assigned.filter(id => !teamMeta.get(id));
        teamNames = act.map(id => teamMeta.get(id).name);
        teamIds = act;
        if (archived) {
          if (assigned.length) { issues.push('Membre archivé avec accès résiduel'); state = 'blocked'; }
        } else {
          if (assigned.length === 0) { issues.push('Aucune équipe attribuée'); state = 'warn'; }
          if (arch.length) { issues.push(arch.length + ' équipe(s) archivée(s) attribuée(s)'); if (state !== 'blocked') state = 'warn'; }
          if (unknown.length) { issues.push('Accès à une équipe inexistante'); state = 'blocked'; }
          // Accès complet VOLONTAIRE (toutes les équipes attribuées explicitement) = normal → OK + détail discret.
          else if (activeTeamCount > 1 && act.length === activeTeamCount && !arch.length) { issues.push('Toutes les équipes attribuées'); }
        }
      }
      return { user_id: uid, email, name, role, is_owner: isOwner, archived: !!archived, suspended: !!suspended,
               all_teams: isAdmin, teams: teamNames, team_ids: teamIds,
               invited: !isAdmin && !archived && !initById.get(uid),
               state, issues };
    }
    const teamAccess = [];
    for (const a of accounts) {
      teamAccess.push(accessRow(a.user_id, a.email, [a.first_name, a.last_name].filter(Boolean).join(' '), a.role, a.is_owner, false, a.suspended));
    }
    for (const p of (profs || [])) {                 // archivés : visibles pour réactivation (accès résiduel = anomalie séparée)
      if (!p.archived_at) continue;
      teamAccess.push(accessRow(p.user_id, emailById.get(p.user_id) || null, [p.first_name, p.last_name].filter(Boolean).join(' '), p.role || 'membre', false, true, false));
    }

    // INDICATEURS DE SANTÉ PAR ÉQUIPE (Bloc 2) — on parcourt le jsonb pour COMPTER, jamais pour exposer
    const ACTIVE_ETATS = new Set(['ouvert', 'echange_prevu', 'a_faire', 'en_cours']);
    function blankHealth() {
      return { collaborators: 0, topics: 0, topics_done: 0, active_topics: 0, planned_exchanges: 0,
               journal_entries: 0, kpi_months: 0, thermometres: 0, goals: 0, last_activity: null };
    }
    const byTeam = new Map();   // team_id -> compteurs
    function bucket(teamId) { if (!byTeam.has(teamId)) byTeam.set(teamId, blankHealth()); return byTeam.get(teamId); }

    for (const row of (collabRes.data || [])) {
      const h = bucket(row.team_id);
      h.collaborators += 1;
      const tps = (row.data && Array.isArray(row.data.topics)) ? row.data.topics : [];
      for (const t of tps) {
        h.topics += 1;
        const e = t.etat || '';
        if (e === 'traite' || e === 'fait') h.topics_done += 1;
        if (ACTIVE_ETATS.has(e)) h.active_topics += 1;
        if (e === 'echange_prevu') h.planned_exchanges += 1;
      }
      if (row.updated_at && (!h.last_activity || row.updated_at > h.last_activity)) h.last_activity = row.updated_at;
    }
    for (const row of (journalRes.data || [])) {
      const d = row.data || {};
      const arr = Array.isArray(d.entries) ? d.entries : (Array.isArray(d) ? d : []);
      bucket(row.team_id).journal_entries += arr.length;
    }
    for (const row of (kpiRes.data || [])) bucket(row.team_id).kpi_months += 1;
    for (const row of (thermoRes.data || [])) bucket(row.team_id).thermometres += 1;
    for (const row of (goalsRes.data || [])) bucket(row.team_id).goals += 1;

    // Santé par équipe ACTIVE (nom résolu)
    const teamHealth = (teamsRes.data || []).filter(t => !t.archived_at).map(t => {
      const h = byTeam.get(t.id) || blankHealth();
      return Object.assign({ team_id: t.id, name: t.name || '—' }, h);
    }).sort((a, b) => String(a.name).localeCompare(String(b.name)));

    // Santé GLOBALE = somme de toutes les équipes (y compris orphelines)
    let topics = 0, topicsDone = 0, journalEntries = 0, kpiMonths = 0, thermoCount = 0, goalsCount = 0, lastSync = null;
    for (const h of byTeam.values()) {
      topics += h.topics; topicsDone += h.topics_done;
      journalEntries += h.journal_entries; kpiMonths += h.kpi_months;
      thermoCount += h.thermometres; goalsCount += h.goals;
      if (h.last_activity && (!lastSync || h.last_activity > lastSync)) lastSync = h.last_activity;
    }

    // --- DIAGNOSTIC Bloc 3 : anomalies détectées (titre + description + action) ---
    let dataArchivedTeam = 0, dataUnknownTeam = 0, dataNoTeam = 0, topicsNoCreated = 0;
    for (const row of (collabRes.data || [])) {
      const tid = row.team_id;
      if (!tid) dataNoTeam += 1;
      else if (!teamMeta.has(tid)) dataUnknownTeam += 1;
      else if (teamMeta.get(tid).archived) dataArchivedTeam += 1;
      const tps = (row.data && Array.isArray(row.data.topics)) ? row.data.topics : [];
      for (const t of tps) if (!t.createdAt && !t.created_at) topicsNoCreated += 1;
    }
    const anomalies = [];
    const A = (level, title, detail, hint) => anomalies.push({ level, title, detail, hint: hint || null });

    for (const a of accounts) {
      if (a.is_owner || a.role === 'admin' || a.role === 'propriétaire' || a.suspended) continue;
      const act = (teamsByUser.get(a.user_id) || []).filter(id => teamMeta.get(id) && !teamMeta.get(id).archived);
      if (act.length === 0) {
        A('warn', 'Membre sans équipe attribuée',
          (a.email || 'Ce membre') + " est actif mais n'est rattaché à aucune équipe : il ne voit aucun tableau de pilotage.",
          'Lui attribuer au moins une équipe (Comptes › Gérer les accès).');
      }
    }
    for (const p of (profs || [])) {
      if (!p.archived_at || !(teamsByUser.get(p.user_id) || []).length) continue;
      A('blocked', "Accès résiduel d'un membre archivé",
        (emailById.get(p.user_id) || 'Un membre archivé') + " a été archivé (accès retiré) mais figure encore dans des accès d'équipe.",
        'Retirer ses accès équipe pour finaliser le retrait.');
    }
    for (const t of (teamsRes.data || []).filter(t => !t.archived_at)) {
      if (!(membersByTeam.get(t.id) || 0)) {
        A('info', 'Équipe sans membre',
          'L’équipe « ' + (t.name || '—') + ' » n’a aucun membre attribué (seul l’admin la voit).',
          'Normal si gérée par l’admin seul ; sinon attribuer des membres.');
      }
    }
    for (const t of teamHealth) {
      const tot = t.collaborators + t.journal_entries + t.topics + t.kpi_months + t.thermometres + t.goals;
      if (!tot) {
        A('info', 'Équipe sans données de pilotage',
          'L’équipe « ' + t.name + ' » ne contient aucune donnée (ni suivi, ni KPI, ni journal).',
          'Équipe récente ou non utilisée — pas forcément un bug.');
      }
    }
    if (dataArchivedTeam) {
      A('blocked', 'Données sur une équipe archivée',
        dataArchivedTeam + ' donnée(s) de pilotage sont rattachées à une équipe archivée : elles n’apparaissent plus dans l’application.',
        'Restaurer l’équipe, ou réaffecter / supprimer ces données.');
    }
    if (dataUnknownTeam || dataNoTeam) {
      A('blocked', 'Données orphelines',
        (dataUnknownTeam + dataNoTeam) + ' donnée(s) pointent vers une équipe inexistante ou sans identifiant d’équipe (team_id).',
        'Incohérence à investiguer (suppression d’équipe, migration).');
    }
    if (topicsNoCreated) {
      A('info', 'Suivis sans date de création',
        topicsNoCreated + ' suivi(s) n’ont pas de date de création enregistrée.',
        'Donnée probablement ancienne — sans impact visible.');
    }
    const _ord = { blocked: 0, warn: 1, info: 2 };
    anomalies.sort((x, y) => (_ord[x.level] != null ? _ord[x.level] : 9) - (_ord[y.level] != null ? _ord[y.level] : 9));

    // --- DIAGNOSTIC Bloc 4 : dernières actions techniques (métadonnées only, AUCUN nom ni contenu) ---
    const EV_LABELS = { created: 'Suivi créé', status_changed: 'Statut modifié', updated: 'Suivi modifié',
      point_traite: 'Point traité', point_rouvert: 'Point rouvert', point_fait: 'Suivi terminé', suivi_demarre: 'Suivi démarré' };
    const ST_LABELS = { open: 'Ouvert', treated: 'Traité', planned_next_step: 'Prévu', archived: 'Archivé' };
    const ADMIN_LABELS = { update_profile: 'Profil modifié', change_email: 'Email changé', send_password_reset: 'Réinitialisation mot de passe',
      grant_subscription: 'Abonnement accordé', close_subscription: 'Abonnement clôturé', reactivate_renewal: 'Renouvellement réactivé',
      reactivate_subscription: 'Accès réactivé', suspend: 'Compte suspendu', reactivate: 'Compte réactivé', export_rgpd: 'Export RGPD',
      team_access_set: 'Accès équipe modifié', member_removed: 'Accès retiré', member_reactivated: 'Membre réactivé',
      invite_resent: 'Invitation renvoyée', member_invited: 'Membre invité', team_renamed: 'Équipe renommée' };
    const actions = [];
    for (const row of (collabRes.data || [])) {
      const teamName = (teamMeta.get(row.team_id) || {}).name || null;
      const tps = (row.data && Array.isArray(row.data.topics)) ? row.data.topics : [];
      for (const t of tps) {
        const evs = Array.isArray(t.events) ? t.events : [];
        for (const ev of evs) {
          const when = ev.createdAt || ev.date || ev.at || null;
          if (!when) continue;
          actions.push({
            when,
            type: EV_LABELS[ev.type] || 'Action de suivi',
            zone: 'Suivis individuels',
            team: teamName,
            source: 'Pilotage',
            // Auteur = compte INTEGORA ayant fait l'action (createdBy). JAMAIS le collaborateur suivi.
            author: (ev.createdBy && ev.createdBy !== 'Vous') ? ev.createdBy : null,
            status: ev.newStatus ? (ST_LABELS[ev.newStatus] || null) : null,
          });
        }
      }
    }
    for (const row of ((auditRes && auditRes.data) || [])) {
      actions.push({
        when: row.created_at, type: ADMIN_LABELS[row.action] || row.action || 'Action admin',
        zone: 'Administration', team: null, source: 'Admin', author: row.admin_email || null, status: null,
      });
    }
    // Journal technique d'entreprise (actions équipe/accès) — acteur = compte INTEGORA, jamais le collaborateur.
    const TECH_LABELS = { team_invite: 'Invitation envoyée', team_access_set: 'Accès équipe modifié',
      member_removed: 'Accès retiré', member_reactivated: 'Membre réactivé', team_renamed: 'Équipe renommée' };
    for (const row of ((techRes && techRes.data) || [])) {
      const p = profById.get(row.actor_user_id);
      const name = p ? [p.first_name, p.last_name].filter(Boolean).join(' ') : null;
      actions.push({
        when: row.created_at,
        type: TECH_LABELS[row.action] || row.action || 'Action technique',
        zone: 'Équipes & accès',
        team: row.team_id ? ((teamMeta.get(row.team_id) || {}).name || null) : null,
        source: 'Équipe',
        author: name || emailById.get(row.actor_user_id) || null,
        status: null,
      });
    }
    actions.sort((a, b) => String(b.when).localeCompare(String(a.when)));
    const recentActions = actions.slice(0, 40);

    const ownerSub = subById.get(company.owner_id) || {};
    return res.json({
      ok: true,
      company: {
        id: company.id,
        name: company.display_name || company.legal_name || '—',
        legal_name: company.legal_name || null,
        created_at: company.created_at || null,
        size: ownerSub.current_paid_tier || ownerSub.tier || null,
        plan: ownerSub.plan || null,
        status: ownerSub.status || null,
        current_period_end: ownerSub.current_period_end || null,
        trial_end: ownerSub.trial_end || null,
        has_stripe: !!ownerSub.stripe_subscription_id,
      },
      accounts,
      teams,
      team_access: teamAccess,
      team_health: teamHealth,
      anomalies,
      actions: recentActions,
      health: {
        collaborators: (collabRes.data || []).length,
        topics, topics_done: topicsDone,
        kpi_months: kpiMonths,
        journal_entries: journalEntries,
        thermometres: thermoCount,
        goals: goalsCount,
        last_sync: lastSync,
      },
    });
  } catch (e) {
    log.error('❌ /api/admin/companies/:id:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur fiche entreprise' });
  }
});


// ✅ [ADMIN] Gérer les accès équipe d'un membre d'une entreprise (override admin, inter-tenant).
//    requireAdmin + requireCsrf. Le serveur VALIDE que le membre ET les équipes appartiennent
//    bien à l'entreprise :id (zéro accès croisé). Action tracée (admin_audit_log).
app.post('/api/admin/companies/:id/member-teams', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const companyId = String(req.params.id || '');
    if (!/^[0-9a-f-]{36}$/i.test(companyId)) return res.status(400).json({ ok: false, error: 'Entreprise invalide' });
    const userId = String(req.body?.user_id || '');
    if (!/^[0-9a-f-]{36}$/i.test(userId)) return res.status(400).json({ ok: false, error: 'Membre invalide' });
    let teamIds = Array.isArray(req.body?.team_ids) ? req.body.team_ids.map((x) => String(x)) : null;
    if (!teamIds) return res.status(400).json({ ok: false, error: "Liste d'équipes invalide" });
    teamIds = [...new Set(teamIds)];
    for (const tid of teamIds) if (!/^[0-9a-f-]{36}$/i.test(tid)) return res.status(400).json({ ok: false, error: 'Équipe invalide' });

    // Le membre doit appartenir à CETTE entreprise et être de rôle 'membre'
    const { data: target, error: tErr } = await supabaseAdmin
      .from('profiles').select('user_id, company_id, role').eq('user_id', userId).maybeSingle();
    if (tErr) throw tErr;
    if (!target || target.company_id !== companyId || String(target.role || '').toLowerCase() !== 'membre') {
      return res.status(404).json({ ok: false, error: 'Membre introuvable dans cette entreprise' });
    }

    // Toutes les équipes demandées doivent appartenir à CETTE entreprise (et être actives)
    if (teamIds.length) {
      const { data: validTeams, error: vErr } = await supabaseAdmin
        .from('teams').select('id').eq('company_id', companyId).is('archived_at', null).in('id', teamIds);
      if (vErr) throw vErr;
      const validSet = new Set((validTeams || []).map((t) => t.id));
      if (teamIds.some((t) => !validSet.has(t))) {
        return res.status(400).json({ ok: false, error: "Une équipe n'appartient pas à cette entreprise (ou est archivée)" });
      }
    }

    // Réconciliation (scopée company + user) : on ajoute le manquant, on retire le surplus
    const { data: existing, error: exErr } = await supabaseAdmin
      .from('team_members').select('team_id').eq('company_id', companyId).eq('user_id', userId);
    if (exErr) throw exErr;
    const existingSet = new Set((existing || []).map((r) => r.team_id));
    const toAdd = teamIds.filter((t) => !existingSet.has(t));
    const toRemove = [...existingSet].filter((t) => !teamIds.includes(t));

    if (toAdd.length) {
      const rows = toAdd.map((t) => ({ team_id: t, user_id: userId, company_id: companyId, created_by: req.user.id }));
      const { error: insErr } = await supabaseAdmin.from('team_members').insert(rows);
      if (insErr) throw insErr;
    }
    if (toRemove.length) {
      const { error: delErr } = await supabaseAdmin
        .from('team_members').delete().eq('company_id', companyId).eq('user_id', userId).in('team_id', toRemove);
      if (delErr) throw delErr;
    }

    if (toAdd.length || toRemove.length) {
      logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'team_access_set',
        detail: 'Accès équipe modifié (admin) — +' + toAdd.length + ' / -' + toRemove.length });
    }
    return res.json({ ok: true, teams: teamIds });
  } catch (e) {
    log.error('❌ /api/admin/companies/:id/member-teams:', e?.message);
    return res.status(500).json({ ok: false, error: "Erreur lors de la mise à jour des accès" });
  }
});


// ✅ [ADMIN] Retirer un membre (archiver) d'une entreprise — coupe sessions + accès équipe.
app.post('/api/admin/companies/:id/members/:userId/remove', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const companyId = String(req.params.id || '');
    const userId = String(req.params.userId || '');
    if (!/^[0-9a-f-]{36}$/i.test(companyId) || !/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'Identifiant invalide' });
    }
    const { data: target, error: tErr } = await supabaseAdmin
      .from('profiles').select('user_id, company_id, role, archived_at').eq('user_id', userId).maybeSingle();
    if (tErr) throw tErr;
    if (!target || target.company_id !== companyId || target.role !== 'membre') {
      return res.status(404).json({ ok: false, error: 'Membre introuvable dans cette entreprise' });
    }
    if (target.archived_at) return res.json({ ok: true, already: true });

    const nowIso = new Date().toISOString();
    const { error: archErr } = await supabaseAdmin
      .from('profiles').update({ archived_at: nowIso, updated_at: nowIso }).eq('user_id', userId);
    if (archErr) throw archErr;
    await supabaseAdmin.from('token_sessions').update({ is_active: false, revoked_at: nowIso }).eq('user_id', userId).eq('is_active', true);
    await supabaseAdmin.from('team_members').delete().eq('user_id', userId);

    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'member_removed', detail: 'Accès membre retiré (archivé) — admin' });
    return res.json({ ok: true });
  } catch (e) {
    log.error('❌ admin member remove:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur lors du retrait' });
  }
});

// ✅ [ADMIN] Réactiver un membre archivé d'une entreprise (respecte la limite de membres actifs).
app.post('/api/admin/companies/:id/members/:userId/reactivate', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const companyId = String(req.params.id || '');
    const userId = String(req.params.userId || '');
    if (!/^[0-9a-f-]{36}$/i.test(companyId) || !/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'Identifiant invalide' });
    }
    const { data: target, error: tErr } = await supabaseAdmin
      .from('profiles').select('user_id, company_id, role, archived_at').eq('user_id', userId).maybeSingle();
    if (tErr) throw tErr;
    if (!target || target.company_id !== companyId || target.role !== 'membre') {
      return res.status(404).json({ ok: false, error: 'Membre introuvable dans cette entreprise' });
    }
    if (!target.archived_at) return res.json({ ok: true, already: true });

    const { count: activeCount, error: cErr } = await supabaseAdmin
      .from('profiles').select('user_id', { count: 'exact', head: true })
      .eq('company_id', companyId).eq('role', 'membre').is('archived_at', null);
    if (cErr) throw cErr;
    if ((activeCount || 0) >= MAX_TEAM_MEMBERS) {
      return res.status(409).json({ ok: false, error: `Limite atteinte (${MAX_TEAM_MEMBERS} membres actifs). Retirez d'abord un membre actif.` });
    }
    const { error: updErr } = await supabaseAdmin
      .from('profiles').update({ archived_at: null, updated_at: new Date().toISOString() }).eq('user_id', userId);
    if (updErr) throw updErr;

    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'member_reactivated', detail: 'Membre réactivé — admin' });
    return res.json({ ok: true });
  } catch (e) {
    log.error('❌ admin member reactivate:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur lors de la réactivation' });
  }
});

// ✅ [ADMIN] Renvoyer une invitation à un membre (compte créé mais mot de passe non encore défini).
app.post('/api/admin/companies/:id/members/:userId/resend-invite', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const companyId = String(req.params.id || '');
    const userId = String(req.params.userId || '');
    if (!/^[0-9a-f-]{36}$/i.test(companyId) || !/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'Identifiant invalide' });
    }
    const { data: target, error: tErr } = await supabaseAdmin
      .from('profiles').select('user_id, company_id, role, archived_at, first_name').eq('user_id', userId).maybeSingle();
    if (tErr) throw tErr;
    if (!target || target.company_id !== companyId || target.role !== 'membre') {
      return res.status(404).json({ ok: false, error: 'Membre introuvable dans cette entreprise' });
    }
    if (target.archived_at) return res.status(400).json({ ok: false, error: "Membre archivé — réactivez-le d'abord" });

    const { data: au, error: auErr } = await supabaseAdmin.auth.admin.getUserById(userId);
    if (auErr || !au?.user?.email) return res.status(404).json({ ok: false, error: 'Compte introuvable' });
    const email = au.user.email;
    if (au.user.user_metadata?.password_initialized) {
      return res.status(400).json({ ok: false, error: 'Ce membre a déjà activé son compte (aucune invitation à renvoyer)' });
    }

    const FRONT = process.env.FRONTEND_URL || (IS_PROD ? 'https://integora.fr' : 'http://localhost:3000');
    const { data: linkData, error: linkErr } = await supabaseAdmin.auth.admin.generateLink({
      type: 'recovery', email, options: { redirectTo: `${FRONT}/create-password.html` },
    });
    if (linkErr || !linkData?.properties?.action_link) {
      log.error('❌ admin resend-invite generateLink:', safeError(linkErr));
      return res.status(500).json({ ok: false, error: 'Erreur lors de la génération du lien' });
    }
    const link = linkData.properties.action_link;
    const prenom = target.first_name ? ' ' + escapeHtml(target.first_name) : '';
    const html = `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#1a1a1a;font-size:15px;line-height:1.6;">
        <h2 style="font-size:18px;margin:0 0 12px;">Votre accès INTEGORA</h2>
        <p>Bonjour${prenom}, vous avez été invité(e) à rejoindre INTEGORA. Cliquez ci-dessous pour créer votre mot de passe et activer votre accès.</p>
        <p style="margin:22px 0;"><a href="${link}" style="display:inline-block;background:#4a90e2;color:#fff;text-decoration:none;padding:12px 26px;border-radius:8px;font-weight:700;">Créer mon mot de passe</a></p>
        <p style="font-size:12px;color:#64748b;">Si le bouton ne fonctionne pas, copiez ce lien dans votre navigateur :<br>${link}</p>
      </div>`;
    await sendResendEmail({ to: email, subject: 'Votre accès INTEGORA — créez votre mot de passe', html });

    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'invite_resent', detail: 'Invitation renvoyée (admin)' });
    return res.json({ ok: true });
  } catch (e) {
    log.error('❌ admin resend-invite:', e?.message);
    return res.status(500).json({ ok: false, error: "Erreur lors du renvoi de l'invitation" });
  }
});

// ✅ [ADMIN] Inviter un nouveau membre dans une entreprise (crée le compte + email d'invitation Supabase).
app.post('/api/admin/companies/:id/invite', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const companyId = String(req.params.id || '');
    if (!/^[0-9a-f-]{36}$/i.test(companyId)) return res.status(400).json({ ok: false, error: 'Entreprise invalide' });

    const { data: company, error: cErr } = await supabaseAdmin
      .from('companies').select('id, display_name, legal_name').eq('id', companyId).maybeSingle();
    if (cErr) throw cErr;
    if (!company) return res.status(404).json({ ok: false, error: 'Entreprise introuvable' });

    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ ok: false, error: 'Email invalide' });
    const firstName = String(req.body?.first_name || '').trim().slice(0, 50) || null;
    const lastName = String(req.body?.last_name || '').trim().slice(0, 50) || null;
    let teamIds = Array.isArray(req.body?.team_ids) ? [...new Set(req.body.team_ids.map((x) => String(x)))] : [];
    for (const tid of teamIds) if (!/^[0-9a-f-]{36}$/i.test(tid)) return res.status(400).json({ ok: false, error: 'Équipe invalide' });

    // Limite de membres actifs (comme côté client)
    const { count: activeCount, error: cntErr } = await supabaseAdmin
      .from('profiles').select('user_id', { count: 'exact', head: true })
      .eq('company_id', companyId).eq('role', 'membre').is('archived_at', null);
    if (cntErr) throw cntErr;
    if ((activeCount || 0) >= MAX_TEAM_MEMBERS) {
      return res.status(409).json({ ok: false, error: `Limite atteinte (${MAX_TEAM_MEMBERS} membres actifs).` });
    }

    // Équipes ciblées : doivent appartenir à CETTE entreprise (actives)
    if (teamIds.length) {
      const { data: vt, error: vErr } = await supabaseAdmin
        .from('teams').select('id').eq('company_id', companyId).is('archived_at', null).in('id', teamIds);
      if (vErr) throw vErr;
      const vset = new Set((vt || []).map((t) => t.id));
      if (teamIds.some((t) => !vset.has(t))) return res.status(400).json({ ok: false, error: "Une équipe n'appartient pas à cette entreprise" });
    }

    const FRONT = process.env.FRONTEND_URL || (IS_PROD ? 'https://integora.fr' : 'http://localhost:3000');
    const companyName = company.display_name || company.legal_name || '';
    const { data: inviteData, error: inviteErr } = await supabaseAdmin.auth.admin.inviteUserByEmail(email, {
      redirectTo: `${FRONT}/create-password.html`,
      data: { first_name: firstName, last_name: lastName, company_name: companyName, role: 'membre', company_id: companyId, invited_by: req.user.id },
    });
    if (inviteErr) {
      if (String(inviteErr.message || '').toLowerCase().includes('already been registered')) {
        return res.status(409).json({ ok: false, error: 'Cet email a déjà un compte Integora' });
      }
      log.error('❌ admin invite inviteUserByEmail:', safeError(inviteErr));
      return res.status(500).json({ ok: false, error: "Erreur lors de l'invitation" });
    }
    const newUserId = inviteData?.user?.id || null;
    if (!newUserId) return res.status(500).json({ ok: false, error: 'Compte non créé' });

    const { error: profErr } = await supabaseAdmin.from('profiles').upsert({
      user_id: newUserId, first_name: firstName, last_name: lastName, company_id: companyId, role: 'membre', updated_at: new Date().toISOString(),
    }, { onConflict: 'user_id' });
    if (profErr) {
      log.error('❌ admin invite profile:', safeError(profErr));
      await supabaseAdmin.auth.admin.deleteUser(newUserId).catch(() => { });
      return res.status(500).json({ ok: false, error: 'Erreur création du profil membre' });
    }

    if (teamIds.length) {
      const rows = teamIds.map((t) => ({ team_id: t, user_id: newUserId, company_id: companyId, created_by: req.user.id }));
      const { error: tmErr } = await supabaseAdmin.from('team_members').insert(rows);
      if (tmErr) log.warn('⚠️ admin invite team_members:', safeError(tmErr));
    }

    logAdminAction({ targetUserId: newUserId, adminEmail: req.user?.email, action: 'member_invited',
      detail: 'Membre invité (admin)' + (teamIds.length ? ' — ' + teamIds.length + ' équipe(s)' : '') });
    return res.json({ ok: true });
  } catch (e) {
    log.error('❌ admin invite:', e?.message);
    return res.status(500).json({ ok: false, error: "Erreur lors de l'invitation" });
  }
});

// ✅ [ADMIN] Renommer une équipe d'une entreprise.
app.post('/api/admin/companies/:id/teams/:teamId/rename', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const companyId = String(req.params.id || '');
    const teamId = String(req.params.teamId || '');
    if (!/^[0-9a-f-]{36}$/i.test(companyId) || !/^[0-9a-f-]{36}$/i.test(teamId)) {
      return res.status(400).json({ ok: false, error: 'Identifiant invalide' });
    }
    const name = String(req.body?.name || '').trim().slice(0, 80);
    if (!name) return res.status(400).json({ ok: false, error: "Nom d'équipe requis" });

    const { data: team, error: tErr } = await supabaseAdmin
      .from('teams').select('id, company_id').eq('id', teamId).maybeSingle();
    if (tErr) throw tErr;
    if (!team || team.company_id !== companyId) return res.status(404).json({ ok: false, error: 'Équipe introuvable dans cette entreprise' });

    const { error: updErr } = await supabaseAdmin
      .from('teams').update({ name, updated_at: new Date().toISOString() }).eq('id', teamId);
    if (updErr) throw updErr;

    logAdminAction({ targetUserId: null, adminEmail: req.user?.email, action: 'team_renamed', detail: 'Équipe renommée (admin) : ' + name });
    return res.json({ ok: true });
  } catch (e) {
    log.error('❌ admin team rename:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur lors du renommage' });
  }
});


// ✅ [ADMIN] Modifie nom/prénom/téléphone d'un compte (table profiles)
app.post('/api/admin/users/update-profile', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }

    // Nettoyage défensif (backend = source de vérité, MÊMES limites que le profil self-service :
    // prénom 50, nom 50, téléphone 5-15 chiffres)
    const firstName = String(req.body?.firstName || '').trim().slice(0, 50) || null;
    const lastName  = String(req.body?.lastName  || '').trim().slice(0, 50) || null;
    const phone     = String(req.body?.phone || '').replace(/\D/g, '').slice(0, 15) || null;

    const { data, error } = await supabaseAdmin
      .from('profiles')
      .update({ first_name: firstName, last_name: lastName, phone, updated_at: new Date().toISOString() })
      .eq('user_id', userId)
      .select('user_id, first_name, last_name, phone')
      .maybeSingle();

    if (error) return res.status(400).json({ ok: false, error: error.message });
    if (!data) return res.status(404).json({ ok: false, error: 'Profil introuvable' });

    // 🔄 Synchronise le "Display name" des métadonnées Supabase Auth avec le profil.
    //    Non bloquant : si ça échoue, le profil (source de vérité) est déjà à jour.
    try {
      const { data: cur } = await supabaseAdmin.auth.admin.getUserById(userId);
      const meta = cur?.user?.user_metadata || {};
      const display = ((firstName || '') + ' ' + (lastName || '')).trim();
      await supabaseAdmin.auth.admin.updateUserById(userId, {
        user_metadata: {
          ...meta,
          first_name: firstName,
          last_name: lastName,
          display_name: display || null,
          name: display || null,
          full_name: display || null,
        },
      });
    } catch (metaErr) {
      log.warn('⚠️ admin update-profile: sync métadonnées auth échouée:', metaErr?.message);
    }

    // 📝 Audit RGPD : qui a modifié quoi
    log.info('🛠️ [ADMIN] profil modifié', { by: req.user?.email, target: userId });
    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'update_profile', detail: 'Profil modifié (nom / prénom / téléphone)' });

    return res.json({ ok: true, user: data });
  } catch (e) {
    log.error('💥 admin update-profile:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});


// ✅ [ADMIN] Change l'email d'un compte (auth.users + auth.identities via API admin)
app.post('/api/admin/users/change-email', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }

    const newEmail = String(req.body?.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail) || newEmail.length > 254) {
      return res.status(400).json({ ok: false, error: 'Email invalide' });
    }

    // Met à jour auth.users ET auth.identities ensemble (+ email confirmé)
    const { error: updErr } = await supabaseAdmin.auth.admin.updateUserById(userId, {
      email: newEmail,
      email_confirm: true,
    });
    if (updErr) {
      // ex : "email already registered"
      return res.status(400).json({ ok: false, error: updErr.message });
    }

    // Best-effort : synchronise aussi l'email du client Stripe s'il existe (non bloquant)
    try {
      const { data: sub } = await supabaseAdmin
        .from('subscriptions').select('stripe_customer_id').eq('user_id', userId).maybeSingle();
      if (sub?.stripe_customer_id) {
        await stripe.customers.update(sub.stripe_customer_id, { email: newEmail });
      }
    } catch (stripeErr) {
      log.warn('⚠️ admin change-email: sync Stripe échouée:', stripeErr?.message);
    }

    log.info('🛠️ [ADMIN] email modifié', { by: req.user?.email, target: userId });
    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'change_email', detail: "Email de connexion du compte modifié" });
    return res.json({ ok: true, email: newEmail });
  } catch (e) {
    log.error('💥 admin change-email:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});


// ✅ [ADMIN] Envoie un lien de réinitialisation de mot de passe au compte
app.post('/api/admin/users/send-password-reset', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }

    // Email récupéré côté serveur (source sûre = auth.users), pas envoyé par le front
    const { data: cur, error: getErr } = await supabaseAdmin.auth.admin.getUserById(userId);
    if (getErr || !cur?.user?.email) {
      return res.status(404).json({ ok: false, error: 'Compte introuvable' });
    }
    const email = cur.user.email;

    const FRONT = process.env.FRONTEND_URL || (IS_PROD ? 'https://integora.fr' : 'http://localhost:3000');
    const { error: resetErr } = await supabaseAdmin.auth.resetPasswordForEmail(email, {
      redirectTo: `${FRONT}/reset-password.html`,
    });
    if (resetErr) return res.status(400).json({ ok: false, error: resetErr.message });

    log.info('🛠️ [ADMIN] lien reset mdp envoyé', { by: req.user?.email, target: userId });
    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'send_password_reset', detail: 'Lien de réinitialisation du mot de passe envoyé' });
    return res.json({ ok: true, email });
  } catch (e) {
    log.error('💥 admin send-password-reset:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});


// ✅ [ADMIN] Offre/prolonge un abonnement (comptes SANS Stripe uniquement)
app.post('/api/admin/users/grant-subscription', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }

    // Date d'échéance exacte (AAAA-MM-JJ), validée côté serveur
    const endDateRaw = String(req.body?.endDate || '').trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(endDateRaw)) {
      return res.status(400).json({ ok: false, error: 'Date invalide (format attendu AAAA-MM-JJ)' });
    }
    const now = new Date();
    const newEnd = new Date(endDateRaw + 'T23:59:59');
    if (isNaN(newEnd.getTime())) {
      return res.status(400).json({ ok: false, error: 'Date invalide' });
    }
    if (newEnd <= now) {
      return res.status(400).json({ ok: false, error: 'La date doit être dans le futur' });
    }
    const maxDate = new Date(now); maxDate.setFullYear(maxDate.getFullYear() + 5);
    if (newEnd > maxDate) {
      return res.status(400).json({ ok: false, error: 'Date trop lointaine (max 5 ans)' });
    }

    const { data: sub, error: subErr } = await supabaseAdmin
      .from('subscriptions')
      .select('plan, status, tier, current_paid_tier, current_period_end, stripe_subscription_id')
      .eq('user_id', userId).maybeSingle();
    if (subErr) return res.status(500).json({ ok: false, error: subErr.message });
    if (!sub) return res.status(404).json({ ok: false, error: 'Abonnement introuvable' });

    // 🔒 Refuse si géré par Stripe (Stripe écraserait la date au prochain événement)
    if (sub.stripe_subscription_id) {
      return res.status(400).json({ ok: false, error: "Abonnement Stripe actif — prolongation manuelle non supportée (à gérer côté Stripe)." });
    }

    // Type d'accès cible : 'trial' (accès limité) ou 'paid' (accès complet)
    const targetPlan = req.body?.plan === 'trial' ? 'trial' : 'paid';

    let update;
    if (targetPlan === 'trial') {
      // Essai : l'accès reste LIMITÉ, la date = fin de l'essai
      update = {
        plan: 'trial',
        status: 'trialing',
        trial_end: newEnd.toISOString(),
        current_period_end: null,
        cancel_at: null,
        canceled_at: null,
        updated_at: new Date().toISOString(),
      };
    } else {
      // Payant : accès COMPLET, la date = échéance de l'abonnement
      update = {
        plan: 'paid',
        status: 'active',
        current_period_end: newEnd.toISOString(),
        trial_end: null,
        cancel_at: null,
        canceled_at: null,
        updated_at: new Date().toISOString(),
      };
      const tierToUse = sub.current_paid_tier || sub.tier || null;
      if (tierToUse) update.current_paid_tier = tierToUse;
    }

    const { data, error } = await supabaseAdmin
      .from('subscriptions').update(update).eq('user_id', userId)
      .select('plan, status, current_period_end, trial_end, current_paid_tier').maybeSingle();
    if (error) return res.status(400).json({ ok: false, error: error.message });

    log.info('🛠️ [ADMIN] abo modifié', { by: req.user?.email, target: userId, plan: targetPlan, newEnd: newEnd.toISOString() });
    logAdminAction({
      targetUserId: userId, adminEmail: req.user?.email, action: 'grant_subscription',
      detail: (targetPlan === 'paid' ? 'Payant' : 'Essai') + " jusqu'au " + newEnd.toISOString().slice(0, 10).split('-').reverse().join('/'),
      motif: req.body?.motif,
    });
    return res.json({ ok: true, subscription: data });
  } catch (e) {
    log.error('💥 admin grant-subscription:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});


// ✅ [ADMIN] Clôture/résilie un abonnement (manuel = immédiat ; Stripe = à l'échéance)
app.post('/api/admin/users/close-subscription', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }

    const { data: sub, error: subErr } = await supabaseAdmin
      .from('subscriptions')
      .select('plan, status, current_period_end, trial_end, stripe_subscription_id')
      .eq('user_id', userId).maybeSingle();
    if (subErr) return res.status(500).json({ ok: false, error: subErr.message });
    if (!sub) return res.status(404).json({ ok: false, error: 'Abonnement introuvable' });

    const nowIso = new Date().toISOString();

    if (sub.stripe_subscription_id) {
      // Résiliation Stripe : à l'échéance (le client garde l'accès déjà payé, pas de renouvellement)
      let cancelAt = sub.current_period_end || null;
      try {
        const updated = await stripe.subscriptions.update(sub.stripe_subscription_id, { cancel_at_period_end: true });
        if (updated?.cancel_at) cancelAt = new Date(updated.cancel_at * 1000).toISOString();
      } catch (stripeErr) {
        return res.status(400).json({ ok: false, error: 'Échec résiliation Stripe : ' + (stripeErr?.message || '') });
      }
      await supabaseAdmin.from('subscriptions').update({ cancel_at: cancelAt, updated_at: nowIso }).eq('user_id', userId);
      log.info('🛠️ [ADMIN] abo résilié (Stripe, à échéance)', { by: req.user?.email, target: userId });
      logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'close_subscription', detail: "Résiliation Stripe à l'échéance (pas de renouvellement)", motif: req.body?.motif });
      return res.json({ ok: true, mode: 'stripe_period_end', cancel_at: cancelAt });
    }

    // Manuel : on coupe l'accès IMMÉDIATEMENT (status canceled + échéances au présent)
    const { data, error } = await supabaseAdmin
      .from('subscriptions')
      .update({ status: 'canceled', current_period_end: nowIso, trial_end: nowIso, canceled_at: nowIso, updated_at: nowIso })
      .eq('user_id', userId)
      .select('plan, status, current_period_end, trial_end').maybeSingle();
    if (error) return res.status(400).json({ ok: false, error: error.message });

    log.info('🛠️ [ADMIN] abo clôturé (manuel, immédiat)', { by: req.user?.email, target: userId });
    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'close_subscription', detail: 'Accès coupé immédiatement (manuel)', motif: req.body?.motif });
    return res.json({ ok: true, mode: 'immediate', subscription: data });
  } catch (e) {
    log.error('💥 admin close-subscription:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});


// ✅ [ADMIN] Réactive le renouvellement d'un abonnement Stripe (annule la résiliation programmée)
app.post('/api/admin/users/reactivate-subscription', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }
    const { data: sub, error: subErr } = await supabaseAdmin
      .from('subscriptions').select('stripe_subscription_id').eq('user_id', userId).maybeSingle();
    if (subErr) return res.status(500).json({ ok: false, error: subErr.message });
    if (!sub) return res.status(404).json({ ok: false, error: 'Abonnement introuvable' });
    if (!sub.stripe_subscription_id) {
      return res.status(400).json({ ok: false, error: "Pas d'abonnement Stripe — utilise Offrir/Prolonger pour réactiver un accès manuel." });
    }
    try {
      await stripe.subscriptions.update(sub.stripe_subscription_id, { cancel_at_period_end: false });
    } catch (stripeErr) {
      return res.status(400).json({ ok: false, error: 'Échec Stripe : ' + (stripeErr?.message || '') });
    }
    await supabaseAdmin.from('subscriptions')
      .update({ cancel_at: null, status: 'active', updated_at: new Date().toISOString() })
      .eq('user_id', userId);
    log.info('🛠️ [ADMIN] renouvellement réactivé (Stripe)', { by: req.user?.email, target: userId });
    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'reactivate_renewal', detail: 'Renouvellement automatique Stripe réactivé' });
    return res.json({ ok: true });
  } catch (e) {
    log.error('💥 admin reactivate-subscription:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});


// ✅ [ADMIN] Suspendre un compte (blocage admin, n'affecte PAS la facturation)
app.post('/api/admin/users/suspend', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }
    // Anti-verrouillage : un admin ne peut pas se suspendre lui-même
    if (userId === req.user?.id) {
      return res.status(400).json({ ok: false, error: 'Vous ne pouvez pas suspendre votre propre compte.' });
    }
    const { error } = await supabaseAdmin
      .from('subscriptions')
      .update({ access_locked: true, access_locked_reason: 'admin_suspended', access_locked_at: new Date().toISOString() })
      .eq('user_id', userId);
    if (error) throw error;
    log.info('🛠️ [ADMIN] compte suspendu', { by: req.user?.email, target: userId });
    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'suspend', detail: "Accès suspendu (blocage admin)", motif: req.body?.motif });
    return res.json({ ok: true });
  } catch (e) {
    log.error('💥 admin suspend:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur suspension' });
  }
});


// ✅ [ADMIN] Réactiver un compte suspendu (ne lève QUE les suspensions admin, jamais un verrou facturation)
app.post('/api/admin/users/reactivate', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const userId = String(req.body?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }
    const { error } = await supabaseAdmin
      .from('subscriptions')
      .update({ access_locked: false, access_locked_reason: null, access_locked_at: null })
      .eq('user_id', userId)
      .eq('access_locked_reason', 'admin_suspended'); // sécurité : ne touche pas un verrou facturation
    if (error) throw error;
    log.info('🛠️ [ADMIN] compte réactivé', { by: req.user?.email, target: userId });
    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'reactivate', detail: 'Accès réactivé (fin de suspension)' });
    return res.json({ ok: true });
  } catch (e) {
    log.error('💥 admin reactivate:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur réactivation' });
  }
});


// ✅ [ADMIN] Historique des actions admin sur UN compte (les 50 dernières)
app.get('/api/admin/user-audit', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = String(req.query?.userId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }
    const { data, error } = await supabaseAdmin
      .from('admin_audit_log')
      .select('action, detail, motif, admin_email, created_at')
      .eq('target_user_id', userId)
      .order('created_at', { ascending: false })
      .limit(50);
    if (error) throw error;
    return res.json({ ok: true, history: data || [] });
  } catch (e) {
    log.error('❌ /api/admin/user-audit:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur historique' });
  }
});


// ===== [ADMIN] Export RGPD des données d'un compte (lecture seule, à la demande) =====
// Génère un document HTML lisible (ouvrable dans un navigateur, imprimable en PDF) listant
// EN FRANÇAIS CLAIR toutes les données personnelles détenues sur la personne.
// Ne renvoie JAMAIS de secret : mot de passe, jeton de session, secret 2FA, codes de récup.
const RGPD_PAGE_LABELS = {
  admin: 'Espace administration', 'admin-users': 'Gestion des comptes utilisateurs',
  'admin-subscriptions': 'Gestion des accès clients', 'admin-stats': "Statistiques d'utilisation",
  'admin-maintenance': 'Maintenance', 'admin-security': 'Sécurité du compte',
  profile: 'Profil utilisateur', support: 'Support', choix_irl_digital: 'Choix du format',
  tableau_de_pilotage: 'Tableau de pilotage', jeu_irl: 'Jeux en présentiel',
  le_relai_des_mimes: 'Le Relais des Mimes', carte_rh_express: 'Cartes RH Express',
  invento: 'Invento', instant_zen: 'Instant Zen', qui_est_qui: 'Qui est qui ?',
  un_mot_pour_avancer: 'Un mot pour avancer', fiche_de_poste: 'Fiche de poste',
  entretiens_rh: 'Entretiens RH', thermometre_des_situations: 'Thermomètre des situations',
};
function rgpdPrettify(s) {
  if (!s) return '';
  const t = String(s).replace(/_/g, ' ').replace(/\//g, ' › ');
  return t.charAt(0).toUpperCase() + t.slice(1);
}
function rgpdPageLabel(p) { return RGPD_PAGE_LABELS[p] || rgpdPrettify(p); }
function rgpdEsc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function rgpdDateFR(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()} à ${p(d.getHours())}h${p(d.getMinutes())}`;
}

app.get('/api/admin/users/:id/export', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = String(req.params?.id || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(userId)) {
      return res.status(400).json({ ok: false, error: 'userId invalide' });
    }

    // 1) Identité + données liées (tout en lecture seule)
    const authU = await supabaseAdmin.auth.admin.getUserById(userId);
    const email = authU?.data?.user?.email || null;
    const accountCreated = authU?.data?.user?.created_at || null;

    const [profRes, subRes, mfaRes, actRes, sessRes, supRes] = await Promise.all([
      supabaseAdmin.from('profiles').select('first_name, last_name, phone, company_id, avatar_url, terms_accepted_at, terms_version').eq('user_id', userId).maybeSingle(),
      supabaseAdmin.from('subscriptions').select('plan, status, tier, current_paid_tier, current_period_end, trial_end, cancel_at, started_at, stripe_subscription_id').eq('user_id', userId).maybeSingle(),
      supabaseAdmin.from('user_mfa').select('enabled').eq('user_id', userId).maybeSingle(),
      supabaseAdmin.from('activity_log').select('page, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(5000),
      supabaseAdmin.from('token_sessions').select('expires_at, is_active').eq('user_id', userId).order('expires_at', { ascending: false }).limit(200),
      supabaseAdmin.from('support_tickets').select('subject, message, type, status, created_at').eq('user_id', userId).order('created_at', { ascending: false }).limit(200),
    ]);

    const prof = profRes?.data || {};
    let company = null;
    if (prof.company_id) {
      const c = await supabaseAdmin.from('companies').select('display_name, legal_name').eq('id', prof.company_id).maybeSingle();
      company = c?.data ? (c.data.display_name || c.data.legal_name || null) : null;
    }
    let contactTickets = [];
    if (email) {  // contact_tickets relié par EMAIL (pas de user_id sur cette table)
      const ct = await supabaseAdmin.from('contact_tickets').select('subject, message, status, created_at').eq('email', email).order('created_at', { ascending: false }).limit(200);
      contactTickets = ct?.data || [];
    }

    const sub = subRes?.data || {};
    const mfaOn = !!(mfaRes?.data?.enabled);
    const activity = actRes?.data || [];
    const sessions = sessRes?.data || [];
    const supportTickets = supRes?.data || [];

    // 2) Activité regroupée par page (bien plus lisible que des milliers de lignes)
    const byPage = new Map();
    for (const a of activity) {
      let e = byPage.get(a.page);
      if (!e) { e = { page: a.page, count: 0, last: a.created_at }; byPage.set(a.page, e); }
      e.count++;
      if (new Date(a.created_at) > new Date(e.last)) e.last = a.created_at;
    }
    const pageRows = Array.from(byPage.values()).sort((x, y) => y.count - x.count);

    // 3) Construction du document HTML lisible
    const fullName = [prof.first_name, prof.last_name].filter(Boolean).join(' ') || '—';
    const row = (l, v) => `<tr><th>${rgpdEsc(l)}</th><td>${rgpdEsc(v ?? '—')}</td></tr>`;
    const ticketBlock = (t) => `
      <div class="ticket">
        <div class="ticket-h"><strong>${rgpdEsc(t.subject || 'Demande')}</strong>
          <span class="muted"> — ${rgpdDateFR(t.created_at)}${t.status ? ' · ' + rgpdEsc(t.status) : ''}</span></div>
        <div class="ticket-m">${rgpdEsc(t.message || '').replace(/\n/g, '<br>')}</div>
      </div>`;

    const html = `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Export de mes données — INTEGORA</title>
<style>
  body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1f2937;max-width:820px;margin:0 auto;padding:32px 20px;line-height:1.5}
  h1{font-size:1.5rem;margin:0 0 4px} h2{font-size:1.1rem;margin:28px 0 10px;color:#2563eb;border-bottom:1px solid #e5e7eb;padding-bottom:6px}
  .intro{color:#4b5563;font-size:.95rem} .muted{color:#6b7280}
  table{border-collapse:collapse;width:100%;margin:6px 0} th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #eef1f4;vertical-align:top;font-size:.93rem}
  th{width:42%;color:#374151;font-weight:600}
  .ticket{border:1px solid #e5e7eb;border-radius:8px;padding:10px 12px;margin:8px 0} .ticket-m{margin-top:6px;white-space:normal;color:#374151;font-size:.92rem}
  .foot{margin-top:36px;font-size:.78rem;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:12px}
  .empty{color:#9ca3af;font-style:italic;font-size:.9rem}
</style></head><body>
  <h1>Export de mes données personnelles</h1>
  <p class="intro">Document généré par INTEGORA le ${rgpdDateFR(new Date().toISOString())}. Il rassemble l'ensemble des informations que nous détenons sur ce compte, conformément au RGPD (droit d'accès). Vous pouvez l'enregistrer en PDF via « Imprimer ».</p>

  <h2>Vos informations personnelles</h2>
  <table>
    ${row('Nom complet', fullName)}${row('Adresse e-mail', email)}${row('Téléphone', prof.phone)}
    ${row('Compte créé le', rgpdDateFR(accountCreated))}
    ${row('Conditions acceptées le', prof.terms_accepted_at ? rgpdDateFR(prof.terms_accepted_at) : '—')}
    ${row('Version des conditions', prof.terms_version)}
    ${row('Photo de profil', prof.avatar_url ? 'Oui (enregistrée)' : 'Aucune')}
  </table>

  <h2>Votre entreprise</h2>
  <table>${row('Entreprise', company)}</table>

  <h2>Votre abonnement</h2>
  <table>
    ${row('Formule', sub.plan)}${row('Statut', sub.status)}${row('Palier', sub.current_paid_tier || sub.tier)}
    ${row('Début', sub.started_at ? rgpdDateFR(sub.started_at) : '—')}
    ${row('Fin de période en cours', sub.current_period_end ? rgpdDateFR(sub.current_period_end) : '—')}
    ${row("Fin d'essai", sub.trial_end ? rgpdDateFR(sub.trial_end) : '—')}
    ${row('Facturation', sub.stripe_subscription_id ? 'Gérée par Stripe (vos données de paiement sont conservées par Stripe, pas par INTEGORA)' : 'Aucune facturation Stripe')}
  </table>

  <h2>Sécurité de votre compte</h2>
  <table>
    ${mfaOn ? row('Double authentification', 'Activée') : ''}
    ${row('Nombre de sessions enregistrées', String(sessions.length))}
  </table>

  <h2>Votre activité sur la plateforme</h2>
  ${pageRows.length ? `<table><tr><th>Page consultée</th><td>Consultations / dernière visite</td></tr>
    ${pageRows.map(p => `<tr><th>${rgpdEsc(rgpdPageLabel(p.page))}</th><td>${p.count} fois · dernière le ${rgpdDateFR(p.last)}</td></tr>`).join('')}
  </table><p class="muted" style="font-size:.82rem">Total : ${activity.length} consultations enregistrées.</p>`
   : '<p class="empty">Aucune activité enregistrée.</p>'}

  <h2>Vos demandes au support</h2>
  ${(supportTickets.length || contactTickets.length)
    ? supportTickets.map(t => ticketBlock(t)).join('') + contactTickets.map(t => ticketBlock(t)).join('')
    : '<p class="empty">Aucune demande enregistrée.</p>'}

  <div class="foot">
    Références techniques (usage interne) — Identifiant du compte : ${rgpdEsc(userId)}.<br>
    Les données de paiement (carte, factures) sont conservées par notre prestataire Stripe conformément à ses obligations légales.
  </div>
</body></html>`;

    logAdminAction({ targetUserId: userId, adminEmail: req.user?.email, action: 'export_rgpd', detail: 'Export RGPD des données généré' });

    const safe = String(email || userId).replace(/[^a-z0-9._-]/gi, '_').slice(0, 60);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="export-donnees-${safe}.html"`);
    return res.send(html);
  } catch (e) {
    log.error('❌ /api/admin/users/:id/export:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur export' });
  }
});


// ===== [ADMIN] Maintenance plateforme (Phase 1 : panneau de contrôle, sans blocage réel) =====
// Stocke les opérations de maintenance (globale / partielle / bandeau). Le BLOCAGE effectif
// sera branché en Phase 2 (auth-guard.js + /api/maintenance/status). Ici : lister / créer / terminer.

// Liste (100 dernières, récentes d'abord) — sert à l'état actuel + l'historique de la page admin.
app.get('/api/admin/maintenance', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('maintenance')
      .select('id, type, scope_kind, scope_value, message, starts_at, ends_at, allow_admins, visibility, active, created_by, created_at')
      .order('created_at', { ascending: false })
      .limit(100);
    if (error) throw error;
    return res.json({ ok: true, items: data || [] });
  } catch (e) {
    log.error('❌ /api/admin/maintenance (list):', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur maintenance' });
  }
});

// Crée une opération de maintenance
app.post('/api/admin/maintenance', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const type = String(req.body?.type || '').trim();
    if (!['global', 'partial', 'banner'].includes(type)) {
      return res.status(400).json({ ok: false, error: 'Type invalide' });
    }
    const message = String(req.body?.message || '').trim().slice(0, 500);
    if (!message) return res.status(400).json({ ok: false, error: 'Message requis' });

    let scopeKind = null, scopeValue = null;
    if (type === 'partial') {
      scopeKind = req.body?.scopeKind === 'page' ? 'page' : 'category';
      scopeValue = String(req.body?.scopeValue || '').trim().slice(0, 120);
      if (!scopeValue) return res.status(400).json({ ok: false, error: 'Périmètre requis pour une maintenance partielle' });
    }

    const parseDate = (v) => { if (!v) return null; const d = new Date(v); return isNaN(d.getTime()) ? null : d.toISOString(); };
    const startsAt = parseDate(req.body?.startsAt);
    const endsAt = parseDate(req.body?.endsAt);
    const allowAdmins = req.body?.allowAdmins !== false; // défaut : true

    const row = {
      type, scope_kind: scopeKind, scope_value: scopeValue, message,
      starts_at: startsAt, ends_at: endsAt, allow_admins: allowAdmins,
      visibility: 'all', active: true, created_by: req.user?.email || null,
    };
    const { data, error } = await supabaseAdmin.from('maintenance').insert(row).select().maybeSingle();
    if (error) return res.status(400).json({ ok: false, error: error.message });

    const label = type === 'global' ? 'Maintenance globale'
      : (type === 'banner' ? "Bandeau d'information"
        : ('Maintenance partielle — ' + (scopeValue || '')));
    logAdminAction({ targetUserId: null, adminEmail: req.user?.email, action: 'maintenance_create', detail: label });
    return res.json({ ok: true, item: data });
  } catch (e) {
    log.error('❌ /api/admin/maintenance (create):', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Termine (désactive) une opération de maintenance
app.post('/api/admin/maintenance/end', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const id = parseInt(String(req.body?.id || ''), 10);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ ok: false, error: 'id invalide' });
    const { error } = await supabaseAdmin.from('maintenance').update({ active: false }).eq('id', id);
    if (error) throw error;
    logAdminAction({ targetUserId: null, adminEmail: req.user?.email, action: 'maintenance_end', detail: 'Maintenance #' + id + ' terminée' });
    return res.json({ ok: true });
  } catch (e) {
    log.error('❌ /api/admin/maintenance (end):', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// ✅ [PHASE 2] État de maintenance vu par le FRONT (auth-guard) — tout utilisateur connecté.
// Renvoie : maintenance globale active, pages bloquées (partielles dépliées), bandeau, + isAdmin.
// FAIL-OPEN : toute erreur → "aucune maintenance" pour ne JAMAIS bloquer par accident.
app.get('/api/maintenance/status', authenticateToken, async (req, res) => {
  try {
    const email = String(req.user?.email || '').trim().toLowerCase();
    const isAdmin = !!email && ADMIN_EMAILS.has(email);

    const { data, error } = await supabaseAdmin
      .from('maintenance')
      .select('id, type, scope_kind, scope_value, message, starts_at, ends_at, allow_admins, active')
      .eq('active', true);
    if (error) throw error;

    const now = Date.now();
    const live = (data || []).filter((m) => {
      if (m.starts_at && new Date(m.starts_at).getTime() > now) return false;   // planifiée → pas encore
      if (m.ends_at && new Date(m.ends_at).getTime() <= now) return false;       // fin dépassée
      return true;
    });

    let global = null, banner = null;
    const pages = {};
    const ADMIN_PAGES = ['admin', 'admin-users', 'admin-subscriptions', 'admin-stats', 'admin-maintenance'];
    const appPages = getAppPages();
    const prettifyPage = (p) => { const t = String(p || '').replace(/_/g, ' '); return t.charAt(0).toUpperCase() + t.slice(1); };

    for (const m of live) {
      if (m.type === 'global') {
        if (!global) global = { message: m.message, allowAdmins: m.allow_admins !== false, endsAt: m.ends_at || null };
      } else if (m.type === 'banner') {
        if (!banner) banner = { id: m.id, message: m.message };
      } else if (m.type === 'partial' && m.scope_value) {
        if (m.scope_kind === 'page') {
          pages[m.scope_value] = { message: m.message, allowAdmins: m.allow_admins !== false, scopeKind: 'page', scopeLabel: prettifyPage(m.scope_value), endsAt: m.ends_at || null };
        } else { // catégorie : on déplie en noms de pages
          const info = { message: m.message, allowAdmins: m.allow_admins !== false, scopeKind: 'category', scopeLabel: m.scope_value, endsAt: m.ends_at || null };
          if (m.scope_value === 'Administration interne') ADMIN_PAGES.forEach((p) => { pages[p] = info; });
          appPages.forEach((p) => { if (usageCategory(p.page, p.folder) === m.scope_value) pages[p.page] = info; });
        }
      }
    }

    return res.json({ ok: true, isAdmin, global, banner, pages });
  } catch (e) {
    log.error('❌ /api/maintenance/status:', e?.message);
    return res.json({ ok: true, isAdmin: false, global: null, banner: null, pages: {} }); // fail-open
  }
});


// ===== [ADMIN] 2FA (TOTP) — PHASE A : enrôlement uniquement (n'affecte PAS encore le login) =====
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
authenticator.options = { window: 4 }; // tolère ±2 min de décalage d'horloge PC/téléphone (sûr : code 6 chiffres + rate-limit login)

function genRecoveryCode() {
  const hex = require('crypto').randomBytes(4).toString('hex').toUpperCase();
  return hex.slice(0, 4) + '-' + hex.slice(4, 8);
}

// État 2FA du compte admin courant
app.get('/api/admin/mfa/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { data } = await supabaseAdmin.from('user_mfa').select('enabled').eq('user_id', req.user.id).maybeSingle();
    return res.json({ ok: true, enabled: !!(data && data.enabled) });
  } catch (e) {
    log.error('❌ mfa/status:', e?.message);
    return res.json({ ok: true, enabled: false });
  }
});

// Démarre l'enrôlement : génère un secret (NON activé) + le QR à scanner
app.post('/api/admin/mfa/enroll', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const secret = authenticator.generateSecret();
    const uri = authenticator.keyuri(req.user.email || 'admin', 'INTEGORA Admin', secret);
    const qr = await QRCode.toDataURL(uri);
    const { error } = await supabaseAdmin.from('user_mfa').upsert(
      { user_id: req.user.id, secret: secret, enabled: false, recovery_codes: [], updated_at: new Date().toISOString() },
      { onConflict: 'user_id' }
    );
    if (error) return res.status(400).json({ ok: false, error: error.message });
    return res.json({ ok: true, secret: secret, qr: qr });
  } catch (e) {
    log.error('❌ mfa/enroll:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Confirme l'enrôlement : vérifie le 1er code → active la 2FA + renvoie les codes de secours (affichés UNE fois)
app.post('/api/admin/mfa/confirm', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const code = String(req.body?.code || '').replace(/\D/g, '');
    const { data } = await supabaseAdmin.from('user_mfa').select('secret').eq('user_id', req.user.id).maybeSingle();
    if (!data || !data.secret) return res.status(400).json({ ok: false, error: "Aucun enrôlement en cours. Relance l'activation." });
    if (!authenticator.verify({ token: code, secret: data.secret })) {
      if (!IS_PROD) {
        const prev = authenticator.options;
        authenticator.options = Object.assign({}, prev, { window: 20 }); // cherche le code sur ±10 min
        const delta = authenticator.checkDelta(code, data.secret);
        authenticator.options = prev;
        log.warn('🔎 [DEV] MFA échec — reçu:', code, '· attendu:', authenticator.generate(data.secret), '· delta(±10min):', delta,
          delta === null
            ? '→ SECRET DIFFÉRENT : vieille entrée Google Auth, supprime-la et rescanne le QR actuel'
            : ('→ décalage horloge ≈ ' + (delta * 30) + 's (augmenter window ou synchroniser)'));
      }
      return res.status(400).json({ ok: false, error: "Code incorrect. Vérifie l'heure de ton téléphone et réessaie." });
    }
    const bcrypt = require('bcryptjs');
    const codes = [], hashes = [];
    for (let i = 0; i < 8; i++) { const c = genRecoveryCode(); codes.push(c); hashes.push(bcrypt.hashSync(c, 10)); }
    const { error } = await supabaseAdmin.from('user_mfa').update({ enabled: true, recovery_codes: hashes, updated_at: new Date().toISOString() }).eq('user_id', req.user.id);
    if (error) return res.status(400).json({ ok: false, error: error.message });
    logAdminAction({ targetUserId: req.user.id, adminEmail: req.user.email, action: 'mfa_enabled', detail: '2FA (TOTP) activée' });
    return res.json({ ok: true, recoveryCodes: codes });
  } catch (e) {
    log.error('❌ mfa/confirm:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});

// Désactive la 2FA (nécessite un code valide)
app.post('/api/admin/mfa/disable', authenticateToken, requireAdmin, requireCsrf, async (req, res) => {
  try {
    const code = String(req.body?.code || '').replace(/\D/g, '');
    const { data } = await supabaseAdmin.from('user_mfa').select('secret, enabled').eq('user_id', req.user.id).maybeSingle();
    if (!data || !data.enabled) return res.json({ ok: true });
    if (!authenticator.verify({ token: code, secret: data.secret })) {
      return res.status(400).json({ ok: false, error: 'Code incorrect.' });
    }
    const { error } = await supabaseAdmin.from('user_mfa').update({ enabled: false, recovery_codes: [], updated_at: new Date().toISOString() }).eq('user_id', req.user.id);
    if (error) return res.status(400).json({ ok: false, error: error.message });
    logAdminAction({ targetUserId: req.user.id, adminEmail: req.user.email, action: 'mfa_disabled', detail: '2FA (TOTP) désactivée' });
    return res.json({ ok: true });
  } catch (e) {
    log.error('❌ mfa/disable:', e?.message);
    return res.status(500).json({ ok: false, error: 'Erreur serveur' });
  }
});


app.post("/api/company/update-billing", authenticateToken, async (req, res) => {

  try {
    const owner_id = req.user.id;

    const body = req.body || {};

    // 1) Nettoyage/validation (backend = source de vérité sécurité)
    // Max 60 chars : aligné sur contact_tickets.company_name (contrainte SQL contact_company_len)
    const legal_name = cleanTextStrict(body.legal_name, { max: 60, allowEmpty: false });
    if (!legal_name) {
      return res.status(400).json({ ok: false, error: "Raison sociale invalide (max 60 caractères)." });
    }

    // optionnel
    const display_name = cleanTextStrict(body.display_name, { max: 120, allowEmpty: true });

    // company_size est NOT NULL dans ta table, donc on le garde si existant sinon requis
    const company_size_in = cleanTextStrict(body.company_size, { max: 30, allowEmpty: true });

    // ✅ SIRET : OBLIGATOIRE — strict 14 chiffres (pas vide, pas null)
    const company_siret = cleanDigitsStrict(body.company_siret, { min: 14, max: 14, allowEmpty: false });

    // cleanDigitsStrict peut renvoyer null/"" selon ton implémentation → on fail-hard dans tous les cas
    if (!company_siret || company_siret === "") {
      return res.status(400).json({
        ok: false,
        error: "Veuillez indiquer un SIRET valide (14 chiffres) pour continuer.",
      });
    }


    // Adresse : min 6 (cohérent avec ta contrainte SQL) / max 140
    const billing_street = cleanAddress(body.billing_street, { min: 6, max: 140, allowEmpty: true });
    if (billing_street === "") {
      return res.status(400).json({ ok: false, error: "Adresse invalide (min 6 caractères, caractères interdits)." });
    }

    // Code postal : chiffres only (large : 4-10)
    const billing_postal_code = cleanDigitsStrict(body.billing_postal_code, { min: 4, max: 10, allowEmpty: true });
    if (billing_postal_code === "") {
      return res.status(400).json({ ok: false, error: "Code postal invalide : chiffres uniquement (4 à 10)." });
    }

    // Ville : min 2 (cohérent SQL) / max 64
    const billing_city = cleanNameLike(body.billing_city, { min: 2, max: 64, allowEmpty: true });
    if (billing_city === "") {
      return res.status(400).json({ ok: false, error: "Ville invalide (lettres/espaces/tirets/apostrophes/points)." });
    }

    // Pays : ISO2 obligatoire (FR, BE, ...)
    // Le front envoie déjà ISO2 (select), mais on revalide côté backend (fail-hard).
    const billing_country_in = String(body.billing_country ?? "").trim();

    // allowEmpty:true => si vide, on met null (ça suit ta logique actuelle)
    let billing_country = null;
    if (billing_country_in) {
      const iso2 = normalizeCountryISO2(billing_country_in);
      if (!iso2) {
        return res.status(400).json({ ok: false, error: "Pays invalide : choisissez un pays dans la liste." });
      }
      billing_country = iso2;
    }



    // 2) companies.legal_name + company_size sont NOT NULL
    // => soit tu fournis ici, soit ça existe déjà en base
    const { data: existing, error: exErr } = await supabase
      .from("companies")
      .select("id, legal_name, company_size")
      .eq("owner_id", owner_id)
      .maybeSingle();

    if (exErr) return res.status(400).json({ ok: false, error: exErr.message });

    const finalLegal = legal_name || existing?.legal_name || null;

    // ✅ company_size : si ton UI ne le demande pas, on met une valeur par défaut
    // (si tu as une contrainte/enum sur company_size, remplace "unknown" par une valeur autorisée)
    const finalSize = company_size_in || existing?.company_size || "unknown";

    if (!finalLegal) {
      return res.status(400).json({
        ok: false,
        error: "Impossible d'enregistrer: legal_name est requis.",
      });
    }


    // 3) Upsert companies
    const upsertData = {
      owner_id,
      legal_name: finalLegal,
      company_size: finalSize,
      display_name: display_name || null,
      company_siret: company_siret || null,
      billing_street: billing_street || null,
      billing_postal_code: billing_postal_code || null,
      billing_city: billing_city || null,
      billing_country: billing_country || null,
      updated_at: new Date().toISOString(),
    };

    const { data: company, error: upErr } = await supabase
      .from("companies")
      .upsert(upsertData, { onConflict: "owner_id" })
      .select(
        "id, legal_name, display_name, company_size, company_siret, billing_street, billing_postal_code, billing_city, billing_country",
      )
      .single();

    if (upErr) {
      return res.status(400).json({ ok: false, error: upErr.message });
    }

    // 4) Liaison profile -> company_id (comme tu le fais déjà)
    const { error: profErr } = await supabase
      .from("profiles")
      .update({ company_id: company.id, updated_at: new Date().toISOString() })
      .eq("user_id", owner_id);

    if (profErr) {
      return res.status(400).json({
        ok: false,
        error: "Company OK mais échec update profiles.company_id: " + profErr.message,
      });
    }

    // ✅ NOUVEAU : sync Stripe customer immédiatement (garantit factures 100% à jour)
    let stripe_synced = false;
    try {
      const { data: subRow, error: subErr } = await supabase
        .from("subscriptions")
        .select("stripe_customer_id")
        .eq("user_id", owner_id)
        .maybeSingle();

      if (!subErr && subRow?.stripe_customer_id) {
        await syncStripeCustomerBillingFromDb({
          userId: owner_id,
          stripeCustomerId: subRow.stripe_customer_id,
        });
        stripe_synced = true;
      }
    } catch (e) {
      log.warn("⚠️ Stripe sync skipped (update-billing):", e);
    }

    return res.json({ ok: true, message: "Entreprise mise à jour", company, stripe_synced });
  } catch (e) {
    log.error("💥 [API update-billing] Exception:", safeError(e));
    return res.status(500).json({ ok: false, error: "Erreur serveur update-billing" });
  }
});



// ==================== ROUTE UPLOAD AVATAR ====================
// ==================== UPLOAD AVATAR (SECURISÉ) ====================
const multer = require("multer");

const ALLOWED_AVATAR_MIME = new Map([
  ["image/jpeg", "jpg"],
  ["image/png", "png"],
  ["image/webp", "webp"],
  // optionnel:
  // ["image/gif", "gif"],
]);

const uploadAvatar = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_AVATAR_MIME.has(file.mimetype)) {
      return cb(new Error("Format avatar non autorisé. Utilise JPG/PNG/WebP."), false);
    }
    cb(null, true);
  },
});

// middleware erreurs multer (TU L'AVAIS, mais il n'était pas branché sur la route)
function handleMulterError(err, req, res, next) {
  if (err && err.name === "MulterError") {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ ok: false, error: "Fichier trop volumineux (max 5MB)" });
    }
    return res.status(400).json({ ok: false, error: `Erreur upload: ${err.code}` });
  }
  if (err) return res.status(400).json({ ok: false, error: err.message || "Erreur upload" });
  next();
}

function sniffImageType(buffer) {
  if (!buffer || buffer.length < 12) return null;

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  const isPng =
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a;
  if (isPng) return { mime: "image/png", ext: "png" };

  // JPEG: FF D8 FF
  const isJpg = buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  if (isJpg) return { mime: "image/jpeg", ext: "jpg" };

  // WEBP: "RIFF"...."WEBP"
  const isWebp =
    buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
    buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50;
  if (isWebp) return { mime: "image/webp", ext: "webp" };

  return null;
}


app.post(
  "/api/upload-avatar",
  authenticateToken,
  uploadAvatar.single("avatar"),
  handleMulterError,
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ ok: false, error: "Aucun fichier sélectionné" });
      }

      const detected = sniffImageType(req.file.buffer);
      if (!detected) {
        return res.status(400).json({
          ok: false,
          error: "Avatar invalide. Formats autorisés: JPG/PNG/WEBP",
        });
      }

      // ✅ tolérant : on accepte si c'est une image, et sniffImageType est la vérité
      if (!req.file.mimetype || !req.file.mimetype.startsWith("image/")) {
        return res.status(400).json({
          ok: false,
          error: "Avatar invalide (mimetype non image).",
        });
      }



      // 🔒 extension forcée depuis le mimetype
      const ext = detected.ext;
      const fileName = `avatars/${req.user.id}/${Date.now()}.${ext}`;

      const { error: uploadError } = await supabase.storage
        .from("Avatars")
        .upload(fileName, req.file.buffer, {
          contentType: detected.mime,
          upsert: true,
        });

      if (uploadError) {
        return res.status(500).json({ ok: false, error: "Erreur upload storage: " + uploadError.message });
      }

      // 1) Stocke le PATH (pas une URL publique)
      const avatarPath = fileName;

      const { data: updatedProfile, error: updateError } = await supabase
        .from("profiles")
        .update({ avatar_url: avatarPath, updated_at: new Date().toISOString() }) // avatar_url contient maintenant un PATH
        .eq("user_id", req.user.id)
        .select("avatar_url")
        .single();

      if (updateError) {
        return res.status(500).json({ ok: false, error: "Erreur mise à jour profil: " + updateError.message });
      }

      // 2) Retourne une SIGNED URL pour affichage immédiat
      const { data: signed, error: signErr } = await supabase.storage
        .from("Avatars")
        .createSignedUrl(avatarPath, 60 * 60); // 1h

      if (signErr) {
        return res.status(500).json({ ok: false, error: "Erreur signed url: " + signErr.message });
      }

      return res.json({
        ok: true,
        path: avatarPath,

        // ✅ nouveau champ explicite
        signedUrl: signed.signedUrl,

        // ✅ rétro-compat (ton front actuel lit "url")
        url: signed.signedUrl,

        message: "Avatar mis à jour avec succès !"
      });

    } catch (error) {
      return res.status(500).json({ ok: false, error: "Erreur serveur" });
    }
  }
);

app.get("/api/my-avatar-url", authenticateToken, async (req, res) => {
  try {
    const { data: prof, error } = await supabase
      .from("profiles")
      .select("avatar_url")
      .eq("user_id", req.user.id)
      .single();

    if (error) {
      return res.status(500).json({ ok: false, error: "Erreur serveur" });
    }

    // ✅ Normalise avatar_url : on veut TOUJOURS un PATH "dans le bucket"
    const normalizeAvatarPath = (v) => {
      if (!v) return null;

      // si c'est une URL complète => on extrait ce qu'il y a après "/Avatars/"
      if (v.startsWith("http://") || v.startsWith("https://")) {
        const idx = v.indexOf("/Avatars/");
        if (idx !== -1) {
          return v.slice(idx + "/Avatars/".length).split("?")[0];
        }
        return null;
      }

      // sinon on suppose que c'est déjà un path correct
      return v;
    };

    // ✅ IMPORTANT : ton fichier default est dans "avatars/default/default-avatar.webp"
    const DEFAULT_AVATAR_PATH = "avatars/default/default-avatar.webp";

    let path = normalizeAvatarPath(prof?.avatar_url) || DEFAULT_AVATAR_PATH;
    // ✅ Migration PNG → WebP pour l'avatar par défaut
    if (path === "default/default-avatar.png" || path === "avatars/default/default-avatar.png") path = DEFAULT_AVATAR_PATH;

    const { data: signed, error: signErr } = await supabase.storage
      .from("Avatars")
      .createSignedUrl(path, 60 * 60);

    if (signErr) {
      // 🔎 te donne un log explicite pour ne plus être dans le flou
      log.error("❌ /api/my-avatar-url createSignedUrl error:", safeError(signErr), "path:", path);
      return res.status(500).json({ ok: false, error: signErr.message, path });
    }

    return res.json({ ok: true, url: signed.signedUrl, path });
  } catch (e) {
    log.error("💥 /api/my-avatar-url exception:", safeError(e));
    return res.status(500).json({ ok: false, error: "Erreur serveur" });
  }
});








/* Upload fichier support pour la platefor */
const uploadSupport = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB / fichier
  fileFilter: (req, file, cb) => {
    const allowed = new Set([
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "image/jpeg",
      "image/png",
    ]);
    if (allowed.has(file.mimetype)) return cb(null, true);
    cb(new Error("Format de fichier non autorisé"), false);
  },
});



// ==================== GESTION DES ASSETS SUPABASE ====================


function guessMime(filePath) {
  const ext = (filePath.split('.').pop() || '').toLowerCase();
  const mimeTypes = {
    'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'webp': 'image/webp',
    'gif': 'image/gif', 'svg': 'image/svg+xml', 'bmp': 'image/bmp', 'ico': 'image/x-icon',
    'pdf': 'application/pdf', 'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'txt': 'text/plain', 'zip': 'application/zip', 'rar': 'application/vnd.rar',
    '7z': 'application/x-7z-compressed', 'tar': 'application/x-tar', 'gz': 'application/gzip',
    'mp4': 'video/mp4', 'mov': 'video/quicktime', 'avi': 'video/x-msvideo',
    'mkv': 'video/x-matroska', 'webm': 'video/webm', 'mp3': 'audio/mpeg',
    'wav': 'audio/wav', 'ogg': 'audio/ogg', 'm4a': 'audio/mp4'
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

// ✅ PREVIEWS PUBLIQUES (bucket public)
app.get('/api/public/preview/*', async (req, res) => {
  try {
    const pathInBucket = req.params[0];

    // ✅ FIX B19 — Bloquer les chemins qui essaient de remonter dans les dossiers
    if (!pathInBucket || pathInBucket.includes('..')) {
      return res.status(400).json({ error: "Chemin invalide" });
    }

    const { data, error } = await supabase.storage.from('public').download(pathInBucket);
    if (error || !data) {
      return res.status(404).send('Not found');
    }

    const mimeType = guessMime(pathInBucket);
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    return res.send(Buffer.from(await data.arrayBuffer()));
  } catch (e) {
    return res.status(500).send('Server error');
  }
});

// ✅ ASSETS PROTÉGÉS (tous les buckets privés)
app.get('/api/assets/:id', authenticateToken, async (req, res) => {
  try {
    const assetId = req.params.id;

    // 🔄 RÉESSAI AUTOMATIQUE SUR LA REQUÊTE
    const { data: asset, error: assetErr } = await withRetry(
      () => supabase
        .from('assets')
        .select('bucket, path, min_tier, kind, is_active, title')
        .eq('id', assetId)
        .single()
    );

    if (assetErr || !asset || !asset.is_active) {
      return serveFallbackImage(res);
    }

    // 🛡️ IDOR : vérifier que l'utilisateur a le niveau d'abonnement requis
    if (asset.min_tier) {
      const userTier = req.user.subscription_type || 'trial';
      const userLvl = __planRank[userTier] ?? 0;
      const reqLvl = __planRank[asset.min_tier] ?? 0;
      if (userLvl < reqLvl) {
        return res.status(403).json({ error: 'Accès refusé', code: 'TIER_REQUIRED' });
      }
    }

    // 🔄 RÉESSAI SUR LE TÉLÉCHARGEMENT
    const { data: file, error: dlErr } = await withRetry(
      () => supabase.storage
        .from(asset.bucket)
        .download(asset.path)
    );

    if (dlErr || !file) {
      return serveFallbackImage(res);
    }

    const mimeType = guessMime(asset.path);
    const buf = Buffer.from(await file.arrayBuffer());

    // 🛡️ EN-TÊTES DE SÉCURITÉ
    res.setHeader('Content-Type', mimeType);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'private, max-age=3600');

    return res.send(buf);

  } catch (error) {
    log.error('💥 [Protected Asset] Erreur finale:', safeError(error));
    return serveFallbackImage(res);
  }
});

// 🖼️ FONCTION FALLBACK MANQUANTE - AJOUTE-LA !
function serveFallbackImage(res) {
  return res.status(404).json({
    error: 'Asset non disponible',
    code: 'ASSET_NOT_FOUND'
  });
}



// ==================== VÉRIFICATION ACCÈS PAGE ====================

// ==================== INFOS UTILISATEUR ====================

app.get("/api/user-info", authenticateToken, (req, res) => {
  res.json({
    user: req.user,
    subscription_type: req.user.subscription_type,
    has_active_subscription: req.user.has_active_subscription
  });
});


function toIsoFromStripeTs(ts) {
  return ts ? new Date(ts * 1000).toISOString() : null;
}






app.post("/api/start-paid-checkout", async (req, res) => {


  try {
    const emailNorm = normalizeEmail(req.body?.email);
    if (!emailNorm) return res.status(400).json({ error: "email requis" });
    if (!isValidEmail(emailNorm)) return res.status(400).json({ error: "email invalide" });
    if (emailNorm.length > 254) return res.status(400).json({ error: "email trop long" });

    // ✅ IMPORTANT : si l'email existe déjà, on NE doit PAS rediriger vers Stripe
    const alreadyExists = await authEmailExists(emailNorm);
    if (alreadyExists) {
      return res.status(409).json({ error: "ACCOUNT_EXISTS" });
    }


    const desired_plan = String(req.body?.desired_plan || "").trim();
    if (desired_plan !== "paid") {
      return res.status(400).json({ error: "desired_plan invalide" });
    }

    // ✅ CGUV obligatoires (preuve juridique côté serveur)
    const termsAccepted = req.body?.termsAccepted === true;
    const termsVersionRaw = String(req.body?.termsVersion || "").trim();

    // 1) L'utilisateur doit accepter
    if (!termsAccepted) {
      return res.status(400).json({ error: "TERMS_REQUIRED" });
    }

    // 2) termsVersion doit exister (pas de fallback)
    if (!termsVersionRaw) {
      return res.status(400).json({ error: "terms_version manquante" });
    }

    // 3) Whitelist stricte : on accepte uniquement une date YYYY-MM-DD
    //    (dans ton cas: "2025-11-12")
    // [15 mai 2026] Accepte le format DD_MM_YYYY (ex: "14_05_2026") qui est le
    // format actuel de CURRENT_TERMS_VERSION. L'ancien format YYYY-MM-DD est
    // aussi accepte pour retrocompat (au cas ou des comptes legacy l'utilisent).
    if (!/^(\d{2}_\d{2}_\d{4}|\d{4}-\d{2}-\d{2})$/.test(termsVersionRaw)) {
      return res.status(400).json({ error: "terms_version invalide" });
    }

    // 4) Bonus sécurité : optionnel, tu verrouilles sur la version actuellement en prod
    if (termsVersionRaw !== CURRENT_TERMS_VERSION) {
      return res.status(400).json({ error: "terms_version non supportée" });
    }

    const termsVersion = termsVersionRaw; // valeur validée




    const first_name = cleanPersonName(req.body?.first_name, { max: 50 });
    const last_name = cleanPersonName(req.body?.last_name, { max: 50 });
    const company_name = cleanTextStrict(req.body?.company_name, { max: 120, allowEmpty: false });
    const company_size = String(req.body?.company_size || "").trim();
    // =========================
    // VALIDATION FACTURATION (PAYANT)
    // =========================
    const rawSiret = String(req.body?.company_siret || "");
    const company_siret = rawSiret.replace(/\D/g, "");
    const billing_street = cleanTextStrict(req.body?.billing_street, {
      max: 120,
      allowEmpty: false,
    });

    const billing_postal_code_raw = String(req.body?.billing_postal_code || "").trim();
    const billing_city = cleanTextStrict(req.body?.billing_city, {
      max: 60,
      allowEmpty: false,
    });

    const billing_country = cleanTextStrict(req.body?.billing_country, {
      max: 60,
      allowEmpty: false,
    });


    if (!first_name || first_name.length < 2) return res.status(400).json({ error: "first_name invalide" });
    if (!last_name || last_name.length < 2) return res.status(400).json({ error: "last_name invalide" });
    if (!company_name || company_name.length < 2) return res.status(400).json({ error: "company_name invalide" });
    if (!ALLOWED_COMPANY_SIZES.has(company_size)) return res.status(400).json({ error: "company_size invalide" });
    if (company_siret.length !== 14) {
      return res.status(400).json({ error: "INVALID_SIRET" });
    }
    if (!billing_street || billing_street.length < 6) {
      return res.status(400).json({ error: "INVALID_BILLING_STREET" });
    }

    const billing_postal_code = billing_postal_code_raw.replace(/\s+/g, "");
    if (!/^[0-9A-Za-z-]{4,10}$/.test(billing_postal_code)) {
      return res.status(400).json({ error: "INVALID_BILLING_POSTAL_CODE" });
    }

    if (!billing_city || billing_city.length < 2) {
      return res.status(400).json({ error: "INVALID_BILLING_CITY" });
    }

    if (!billing_country || billing_country.length < 2) {
      return res.status(400).json({ error: "INVALID_BILLING_COUNTRY" });
    }
    const billingCountryIso2 = normalizeCountryISO2(billing_country);
    if (!billingCountryIso2) {
      return res.status(400).json({ error: "INVALID_BILLING_COUNTRY_ISO2" });
    }



    // ✅ 0) S'il existe déjà un pending actif pour cet email, on le réutilise
    //     (évite l’erreur unique constraint pending_one_active_per_email)
    const { data: existingPending, error: existingErr } = await supabaseAdmin
      .from("pending_signups")
      .select("*")
      .eq("email", emailNorm)
      .in("status", ["pending", "invited"]) // adapte si tu as d’autres statuts
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (existingErr) {
      log.error("❌ pending_signups select error:", existingErr);
      return res.status(500).json({
        error: "Erreur lecture pending_signups", details: safeDetails(existingErr)
      });
    }

    let pending_id;

    if (existingPending) {
      pending_id = existingPending.id;


      // Optionnel mais utile : mettre à jour les infos du pending (si l'utilisateur a changé)
      const { error: updErr } = await supabaseAdmin
        .from("pending_signups")
        .update({
          first_name: first_name ?? existingPending.first_name,
          last_name: last_name ?? existingPending.last_name,
          company_name: company_name ?? existingPending.company_name,
          company_size: company_size ?? existingPending.company_size,
          desired_plan,
          company_siret,
          status: "pending",
          billing_street,
          billing_postal_code,
          billing_city,
          billing_country,
          terms_accepted_at: new Date().toISOString(),
          terms_version: termsVersion,

          updated_at: new Date().toISOString()
        })
        .eq("id", pending_id);

      if (updErr) {
        log.error("❌ pending_signups update error:", updErr);
        return res.status(500).json({
          error: "Erreur update pending_signup", details: safeDetails(updErr)
        });
      }

    } else {
      // ✅ 1) Créer pending si aucun n'existe
      const { data: pending, error: pendingErr } = await supabaseAdmin
        .from("pending_signups")
        .insert([{
          email: emailNorm,
          first_name: first_name ?? null,
          last_name: last_name ?? null,
          company_name: company_name ?? null,
          company_size: company_size ?? null,
          desired_plan,
          company_siret,
          billing_street,
          billing_postal_code,
          billing_city,
          billing_country,
          status: "pending",
          terms_accepted_at: new Date().toISOString(),
          terms_version: termsVersion,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }])
        .select("*")
        .single();

      if (pendingErr || !pending) {
        log.error("❌ pending_signups insert error:", pendingErr);
        return res.status(500).json({ error: "Impossible de créer pending_signup", details: safeDetails(pendingErr) });
      }

      pending_id = pending.id;
    }

    // [15 mai 2026] Notification interne (contact@ + mehdi.joalland@)
    // a chaque nouvelle inscription paid soumise. Non-bloquant.
    sendAdminSignupNotification({
      first_name,
      last_name,
      email: emailNorm,
      company_name,
      company_size,
      desired_plan,
    });

    // ✅ 2) Price mapping selon le plan
    let priceId = null;
    let extraMetadata = {};

    // Resolution du price_id selon le palier d'effectif (= company_size)
    if (company_size === "50+") {
      return res.status(400).json({ error: "Le palier 50+ necessite un devis" });
    }
    priceId = STRIPE_PRICE_BY_TIER[company_size];
    if (!priceId) {
      return res.status(500).json({
        error: `PriceId Stripe manquant pour le palier ${company_size}`
      });
    }
    extraMetadata = { tier: company_size, plan: "paid" };

    // ✅ 3) Créer session Stripe (nouvelle session à chaque tentative)
    const FRONT = process.env.FRONTEND_URL || (IS_PROD ? "https://integora.fr" : "http://localhost:3000");

    // ✅ 3) Créer un Customer Stripe AVANT checkout (pour facture parfaite)
    const contactName =
      `${first_name ?? ""} ${last_name ?? ""}`.trim() || null;

    const siret = company_siret ? String(company_siret).replace(/\s+/g, "") : null;
    const siren = siret && siret.length >= 9 ? siret.slice(0, 9) : null;

    const stripeCustomer = await stripe.customers.create({
      email: emailNorm,
      name: String(company_name || "").slice(0, 120),
      preferred_locales: ["fr"],

      address: {
        line1: billing_street,
        postal_code: billing_postal_code,
        city: billing_city,
        country: billingCountryIso2,
      },

      // ✅ Ce bloc fait apparaître "Raison sociale / SIRET / SIREN / Contact" en haut à droite
      // ⚠️ max 4 champs Stripe
      invoice_settings: {
        custom_fields: [
          { name: "Raison sociale", value: String(company_name || "").slice(0, 120) },
          ...(siret ? [{ name: "SIRET", value: siret }] : []),
          ...(siren ? [{ name: "SIREN", value: siren }] : []),
          ...(contactName ? [{ name: "Contact", value: contactName.slice(0, 120) }] : []),
        ].slice(0, 4),
      },

      metadata: {
        source: "integora_signup",
        pending_id,
        company_name,
        company_siret: siret || "",
      },
    });



    // ✅ 4) Créer session Stripe (facture = infos Customer)
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: stripeCustomer.id,
      locale: "fr",

      // ✅ TVA auto (Stripe Tax)
      automatic_tax: { enabled: true },
      billing_address_collection: "required",

      tax_id_collection: { enabled: true },
      customer_update: { name: "auto", address: "auto" },




      payment_method_collection: "always",
      line_items: [{ price: priceId, quantity: 1 }],

      success_url: `${FRONT}/email-sent-paiement.html?session_id={CHECKOUT_SESSION_ID}&pending_id=${pending_id}`,
      cancel_url: `${FRONT}/inscription.html?canceled=1`,

      metadata: {
        pending_id,
        desired_plan,
        user_email: emailNorm,
        stripe_customer_id: stripeCustomer.id, // ✅ utile pour debug
        ...extraMetadata, // ✅ ajoute "tier" et "plan: paid" pour le new flow
      },

      subscription_data: {
        metadata: {
          pending_id,
          desired_plan,
          user_email: emailNorm,
          // [15 mai 2026] FIX bug "Renouvellement annulé" a la 1ere connexion apres inscription :
          // sans renewal_mode explicite, l'edge function (enforceRenewalModeOnStripeSubscription)
          // considere la sub comme "manual" par defaut et force cancel_at_period_end=true.
          // Du coup Stripe set cancel_at = current_period_end -> le frontend affiche "annule".
          // Meme fix que /api/subscribe/session (utilise pour reactivation).
          renewal_mode: "auto",
          ...extraMetadata,
        },
      },
    });



    // ✅ 4) Stocker stripe_session_id dans pending
    const { error: sessUpdErr } = await supabaseAdmin
      .from("pending_signups")
      .update({
        stripe_session_id: session.id,
        stripe_customer_id: stripeCustomer.id, // ✅ IMPORTANT
        terms_version: termsVersion,
        updated_at: new Date().toISOString()
      })
      .eq("id", pending_id);


    if (sessUpdErr) {
      log.error("❌ pending_signups update stripe_session_id error:", sessUpdErr);
      return res.status(500).json({
        error: "Erreur update stripe_session_id", details: safeDetails(sessUpdErr)
      });
    }

    return res.json({
      checkoutUrl: session.url,
      pending_id,
      session_id: session.id
    });

  } catch (e) {
    log.error("❌ [START-PAID] error:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});



app.post("/api/complete-signup", async (req, res) => {

  try {
    const { pending_id, session_id } = req.body;
    if (!pending_id || !session_id) {
      return res.status(400).send("pending_id + session_id requis");
    }

    // 1) charger pending
    const { data: pending, error: pendingErr } = await supabaseAdmin
      .from("pending_signups")
      .select("*")
      .eq("id", pending_id)
      .single();

    if (pendingErr || !pending) {
      return res.status(404).send("pending introuvable");
    }

    if (pending.desired_plan !== "paid") {
      return res.status(400).send("pending n'est pas un plan payant");
    }

    // 2) vérifier Stripe session
    const session = await stripe.checkout.sessions.retrieve(session_id, {
      expand: ["subscription", "subscription.items.data.price"]
    });


    // sécurité : session doit correspondre à pending
    const metaPending = session?.metadata?.pending_id;
    if (metaPending !== pending_id) {
      return res.status(403).send("Mismatch pending_id (sécurité)");
    }

    if (session.status !== "complete" || session.payment_status !== "paid") {
      return res.status(402).send("Paiement non validé (Stripe pas en PAID)");
    }

    const stripe_customer_id = session.customer || null;
    const stripe_subscription_id = session.subscription?.id || null;

    // 3) envoyer email d’invite (OVH via Supabase)
    const FRONT =
      process.env.FRONTEND_URL || (IS_PROD ? "https://integora.fr" : "http://localhost:3000");
    const redirectTo = `${FRONT}/welcome.html?pending_id=${pending_id}`;


    const { data: inviteData, error: inviteErr } =
      await supabaseAdmin.auth.admin.inviteUserByEmail(pending.email, {
        redirectTo,
        data: {
          first_name: pending.first_name,
          last_name: pending.last_name,
          company_name: pending.company_name,
          company_size: pending.company_size,
          plan: pending.desired_plan,
          pending_id
        }
      });

    if (inviteErr) {
      const msg = String(inviteErr.message || "");

      // ✅ Cas : user déjà créé -> on renvoie un lien de création de mot de passe
      if (msg.toLowerCase().includes("already been registered")) {
        const FRONT = FRONTEND_URL;
        const redirectTo = `${FRONT}/create-password.html?pending_id=${pending_id}`;

        const { data: linkData, error: linkErr } =
          await supabaseAdmin.auth.admin.generateLink({
            type: "recovery",
            email: pending.email,
            options: { redirectTo },
          });

        if (linkErr) return res.status(500).json({ error: linkErr.message });

        const setPasswordLink =
          linkData?.properties?.action_link ||
          linkData?.properties?.actionLink ||
          null;

        if (!setPasswordLink) {
          return res.status(500).json({ error: "Missing set_password_link" });
        }

        if (!devToolsAllowed(req)) {
          return res.json({ ok: true, account_exists: true });
        }

        return res.json({
          ok: true,
          account_exists: true,
          set_password_link: setPasswordLink,
        });

      }

      // autres erreurs -> on garde 409
      return res.status(409).json({ error: msg });
    }



    const user_id = inviteData?.user?.id || null;





    // 4) update pending
    await supabaseAdmin
      .from("pending_signups")
      .update({
        status: "invited",
        user_id,
        stripe_customer_id,
        stripe_subscription_id,
        stripe_session_id: session_id
      })
      .eq("id", pending_id);

    return res.json({
      ok: true,
      invited: true,
      user_id,
      email: pending.email,
      redirectTo
    });

  } catch (e) {
    log.error("❌ [COMPLETE] error:", safeError(e));
    return res.status(500).send(`Erreur complete-signup: ${e.message}`);
  }
});

//remplir table subscriptions quand la personne clique sur le mail
app.post("/api/finalize-pending", async (req, res) => {

  try {
    const pending_id = String(req.body?.pending_id || "").trim();
    if (!pending_id) return res.status(400).json({ error: "pending_id requis" });

    // 1) Vérifier session Supabase (user connecté via lien email)
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    log.debug("🧪 FINALIZE auth header present:", Boolean(auth));
    log.debug("🧪 FINALIZE token length:", token ? token.length : 0);

    if (!token) return res.status(401).json({ error: "Missing bearer token" });

    // ✅ AJOUT ICI
    const payload = decodeJwtPayload(token);

    // puis ton getUser existant
    const { data: userData, error: userErr } = await supabaseAdmin.auth.getUser(token);
    log.debug("🧪 FINALIZE getUser has user:", Boolean(userData?.user));


    const user = userData?.user;
    if (userErr || !user) return res.status(401).json({ error: "Invalid session" });

    // 2) Charger pending
    const { data: pending, error: pErr } = await supabaseAdmin
      .from("pending_signups")
      .select("*")
      .eq("id", pending_id)
      .single();

    log.debug("🟦 FINALIZE pending.desired_plan:", pending?.desired_plan);


    if (pErr || !pending) return res.status(404).json({ error: "pending introuvable" });

    // 3) Sécurité email
    // ✅ Sécurité principale : le pending doit appartenir au user du token
    const pendingUserId = String(pending.user_id || "").trim();
    if (!pendingUserId || pendingUserId !== user.id) {
      return res.status(403).json({ error: "Pending mismatch" });
    }

    // (optionnel) Sécurité bonus : email doit aussi matcher
    const emailUser = (user.email || "").toLowerCase().trim();
    const emailPending = (pending.email || "").toLowerCase().trim();
    if (emailUser && emailPending && emailUser !== emailPending) {
      return res.status(403).json({ error: "Email mismatch" });
    }

    // Créer upsert pour CGUV : on récupère la preuve depuis pending_signups
    const termsAcceptedAt = pending.terms_accepted_at;
    const termsVersion = pending.terms_version;

    // 🔒 Sécurité ultime (normalement impossible si start-trial est clean)
    if (!termsAcceptedAt || !termsVersion) {
      return res.status(400).json({
        error: "CGUV non acceptées dans pending_signups",
      });
    }



    // 3b) ✅ Créer/Upsert company + profile (service_role) avant subscription

    const companyName = String(pending.company_name ?? "").trim();
    const companySize = String(pending.company_size ?? "").trim();

    if (!companyName) {
      return res.status(400).json({ error: "company_name missing in pending_signups" });
    }

    if (!companySize) {
      return res.status(400).json({ error: "company_size missing in pending_signups" });
    }

    // ✅ Gate payant AVANT companies/profiles
    const plan = String(pending.desired_plan || "").trim();

    if (plan !== "trial") {
      const hasStripeCustomer = !!pending.stripe_customer_id;
      const hasStripeSub = !!pending.stripe_subscription_id;


      // ✅ Condition “READY” = IDs Stripe présents
      if (!hasStripeCustomer || !hasStripeSub) {
        return res.status(409).json({
          error: "Subscription not ready yet",
          code: "PAYMENT_PENDING",
          details: IS_PROD ? undefined : { hasStripeCustomer, hasStripeSub },
        });
      }
    }


    // --- COMPANY ---
    const { data: companyRow, error: compErr } = await supabaseAdmin
      .from("companies")
      .upsert(
        {
          owner_id: user.id,
          legal_name: companyName,
          display_name: companyName,
          company_size: companySize,
          company_siret: pending.company_siret ?? null,
          billing_street: pending.billing_street,
          billing_postal_code: pending.billing_postal_code,
          billing_city: pending.billing_city,
          billing_country: pending.billing_country,

          updated_at: new Date().toISOString(),
        },
        { onConflict: "owner_id" }
      )
      .select("id")
      .single();

    if (compErr) {
      return res.status(500).json({ error: `companies: ${compErr.message}` });
    }

    const companyId = companyRow.id;



    // --- PROFILE ---
    const { data: profileRow, error: profErr } = await supabaseAdmin
      .from("profiles")
      .upsert(
        {
          user_id: user.id,
          first_name: pending.first_name || null,
          last_name: pending.last_name || null,
          company_id: companyId,
          terms_accepted_at: termsAcceptedAt,
          terms_version: termsVersion,
          updated_at: new Date().toISOString(),
        },
        { onConflict: "user_id" }
      )
      .select("user_id, company_id, first_name, last_name")
      .single();

    if (profErr) {
      log.error("❌ profiles upsert error:", profErr);
      return res.status(500).json({ error: `profiles: ${profErr.message}` });
    }



    // 4) Créer subscription AU MOMENT DU CLIC
    log.debug("🟦 FINALIZE desired_plan:", pending.desired_plan);
    log.debug("🟦 FINALIZE will create subscription?", pending.desired_plan === "trial");

    if (pending.desired_plan === "trial") {
      const now = new Date();
      const trialEnd = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

      const payload = {
        user_id: user.id,
        plan: "trial",
        status: "trialing", // ⚠️ à remplacer par une valeur EXISTANTE de ton enum
        current_period_start: now.toISOString(),
        trial_end: trialEnd.toISOString(),
        started_at: now.toISOString(),
        updated_at: now.toISOString(),
      };

      // [15 mai 2026] On stocke aussi le tier (= palier choisi a l'inscription)
      // pour les comptes trial. Cela facilite les requetes business (pas besoin
      // de JOIN avec companies) et pre-renseigne le palier au moment de la
      // conversion en paid. current_paid_tier reste NULL : un trial ne paie
      // rien actuellement, il n'a donc pas de "palier facture en cours".
      if (companySize) {
        payload.tier = companySize;
      }


      const { data: subSaved, error: upErr } = await supabaseAdmin
        .from("subscriptions")
        .upsert(payload, { onConflict: "user_id" })
        .select("id, user_id, plan, status, trial_end")
        .single();

      if (upErr) {
        log.error("❌ subscriptions upsert error:", upErr);
        return res.status(500).json({ error: `subscriptions: ${upErr.message}` });
      }

    } else {

      // ✅ Payant : la subscription doit déjà exister (créée par webhook Stripe)
      const { data: subRow, error: subErr } = await supabaseAdmin
        .from("subscriptions")
        .select("user_id, plan, status")
        .eq("user_id", user.id)
        .maybeSingle();

      if (subErr) return res.status(500).json({ error: subErr.message });

      if (!subRow) {

        // Construire le payload pour un plan paid
        const subscriptionPayload = {
          user_id: user.id,
          plan: plan,                  // "paid"
          status: "active",            // ✅ dans ton enum sub_status
          stripe_customer_id: pending.stripe_customer_id,
          stripe_subscription_id: pending.stripe_subscription_id,
          started_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };

        // ✅ Pour le flow 'paid', stocker le tier (= company_size)
        if (plan === "paid" && companySize) {
          subscriptionPayload.tier = companySize;
          // [14 mai 2026] A la creation, current_paid_tier = tier (= ce qui va etre facture immediatement)
          // Par la suite, current_paid_tier ne sera mis a jour qu'au renouvellement annuel
          // (webhook invoice.paid). Si le user change de tier entre-temps, seul 'tier' change.
          subscriptionPayload.current_paid_tier = companySize;
        }

        // ✅ Enrichir avec les donnees Stripe (current_period_end, stripe_price_id, etc.)
        //    Necessaire car le webhook n'a pas pu remplir ces champs : a ce moment-la,
        //    l'utilisateur n'existait pas encore en Supabase Auth (timing issue).
        if (pending.stripe_subscription_id) {
          try {
            const stripeSub = await stripe.subscriptions.retrieve(pending.stripe_subscription_id);
            const firstItem = stripeSub.items?.data?.[0] ?? null;

            // ✅ Defensif : essaie d'abord au niveau subscription, puis au niveau item
            //    (depend de la version d'API Stripe)
            const periodStartTs =
              stripeSub.current_period_start ||
              firstItem?.current_period_start ||
              null;
            const periodEndTs =
              stripeSub.current_period_end ||
              firstItem?.current_period_end ||
              null;

            log.debug("🔍 FINALIZE: Stripe subscription fetched", {
              sub_id: stripeSub.id,
              status: stripeSub.status,
              top_level_period_start: stripeSub.current_period_start,
              top_level_period_end: stripeSub.current_period_end,
              item_period_start: firstItem?.current_period_start,
              item_period_end: firstItem?.current_period_end,
              cancel_at: stripeSub.cancel_at,
              price_id: firstItem?.price?.id,
              resolved_period_start: periodStartTs,
              resolved_period_end: periodEndTs,
            });

            if (periodStartTs) {
              subscriptionPayload.current_period_start = new Date(periodStartTs * 1000).toISOString();
            }
            if (periodEndTs) {
              subscriptionPayload.current_period_end = new Date(periodEndTs * 1000).toISOString();
            }
            if (stripeSub.cancel_at) {
              subscriptionPayload.cancel_at = new Date(stripeSub.cancel_at * 1000).toISOString();
            }
            if (firstItem?.price?.id) {
              subscriptionPayload.stripe_price_id = firstItem.price.id;
            }
            // ✅ Patch user_id dans la metadata Stripe pour que les futurs events trouvent l'user
            await stripe.subscriptions.update(pending.stripe_subscription_id, {
              metadata: { ...(stripeSub.metadata ?? {}), user_id: user.id },
            });
          } catch (e) {
            log.warn("⚠️ FINALIZE: failed to fetch Stripe sub for enrichment:", e?.message);
            // On continue sans bloquer - le prochain webhook (renewal) repopulera
          }
        }

        const { data: createdSub, error: createErr } = await supabaseAdmin
          .from("subscriptions")
          .upsert(subscriptionPayload, { onConflict: "user_id" })
          .select("id, user_id, plan, status, stripe_subscription_id, tier")
          .single();

        if (createErr) {
          log.error("❌ FINALIZE fallback subscriptions upsert error:", createErr);
          return res.status(500).json({ error: `subscriptions: ${createErr.message}` });
        }
        log.debug("FINALIZE upsert subscriptions", { hasPayload: Boolean(payload), plan: payload?.plan });

      }

    }

    // 5) Marquer pending comme activé
    // ✅ Idempotence: conserver la date du premier clic
    const { data: curPending, error: curErr } = await supabaseAdmin
      .from("pending_signups")
      .select("activated_at")
      .eq("id", pending_id)
      .maybeSingle();

    if (curErr) return res.status(500).json({ error: curErr.message });

    await supabaseAdmin
      .from("pending_signups")
      .update({
        status: "activated",
        user_id: user.id,
        updated_at: new Date().toISOString(),
        activated_at: curPending?.activated_at ?? new Date().toISOString(),
      })
      .eq("id", pending_id);



    // ✅ Générer un lien de création de mot de passe (flow recovery) SANS envoyer un 2e mail
    const FRONT = process.env.FRONTEND_URL || "https://integora.fr";
    const redirectTo = `${FRONT}/create-password.html`;

    const { data: linkData, error: linkErr } = await supabaseAdmin.auth.admin.generateLink({
      type: "recovery",
      email: user.email,
      options: { redirectTo },
    });

    if (linkErr) return res.status(500).json({ error: linkErr.message });

    const setPasswordLink =
      linkData?.properties?.action_link ||
      linkData?.properties?.actionLink ||
      null;

    if (!setPasswordLink) {
      return res.status(500).json({ error: "Missing set_password_link" });
    }


    return res.json({ ok: true, set_password_link: setPasswordLink });

  } catch (e) {
    log.error("❌ /api/finalize-pending:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});



// ==========================================
// [15 mai 2026] SET MDP INITIAL (apres clic sur lien d'invitation)
//
// Pourquoi cette route ?
//   Quand le user clique sur le lien d'invitation et arrive sur
//   create-password.html, on appelait avant sb.auth.updateUser({ password }).
//   Or Supabase Auth declenche AUTOMATIQUEMENT l'email "Mot de passe modifie"
//   sur toute action updateUser({ password }), meme pour une creation initiale.
//   C'est trompeur pour le user.
//
// Solution :
//   On passe par l'API admin Supabase (supabase.auth.admin.updateUserById)
//   qui NE declenche PAS le template "Password changed". Pour proteger cet
//   endpoint contre les abus, on verifie :
//     1. L'access_token Supabase est valide (donc user authentifie)
//     2. C'est bien une creation initiale (last_sign_in_at null OU pas
//        encore de flag password_initialized dans user_metadata)
//
// Pour TOUT autre changement de mdp ulterieur (profile.html ou reset-password.html),
// on continue a appeler sb.auth.updateUser({ password }) directement -> email envoye
// pour la securite (notif au vrai proprietaire en cas de tentative de hack).
// ==========================================
app.post("/api/auth/set-initial-password", async (req, res) => {
  try {
    const password = String(req.body?.password || "");
    // Le frontend peut envoyer le token soit dans le body, soit en header Authorization
    const accessToken = String(
      req.body?.accessToken ||
        (req.headers.authorization || "").replace(/^Bearer\s+/i, "") ||
        ""
    );

    // 1) Validation basique du mdp (la verif forte est faite par Supabase Auth derriere)
    if (!password) {
      return res.status(400).json({ error: "Mot de passe requis" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Mot de passe trop court (8 caracteres minimum)" });
    }
    if (password.length > 72) {
      return res.status(400).json({ error: "Mot de passe trop long (72 caracteres maximum)" });
    }
    if (!accessToken) {
      return res.status(401).json({ error: "Session manquante" });
    }

    // 2) Verifier le token via Supabase admin -> recupere le user
    const { data: userData, error: getUserErr } = await supabaseAdmin.auth.getUser(accessToken);
    if (getUserErr || !userData?.user) {
      return res.status(401).json({ error: "Session invalide ou expiree" });
    }
    const user = userData.user;

    // 3) Verifier que c'est bien une CREATION INITIALE.
    //    On se base UNIQUEMENT sur le flag user_metadata.password_initialized
    //    qu'on controle nous-meme (set a true des le premier passage via ce endpoint).
    //
    //    On ne se base PAS sur last_sign_in_at car Supabase Auth peut le remplir
    //    automatiquement au moment ou le user clique sur le lien d'invitation
    //    (verification du token = "sign in" du point de vue Supabase), ce qui
    //    rendrait le check trop strict.
    //
    //    Risque residuel : un user legacy (sans le flag) pourrait theoriquement
    //    utiliser cette route une fois. Mais il faut deja un access_token valide
    //    (= acces deja confirme), donc pas d'elevation de privilege reelle.
    const alreadyInitialized = !!user.user_metadata?.password_initialized;

    if (alreadyInitialized) {
      return res.status(403).json({
        error: "Cet endpoint est reserve a la creation initiale du mot de passe. " +
               "Pour modifier votre mot de passe, utilisez votre espace profil ou la procedure d'oubli.",
      });
    }

    // 4) Set du password via l'API admin -> ne declenche PAS le template Supabase "Password changed"
    //    On marque aussi user_metadata.password_initialized = true pour bloquer toute
    //    reutilisation de ce endpoint pour ce user.
    const { error: updErr } = await supabaseAdmin.auth.admin.updateUserById(user.id, {
      password,
      user_metadata: {
        ...(user.user_metadata || {}),
        password_initialized: true,
        password_initialized_at: new Date().toISOString(),
      },
    });

    if (updErr) {
      log.warn("⚠️ /api/auth/set-initial-password update error:", safeError(updErr));
      // On renvoie le message brut Supabase pour que le frontend gere
      // les cas "mdp trop faible / leaked / etc." comme avant.
      return res.status(updErr.status || 400).json({
        error: updErr.message || "Erreur lors de la creation du mot de passe",
      });
    }

    log.debug("✅ Initial password set via admin API (no security email sent)", {
      user_id: user.id,
    });

    // ✅ Membre invité : on enregistre la PRISE DE CONNAISSANCE des conditions
    //    au moment de la création du mot de passe. L'admin (le souscripteur) a
    //    déjà accepté les CGUV pour son entreprise lors de l'inscription ; le
    //    membre est informé ici (mention affichée sur create-password.html).
    //    Best-effort : n'empêche pas la création du compte si l'update échoue.
    if (String(user.user_metadata?.role || "").toLowerCase() === "membre") {
      const { error: termsErr } = await supabaseAdmin
        .from("profiles")
        .update({
          terms_accepted_at: new Date().toISOString(),
          terms_version: CURRENT_TERMS_VERSION,
          updated_at: new Date().toISOString(),
        })
        .eq("user_id", user.id);
      if (termsErr) {
        log.warn("⚠️ set-initial-password: enregistrement CGUV membre échoué:", safeError(termsErr));
      }
    }

    return res.json({ success: true });
  } catch (e) {
    log.error("❌ /api/auth/set-initial-password:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});


// ============================================================
// ÉQUIPE — Gestion des membres (admin payant uniquement)
// Étape 1 du chantier multi-tenant : un admin payant peut inviter
// jusqu'à MAX_TEAM_MEMBERS collègues, qui obtiennent de vrais comptes
// Supabase rattachés à la même entreprise en rôle "membre".
// ============================================================
const MAX_TEAM_MEMBERS = 2; // membres invités maximum (hors admin)

// Garde-fou commun : route réservée à l'admin d'une entreprise.
function requireCompanyAdmin(req, res) {
  const me = req.user;
  if (!me || me.role !== 'admin') {
    res.status(403).json({ error: "Réservé à l'administrateur de l'entreprise", code: "NOT_ADMIN" });
    return null;
  }
  return me;
}

// Renvoie l'équipe SI l'utilisateur courant y a accès (admin -> toute équipe de SA company ;
// membre -> uniquement les équipes où il figure dans team_members). Sinon null.
// Socle de sécurité réutilisé par toutes les routes de données du pilotage.
async function getAccessibleTeam(me, teamId) {
  if (!me || !me.company_id) return null;
  if (!/^[0-9a-f-]{36}$/i.test(String(teamId || ""))) return null;
  const { data: team, error } = await supabaseAdmin
    .from("teams")
    .select("id, company_id, archived_at")
    .eq("id", teamId)
    .maybeSingle();
  if (error || !team || team.company_id !== me.company_id) return null;
  if (me.role === 'admin') return team;
  const { data: link } = await supabaseAdmin
    .from("team_members")
    .select("team_id")
    .eq("team_id", teamId)
    .eq("user_id", me.id)
    .maybeSingle();
  return link ? team : null;
}

// --- Inviter un membre ---
app.post("/api/team/invite", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;

    // Compte payant actif uniquement (les essais ne peuvent pas inviter)
    if (!(me.subscription_type === 'paid' && me.has_active_subscription)) {
      return res.status(403).json({ error: "Réservé aux abonnements payants actifs", code: "NOT_PAID" });
    }
    if (!me.company_id) {
      return res.status(400).json({ error: "Aucune entreprise rattachée au compte", code: "NO_COMPANY" });
    }

    const email = normalizeEmail(req.body?.email);
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({ error: "Email invalide" });
    }
    if (email === normalizeEmail(me.email)) {
      return res.status(400).json({ error: "Vous ne pouvez pas vous inviter vous-même" });
    }
    const firstName = String(req.body?.first_name || "").trim().slice(0, 50) || null;
    const lastName = String(req.body?.last_name || "").trim().slice(0, 50) || null;

    // Limite de membres pour cette entreprise
    const { count: memberCount, error: countErr } = await supabaseAdmin
      .from("profiles")
      .select("user_id", { count: "exact", head: true })
      .eq("company_id", me.company_id)
      .eq("role", "membre")
      .is("archived_at", null);
    if (countErr) {
      log.error("❌ team/invite count error:", safeError(countErr));
      return res.status(500).json({ error: "Erreur lecture des membres" });
    }
    if ((memberCount || 0) >= MAX_TEAM_MEMBERS) {
      return res.status(409).json({ error: `Limite atteinte (${MAX_TEAM_MEMBERS} membres maximum)`, code: "LIMIT_REACHED" });
    }

    // Invitation Supabase : crée le compte Auth + envoie l'email d'invitation.
    // Le membre choisit lui-même son mot de passe sur create-password.html (Option B).
    const FRONT = process.env.FRONTEND_URL || (IS_PROD ? "https://integora.fr" : "http://localhost:3000");
    const redirectTo = `${FRONT}/create-password.html`;

    // Nom de l'entreprise -> alimente le champ "Organisation" de l'email d'invitation
    const { data: companyRow } = await supabaseAdmin
      .from("companies")
      .select("display_name, legal_name")
      .eq("id", me.company_id)
      .maybeSingle();
    const companyName = companyRow?.display_name || companyRow?.legal_name || "";

    const { data: inviteData, error: inviteErr } = await supabaseAdmin.auth.admin.inviteUserByEmail(email, {
      redirectTo,
      data: {
        first_name: firstName,
        last_name: lastName,
        company_name: companyName,
        role: "membre",
        company_id: me.company_id,
        invited_by: me.id,
      },
    });

    if (inviteErr) {
      const msg = String(inviteErr.message || "");
      if (msg.toLowerCase().includes("already been registered")) {
        return res.status(409).json({ error: "Cet email a déjà un compte Integora", code: "EMAIL_TAKEN" });
      }
      log.error("❌ team/invite inviteUserByEmail:", safeError(inviteErr));
      return res.status(500).json({ error: "Erreur lors de l'invitation" });
    }

    const newUserId = inviteData?.user?.id || null;
    if (!newUserId) {
      return res.status(500).json({ error: "Compte non créé" });
    }

    // Ligne profil du membre, rattachée à l'entreprise, en rôle "membre"
    const { error: profErr } = await supabaseAdmin
      .from("profiles")
      .upsert(
        {
          user_id: newUserId,
          first_name: firstName,
          last_name: lastName,
          company_id: me.company_id,
          role: "membre",
          updated_at: new Date().toISOString(),
        },
        { onConflict: "user_id" }
      );

    if (profErr) {
      log.error("❌ team/invite profiles upsert:", safeError(profErr));
      // Rollback best-effort : pas de compte Auth fantôme sans profil
      await supabaseAdmin.auth.admin.deleteUser(newUserId).catch(() => { });
      return res.status(500).json({ error: "Erreur création du profil membre" });
    }

    logTechAction({ companyId: me.company_id, teamId: null, actorUserId: me.id, action: 'team_invite' });
    return res.json({
      ok: true,
      member: { user_id: newUserId, email, first_name: firstName, last_name: lastName, status: "invited" },
    });
  } catch (e) {
    log.error("❌ /api/team/invite:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Lister les membres de mon entreprise ---
app.get("/api/team/members", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;

    if (!me.company_id) {
      return res.json({ members: [], used: 0, max: MAX_TEAM_MEMBERS });
    }

    const { data: rows, error } = await supabaseAdmin
      .from("profiles")
      .select("user_id, first_name, last_name, created_at, archived_at")
      .eq("company_id", me.company_id)
      .eq("role", "membre")
      .order("created_at", { ascending: true });

    if (error) {
      log.error("❌ team/members select error:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture des membres" });
    }

    // Équipes attribuées à chaque membre (table team_members, scopée company) : 1 requête, regroupée par user.
    const teamsByUser = {};
    {
      const { data: links, error: linkErr } = await supabaseAdmin
        .from("team_members")
        .select("user_id, team_id")
        .eq("company_id", me.company_id);
      if (linkErr) {
        log.error("❌ team/members links error:", safeError(linkErr));
        return res.status(500).json({ error: "Erreur lecture des accès" });
      }
      for (const l of (links || [])) {
        (teamsByUser[l.user_id] = teamsByUser[l.user_id] || []).push(l.team_id);
      }
    }

    // Email + statut depuis Supabase Auth (profiles ne stocke pas l'email).
    // On sépare les membres ACTIFS des membres ARCHIVÉS (accès retiré).
    // ⚡ PERF : les lectures Auth (email + statut) par membre sont lancées EN PARALLÈLE
    // (au lieu d'un await séquentiel par membre = N allers-retours → plusieurs secondes).
    const enriched = await Promise.all((rows || []).map(async (r) => {
      let email = null;
      let status = "invited";
      try {
        const { data: au } = await supabaseAdmin.auth.admin.getUserById(r.user_id);
        email = au?.user?.email || null;
        status = au?.user?.user_metadata?.password_initialized ? "active" : "invited";
      } catch (_) { /* membre listé même si lecture Auth indisponible */ }
      return { r, email, status };
    }));
    const active = [];
    const archived = [];
    for (const { r, email, status } of enriched) {
      const base = { user_id: r.user_id, email, first_name: r.first_name, last_name: r.last_name, teams: teamsByUser[r.user_id] || [] };
      if (r.archived_at) {
        archived.push({ ...base, archived_at: r.archived_at });
      } else {
        active.push({ ...base, status });
      }
    }

    return res.json({ active, archived, used: active.length, max: MAX_TEAM_MEMBERS });
  } catch (e) {
    log.error("❌ /api/team/members:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Définir les équipes d'un membre (réconcilie team_members) ---
// C'est CE qui détermine ce qu'un membre voit (cf. getAccessibleTeam / GET /api/pilotage/teams).
app.post("/api/team/members/:userId/teams", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;
    if (!me.company_id) return res.status(400).json({ error: "Aucune entreprise rattachée", code: "NO_COMPANY" });

    const userId = String(req.params.userId || "");
    if (!/^[0-9a-f-]{36}$/i.test(userId)) return res.status(400).json({ error: "Identifiant invalide" });

    // 🔒 Le membre cible doit être de MA company et de rôle 'membre'.
    const { data: target, error: tErr } = await supabaseAdmin
      .from("profiles")
      .select("user_id, company_id, role")
      .eq("user_id", userId)
      .maybeSingle();
    if (tErr) { log.error("❌ member teams target:", safeError(tErr)); return res.status(500).json({ error: "Erreur serveur" }); }
    if (!target || target.company_id !== me.company_id || String(target.role || "").toLowerCase() !== "membre") {
      return res.status(404).json({ error: "Membre introuvable dans votre entreprise" });
    }

    let teamIds = Array.isArray(req.body?.team_ids) ? req.body.team_ids.map((x) => String(x)) : null;
    if (!teamIds) return res.status(400).json({ error: "Liste d'équipes invalide" });
    teamIds = [...new Set(teamIds)];
    for (const tid of teamIds) {
      if (!/^[0-9a-f-]{36}$/i.test(tid)) return res.status(400).json({ error: "Identifiant d'équipe invalide" });
    }

    // 🔒 Toutes les équipes demandées doivent appartenir à MA company.
    if (teamIds.length) {
      const { data: validTeams, error: vErr } = await supabaseAdmin
        .from("teams")
        .select("id")
        .eq("company_id", me.company_id)
        .in("id", teamIds);
      if (vErr) { log.error("❌ member teams validate:", safeError(vErr)); return res.status(500).json({ error: "Erreur serveur" }); }
      const validSet = new Set((validTeams || []).map((t) => t.id));
      if (teamIds.some((t) => !validSet.has(t))) {
        return res.status(400).json({ error: "Une équipe n'appartient pas à votre entreprise" });
      }
    }

    // Réconciliation : on lit l'existant, on ajoute le manquant, on retire le surplus (scopé company + user).
    const { data: existing, error: exErr } = await supabaseAdmin
      .from("team_members")
      .select("team_id")
      .eq("company_id", me.company_id)
      .eq("user_id", userId);
    if (exErr) { log.error("❌ member teams existing:", safeError(exErr)); return res.status(500).json({ error: "Erreur serveur" }); }
    const existingSet = new Set((existing || []).map((r) => r.team_id));
    const toAdd = teamIds.filter((t) => !existingSet.has(t));
    const toRemove = [...existingSet].filter((t) => !teamIds.includes(t));

    if (toAdd.length) {
      const rows = toAdd.map((t) => ({ team_id: t, user_id: userId, company_id: me.company_id, created_by: me.id }));
      const { error: insErr } = await supabaseAdmin.from("team_members").insert(rows);
      if (insErr) { log.error("❌ member teams insert:", safeError(insErr)); return res.status(500).json({ error: "Erreur d'enregistrement" }); }
    }
    if (toRemove.length) {
      const { error: delErr } = await supabaseAdmin
        .from("team_members")
        .delete()
        .eq("company_id", me.company_id)
        .eq("user_id", userId)
        .in("team_id", toRemove);
      if (delErr) { log.error("❌ member teams delete:", safeError(delErr)); return res.status(500).json({ error: "Erreur de synchronisation" }); }
    }

    if (toAdd.length || toRemove.length) {
      logTechAction({ companyId: me.company_id, teamId: null, actorUserId: me.id, action: 'team_access_set' });
    }
    return res.json({ ok: true, teams: teamIds });
  } catch (e) {
    log.error("❌ /api/team/members/:userId/teams:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Retirer un membre de mon entreprise ---
app.delete("/api/team/members/:userId", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;

    const targetId = String(req.params.userId || "");
    if (!/^[0-9a-f-]{36}$/i.test(targetId)) {
      return res.status(400).json({ error: "Identifiant invalide" });
    }
    if (targetId === me.id) {
      return res.status(400).json({ error: "Vous ne pouvez pas vous retirer vous-même" });
    }

    // La cible doit être un MEMBRE de MON entreprise (sinon 404, jamais d'accès croisé)
    const { data: target, error: tErr } = await supabaseAdmin
      .from("profiles")
      .select("user_id, company_id, role, archived_at")
      .eq("user_id", targetId)
      .maybeSingle();

    if (tErr) {
      log.error("❌ team/archive select error:", safeError(tErr));
      return res.status(500).json({ error: "Erreur lecture du membre" });
    }
    if (!target || target.company_id !== me.company_id || target.role !== 'membre') {
      return res.status(404).json({ error: "Membre introuvable dans votre entreprise" });
    }
    if (target.archived_at) {
      return res.json({ ok: true, already: true }); // déjà archivé
    }

    // ✅ "Retirer l'accès" = ARCHIVER (jamais supprimer). On garde le compte et le
    //    nom pour la traçabilité ("Créé par ...") ; on coupe seulement l'accès.
    const nowIso = new Date().toISOString();
    const { error: archErr } = await supabaseAdmin
      .from("profiles")
      .update({ archived_at: nowIso, updated_at: nowIso })
      .eq("user_id", targetId);
    if (archErr) {
      log.error("❌ team/archive update error:", safeError(archErr));
      return res.status(500).json({ error: "Erreur lors du retrait de l'accès" });
    }

    // Couper ses sessions (déconnexion immédiate)
    const { error: sessErr } = await supabaseAdmin
      .from("token_sessions")
      .update({ is_active: false, revoked_at: nowIso })
      .eq("user_id", targetId)
      .eq("is_active", true);
    if (sessErr) log.warn("⚠️ team/archive sessions:", safeError(sessErr));

    // Retirer ses accès aux équipes (liens d'accès, PAS du contenu métier)
    const { error: tmErr } = await supabaseAdmin
      .from("team_members")
      .delete()
      .eq("user_id", targetId);
    if (tmErr) log.warn("⚠️ team/archive team_members:", safeError(tmErr));

    logTechAction({ companyId: me.company_id, teamId: null, actorUserId: me.id, action: 'member_removed' });
    return res.json({ ok: true });
  } catch (e) {
    log.error("❌ DELETE /api/team/members:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Réactiver un membre archivé (lui rendre l'accès) ---
app.post("/api/team/members/:userId/reactivate", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;

    const targetId = String(req.params.userId || "");
    if (!/^[0-9a-f-]{36}$/i.test(targetId)) {
      return res.status(400).json({ error: "Identifiant invalide" });
    }

    // La cible doit être un membre ARCHIVÉ de MON entreprise
    const { data: target, error: tErr } = await supabaseAdmin
      .from("profiles")
      .select("user_id, company_id, role, archived_at")
      .eq("user_id", targetId)
      .maybeSingle();
    if (tErr) {
      log.error("❌ team/reactivate select error:", safeError(tErr));
      return res.status(500).json({ error: "Erreur lecture du membre" });
    }
    if (!target || target.company_id !== me.company_id || target.role !== 'membre') {
      return res.status(404).json({ error: "Membre introuvable dans votre entreprise" });
    }
    if (!target.archived_at) {
      return res.json({ ok: true, already: true }); // déjà actif
    }

    // 🚧 GARDE-FOU : jamais plus de MAX_TEAM_MEMBERS membres ACTIFS.
    const { count: activeCount, error: countErr } = await supabaseAdmin
      .from("profiles")
      .select("user_id", { count: "exact", head: true })
      .eq("company_id", me.company_id)
      .eq("role", "membre")
      .is("archived_at", null);
    if (countErr) {
      log.error("❌ team/reactivate count error:", safeError(countErr));
      return res.status(500).json({ error: "Erreur serveur" });
    }
    if ((activeCount || 0) >= MAX_TEAM_MEMBERS) {
      return res.status(409).json({
        error: `Limite atteinte (${MAX_TEAM_MEMBERS} membres maximum). Retirez d'abord l'accès d'un membre actif.`,
        code: "LIMIT_REACHED",
      });
    }

    // Réactivation : on enlève l'archivage. Le compte/mot de passe existant
    // restent valides -> le membre peut se reconnecter immédiatement.
    const { error: updErr } = await supabaseAdmin
      .from("profiles")
      .update({ archived_at: null, updated_at: new Date().toISOString() })
      .eq("user_id", targetId);
    if (updErr) {
      log.error("❌ team/reactivate update error:", safeError(updErr));
      return res.status(500).json({ error: "Erreur lors de la réactivation" });
    }

    logTechAction({ companyId: me.company_id, teamId: null, actorUserId: me.id, action: 'member_reactivated' });
    return res.json({ ok: true });
  } catch (e) {
    log.error("❌ /api/team/members/:id/reactivate:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});


// ============================================================
// ÉQUIPES — Gestion des équipes de l'entreprise (admin uniquement)
// Brique du chantier multi-tenant. On ARCHIVE plutôt que supprimer :
// le contenu métier rattaché (à venir) ne doit jamais être détruit.
// ============================================================
const TEAM_NAME_MAX = 60;
// Couleur d'équipe : donnée PARTAGÉE entreprise (colonne teams.color). Clés autorisées
// alignées sur le front (TEAM_COLORS). null = pas de couleur choisie (le front retombe sur
// un repli stable par position).
const TEAM_COLOR_KEYS = ['blue', 'green', 'violet', 'cyan', 'orange', 'rose', 'amber', 'teal', 'pink'];
function sanitizeTeamColor(v) {
  const c = String(v || '').trim().toLowerCase();
  return TEAM_COLOR_KEYS.includes(c) ? c : null;
}

// --- Lister les équipes (actives) de mon entreprise ---
app.get("/api/teams", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;
    if (!me.company_id) return res.json({ teams: [] });

    const { data, error } = await supabaseAdmin
      .from("teams")
      .select("id, name, color, created_at, archived_at")
      .eq("company_id", me.company_id)
      .is("archived_at", null)
      .order("created_at", { ascending: true });

    if (error) {
      log.error("❌ teams list error:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture des équipes" });
    }
    return res.json({ teams: data || [] });
  } catch (e) {
    log.error("❌ /api/teams GET:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Équipes ACCESSIBLES à l'utilisateur courant (socle du tableau de pilotage) ---
// Admin  : toutes les équipes actives de SON entreprise.
// Membre : uniquement les équipes où il figure dans team_members (scopées company_id).
// Lecture seule, ouverte admin ET membre (le pilotage doit être consultable par les membres).
app.get("/api/pilotage/teams", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    if (!me) return res.status(401).json({ error: "Non authentifié" });
    if (!me.company_id) return res.json({ teams: [], role: me.role || null });

    if (me.role === 'admin') {
      // On renvoie AUSSI les archivées (archived_at non null) : le front gère
      // la liste active ET la modale "Équipes archivées".
      const { data, error } = await supabaseAdmin
        .from("teams")
        .select("id, name, color, created_at, archived_at")
        .eq("company_id", me.company_id)
        .order("created_at", { ascending: true });
      if (error) {
        log.error("❌ pilotage/teams admin error:", safeError(error));
        return res.status(500).json({ error: "Erreur lecture des équipes" });
      }
      return res.json({ teams: data || [], role: 'admin' });
    }

    // Membre : on récupère d'abord ses rattachements, puis les équipes correspondantes.
    const { data: links, error: linkErr } = await supabaseAdmin
      .from("team_members")
      .select("team_id")
      .eq("company_id", me.company_id)
      .eq("user_id", me.id);
    if (linkErr) {
      log.error("❌ pilotage/teams member links error:", safeError(linkErr));
      return res.status(500).json({ error: "Erreur lecture des équipes" });
    }
    const teamIds = (links || []).map((r) => r.team_id);
    if (!teamIds.length) return res.json({ teams: [], role: 'membre' });

    const { data, error } = await supabaseAdmin
      .from("teams")
      .select("id, name, color, created_at, archived_at")
      .eq("company_id", me.company_id)
      .in("id", teamIds)
      .is("archived_at", null)
      .order("created_at", { ascending: true });
    if (error) {
      log.error("❌ pilotage/teams member error:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture des équipes" });
    }
    return res.json({ teams: data || [], role: 'membre' });
  } catch (e) {
    log.error("❌ /api/pilotage/teams GET:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// =========================================================================
// PILOTAGE — BOOTSTRAP : toutes les données d'UNE équipe en UN seul appel.
// ⚡ PERF : 6 requêtes Supabase lancées EN PARALLÈLE côté serveur (le backend est
//    proche de Supabase) → 1 seul aller-retour navigateur au lieu de 6-12.
//    Même isolation que les routes individuelles (getAccessibleTeam + company_id forcé).
// =========================================================================
app.get("/api/pilotage/bootstrap", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.query.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });

    const [monthly, goals, thermometres, annotations, collaborators, journal] = await Promise.all([
      supabaseAdmin.from("pilotage_monthly_kpis")
        .select("month, absenteeism, overtime, training, headcount")
        .eq("company_id", me.company_id).eq("team_id", teamId)
        .order("month", { ascending: true }),
      supabaseAdmin.from("pilotage_goals")
        .select("id, kpi_key, title, start_value, start_week_num, target_value, deadline, description, created_at")
        .eq("company_id", me.company_id).eq("team_id", teamId)
        .order("created_at", { ascending: true }),
      supabaseAdmin.from("pilotage_thermometres")
        .select("id, year, week_num, date, participants, distribution, note, is_retroactive, created_at, updated_at")
        .eq("company_id", me.company_id).eq("team_id", teamId)
        .order("year", { ascending: true }).order("week_num", { ascending: true }),
      supabaseAdmin.from("pilotage_annotations")
        .select("id, year, week_num, category, kpi_key, title, description, author, created_at")
        .eq("company_id", me.company_id).eq("team_id", teamId)
        .order("created_at", { ascending: true }),
      supabaseAdmin.from("pilotage_collaborators")
        .select("id, data")
        .eq("company_id", me.company_id).eq("team_id", teamId)
        .order("created_at", { ascending: true }),
      supabaseAdmin.from("pilotage_journal")
        .select("id, data")
        .eq("company_id", me.company_id).eq("team_id", teamId)
        .order("created_at", { ascending: true }),
    ]);

    const failed = [monthly, goals, thermometres, annotations, collaborators, journal].find((r) => r.error);
    if (failed) {
      log.error("❌ pilotage/bootstrap:", safeError(failed.error));
      return res.status(500).json({ error: "Erreur de chargement du tableau" });
    }

    return res.json({
      team_id: teamId,
      monthly_kpis: monthly.data || [],
      goals: goals.data || [],
      thermometres: thermometres.data || [],
      annotations: annotations.data || [],
      collaborators: collaborators.data || [],
      journal: journal.data || [],
    });
  } catch (e) {
    log.error("❌ /api/pilotage/bootstrap:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// =========================================================================
// PILOTAGE — KPI MENSUELS (absentéisme / charge / formation + effectif)
// =========================================================================
const PILOTAGE_MONTHLY_KEYS = ["absenteeism", "overtime", "training"];

// Lire les KPI mensuels d'une équipe (accès admin OU membre de l'équipe).
app.get("/api/pilotage/monthly-kpis", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.query.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });

    const { data, error } = await supabaseAdmin
      .from("pilotage_monthly_kpis")
      .select("month, absenteeism, overtime, training, headcount")
      .eq("company_id", me.company_id)
      .eq("team_id", teamId)
      .order("month", { ascending: true });
    if (error) {
      log.error("❌ pilotage/monthly-kpis GET error:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture des indicateurs" });
    }
    return res.json({ items: data || [] });
  } catch (e) {
    log.error("❌ /api/pilotage/monthly-kpis GET:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// Enregistrer UNE valeur d'indicateur pour un mois (upsert ; company_id/team_id FORCÉS serveur).
// L'effectif (headcount) est figé au 1er enregistrement du mois (on ne l'écrase plus ensuite).
app.post("/api/pilotage/monthly-kpis/set", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.body?.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });

    const month = String(req.body?.month || "");
    if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: "Mois invalide" });
    const kpiKey = String(req.body?.kpi_key || "");
    if (!PILOTAGE_MONTHLY_KEYS.includes(kpiKey)) return res.status(400).json({ error: "Indicateur invalide" });

    let value = req.body?.value;
    if (value === null || value === undefined || value === "") value = null;
    else { value = Number(value); if (!Number.isFinite(value)) return res.status(400).json({ error: "Valeur invalide" }); }

    let headcount = req.body?.headcount;
    headcount = (headcount === null || headcount === undefined || headcount === "") ? null : Math.trunc(Number(headcount));
    if (headcount != null && !Number.isFinite(headcount)) headcount = null;

    const { data: existing, error: readErr } = await supabaseAdmin
      .from("pilotage_monthly_kpis")
      .select("id, absenteeism, overtime, training, headcount")
      .eq("company_id", me.company_id)
      .eq("team_id", teamId)
      .eq("month", month)
      .maybeSingle();
    if (readErr) {
      log.error("❌ pilotage/monthly-kpis read error:", safeError(readErr));
      return res.status(500).json({ error: "Erreur serveur" });
    }

    const row = {
      company_id: me.company_id,
      team_id: teamId,
      month,
      absenteeism: existing ? existing.absenteeism : null,
      overtime: existing ? existing.overtime : null,
      training: existing ? existing.training : null,
      headcount: existing ? existing.headcount : null,
      updated_at: new Date().toISOString(),
    };
    row[kpiKey] = value;
    if (!row.headcount && headcount > 0) row.headcount = headcount; // figé au 1er enregistrement (≥1 ; null OU 0 = effectif pas encore connu → à (re)remplir)

    let result, error;
    if (existing) {
      ({ data: result, error } = await supabaseAdmin
        .from("pilotage_monthly_kpis")
        .update(row)
        .eq("id", existing.id)
        .select("month, absenteeism, overtime, training, headcount")
        .single());
    } else {
      ({ data: result, error } = await supabaseAdmin
        .from("pilotage_monthly_kpis")
        .insert(row)
        .select("month, absenteeism, overtime, training, headcount")
        .single());
    }
    if (error) {
      log.error("❌ pilotage/monthly-kpis write error:", safeError(error));
      return res.status(500).json({ error: "Erreur lors de l'enregistrement" });
    }
    return res.json({ ok: true, item: result });
  } catch (e) {
    log.error("❌ /api/pilotage/monthly-kpis/set:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// =========================================================================
// PILOTAGE — OBJECTIFS (1 par KPI par équipe ; unique(team_id,kpi_key) en base)
// =========================================================================
const PILOTAGE_GOAL_KEYS = ["absenteeism", "overtime", "engagement", "training"];

function sanitizeGoalPayload(body) {
  const out = {};
  if (typeof body.title === "string") out.title = body.title.trim().slice(0, 200);
  if (body.kpi_key !== undefined) out.kpi_key = String(body.kpi_key);
  if (body.target_value !== undefined) {
    const n = Number(body.target_value);
    out.target_value = Number.isFinite(n) ? n : null;
  }
  if (body.deadline !== undefined) {
    out.deadline = (typeof body.deadline === "string" && /^\d{4}-\d{2}-\d{2}$/.test(body.deadline)) ? body.deadline : null;
  }
  if (body.description !== undefined) out.description = String(body.description || "").slice(0, 1000);
  if (body.start_value !== undefined) {
    out.start_value = (body.start_value === null || body.start_value === "") ? null
      : (Number.isFinite(Number(body.start_value)) ? Number(body.start_value) : null);
  }
  if (body.start_week_num !== undefined) {
    const w = (body.start_week_num === null || body.start_week_num === "") ? null : Math.trunc(Number(body.start_week_num));
    out.start_week_num = (w != null && Number.isFinite(w)) ? w : null;
  }
  return out;
}

// Renvoie l'objectif SI il appartient à la company de l'utilisateur ET à une équipe
// qu'il peut atteindre. Sinon null. (On ne fait JAMAIS confiance à l'id seul.)
async function getOwnedGoal(me, goalId) {
  if (!me || !me.company_id) return null;
  if (!/^[0-9a-f-]{36}$/i.test(String(goalId || ""))) return null;
  const { data: g, error } = await supabaseAdmin
    .from("pilotage_goals")
    .select("id, company_id, team_id, kpi_key")
    .eq("id", goalId)
    .maybeSingle();
  if (error || !g || g.company_id !== me.company_id) return null;
  const team = await getAccessibleTeam(me, g.team_id);
  return team ? g : null;
}

app.get("/api/pilotage/goals", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.query.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });
    const { data, error } = await supabaseAdmin
      .from("pilotage_goals")
      .select("id, kpi_key, title, start_value, start_week_num, target_value, deadline, description, created_at")
      .eq("company_id", me.company_id)
      .eq("team_id", teamId)
      .order("created_at", { ascending: true });
    if (error) {
      log.error("❌ pilotage/goals GET:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture des objectifs" });
    }
    return res.json({ items: data || [] });
  } catch (e) {
    log.error("❌ /api/pilotage/goals GET:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/pilotage/goals", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.body?.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });
    const p = sanitizeGoalPayload(req.body || {});
    if (!p.title) return res.status(400).json({ error: "Titre requis" });
    if (!PILOTAGE_GOAL_KEYS.includes(p.kpi_key)) return res.status(400).json({ error: "Indicateur invalide" });
    if (p.target_value == null) return res.status(400).json({ error: "Valeur cible invalide" });

    const { data, error } = await supabaseAdmin
      .from("pilotage_goals")
      .insert({
        company_id: me.company_id,   // forcé serveur
        team_id: teamId,             // forcé serveur (équipe déjà validée)
        kpi_key: p.kpi_key,
        title: p.title,
        target_value: p.target_value,
        deadline: p.deadline ?? null,
        description: p.description ?? null,
        start_value: p.start_value ?? null,
        start_week_num: p.start_week_num ?? null,
        created_by: me.id,
      })
      .select("id, kpi_key, title, start_value, start_week_num, target_value, deadline, description, created_at")
      .single();
    if (error) {
      if (String(error.code) === "23505") return res.status(409).json({ error: "Un objectif existe déjà pour cet indicateur", code: "GOAL_EXISTS" });
      log.error("❌ pilotage/goals POST:", safeError(error));
      return res.status(500).json({ error: "Erreur création de l'objectif" });
    }
    return res.json({ ok: true, item: data });
  } catch (e) {
    log.error("❌ /api/pilotage/goals POST:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.patch("/api/pilotage/goals/:id", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const owned = await getOwnedGoal(me, req.params.id);
    if (!owned) return res.status(404).json({ error: "Objectif introuvable ou non autorisé" });
    const p = sanitizeGoalPayload(req.body || {});
    const update = { updated_at: new Date().toISOString() };
    if (p.title !== undefined) { if (!p.title) return res.status(400).json({ error: "Titre requis" }); update.title = p.title; }
    if (p.kpi_key !== undefined) { if (!PILOTAGE_GOAL_KEYS.includes(p.kpi_key)) return res.status(400).json({ error: "Indicateur invalide" }); update.kpi_key = p.kpi_key; }
    if (p.target_value !== undefined) { if (p.target_value == null) return res.status(400).json({ error: "Valeur cible invalide" }); update.target_value = p.target_value; }
    if (p.deadline !== undefined) update.deadline = p.deadline;
    if (p.description !== undefined) update.description = p.description;
    if (p.start_value !== undefined) update.start_value = p.start_value;
    if (p.start_week_num !== undefined) update.start_week_num = p.start_week_num;

    const { data, error } = await supabaseAdmin
      .from("pilotage_goals")
      .update(update)
      .eq("id", owned.id)
      .select("id, kpi_key, title, start_value, start_week_num, target_value, deadline, description, created_at")
      .single();
    if (error) {
      if (String(error.code) === "23505") return res.status(409).json({ error: "Un objectif existe déjà pour cet indicateur", code: "GOAL_EXISTS" });
      log.error("❌ pilotage/goals PATCH:", safeError(error));
      return res.status(500).json({ error: "Erreur mise à jour de l'objectif" });
    }
    return res.json({ ok: true, item: data });
  } catch (e) {
    log.error("❌ /api/pilotage/goals PATCH:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.delete("/api/pilotage/goals/:id", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const owned = await getOwnedGoal(me, req.params.id);
    if (!owned) return res.status(404).json({ error: "Objectif introuvable ou non autorisé" });
    const { error } = await supabaseAdmin.from("pilotage_goals").delete().eq("id", owned.id);
    if (error) {
      log.error("❌ pilotage/goals DELETE:", safeError(error));
      return res.status(500).json({ error: "Erreur suppression de l'objectif" });
    }
    return res.json({ ok: true });
  } catch (e) {
    log.error("❌ /api/pilotage/goals DELETE:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// =========================================================================
// PILOTAGE — THERMOMÈTRES (climat hebdo : 1 par (équipe, année, semaine))
// =========================================================================
function sanitizeDistribution(d) {
  if (!Array.isArray(d) || d.length !== 10) return null;
  const out = d.map((x) => Math.trunc(Number(x)));
  if (out.some((x) => !Number.isFinite(x) || x < 0)) return null;
  return out;
}

app.get("/api/pilotage/thermometres", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.query.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });
    const { data, error } = await supabaseAdmin
      .from("pilotage_thermometres")
      .select("id, year, week_num, date, participants, distribution, note, is_retroactive, created_at, updated_at")
      .eq("company_id", me.company_id)
      .eq("team_id", teamId)
      .order("year", { ascending: true })
      .order("week_num", { ascending: true });
    if (error) {
      log.error("❌ pilotage/thermometres GET:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture des thermomètres" });
    }
    return res.json({ items: data || [] });
  } catch (e) {
    log.error("❌ /api/pilotage/thermometres GET:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// Upsert d'un thermomètre pour une (année, semaine) — company_id/team_id forcés serveur.
app.post("/api/pilotage/thermometres", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.body?.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });

    const year = Math.trunc(Number(req.body?.year));
    const weekNum = Math.trunc(Number(req.body?.week_num));
    if (!Number.isFinite(year) || year < 2000 || year > 2100) return res.status(400).json({ error: "Année invalide" });
    if (!Number.isFinite(weekNum) || weekNum < 1 || weekNum > 53) return res.status(400).json({ error: "Semaine invalide" });
    const participants = Math.trunc(Number(req.body?.participants));
    if (!Number.isFinite(participants) || participants < 1) return res.status(400).json({ error: "Nombre de participants invalide" });
    const dist = sanitizeDistribution(req.body?.distribution);
    if (!dist) return res.status(400).json({ error: "Répartition invalide (10 entiers ≥ 0 attendus)" });
    const total = dist.reduce((a, b) => a + b, 0);
    if (total < 1) return res.status(400).json({ error: "Au moins une note est requise" });
    if (total > participants) return res.status(400).json({ error: "Le total des réponses dépasse le nombre de participants" });
    const date = (typeof req.body?.date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(req.body.date)) ? req.body.date : null;
    const note = String(req.body?.note || "").slice(0, 2000);
    const isRetro = req.body?.is_retroactive === true;

    const { data: existing, error: readErr } = await supabaseAdmin
      .from("pilotage_thermometres")
      .select("id")
      .eq("company_id", me.company_id)
      .eq("team_id", teamId)
      .eq("year", year)
      .eq("week_num", weekNum)
      .maybeSingle();
    if (readErr) {
      log.error("❌ pilotage/thermometres read:", safeError(readErr));
      return res.status(500).json({ error: "Erreur serveur" });
    }

    const row = {
      company_id: me.company_id, team_id: teamId, year, week_num: weekNum,
      date, participants, distribution: dist, note, is_retroactive: isRetro,
      updated_at: new Date().toISOString(),
    };
    let result, error;
    if (existing) {
      ({ data: result, error } = await supabaseAdmin
        .from("pilotage_thermometres")
        .update(row)
        .eq("id", existing.id)
        .select("id, year, week_num, date, participants, distribution, note, is_retroactive, created_at, updated_at")
        .single());
    } else {
      row.created_by = me.id;
      ({ data: result, error } = await supabaseAdmin
        .from("pilotage_thermometres")
        .insert(row)
        .select("id, year, week_num, date, participants, distribution, note, is_retroactive, created_at, updated_at")
        .single());
    }
    if (error) {
      log.error("❌ pilotage/thermometres write:", safeError(error));
      return res.status(500).json({ error: "Erreur lors de l'enregistrement" });
    }
    return res.json({ ok: true, item: result });
  } catch (e) {
    log.error("❌ /api/pilotage/thermometres POST:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// =========================================================================
// PILOTAGE — ANNOTATIONS (repères posés sur la courbe d'évolution)
// =========================================================================
const PILOTAGE_ANNOTATION_CATS = ["event", "change", "action", "note"];

async function getOwnedAnnotation(me, annId) {
  if (!me || !me.company_id) return null;
  if (!/^[0-9a-f-]{36}$/i.test(String(annId || ""))) return null;
  const { data: a, error } = await supabaseAdmin
    .from("pilotage_annotations")
    .select("id, company_id, team_id")
    .eq("id", annId)
    .maybeSingle();
  if (error || !a || a.company_id !== me.company_id) return null;
  const team = await getAccessibleTeam(me, a.team_id);
  return team ? a : null;
}

function sanitizeAnnotationPayload(body) {
  const out = {};
  if (typeof body.title === "string") out.title = body.title.trim().slice(0, 200);
  if (body.category !== undefined) out.category = String(body.category);
  if (body.kpi_key !== undefined) {
    const k = String(body.kpi_key || "");
    // Annotation liée à UN indicateur (ou null = visible partout). On n'accepte que les vrais KPI.
    out.kpi_key = ["absenteeism", "overtime", "training", "engagement"].includes(k) ? k : null;
  }
  if (body.description !== undefined) out.description = String(body.description || "").slice(0, 2000);
  if (body.author !== undefined) out.author = String(body.author || "").slice(0, 120);
  if (body.year !== undefined) { const y = Math.trunc(Number(body.year)); out.year = Number.isFinite(y) ? y : null; }
  if (body.week_num !== undefined) { const w = Math.trunc(Number(body.week_num)); out.week_num = Number.isFinite(w) ? w : null; }
  return out;
}

app.get("/api/pilotage/annotations", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.query.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });
    const { data, error } = await supabaseAdmin
      .from("pilotage_annotations")
      .select("id, year, week_num, category, kpi_key, title, description, author, created_at")
      .eq("company_id", me.company_id)
      .eq("team_id", teamId)
      .order("created_at", { ascending: true });
    if (error) {
      log.error("❌ pilotage/annotations GET:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture des annotations" });
    }
    return res.json({ items: data || [] });
  } catch (e) {
    log.error("❌ /api/pilotage/annotations GET:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/pilotage/annotations", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.body?.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });
    const p = sanitizeAnnotationPayload(req.body || {});
    if (!p.title) return res.status(400).json({ error: "Titre requis" });
    if (!PILOTAGE_ANNOTATION_CATS.includes(p.category)) return res.status(400).json({ error: "Catégorie invalide" });

    const { data, error } = await supabaseAdmin
      .from("pilotage_annotations")
      .insert({
        company_id: me.company_id,   // forcé serveur
        team_id: teamId,             // forcé serveur (équipe déjà validée)
        year: p.year ?? null,
        week_num: p.week_num ?? null,
        category: p.category,
        kpi_key: p.kpi_key ?? null,   // indicateur lié (null = visible partout)
        title: p.title,
        description: p.description ?? null,
        author: p.author ?? null,
        created_by: me.id,
      })
      .select("id, year, week_num, category, kpi_key, title, description, author, created_at")
      .single();
    if (error) {
      log.error("❌ pilotage/annotations POST:", safeError(error));
      return res.status(500).json({ error: "Erreur création de l'annotation" });
    }
    return res.json({ ok: true, item: data });
  } catch (e) {
    log.error("❌ /api/pilotage/annotations POST:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.patch("/api/pilotage/annotations/:id", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const owned = await getOwnedAnnotation(me, req.params.id);
    if (!owned) return res.status(404).json({ error: "Annotation introuvable ou non autorisée" });
    const p = sanitizeAnnotationPayload(req.body || {});
    const update = { updated_at: new Date().toISOString() };
    if (p.title !== undefined) { if (!p.title) return res.status(400).json({ error: "Titre requis" }); update.title = p.title; }
    if (p.category !== undefined) { if (!PILOTAGE_ANNOTATION_CATS.includes(p.category)) return res.status(400).json({ error: "Catégorie invalide" }); update.category = p.category; }
    if (p.description !== undefined) update.description = p.description;
    if (p.year !== undefined) update.year = p.year;
    if (p.week_num !== undefined) update.week_num = p.week_num;

    const { data, error } = await supabaseAdmin
      .from("pilotage_annotations")
      .update(update)
      .eq("id", owned.id)
      .select("id, year, week_num, category, kpi_key, title, description, author, created_at")
      .single();
    if (error) {
      log.error("❌ pilotage/annotations PATCH:", safeError(error));
      return res.status(500).json({ error: "Erreur mise à jour de l'annotation" });
    }
    return res.json({ ok: true, item: data });
  } catch (e) {
    log.error("❌ /api/pilotage/annotations PATCH:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.delete("/api/pilotage/annotations/:id", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const owned = await getOwnedAnnotation(me, req.params.id);
    if (!owned) return res.status(404).json({ error: "Annotation introuvable ou non autorisée" });
    const { error } = await supabaseAdmin.from("pilotage_annotations").delete().eq("id", owned.id);
    if (error) {
      log.error("❌ pilotage/annotations DELETE:", safeError(error));
      return res.status(500).json({ error: "Erreur suppression de l'annotation" });
    }
    return res.json({ ok: true });
  } catch (e) {
    log.error("❌ /api/pilotage/annotations DELETE:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// =========================================================================
// PILOTAGE — COLLABORATEURS (modèle DOCUMENT : 1 collaborateur = 1 ligne JSONB)
// L'objet complet (personne + notes + entretiens + points à suivre) vit dans
// la colonne `data`. Isolation : company_id + team_id forcés serveur + RLS.
// =========================================================================
const UUID_RX = /^[0-9a-f-]{36}$/i;

app.get("/api/pilotage/collaborators", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.query.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });
    const { data, error } = await supabaseAdmin
      .from("pilotage_collaborators")
      .select("id, data")
      .eq("company_id", me.company_id)
      .eq("team_id", teamId)
      .order("created_at", { ascending: true });
    if (error) {
      log.error("❌ pilotage/collaborators GET:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture des collaborateurs" });
    }
    return res.json({ items: data || [] });
  } catch (e) {
    log.error("❌ /api/pilotage/collaborators GET:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// ============================================================
// FUSION JSONB PAR IDENTIFIANT (multi-utilisateurs sans perte) — testée (scratchpad/merge_test.js)
//  - Ajouts de plusieurs comptes → coexistent (union par clé id / at / createdAt)
//  - Modif du même élément → la plus récente gagne (editedAt/updatedAt/at)
//  - Suppression → soft-delete (_del:true + horodatage) : se résout par la même fusion,
//    impossible à ressusciter par un onglet périmé. (Purge des _del anciens : à prévoir.)
// ============================================================
function _pilKey(it) {
  if (!it || typeof it !== "object") return null;
  if (it.id != null) return "id:" + it.id;
  if (it._uid != null) return "u:" + it._uid;     // entretiens (clé interne)
  if (it.at != null) return "at:" + it.at;
  if (it.createdAt != null) return "ct:" + it.createdAt;
  return null;
}
function _pilTime(it) {
  // Récence = le PLUS RÉCENT de tous les horodatages connus (édition, statut, archivage…).
  // => un changement de statut/archive (qui ne bump pas updatedAt) est quand même vu comme "récent"
  //    par la fusion, sans toucher au libellé "Modifié le" des cartes (qui, lui, lit updatedAt).
  if (!it || typeof it !== "object") return "";
  let t = "";
  for (const k of ["editedAt", "updatedAt", "lastActivityAt", "archivedAt", "at", "createdAt"]) {
    const v = it[k];
    if (typeof v === "string" && v > t) t = v;
  }
  return t;
}
function pilMergeJson(base, inc) {
  if (Array.isArray(base) && Array.isArray(inc)) {
    const all = base.concat(inc);
    const hasKeys = all.some((it) => _pilKey(it) != null);
    if (!hasKeys) {
      const allPrim = all.every((x) => x == null || typeof x !== "object");
      return allPrim ? [...new Set(all)] : inc;
    }
    const out = [];
    const pos = new Map();
    const put = (it) => {
      const k = _pilKey(it);
      if (k == null) { out.push(it); return; }
      if (pos.has(k)) out[pos.get(k)] = pilMergeJson(out[pos.get(k)], it);
      else { pos.set(k, out.length); out.push(it); }
    };
    base.forEach(put); inc.forEach(put);
    return out;
  }
  if (base && inc && typeof base === "object" && typeof inc === "object" && !Array.isArray(base) && !Array.isArray(inc)) {
    const incNewer = _pilTime(inc) >= _pilTime(base);
    const out = {};
    for (const k of new Set([...Object.keys(base), ...Object.keys(inc)])) {
      const a = base[k], b = inc[k];
      if (a !== undefined && b !== undefined) {
        if (a && typeof a === "object" && b && typeof b === "object") out[k] = pilMergeJson(a, b);
        else out[k] = incNewer ? b : a;
      } else {
        out[k] = (b !== undefined) ? b : a;
      }
    }
    return out;
  }
  return (inc !== undefined) ? inc : base;
}

// Synchronise l'ÉTAT COMPLET des collaborateurs d'une équipe : FUSIONNE chaque fiche
// avec sa version en base (par id), supprime ceux disparus. company_id/team_id FORCÉS serveur.
app.post("/api/pilotage/collaborators/sync", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.body?.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });

    const members = Array.isArray(req.body?.members) ? req.body.members : null;
    if (!members) return res.status(400).json({ error: "Liste de collaborateurs invalide" });
    if (members.length > 500) return res.status(400).json({ error: "Trop de collaborateurs" });
    for (const m of members) {
      if (!m || typeof m !== "object" || !UUID_RX.test(String(m.id || ""))) {
        return res.status(400).json({ error: "Identifiant de collaborateur invalide" });
      }
      // Borne la taille de CHAQUE fiche (le maxlength HTML est seulement côté client).
      // 64 ko : marge pour la fusion + historique + soft-delete (purge des _del anciens à prévoir).
      if (JSON.stringify(m).length > 65536) {
        return res.status(400).json({ error: "Fiche collaborateur trop volumineuse" });
      }
    }
    const keepIds = members.map((m) => String(m.id));

    // On récupère la version ACTUELLE de chaque fiche (pour FUSIONNER au lieu d'écraser),
    // ET 🔒 CYBER : aucun id du payload ne doit appartenir à une AUTRE entreprise/équipe
    // (sinon un client malveillant pourrait écraser/voler la ligne d'un autre tenant).
    const existingById = new Map();   // id → data jsonb en base
    if (keepIds.length) {
      const { data: clash, error: clashErr } = await supabaseAdmin
        .from("pilotage_collaborators")
        .select("id, company_id, team_id, data")
        .in("id", keepIds);
      if (clashErr) {
        log.error("❌ collaborators sync clash check:", safeError(clashErr));
        return res.status(500).json({ error: "Erreur serveur" });
      }
      const hijack = (clash || []).some((r) => r.company_id !== me.company_id || r.team_id !== teamId);
      if (hijack) return res.status(403).json({ error: "Conflit d'identifiants" });
      for (const r of (clash || [])) existingById.set(String(r.id), r.data);
    }

    const rows = members.map((m) => {
      const prev = existingById.get(String(m.id));
      // FUSION par id si la fiche existe déjà → les ajouts des autres comptes ne sont pas écrasés.
      const data = prev ? pilMergeJson(prev, m) : m;
      return {
        id: String(m.id),
        company_id: me.company_id,   // forcé serveur
        team_id: teamId,             // forcé serveur
        name: (String((data && data.name) || m.name || "").slice(0, 200) || "—"),
        data,                        // objet collaborateur fusionné
        updated_at: new Date().toISOString(),
      };
    });

    if (rows.length) {
      const { error: upErr } = await supabaseAdmin
        .from("pilotage_collaborators")
        .upsert(rows, { onConflict: "id" });
      if (upErr) {
        log.error("❌ collaborators sync upsert:", safeError(upErr));
        return res.status(500).json({ error: "Erreur d'enregistrement" });
      }
    }

    // CONCURRENCE : on ne supprime QUE ce qui a été explicitement supprimé côté client
    // (deleted_ids), JAMAIS "ce qui manque" — sinon on écraserait un ajout fait entre-temps
    // par un autre utilisateur de la même équipe. Suppression scopée company+team (cyber).
    let delIds = Array.isArray(req.body?.deleted_ids) ? req.body.deleted_ids.map((x) => String(x)).filter((x) => UUID_RX.test(x)) : [];
    delIds = [...new Set(delIds)];
    if (delIds.length) {
      const { error: delErr } = await supabaseAdmin
        .from("pilotage_collaborators")
        .delete()
        .eq("company_id", me.company_id)
        .eq("team_id", teamId)
        .in("id", delIds);
      if (delErr) {
        log.error("❌ collaborators sync delete:", safeError(delErr));
        return res.status(500).json({ error: "Erreur de synchronisation" });
      }
    }

    return res.json({ ok: true, count: rows.length });
  } catch (e) {
    log.error("❌ /api/pilotage/collaborators/sync:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// =========================================================================
// PILOTAGE — JOURNAL D'ÉQUIPE (modèle DOCUMENT : 1 entrée = 1 ligne JSONB)
// Par équipe. Isolation : company_id + team_id forcés serveur + RLS.
// =========================================================================
app.get("/api/pilotage/journal", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.query.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });
    const { data, error } = await supabaseAdmin
      .from("pilotage_journal")
      .select("id, data")
      .eq("company_id", me.company_id)
      .eq("team_id", teamId)
      .order("created_at", { ascending: true });
    if (error) {
      log.error("❌ pilotage/journal GET:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture du journal" });
    }
    return res.json({ items: data || [] });
  } catch (e) {
    log.error("❌ /api/pilotage/journal GET:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

app.post("/api/pilotage/journal/sync", authenticateToken, async (req, res) => {
  try {
    const me = req.user;
    const teamId = String(req.body?.team_id || "");
    const team = await getAccessibleTeam(me, teamId);
    if (!team) return res.status(404).json({ error: "Équipe introuvable ou non autorisée" });

    const entries = Array.isArray(req.body?.entries) ? req.body.entries : null;
    if (!entries) return res.status(400).json({ error: "Liste d'entrées invalide" });
    if (entries.length > 5000) return res.status(400).json({ error: "Trop d'entrées" });
    for (const e of entries) {
      if (!e || typeof e !== "object" || !UUID_RX.test(String(e.id || ""))) {
        return res.status(400).json({ error: "Identifiant d'entrée invalide" });
      }
      // Borne la taille de CHAQUE entrée (le maxlength HTML est seulement côté client).
      // 32 ko : marge pour la fusion (suivis multi-comptes) + soft-delete.
      if (JSON.stringify(e).length > 32768) {
        return res.status(400).json({ error: "Entrée de journal trop volumineuse" });
      }
    }
    const keepIds = entries.map((e) => String(e.id));

    // Fusion multi-utilisateurs : version ACTUELLE de chaque entrée (pour fusionner au lieu d'écraser),
    // ET 🔒 CYBER : aucun id du payload ne doit appartenir à une autre entreprise/équipe.
    const existingById = new Map();   // id → data jsonb en base
    if (keepIds.length) {
      const { data: clash, error: clashErr } = await supabaseAdmin
        .from("pilotage_journal")
        .select("id, company_id, team_id, data")
        .in("id", keepIds);
      if (clashErr) {
        log.error("❌ journal sync clash check:", safeError(clashErr));
        return res.status(500).json({ error: "Erreur serveur" });
      }
      const hijack = (clash || []).some((r) => r.company_id !== me.company_id || r.team_id !== teamId);
      if (hijack) return res.status(403).json({ error: "Conflit d'identifiants" });
      for (const r of (clash || [])) existingById.set(String(r.id), r.data);
    }

    const rows = entries.map((e) => {
      const prev = existingById.get(String(e.id));
      // FUSION par id si l'entrée existe déjà → suivis ajoutés par d'autres comptes non écrasés.
      const data = prev ? pilMergeJson(prev, e) : e;
      return {
        id: String(e.id),
        company_id: me.company_id,   // forcé serveur
        team_id: teamId,             // forcé serveur
        data,
        updated_at: new Date().toISOString(),
      };
    });

    if (rows.length) {
      const { error: upErr } = await supabaseAdmin
        .from("pilotage_journal")
        .upsert(rows, { onConflict: "id" });
      if (upErr) {
        log.error("❌ journal sync upsert:", safeError(upErr));
        return res.status(500).json({ error: "Erreur d'enregistrement" });
      }
    }

    // CONCURRENCE : suppressions EXPLICITES uniquement (deleted_ids), jamais "ce qui manque".
    let delIds = Array.isArray(req.body?.deleted_ids) ? req.body.deleted_ids.map((x) => String(x)).filter((x) => UUID_RX.test(x)) : [];
    delIds = [...new Set(delIds)];
    if (delIds.length) {
      const { error: delErr } = await supabaseAdmin
        .from("pilotage_journal")
        .delete()
        .eq("company_id", me.company_id)
        .eq("team_id", teamId)
        .in("id", delIds);
      if (delErr) {
        log.error("❌ journal sync delete:", safeError(delErr));
        return res.status(500).json({ error: "Erreur de synchronisation" });
      }
    }

    return res.json({ ok: true, count: rows.length });
  } catch (e) {
    log.error("❌ /api/pilotage/journal/sync:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Créer une équipe ---
app.post("/api/teams", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;
    if (!me.company_id) {
      return res.status(400).json({ error: "Aucune entreprise rattachée au compte", code: "NO_COMPANY" });
    }

    const name = String(req.body?.name || "").trim();
    if (!name) return res.status(400).json({ error: "Le nom de l'équipe est requis" });
    if (name.length > TEAM_NAME_MAX) {
      return res.status(400).json({ error: `Nom trop long (${TEAM_NAME_MAX} caractères maximum)` });
    }

    // Pas deux équipes actives du même nom dans l'entreprise
    const { data: existing, error: existErr } = await supabaseAdmin
      .from("teams")
      .select("id")
      .eq("company_id", me.company_id)
      .is("archived_at", null)
      .ilike("name", name)
      .maybeSingle();
    if (existErr) {
      log.error("❌ teams create check error:", safeError(existErr));
      return res.status(500).json({ error: "Erreur serveur" });
    }
    if (existing) {
      return res.status(409).json({ error: "Une équipe porte déjà ce nom", code: "NAME_TAKEN" });
    }

    const { data: team, error } = await supabaseAdmin
      .from("teams")
      .insert({
        company_id: me.company_id,
        name,
        color: sanitizeTeamColor(req.body?.color),
        created_by: me.id,
      })
      .select("id, name, color, created_at, archived_at")
      .single();

    if (error) {
      log.error("❌ teams create error:", safeError(error));
      return res.status(500).json({ error: "Erreur création de l'équipe" });
    }
    return res.json({ ok: true, team });
  } catch (e) {
    log.error("❌ /api/teams POST:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Renommer une équipe ---
app.patch("/api/teams/:id", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;

    const teamId = String(req.params.id || "");
    if (!/^[0-9a-f-]{36}$/i.test(teamId)) {
      return res.status(400).json({ error: "Identifiant invalide" });
    }
    const name = String(req.body?.name || "").trim();
    if (!name) return res.status(400).json({ error: "Le nom de l'équipe est requis" });
    if (name.length > TEAM_NAME_MAX) {
      return res.status(400).json({ error: `Nom trop long (${TEAM_NAME_MAX} caractères maximum)` });
    }

    // L'équipe doit appartenir à MON entreprise
    const { data: team, error: tErr } = await supabaseAdmin
      .from("teams")
      .select("id, company_id")
      .eq("id", teamId)
      .maybeSingle();
    if (tErr) return res.status(500).json({ error: "Erreur lecture de l'équipe" });
    if (!team || team.company_id !== me.company_id) {
      return res.status(404).json({ error: "Équipe introuvable dans votre entreprise" });
    }

    // Couleur = donnée partagée entreprise : on la met à jour si le client l'envoie.
    const updatePatch = { name, updated_at: new Date().toISOString() };
    if (req.body && Object.prototype.hasOwnProperty.call(req.body, "color")) {
      updatePatch.color = sanitizeTeamColor(req.body.color);
    }
    const { data: updated, error } = await supabaseAdmin
      .from("teams")
      .update(updatePatch)
      .eq("id", teamId)
      .select("id, name, color, created_at, archived_at")
      .single();
    if (error) {
      log.error("❌ teams rename error:", safeError(error));
      return res.status(500).json({ error: "Erreur lors du renommage" });
    }
    logTechAction({ companyId: me.company_id, teamId: teamId, actorUserId: me.id, action: 'team_renamed' });
    return res.json({ ok: true, team: updated });
  } catch (e) {
    log.error("❌ /api/teams PATCH:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Archiver une équipe (jamais de suppression brutale) ---
app.post("/api/teams/:id/archive", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;

    const teamId = String(req.params.id || "");
    if (!/^[0-9a-f-]{36}$/i.test(teamId)) {
      return res.status(400).json({ error: "Identifiant invalide" });
    }

    const { data: team, error: tErr } = await supabaseAdmin
      .from("teams")
      .select("id, company_id, archived_at")
      .eq("id", teamId)
      .maybeSingle();
    if (tErr) return res.status(500).json({ error: "Erreur lecture de l'équipe" });
    if (!team || team.company_id !== me.company_id) {
      return res.status(404).json({ error: "Équipe introuvable dans votre entreprise" });
    }

    const { error } = await supabaseAdmin
      .from("teams")
      .update({ archived_at: new Date().toISOString(), updated_at: new Date().toISOString() })
      .eq("id", teamId);
    if (error) {
      log.error("❌ teams archive error:", safeError(error));
      return res.status(500).json({ error: "Erreur lors de l'archivage" });
    }
    return res.json({ ok: true });
  } catch (e) {
    log.error("❌ /api/teams archive:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Réactiver une équipe archivée (miroir de l'archivage) ---
app.post("/api/teams/:id/restore", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;

    const teamId = String(req.params.id || "");
    if (!/^[0-9a-f-]{36}$/i.test(teamId)) {
      return res.status(400).json({ error: "Identifiant invalide" });
    }

    const { data: team, error: tErr } = await supabaseAdmin
      .from("teams")
      .select("id, company_id, archived_at")
      .eq("id", teamId)
      .maybeSingle();
    if (tErr) return res.status(500).json({ error: "Erreur lecture de l'équipe" });
    if (!team || team.company_id !== me.company_id) {
      return res.status(404).json({ error: "Équipe introuvable dans votre entreprise" });
    }

    const { error } = await supabaseAdmin
      .from("teams")
      .update({ archived_at: null, updated_at: new Date().toISOString() })
      .eq("id", teamId);
    if (error) {
      log.error("❌ teams restore error:", safeError(error));
      return res.status(500).json({ error: "Erreur lors de la réactivation" });
    }
    return res.json({ ok: true });
  } catch (e) {
    log.error("❌ /api/teams restore:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Supprimer DÉFINITIVEMENT une équipe ARCHIVÉE (+ toutes ses données, en cascade) ---
// Irréversible. company_id forcé. Les tables pilotage_* ont team_id ON DELETE CASCADE
// → supprimer la ligne de l'équipe efface automatiquement tout son contenu.
app.delete("/api/teams/:id", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;

    const teamId = String(req.params.id || "");
    if (!/^[0-9a-f-]{36}$/i.test(teamId)) return res.status(400).json({ error: "Identifiant invalide" });

    const { data: team, error: tErr } = await supabaseAdmin
      .from("teams")
      .select("id, company_id, archived_at")
      .eq("id", teamId)
      .maybeSingle();
    if (tErr) return res.status(500).json({ error: "Erreur lecture de l'équipe" });
    if (!team || team.company_id !== me.company_id) {
      return res.status(404).json({ error: "Équipe introuvable dans votre entreprise" });
    }
    // Garde-fou : suppression définitive UNIQUEMENT sur une équipe déjà archivée (2 étapes).
    if (!team.archived_at) {
      return res.status(409).json({ error: "Archivez l'équipe avant de la supprimer définitivement", code: "NOT_ARCHIVED" });
    }

    // Retire d'abord les accès membres (au cas où team_members n'aurait pas ON DELETE CASCADE).
    await supabaseAdmin.from("team_members").delete().eq("company_id", me.company_id).eq("team_id", teamId);

    // Supprime l'équipe → cascade sur pilotage_* (collaborateurs, KPI, thermos, objectifs, annotations, journal).
    const { error: delErr } = await supabaseAdmin
      .from("teams")
      .delete()
      .eq("id", teamId)
      .eq("company_id", me.company_id);   // double garde cyber
    if (delErr) {
      log.error("❌ teams delete-perm:", safeError(delErr));
      return res.status(500).json({ error: "Erreur lors de la suppression" });
    }
    return res.json({ ok: true });
  } catch (e) {
    log.error("❌ /api/teams DELETE:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Lister les membres d'une équipe ---
app.get("/api/teams/:id/members", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;
    const teamId = String(req.params.id || "");
    if (!/^[0-9a-f-]{36}$/i.test(teamId)) {
      return res.status(400).json({ error: "Identifiant invalide" });
    }

    // L'équipe doit appartenir à MON entreprise
    const { data: team, error: tErr } = await supabaseAdmin
      .from("teams").select("id, company_id").eq("id", teamId).maybeSingle();
    if (tErr) return res.status(500).json({ error: "Erreur lecture de l'équipe" });
    if (!team || team.company_id !== me.company_id) {
      return res.status(404).json({ error: "Équipe introuvable dans votre entreprise" });
    }

    const { data: links, error } = await supabaseAdmin
      .from("team_members")
      .select("user_id, created_at")
      .eq("team_id", teamId)
      .order("created_at", { ascending: true });
    if (error) {
      log.error("❌ team members list error:", safeError(error));
      return res.status(500).json({ error: "Erreur lecture des membres" });
    }

    // Compléter avec prénom/nom (profiles)
    const userIds = (links || []).map((l) => l.user_id);
    const profilesById = {};
    if (userIds.length) {
      const { data: profs } = await supabaseAdmin
        .from("profiles").select("user_id, first_name, last_name").in("user_id", userIds);
      (profs || []).forEach((p) => { profilesById[p.user_id] = p; });
    }
    const members = (links || []).map((l) => ({
      user_id: l.user_id,
      first_name: profilesById[l.user_id]?.first_name || null,
      last_name: profilesById[l.user_id]?.last_name || null,
    }));
    return res.json({ members });
  } catch (e) {
    log.error("❌ /api/teams/:id/members GET:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Ajouter un membre à une équipe ---
app.post("/api/teams/:id/members", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;
    const teamId = String(req.params.id || "");
    const targetId = String(req.body?.user_id || "");
    if (!/^[0-9a-f-]{36}$/i.test(teamId) || !/^[0-9a-f-]{36}$/i.test(targetId)) {
      return res.status(400).json({ error: "Identifiant invalide" });
    }

    // L'équipe doit être à MON entreprise (et active)
    const { data: team, error: tErr } = await supabaseAdmin
      .from("teams").select("id, company_id, archived_at").eq("id", teamId).maybeSingle();
    if (tErr) return res.status(500).json({ error: "Erreur lecture de l'équipe" });
    if (!team || team.company_id !== me.company_id) {
      return res.status(404).json({ error: "Équipe introuvable dans votre entreprise" });
    }
    if (team.archived_at) {
      return res.status(409).json({ error: "Cette équipe est archivée" });
    }

    // La cible doit être un MEMBRE de MON entreprise
    const { data: target, error: pErr } = await supabaseAdmin
      .from("profiles").select("user_id, company_id, role").eq("user_id", targetId).maybeSingle();
    if (pErr) return res.status(500).json({ error: "Erreur lecture du membre" });
    if (!target || target.company_id !== me.company_id || target.role !== 'membre') {
      return res.status(404).json({ error: "Membre introuvable dans votre entreprise" });
    }

    const { error } = await supabaseAdmin
      .from("team_members")
      .insert({ team_id: teamId, user_id: targetId, company_id: me.company_id, created_by: me.id });
    if (error) {
      // 23505 = déjà dans l'équipe (contrainte d'unicité) -> on considère OK
      if (String(error.code) === "23505") {
        return res.json({ ok: true, already: true });
      }
      log.error("❌ team member add error:", safeError(error));
      return res.status(500).json({ error: "Erreur lors de l'ajout à l'équipe" });
    }
    return res.json({ ok: true });
  } catch (e) {
    log.error("❌ /api/teams/:id/members POST:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// --- Retirer un membre d'une équipe (supprime le lien d'accès, pas la personne) ---
app.delete("/api/teams/:id/members/:userId", authenticateToken, async (req, res) => {
  try {
    const me = requireCompanyAdmin(req, res);
    if (!me) return;
    const teamId = String(req.params.id || "");
    const targetId = String(req.params.userId || "");
    if (!/^[0-9a-f-]{36}$/i.test(teamId) || !/^[0-9a-f-]{36}$/i.test(targetId)) {
      return res.status(400).json({ error: "Identifiant invalide" });
    }

    // L'équipe doit être à MON entreprise
    const { data: team, error: tErr } = await supabaseAdmin
      .from("teams").select("id, company_id").eq("id", teamId).maybeSingle();
    if (tErr) return res.status(500).json({ error: "Erreur lecture de l'équipe" });
    if (!team || team.company_id !== me.company_id) {
      return res.status(404).json({ error: "Équipe introuvable dans votre entreprise" });
    }

    const { error } = await supabaseAdmin
      .from("team_members").delete().eq("team_id", teamId).eq("user_id", targetId);
    if (error) {
      log.error("❌ team member remove error:", safeError(error));
      return res.status(500).json({ error: "Erreur lors du retrait de l'équipe" });
    }
    return res.json({ ok: true });
  } catch (e) {
    log.error("❌ /api/teams/:id/members DELETE:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});


app.post("/api/start-trial-invite", async (req, res) => {


  try {
    const emailNorm = normalizeEmail(req.body?.email);
    if (!emailNorm) return res.status(400).json({ error: "email requis" });
    if (!isValidEmail(emailNorm)) return res.status(400).json({ error: "email invalide" });
    if (emailNorm.length > 254) return res.status(400).json({ error: "email trop long" });

    // ✅ IMPORTANT : si l'email existe déjà, on NE doit PAS créer une session Stripe
    // -> même comportement que TRIAL : message générique côté front
    const alreadyExists = await authEmailExists(emailNorm);
    if (alreadyExists) {
      return res.status(409).json({ error: "ACCOUNT_EXISTS" });
    }

    // ✅ CGUV obligatoires (preuve juridique côté serveur)
    const termsAccepted = req.body?.termsAccepted === true;
    const termsVersionRaw = String(req.body?.termsVersion || "").trim();

    if (!termsAccepted) {
      return res.status(400).json({ error: "TERMS_REQUIRED" });
    }

    if (!termsVersionRaw) {
      return res.status(400).json({ error: "terms_version manquante" });
    }

    // [15 mai 2026] Accepte le format DD_MM_YYYY (ex: "14_05_2026") qui est le
    // format actuel de CURRENT_TERMS_VERSION. L'ancien format YYYY-MM-DD est
    // aussi accepte pour retrocompat (au cas ou des comptes legacy l'utilisent).
    if (!/^(\d{2}_\d{2}_\d{4}|\d{4}-\d{2}-\d{2})$/.test(termsVersionRaw)) {
      return res.status(400).json({ error: "terms_version invalide" });
    }

    // ✅ même verrouillage que la route payante
    if (termsVersionRaw !== CURRENT_TERMS_VERSION) {
      return res.status(400).json({ error: "terms_version non supportée" });
    }

    const termsVersion = termsVersionRaw;



    const first_name = cleanPersonName(req.body?.first_name, { max: 50 });
    const last_name = cleanPersonName(req.body?.last_name, { max: 50 });
    const company_name = cleanTextStrict(req.body?.company_name, { max: 120, allowEmpty: false });
    const company_size = String(req.body?.company_size || "").trim();

    if (!first_name || first_name.length < 2) return res.status(400).json({ error: "first_name invalide" });
    if (!last_name || last_name.length < 2) return res.status(400).json({ error: "last_name invalide" });
    if (!company_name || company_name.length < 2) return res.status(400).json({ error: "company_name invalide" });
    if (!ALLOWED_COMPANY_SIZES.has(company_size)) return res.status(400).json({ error: "company_size invalide" });

    const desired_plan = "trial";


    // 1) pending (réutiliser si déjà existant)
    let pending_id = null;

    // 1a) chercher un pending existant (évite l'erreur de contrainte unique)
    const { data: existingPending, error: existingErr } = await supabaseAdmin
      .from("pending_signups")
      .select("id, first_name, last_name, company_name, company_size, status")
      .eq("email", emailNorm)
      .in("status", ["pending", "invited"])
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (existingErr) {
      log.error("❌ pending_signups select error:", existingErr);
      return res.status(500).json({
        error: "Erreur lecture pending_signups", details: safeDetails(existingErr)
      });
    }

    if (existingPending) {
      pending_id = existingPending.id;

      // 1b) update (optionnel mais propre : tu mets à jour les infos si elles ont changé)
      const { error: updErr } = await supabaseAdmin
        .from("pending_signups")
        .update({
          first_name: first_name ?? existingPending.first_name,
          last_name: last_name ?? existingPending.last_name,
          company_name: company_name ?? existingPending.company_name,
          company_size: company_size ?? existingPending.company_size,
          desired_plan: "trial",
          status: "pending",
          terms_accepted_at: new Date().toISOString(),
          terms_version: termsVersion,
          updated_at: new Date().toISOString()
        })
        .eq("id", pending_id);

      if (updErr) {
        log.error("❌ pending_signups update error:", updErr);
        return res.status(500).json({
          error: "Erreur update pending_signup trial", details: safeDetails(updErr)
        });
      }

    } else {
      // 1c) sinon : insert normal
      const { data: pending, error: pendingErr } = await supabaseAdmin
        .from("pending_signups")
        .insert([{
          email: emailNorm,
          first_name,
          last_name,
          company_name,
          company_size,
          desired_plan: "trial",
          status: "pending",
          terms_accepted_at: new Date().toISOString(),
          terms_version: termsVersion,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }])
        .select("id")
        .single();

      if (pendingErr || !pending) {
        log.error("❌ pending_signups insert error:", pendingErr);
        return res.status(500).json({
          error: "Impossible de créer pending_signup trial",
          details: safeDetails(pendingErr)
        });
      }

      pending_id = pending.id;
    }


    // ✅ Alerte commerciale : trial 50+ collaborateurs
    //    Notre equipe doit contacter ce prospect pendant les 7 jours d'essai
    //    pour preparer un devis personnalise (Option C : pas de checkout
    //    self-service pour 50+, mais essai gratuit accessible).
    if (company_size === "50+") {
      try {
        const subjectMail = `🚨 Nouveau trial 50+ — ${company_name}`;
        const htmlAlert = `
          <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#1a1a1a;font-size:15px;line-height:1.6;">
            <h2 style="margin:0 0 16px 0;font-size:18px;font-weight:700;">Nouveau trial pour effectif 50+ collaborateurs</h2>
            <p>Un prospect avec un effectif <strong>50 collaborateurs ou plus</strong> vient de demarrer un essai gratuit.</p>
            <p>Action recommandee : <strong>contacter ce prospect rapidement</strong> pendant les 7 jours d'essai pour preparer un devis personnalise.</p>
            <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:16px 0;">
              <p style="margin:0 0 6px 0;"><strong>Client :</strong> ${escapeHtml(first_name)} ${escapeHtml(last_name)}</p>
              <p style="margin:0 0 6px 0;"><strong>Email :</strong> ${escapeHtml(emailNorm)}</p>
              <p style="margin:0 0 6px 0;"><strong>Entreprise :</strong> ${escapeHtml(company_name)}</p>
              <p style="margin:0;"><strong>Effectif declare :</strong> 50 collaborateurs ou plus</p>
            </div>
            <p style="font-size:13px;color:#64748b;margin-top:24px;">
              Pending ID : <code>${pending_id}</code><br/>
              Recu le ${new Date().toLocaleString("fr-FR")}
            </p>
          </div>
        `;
        await sendResendEmail({
          // [16 mai 2026] Destinataires internes : uniquement mehdi.joalland (compte solo).
          to: ["mehdi.joalland@integora.fr"],
          subject: subjectMail,
          html: htmlAlert,
        });
        log.info(`📧 Alerte trial 50+ envoyee pour ${company_name}`);
      } catch (alertErr) {
        log.warn("⚠️ Trial 50+ alert email failed:", safeError(alertErr));
      }
    }


    // [15 mai 2026] Notification interne (contact@ + mehdi.joalland@)
    // a chaque nouvelle inscription trial. Non-bloquant.
    sendAdminSignupNotification({
      first_name,
      last_name,
      email: emailNorm,
      company_name,
      company_size,
      desired_plan: "trial",
    });

    // 2) invite email
    const FRONT = FRONTEND_URL;
    const redirectTo = `${FRONT}/welcome.html?pending_id=${pending_id}`;

    const { data: inviteData, error: inviteErr } =
      await supabaseAdmin.auth.admin.inviteUserByEmail(emailNorm, {
        redirectTo,
        data: {
          first_name,
          last_name,
          company_name,
          company_size,
          plan: "trial",
          pending_id
        }
      });

    if (inviteErr) {
      const msg = String(inviteErr.message || "");
      log.error("❌ inviteUserByEmail error:", safeError(inviteErr));

      if (msg.toLowerCase().includes("already been registered")) {
        const FRONT = FRONTEND_URL;
        const redirectTo = `${FRONT}/create-password.html?pending_id=${pending_id}`;

        const { data: linkData, error: linkErr } =
          await supabaseAdmin.auth.admin.generateLink({
            type: "recovery",
            email: emailNorm, // ou pending.email selon la route
            options: { redirectTo },
          });

        if (linkErr) return res.status(500).json({ error: linkErr.message });

        const setPasswordLink =
          linkData?.properties?.action_link ||
          linkData?.properties?.actionLink ||
          null;

        if (!setPasswordLink) {
          return res.status(500).json({ error: "Missing set_password_link" });
        }

        if (!devToolsAllowed(req)) {
          return res.json({ ok: true, account_exists: true });
        }

        return res.json({
          ok: true,
          account_exists: true,
          set_password_link: setPasswordLink,
        });

      }

      return res.status(409).json({ error: msg });
    }


    const user_id = inviteData?.user?.id || null;



    await supabaseAdmin
      .from("pending_signups")
      .update({ status: "invited", user_id })
      .eq("id", pending_id);

    return res.json({
      ok: true,
      invited: true,
      pending_id,
      user_id
    });

  } catch (e) {
    log.error("❌ [TRIAL] error:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});


app.post("/api/resend-activation", async (req, res) => {
  try {
    const { pending_id } = req.body;
    if (!pending_id) return res.status(400).json({ error: "pending_id requis" });

    const { data: pending, error: pendingErr } = await supabaseAdmin
      .from("pending_signups")
      .select("*")
      .eq("id", pending_id)
      .single();

    if (pendingErr || !pending) return res.status(404).json({ error: "pending introuvable" });

    const FRONT = FRONTEND_URL;
    const redirectTo = `${FRONT}/welcome.html?pending_id=${pending_id}`;

    const { data: inviteData, error: inviteErr } =
      await supabaseAdmin.auth.admin.inviteUserByEmail(pending.email, {
        redirectTo,
        data: {
          first_name: pending.first_name,
          last_name: pending.last_name,
          company_name: pending.company_name,
          company_size: pending.company_size,
          plan: pending.desired_plan,
          pending_id
        }
      });

    if (inviteErr) {
      const msg = String(inviteErr.message || "");

      // ✅ Cas : user déjà créé
      if (msg.toLowerCase().includes("already been registered")) {
        const FRONT = FRONTEND_URL;

        // Si le compte n'est PAS encore finalisé → indiquer d'utiliser le bouton d'activation directe
        if (pending.status !== "activated") {
          // ✅ SÉCURITÉ : ne plus renvoyer le magic link en JSON
          // L'utilisateur peut utiliser le bouton "Activer sans email" (GET /api/direct-activate)
          return res.json({ ok: true, use_direct_activate: true });
        }

        // Si le compte EST déjà activé → juste informer l'utilisateur
        return res.json({ ok: true, already_activated: true });

      }

      // autres erreurs -> on garde 409
      return res.status(409).json({ error: msg });
    }


    const user_id = inviteData?.user?.id || pending.user_id || null;


    await supabaseAdmin
      .from("pending_signups")
      .update({ status: "invited", user_id })
      .eq("id", pending_id);

    return res.json({ ok: true, resent: true });

  } catch (e) {
    return res.status(500).json({ error: "Erreur serveur" });
  }
});


// ---------------------------
// Activation directe (anti-spam bypass)
// ---------------------------
app.get("/api/direct-activate", async (req, res) => {
  try {
    const pending_id = req.query.pending_id;
    if (!pending_id) return res.status(400).send("pending_id requis");

    // 1) Charger le pending_signup
    const { data: pending, error: pendingErr } = await supabaseAdmin
      .from("pending_signups")
      .select("*")
      .eq("id", pending_id)
      .single();

    if (pendingErr || !pending) {
      return res.status(404).send("Lien invalide ou expiré.");
    }

    // 2) Vérifier que le user existe dans Supabase (status "invited")
    if (!pending.user_id) {
      return res.status(400).send("Compte pas encore prêt. Réessayez dans quelques instants.");
    }

    if (pending.status === "activated") {
      return res.redirect(`${FRONTEND_URL}/login.html`);
    }

    // 3) Confirmer l'email du user (bypasse la vérification email)
    const { error: updateErr } = await supabaseAdmin.auth.admin.updateUserById(
      pending.user_id,
      { email_confirm: true }
    );

    if (updateErr) {
      log.error("❌ direct-activate updateUserById:", safeError(updateErr));
      return res.status(500).send("Impossible de confirmer le compte.");
    }

    // 4) Générer un magic link pointant vers welcome.html
    const FRONT = FRONTEND_URL;
    const redirectTo = `${FRONT}/welcome.html?pending_id=${pending_id}`;

    const { data: linkData, error: linkErr } = await supabaseAdmin.auth.admin.generateLink({
      type: "magiclink",
      email: pending.email,
      options: { redirectTo },
    });

    if (linkErr) {
      log.error("❌ direct-activate generateLink:", safeError(linkErr));
      return res.status(500).send("Impossible de générer le lien d'activation.");
    }

    const actionLink =
      linkData?.properties?.action_link ||
      linkData?.properties?.actionLink ||
      null;

    if (!actionLink) {
      return res.status(500).send("Lien d'activation manquant.");
    }

    // ✅ SÉCURITÉ : redirection serveur — le magic link ne transite jamais en JSON
    return res.redirect(actionLink);

  } catch (e) {
    log.error("❌ /api/direct-activate:", safeError(e));
    return res.status(500).send("Erreur serveur");
  }
});


// ---------------------------
// Traitement mail plateforme via support.html
// ---------------------------

// ✅ Middleware d'erreurs Multer dédié au support (10MB/fichier)
function handleSupportMulterError(err, req, res, next) {
  if (!err) return next();

  // Erreurs Multer natives
  if (err.name === "MulterError") {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ error: "Fichier trop volumineux (max 5 Mo par fichier)." });
    }
    if (err.code === "LIMIT_UNEXPECTED_FILE") {
      return res.status(400).json({ error: "Trop de fichiers (max 2)." });
    }
    return res.status(400).json({ error: `Erreur upload: ${err.code}` });
  }

  // Erreurs custom (fileFilter etc.)
  return res.status(400).json({ error: err.message || "Erreur upload fichier." });
}




// ✅ Support V1 (sans PJ) — protégé par cookie auth + CSRF
app.post(
  "/api/support/ticket",
  authenticateToken,
  supportLimiter,
  uploadSupport.array("attachments", 2),
  handleSupportMulterError,
  async (req, res) => {
    try {
      // champs form-data
      const source = (req.body.source || "app").trim();
      const type = (req.body.type || "support").trim();
      const subject = (req.body.subject || "").trim();
      const message = (req.body.message || "").trim();
      const pageUrl = (req.body.pageUrl || "").trim();

      if (!subject) return res.status(400).json({ error: "Objet manquant." });
      if (!message || message.length < 20) return res.status(400).json({ error: "Message trop court (min 20 caractères)." });
      if (message.length > 1200) return res.status(400).json({ error: "Message trop long (max 1200 caractères)." });


      // ✅ anti doublon (5 min) — À METTRE DANS LA ROUTE
      const dup = await findRecentDuplicateSupport({
        userId: req.user.id,
        subject,
        message,
        minutes: 5
      });

      if (dup) {
        return res.status(200).json({
          ok: true,
          skipped: true,
          reason: "duplicate_recent",
          ticket_id: dup.id
        });
      }

      // infos user depuis le token (source of truth)
      const userId = req.user.id;
      const userEmail = req.user.email;
      const userFirstName = req.user.first_name || null;
      const userLastName = req.user.last_name || null;
      const userPlan = req.user.subscription_type || null;

      // si tu as company dans req.user : récupère, sinon laisse null
      const companyName = req.user.company_display_name || req.user.company_name || null;

      // 1) insert ticket
      const { data: ticket, error: ticketErr } = await supabaseAdmin
        .from("support_tickets")
        .insert({
          source,
          type,
          subject,
          message,
          page_url: pageUrl,
          user_id: userId,
          user_email: userEmail,
          user_first_name: userFirstName,
          user_last_name: userLastName,
          user_plan: userPlan,
          company_name: companyName, // ajoute la colonne si tu ne l’as pas
          status: "open",
        })
        .select("*")
        .single();

      if (ticketErr) {
        // Log complet côté serveur uniquement
        log.error("❌ support_tickets insert error:", ticketErr);

        // Message générique côté client (anti fuite SQL / schéma)
        return res.status(500).json({
          error: "Erreur technique lors de la création du ticket."
        });
      }

      // 2) upload PJ (si présentes)
      const files = req.files || [];
      const totalBytes = files.reduce((sum, f) => sum + (f.size || 0), 0);
      const MAX_TOTAL = 5 * 1024 * 1024; // 5MB total

      if (totalBytes > MAX_TOTAL) {
        return res.status(400).json({
          error: "Pièces jointes trop volumineuses (max 5 Mo au total)."
        });
      }

      const signedLinks = [];

      for (const f of files) {
        const ext = (f.originalname.split(".").pop() || "bin").toLowerCase();
        const safeName = f.originalname.replace(/[^\w.\-() ]+/g, "_");
        const storagePath = `tickets/${ticket.id}/${Date.now()}_${safeName}`;

        const { error: upErr } = await supabaseAdmin
          .storage
          .from("support_attachments")
          .upload(storagePath, f.buffer, { contentType: f.mimetype, upsert: false });

        if (upErr) {
          log.warn("PJ upload error:", upErr.message);
          continue;
        }

        // enregistre metadata (si table)
        await supabaseAdmin.from("support_ticket_attachments").insert({
          ticket_id: ticket.id,
          path: storagePath,
          original_name: f.originalname,
          mime: f.mimetype,
          size: f.size,
        });

        // lien signé (ex: 14 jours)
        const { data: signed, error: signErr } = await supabaseAdmin
          .storage
          .from("support_attachments")
          .createSignedUrl(storagePath, 60 * 60 * 24 * 14);

        if (!signErr && signed?.signedUrl) {
          signedLinks.push({ name: f.originalname, url: signed.signedUrl });
        }
      }

      // 3) email support (FR)
      const supportTo = "support@integora.fr";
      const subjectMail = `🎫 Support INTEGORA — ${ticket.subject} (#${ticket.id})`;

      const prettySubject = escapeHtml(ticket.subject);
      const prettyPlan = escapeHtml(ticket.user_plan || "-");
      const prettySource = escapeHtml(`${ticket.source || "-"} / ${ticket.type || "-"}`);
      const prettyPage = escapeHtml(ticket.page_url || "-");
      const prettyEmail = escapeHtml(ticket.user_email || "-");
      const prettyFirst = escapeHtml(ticket.user_first_name || "");
      const prettyLast = escapeHtml(ticket.user_last_name || "");
      const prettyUser = `${prettyFirst} ${prettyLast}`.trim() || "-";
      const prettyCompany = escapeHtml(ticket.company_name || "—");
      const prettyIdShort = String(ticket.id).slice(0, 8);
      const prettyDate = new Date(ticket.created_at || Date.now()).toLocaleString("fr-FR");

      const subjectBadges = {
        access: { label: "Accès / Connexion", bg: "#E6F3FF", bd: "#66B7FF", tx: "#0B4A7A" },
        bug: { label: "Bug", bg: "#FFECEC", bd: "#FF8A8A", tx: "#7A0B0B" },
        billing: { label: "Facturation", bg: "#FFF4E5", bd: "#FFB84D", tx: "#7A4A0B" },
        usage: { label: "Utilisation", bg: "#EAF7EE", bd: "#7FE0A0", tx: "#0B5A2A" },
        feature: { label: "Suggestion", bg: "#F1ECFF", bd: "#B49BFF", tx: "#3A1A7A" },
        other: { label: "Autre", bg: "#EEF2F7", bd: "#AAB4C3", tx: "#223048" },
      };
      const badge = subjectBadges[ticket.subject] || { label: prettySubject, bg: "#EEF2F7", bd: "#AAB4C3", tx: "#223048" };
      const planBadge = (ticket.user_plan || "").toLowerCase() === "paid"
        ? { label: "Abonnement annuel", bg: "#EAF7EE", bd: "#7FE0A0", tx: "#0B5A2A" }
        : (ticket.user_plan || "").toLowerCase() === "trial"
          ? { label: "Essai gratuit", bg: "#F1ECFF", bd: "#B49BFF", tx: "#3A1A7A" }
          : { label: `Plan ${prettyPlan}`, bg: "#EEF2F7", bd: "#AAB4C3", tx: "#223048" };

      // Generer le lien "Marquer comme traite" (token signe HMAC, expire 90 jours)
      const FRONT_URL = process.env.FRONTEND_URL || "https://integora.fr";
      let markClosedUrl = null;
      try {
        const closeToken = generateCloseTicketToken(ticket.id, "support_tickets");
        markClosedUrl = `${FRONT_URL}/api/admin/ticket-mark-closed?token=${closeToken}`;
      } catch (e) {
        log.warn("⚠️ support ticket: impossible de generer le token close:", safeError(e));
      }

      const html = `
  <div style="margin:0;padding:0;background:#f4f6fb;">
    <div style="max-width:760px;margin:0 auto;padding:28px 14px;font-family:Arial,sans-serif;color:#0f172a;">
      
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
        <span style="display:inline-block;width:10px;height:10px;border-radius:999px;background:#22c55e;"></span>
        <div style="font-weight:800;font-size:16px;">INTEGORA — Nouveau ticket Support</div>
      </div>

      <div style="background:#ffffff;border:1px solid #e6eaf2;border-radius:18px;box-shadow:0 10px 28px rgba(2,6,23,0.06);padding:18px 18px 16px;">
        
        <!-- BADGES -->
        <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;">
          <span style="display:inline-block;padding:8px 12px;border-radius:999px;border:1px solid ${badge.bd};background:${badge.bg};color:${badge.tx};font-weight:700;font-size:13px;">
            ${badge.label}
          </span>

          <span style="display:inline-block;padding:8px 12px;border-radius:999px;border:1px solid #cbd5e1;background:#eef2ff;color:#1e293b;font-weight:700;font-size:13px;">
            Ticket ${escapeHtml(prettyIdShort)}
          </span>

          <span style="display:inline-block;padding:8px 12px;border-radius:999px;border:1px solid ${planBadge.bd};background:${planBadge.bg};color:${planBadge.tx};font-weight:800;font-size:13px;">
            ${planBadge.label}
          </span>
        </div>

        <!-- INFOS -->
        <table role="presentation" style="width:100%;border-collapse:collapse;font-size:14px;line-height:1.5;">
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;width:160px;">Date</td>
            <td style="padding:4px 0;color:#0f172a;">${escapeHtml(prettyDate)}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Source</td>
            <td style="padding:4px 0;color:#0f172a;">${prettySource}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Page</td>
            <td style="padding:4px 0;color:#0f172a;">${prettyPage}</td>
          </tr>

          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Prénom</td>
            <td style="padding:4px 0;color:#0f172a;">${escapeHtml(ticket.user_first_name || "—")}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Nom</td>
            <td style="padding:4px 0;color:#0f172a;">${escapeHtml(ticket.user_last_name || "—")}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Email</td>
            <td style="padding:4px 0;color:#0f172a;">${prettyEmail}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Entreprise</td>
            <td style="padding:4px 0;color:#0f172a;">${prettyCompany}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">User ID</td>
            <td style="padding:4px 0;color:#0f172a;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;font-size:12.5px;">
              ${escapeHtml(ticket.user_id || "—")}
            </td>
          </tr>
        </table>

        <!-- MESSAGE -->
        <div style="margin-top:14px;border:1px solid #e6eaf2;border-radius:14px;background:#f8fafc;padding:14px;">
          <div style="font-weight:800;margin-bottom:8px;color:#0f172a;">Message</div>
          <div style="white-space:pre-wrap;color:#0f172a;">${escapeHtml(ticket.message)}</div>
        </div>

        <!-- PJ -->
        <div style="margin-top:16px;">
          <div style="font-weight:900;font-size:16px;margin-bottom:8px;">Pièces jointes</div>
          ${signedLinks.length
          ? `<ul style="margin:0;padding-left:18px;">
                  ${signedLinks
            .map(
              (x) => `
                      <li style="margin:6px 0;">
                        <a href="${x.url}" style="color:#2563eb;text-decoration:underline;font-weight:700;">
                          ${escapeHtml(x.name)}
                        </a>
                      </li>`
            )
            .join("")}
                </ul>
                <div style="margin-top:8px;color:#64748b;font-size:12px;">
                  Liens signés (expirent automatiquement).
                </div>`
          : `<div style="color:#64748b;">Aucune pièce jointe.</div>`
        }
        </div>

        ${markClosedUrl ? `
        <!-- BOUTON MARQUER COMME TRAITE -->
        <div style="text-align:center;margin:24px 0 16px 0;">
          <a href="${markClosedUrl}"
             style="display:inline-block;background:#16a34a;color:#ffffff;text-decoration:none;padding:13px 28px;border-radius:8px;font-weight:700;font-size:14px;">
            ✓ Marquer ce ticket comme traite
          </a>
          <div style="font-size:12px;color:#64748b;margin-top:8px;">
            Une fois le ticket support traite, cliquez ici pour le cloturer.
          </div>
        </div>
        ` : ""}

        <div style="text-align:center;margin-top:14px;color:#94a3b8;font-size:12px;">
          INTEGORA • Ticket ${escapeHtml(prettyIdShort)}
        </div>
      </div>
    </div>
  </div>
`;


      await sendResendEmail({ to: supportTo, subject: subjectMail, html });

      // 4) accusé de réception user (noreply)
      const ackSubject = "INTEGORA — Demande reçue ✅";
      const ackHtml = `
        <div style="font-family:Arial,sans-serif;line-height:1.5;color:#111">
          <h2 style="margin:0 0 10px">Nous avons bien reçu votre demande</h2>
          <p>Votre ticket a été créé avec succès.</p>
          <p><b>Référence :</b> ${ticket.id}</p>
          <p style="color:#666;font-size:12px">Cet email est envoyé automatiquement. Vous pouvez répondre à cet email si vous le souhaites, ou passer par la page Support.</p>
        </div>
      `;
      await sendResendEmail({ to: userEmail, subject: ackSubject, html: ackHtml });

      return res.json({ ok: true, ticket_id: ticket.id });

    } catch (e) {
      log.error("❌ /api/support/ticket:", safeError(e));
      return res.status(500).json({ error: "Erreur serveur" });
    }

    async function findRecentDuplicateSupport({ userId, subject, message, minutes = 5 }) {
      try {
        const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
        const { data, error } = await supabaseAdmin
          .from("support_tickets")
          .select("id, created_at")
          .eq("user_id", userId)
          .eq("subject", subject)
          .eq("message", message)
          .gte("created_at", since)
          .order("created_at", { ascending: false })
          .limit(1);

        if (error) return null;
        return data?.[0] || null;
      } catch {
        return null;
      }
    }

  }


);



// ---------------------------
// CONTACT PUBLIC (contact.html) 
// ---------------------------

// ✅ Rate limit plus strict (public) — IP + EMAIL
const contactPublicLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, res) => {
    const email = (req.body?.email || "").toString().trim().toLowerCase();
    return `${ipKeyGenerator(req, res)}:${email}`;
  },
});





// ✅ FIX B14 — isValidEmail doublon supprimé (déjà déclaré plus haut ligne ~2407)

async function findRecentDuplicateContact({ email, subject, message, minutes = 10 }) {
  try {
    const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();

    const { data, error } = await supabaseAdmin
      .from("contact_tickets")
      .select("id, created_at")
      .eq("email", email)
      .eq("subject", subject)
      .eq("message", message)
      .gte("created_at", since)
      .order("created_at", { ascending: false })
      .limit(1);

    if (error) return null;
    return data?.[0] || null;
  } catch {
    return null;
  }
}


app.post("/api/contact/ticket", contactPublicLimiter, async (req, res) => {
  try {
    // Parsing du body JSON via express.json()
    const subject = String(req.body?.subject || "").trim();
    const message = cleanMessage(req.body?.message, { max: 1200 });
    const pageUrl = String(req.body?.pageUrl || "").trim() || null;

    const firstName = cleanPersonName(req.body?.firstName, { max: 30 });
    const lastName = cleanPersonName(req.body?.lastName, { max: 40 });

    const email = String(req.body?.email || "").trim().toLowerCase();
    const companyName = cleanTextStrict(req.body?.companyName, { max: 60, allowEmpty: true });
    const position = cleanTextStrict(req.body?.position, { max: 60, allowEmpty: false });
    const phoneRaw = req.body?.phone;
    let phone = null;
    if (typeof phoneRaw === "string") {
      const v = phoneRaw.trim();
      phone = v ? v : null;
    } else {
      phone = null;
    }

    const dup = await findRecentDuplicateContact({ email, subject, message, minutes: 10 });
    if (dup) {
      // ✅ On "fait comme si c'était OK" MAIS on évite tout envoi email
      return res.status(200).json({ ok: true, ticket_id: dup.id, duplicate: true });
    }



    // ✅ Honeypot simple (optionnel mais recommandé)
    // (côté HTML tu mets un input caché name="website")
    const honeypot = String(req.body?.website || "").trim();
    if (honeypot) return res.status(200).json({ ok: true }); // on "fait comme si" pour tromper les bots

    // ✅ Validations
    if (!subject) return res.status(400).json({ error: "Objet manquant." });
    if (!firstName) return res.status(400).json({ error: "Prénom manquant." });
    if (!lastName) return res.status(400).json({ error: "Nom manquant." });
    if (!position) return res.status(400).json({ error: "Fonction / Poste manquant." });
    if (position.length > 60) return res.status(400).json({ error: "Fonction / Poste trop long (max 60 caractères)." });

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ error: "Adresse email invalide." });
    }
    if (!message || message.length < 20) {
      return res.status(400).json({ error: "Message trop court (min 20 caractères)." });
    }
    if (message.length > 1200) {
      return res.status(400).json({ error: "Message trop long (max 1200 caractères)." });
    }

    // 1) insert DB (table dédiée)
    const { data: ticket, error: ticketErr } = await supabaseAdmin
      .from("contact_tickets")
      .insert({
        subject,
        message,
        page_url: pageUrl,
        first_name: firstName,
        last_name: lastName,
        email,
        company_name: companyName,
        position,
        phone,
        status: "open",
      })
      .select("*")
      .single();

    if (ticketErr) {
      log.error("❌ contact_tickets insert error:", ticketErr);
      return res.status(500).json({ error: "Erreur technique lors de l'envoi." });
    }

    // 2) email interne => contact@integora.fr
    const contactTo = "contact@integora.fr";
    const subjectMail = `📩 Contact INTEGORA — ${ticket.subject} (#${ticket.id})`;

    // ✅ mêmes codes couleurs / mêmes pills que Support, mais adapté au Contact public
    const prettySubject = escapeHtml(ticket.subject);
    const prettySource = "public / contact";
    const prettyPage = escapeHtml(ticket.page_url || "—");
    const prettyEmail = escapeHtml(ticket.email || "—");
    const prettyCompany = escapeHtml(ticket.company_name || "—");
    const prettyIdShort = String(ticket.id).slice(0, 8);
    const prettyDate = new Date(ticket.created_at || Date.now()).toLocaleString("fr-FR");

    // Mapping "nature" (contact) -> label + couleurs (tu peux ajuster si tu veux)
    const subjectBadges = {
      general: { label: "Demande générale", bg: "#EEF2F7", bd: "#AAB4C3", tx: "#223048" },
      demo: { label: "Demande de démonstration", bg: "#E6F3FF", bd: "#66B7FF", tx: "#0B4A7A" },
      commercial: { label: "Demande commerciale", bg: "#FFF4E5", bd: "#FFB84D", tx: "#7A4A0B" },
      support: { label: "Support / assistance", bg: "#E6F3FF", bd: "#66B7FF", tx: "#0B4A7A", },
      partnership: { label: "Partenariat", bg: "#F1ECFF", bd: "#B49BFF", tx: "#3A1A7A" },
      other: { label: "Autre demande", bg: "#EEF2F7", bd: "#AAB4C3", tx: "#223048" },
    };

    const badge = subjectBadges[ticket.subject] || { label: prettySubject, bg: "#EEF2F7", bd: "#AAB4C3", tx: "#223048" };

    // Badge "CONTACT" (remplace le badge Plan du support)
    const contactBadge = { label: "Contact public", bg: "#ecfeff", bd: "#67e8f9", tx: "#155e75" };

    // Generer le lien "Marquer comme traite" (token signe HMAC, expire 90 jours)
    const FRONT_URL = process.env.FRONTEND_URL || "https://integora.fr";
    let markClosedUrl = null;
    try {
      const closeToken = generateCloseTicketToken(ticket.id, "contact_tickets");
      markClosedUrl = `${FRONT_URL}/api/admin/ticket-mark-closed?token=${closeToken}`;
    } catch (e) {
      log.warn("⚠️ contact ticket: impossible de generer le token close:", safeError(e));
    }

    const html = `
  <div style="margin:0;padding:0;background:#f4f6fb;">
    <div style="max-width:760px;margin:0 auto;padding:28px 14px;font-family:Arial,sans-serif;color:#0f172a;">

      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
        <span style="display:inline-block;width:10px;height:10px;border-radius:999px;background:#22c55e;"></span>
        <div style="font-weight:800;font-size:16px;">INTEGORA — Nouveau message Contact</div>
      </div>

      <div style="background:#ffffff;border:1px solid #e6eaf2;border-radius:18px;box-shadow:0 10px 28px rgba(2,6,23,0.06);padding:18px 18px 16px;">
        
        <!-- BADGES -->
        <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;">
          <span style="display:inline-block;padding:8px 12px;border-radius:999px;border:1px solid ${badge.bd};background:${badge.bg};color:${badge.tx};font-weight:700;font-size:13px;">
            ${badge.label}
          </span>

          <span style="display:inline-block;padding:8px 12px;border-radius:999px;border:1px solid #cbd5e1;background:#eef2ff;color:#1e293b;font-weight:700;font-size:13px;">
            Ticket ${escapeHtml(prettyIdShort)}
          </span>

          <span style="display:inline-block;padding:8px 12px;border-radius:999px;border:1px solid ${contactBadge.bd};background:${contactBadge.bg};color:${contactBadge.tx};font-weight:800;font-size:13px;">
            ${contactBadge.label}
          </span>
        </div>

        <!-- INFOS -->
        <table role="presentation" style="width:100%;border-collapse:collapse;font-size:14px;line-height:1.5;">
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;width:160px;">Date</td>
            <td style="padding:4px 0;color:#0f172a;">${escapeHtml(prettyDate)}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Source</td>
            <td style="padding:4px 0;color:#0f172a;">${escapeHtml(prettySource)}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Page</td>
            <td style="padding:4px 0;color:#0f172a;">${prettyPage}</td>
          </tr>

          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Prénom</td>
            <td style="padding:4px 0;color:#0f172a;">${escapeHtml(ticket.first_name || "—")}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Nom</td>
            <td style="padding:4px 0;color:#0f172a;">${escapeHtml(ticket.last_name || "—")}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Email</td>
            <td style="padding:4px 0;color:#0f172a;">${prettyEmail}</td>
          </tr>
          ${ticket.phone ? `
          <tr>
             <td style="padding:4px 0;color:#64748b;font-weight:700;">Téléphone</td>
             <td style="padding:4px 0;color:#0f172a;">${escapeHtml(ticket.phone)}</td>
           </tr> `
        : ""}
          <tr>
            <td style="padding:4px 0;color:#64748b;font-weight:700;">Entreprise</td>
            <td style="padding:4px 0;color:#0f172a;">${prettyCompany}</td>
          </tr>
        </table>

        <!-- MESSAGE -->
        <div style="margin-top:14px;border:1px solid #e6eaf2;border-radius:14px;background:#f8fafc;padding:14px;">
          <div style="font-weight:800;margin-bottom:8px;color:#0f172a;">Message</div>
          <div style="white-space:pre-wrap;color:#0f172a;">${escapeHtml(ticket.message)}</div>
        </div>

        <!-- PJ -->
        <div style="margin-top:16px;">
          <div style="font-weight:900;font-size:16px;margin-bottom:8px;">Pièces jointes</div>
          <div style="color:#64748b;">Aucune (formulaire Contact public).</div>
        </div>

        ${markClosedUrl ? `
        <!-- BOUTON MARQUER COMME TRAITE -->
        <div style="text-align:center;margin:24px 0 16px 0;">
          <a href="${markClosedUrl}"
             style="display:inline-block;background:#16a34a;color:#ffffff;text-decoration:none;padding:13px 28px;border-radius:8px;font-weight:700;font-size:14px;">
            ✓ Marquer ce ticket comme traite
          </a>
          <div style="font-size:12px;color:#64748b;margin-top:8px;">
            Une fois le contact traite, cliquez ici pour cloturer la demande.
          </div>
        </div>
        ` : ""}

        <div style="text-align:center;margin-top:14px;color:#94a3b8;font-size:12px;">
          INTEGORA • Ticket ${escapeHtml(prettyIdShort)}
        </div>
      </div>
    </div>
  </div>
`;


    await sendResendEmail({ to: contactTo, subject: subjectMail, html });

    // 3) accusé de réception (public)
    const ackSubject = "INTEGORA — Message reçu ✅";
    const ackHtml = `
      <div style="font-family:Arial,sans-serif;line-height:1.5;color:#111">
        <h2 style="margin:0 0 10px">Nous avons bien reçu votre message</h2>
        <p>Merci, votre demande a été transmise à notre équipe.</p>
        <p><b>Référence :</b> ${escapeHtml(String(ticket.id))}</p>
        <p style="color:#666;font-size:12px">Email automatique — vous pouvez répondre à ce message si nécessaire.</p>
      </div>
    `;
    await sendResendEmail({ to: email, subject: ackSubject, html: ackHtml });

    return res.json({ ok: true, ticket_id: ticket.id });

  } catch (e) {
    log.error("❌ /api/contact/ticket:", safeError(e));
    return res.status(500).json({ error: "Erreur serveur" });
  }
});



// ---------------------------
// DÉCONNEXION
// ---------------------------
app.post("/api/logout", async (req, res) => {
  // Récupérer le token du cookie pour l'invalider en base
  const token = req.cookies?.auth_token;

  if (token) {
    const tokenHash = hashToken(token);
    await supabase
      .from("token_sessions")
      .update({
        is_active: false,
        revoked_at: new Date().toISOString()
      })
      .eq("token_hash", tokenHash);
  }

  // ✅ SUPPRIMER LE COOKIE
  res.clearCookie("auth_token", {
    path: "/",
    secure: IS_PROD,
    sameSite: IS_PROD ? "none" : "lax",
  });


  res.json({
    success: true,
    message: "Déconnexion réussie"
  });
});

// ==================== CRON : RAPPELS EXPIRATION ABONNEMENT ====================

const CRON_SECRET = process.env.CRON_SECRET;
const emailTemplates = require("./email-templates");

app.post("/api/cron/expiration-reminders", async (req, res) => {
  // ✅ Sécurité : secret partagé
  const secret = req.headers["x-cron-secret"] || req.body?.secret;
  if (!CRON_SECRET || secret !== CRON_SECRET) {
    return res.status(403).json({ error: "Forbidden" });
  }

  try {
    const now = new Date();
    const today = now.toISOString().slice(0, 10); // YYYY-MM-DD

    // ✅ MÉNAGE QUOTIDIEN — exécuté EN PREMIER, avant les éventuels return anticipés ci-dessous,
    //    pour qu'il tourne CHAQUE nuit, qu'il y ait des rappels à envoyer ou non.
    //    (a) Purge RGPD : activity_log > 13 mois · admin_audit_log > 12 mois · pilotage_tech_log > 6 mois · token_sessions expirées > 30 j · pending_signups > 30 j
    //    (b) Auto-close des contact_tickets ouverts > 30 j (support_tickets reste manuel).
    const purged = {};
    try {
      const ms = Date.now();
      const cutActivity = new Date(ms - 395 * 86400000).toISOString(); // 13 mois (norme CNIL mesure d'audience)
      const cutAudit = new Date(ms - 365 * 86400000).toISOString();    // 12 mois (journal d'audit admin)
      const cutTech = new Date(ms - 180 * 86400000).toISOString();     // 6 mois (journal technique d'entreprise)
      const cut30 = new Date(ms - 30 * 86400000).toISOString();

      const pa = await supabaseAdmin.from('activity_log').delete({ count: 'exact' }).lt('created_at', cutActivity);
      if (!pa.error) purged.activity_log = pa.count || 0; else log.warn('⚠️ Purge activity_log:', safeError(pa.error));

      const paa = await supabaseAdmin.from('admin_audit_log').delete({ count: 'exact' }).lt('created_at', cutAudit);
      if (!paa.error) purged.admin_audit_log = paa.count || 0; else log.warn('⚠️ Purge admin_audit_log:', safeError(paa.error));

      const pt = await supabaseAdmin.from('pilotage_tech_log').delete({ count: 'exact' }).lt('created_at', cutTech);
      if (!pt.error) purged.pilotage_tech_log = pt.count || 0; else log.warn('⚠️ Purge pilotage_tech_log:', safeError(pt.error));

      const ps = await supabaseAdmin.from('token_sessions').delete({ count: 'exact' }).lt('expires_at', cut30);
      if (!ps.error) purged.token_sessions = ps.count || 0; else log.warn('⚠️ Purge token_sessions:', safeError(ps.error));

      const pp = await supabaseAdmin.from('pending_signups').delete({ count: 'exact' }).lt('created_at', cut30);
      if (!pp.error) purged.pending_signups = pp.count || 0; else log.warn('⚠️ Purge pending_signups:', safeError(pp.error));

      if (Object.values(purged).some((n) => n > 0)) log.info('🧹 Purge RGPD:', purged);
    } catch (e) {
      log.warn('⚠️ Purge RGPD exception:', safeError(e));
    }

    let autoClosed = 0;
    try {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - 30);
      const { data: closedRows, error: autoCloseErr } = await supabaseAdmin
        .from("contact_tickets")
        .update({ status: "closed" })
        .eq("status", "open")
        .lt("created_at", cutoff.toISOString())
        .select("id");
      if (autoCloseErr) {
        log.warn("⚠️ Auto-close contact_tickets failed:", safeError(autoCloseErr));
      } else {
        autoClosed = (closedRows || []).length;
        if (autoClosed > 0) log.info(`🧹 Auto-close: ${autoClosed} contact_ticket(s) > 30j cloture(s)`);
      }
    } catch (e) {
      log.warn("⚠️ Auto-close contact_tickets exception:", safeError(e));
    }

    // ✅ 1. Récupérer tous les abonnements actifs (1 requête)
    const { data: subs, error: subsErr } = await supabaseAdmin
      .from("subscriptions")
      .select("user_id, plan, tier, status, current_period_end, trial_end")
      .in("status", ["active", "trialing"]);

    if (subsErr) throw subsErr;
    if (!subs?.length) return res.json({ ok: true, sent: 0, autoClosed, purged, detail: "Aucun abonnement actif" });

    // ✅ Définir les rappels à vérifier par plan
    const paidReminders = [
      { type: "j-30", days: 30 },
      { type: "j-7", days: 7 },
      { type: "j-3", days: 3 },
      { type: "j-1", days: 1 },
      { type: "expired", days: 0 },
    ];
    const trialReminders = [
      { type: "j-3", days: 3 },
      { type: "j-1", days: 1 },
      { type: "expired", days: 0 },
    ];

    const templateMap = {
      "j-30": emailTemplates.reminderJ30,
      "j-7": emailTemplates.reminderJ7,
      "j-3": emailTemplates.reminderJ3,
      "j-1": emailTemplates.reminderJ1,
      "expired": emailTemplates.reminderExpired,
    };

    // ✅ 2. Pré-filtrer : ne garder que les abonnements qui matchent un rappel
    const candidates = [];
    for (const sub of subs) {
      const plan = (sub.plan || "trial").toLowerCase();
      const isTrial = plan === "trial";
      const endDateRaw = isTrial ? sub.trial_end : sub.current_period_end;
      if (!endDateRaw) continue;

      const endDate = new Date(endDateRaw);
      if (isNaN(endDate.getTime())) continue;

      const endDay = endDate.toISOString().slice(0, 10);
      const diffMs = new Date(endDay) - new Date(today);
      const daysLeft = Math.round(diffMs / (1000 * 60 * 60 * 24));

      const reminders = isTrial ? trialReminders : paidReminders;
      for (const reminder of reminders) {
        if (daysLeft === reminder.days) {
          candidates.push({ sub, plan, endDateRaw, endDay, reminder });
        }
      }
    }

    if (!candidates.length) return res.json({ ok: true, sent: 0, autoClosed, purged, detail: "Aucun rappel à envoyer" });

    // ✅ 3. Charger en bulk les rappels déjà envoyés (1 requête au lieu de N)
    const userIds = [...new Set(candidates.map(c => c.sub.user_id))];
    const { data: existingReminders } = await supabaseAdmin
      .from("subscription_reminders")
      .select("user_id, reminder_type, expiration_date")
      .in("user_id", userIds);

    const alreadySent = new Set(
      (existingReminders || []).map(r => `${r.user_id}|${r.reminder_type}|${r.expiration_date}`)
    );

    // ✅ 4. Charger en bulk les profils (1 requête au lieu de N)
    const { data: profiles } = await supabaseAdmin
      .from("profiles")
      .select("user_id, first_name")
      .in("user_id", userIds);

    const profileMap = new Map((profiles || []).map(p => [p.user_id, p.first_name]));

    // ✅ 5. Envoyer les rappels (seulement getUserById pour les candidats non-doublons)
    let sent = 0;
    const errors = [];

    for (const { sub, plan, endDateRaw, endDay, reminder } of candidates) {
      const key = `${sub.user_id}|${reminder.type}|${endDay}`;
      if (alreadySent.has(key)) continue;

      // Email : getUserById uniquement pour les vrais envois
      const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(sub.user_id);
      const email = authUser?.user?.email;
      if (!email) continue;

      const firstName = profileMap.get(sub.user_id) || "Utilisateur";
      const templateFn = templateMap[reminder.type];
      if (!templateFn) continue;

      const { subject, html } = templateFn({ firstName, plan, endDate: endDateRaw, tier: sub.tier });

      try {
        await sendResendEmail({ to: email, subject, html });

        await supabaseAdmin.from("subscription_reminders").insert({
          user_id: sub.user_id,
          reminder_type: reminder.type,
          expiration_date: endDay,
          sent_at: new Date().toISOString(),
        });

        sent++;
        const maskedEmail = `${email.slice(0, 3)}***@${email.split('@')[1] || '?'}`;
        log.info(`📧 Rappel ${reminder.type} envoyé à ${maskedEmail} (plan: ${plan})`);
      } catch (emailErr) {
        errors.push({ user_id: sub.user_id, type: reminder.type, error: emailErr.message });
        log.error(`❌ Erreur envoi rappel ${reminder.type}:`, safeError(emailErr));
      }
    }

    return res.json({ ok: true, sent, autoClosed, purged, errors: errors.length ? errors : undefined });
  } catch (err) {
    log.error("❌ Cron expiration-reminders:", safeError(err));
    return res.status(500).json({ error: "Erreur interne cron" });
  }
});


// Démarrage du serveur
const FINAL_PORT = process.env.PORT || 3000;
app.listen(FINAL_PORT, () => {
  log.debug(`🚀 Serveur démarré sur http://localhost:${FINAL_PORT}`);
  log.debug(`📊 Types d'abonnements gérés: ${Object.values(SUBSCRIPTION_TYPES).join(', ')}`);
  log.debug('🛡️ Architecture invisible activée');
  log.debug('🔒 Rate limiting: Activé');
  log.debug('📡 Headers de sécurité: Activés');
});
