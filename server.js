//server//

require('dotenv').config();

// Vérification CRITIQUE - doit être fait immédiatement
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.error("❌ ERREUR CRITIQUE: Variables Supabase manquantes !");
  console.error("   SUPABASE_URL:", process.env.SUPABASE_URL ? "✅ Définie" : "❌ MANQUANTE");
  console.error("   SUPABASE_SERVICE_ROLE_KEY:", process.env.SUPABASE_SERVICE_ROLE_KEY ? "✅ Définie" : "❌ MANQUANTE");
  console.error("💡 Vérifie que ton fichier .env est dans le même dossier que server.js");
  process.exit(1);
}


console.log("🔎 ENV CHECK", {
  nodeEnv: process.env.NODE_ENV,
  stripeMode: process.env.STRIPE_MODE,
  isLiveKey: process.env.STRIPE_SECRET_KEY?.startsWith("sk_live_"),
  priceStandard: process.env.STRIPE_PRICE_STANDARD,
  pricePremium: process.env.STRIPE_PRICE_PREMIUM,
  frontendUrl: process.env.FRONTEND_URL,
});


console.log("✅ Variables d'environnement chargées avec succès");
console.log("🧪 SUPABASE_URL USED:", process.env.SUPABASE_URL);
console.log("🧪 ANON prefix:", (process.env.SUPABASE_ANON_KEY || "").slice(0, 12));
console.log("🧪 SERVICE_ROLE prefix:", (process.env.SUPABASE_SERVICE_ROLE_KEY || "").slice(0, 12));


const express = require("express");
const app = express();

// ==================== CORS (TOUT EN HAUT) ====================
const ALLOWED_ORIGINS = new Set([
  "https://integora-frontend.vercel.app",
  "http://localhost:3000",
  "http://localhost:5173",
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  const isVercelPreview =
    origin && /^https:\/\/integora-frontend-.*\.vercel\.app$/.test(origin);

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
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');


// ==========================================
// 📧 RESEND 
// ==========================================
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_FROM = process.env.RESEND_FROM || "INTEGORA <noreply@integora.fr>";

async function sendResendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) {
    console.warn("⚠️ RESEND_API_KEY manquante : email non envoyé.");
    return { skipped: true, reason: "missing_resend_api_key" };
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
  STANDARD: 'standard',
  PREMIUM: 'premium',
};



// ==========================================
// 🗄️ INITIALISATION SUPABASE
// ==========================================
console.log("🔄 Tentative de création du client Supabase...");

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
  console.log("✅ Supabase client ADMIN créé avec succès!");
} catch (error) {
  console.log("❌ Erreur création client Supabase:", error.message);
  process.exit(1);
}


// ==========================================
// 🗄️ DEUX CLIENTS SUPABASE
// ==========================================
// ==========================================
// 🗄️ DEUX CLIENTS SUPABASE - SOLUTION DÉFINITIVE
// ==========================================

console.log("🔄 Création des clients Supabase...");

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



console.log("✅ Clients Supabase créés:");
console.log("   - Auth Client (anon): ✅");
console.log("   - Admin Client (service_role): ✅");



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
      console.log(`🔄 Réessai ${attempt}/${retries} dans ${sleep}ms...`);
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

    console.log("🧪 authEmailExists: checking email=", target, "page=", page);
    console.log("🧪 supabaseAdmin url =", process.env.SUPABASE_URL);

    if (error) {
      console.error("❌ authEmailExists listUsers error:", error);
      // SAFE MODE : si on ne peut pas vérifier, on bloque
      return true;
    }

    console.log("🧪 listUsers error =", error);
    console.log("🧪 listUsers count =", data?.users?.length);
    console.log("🧪 sample emails =", (data?.users || []).slice(0, 3).map(u => u.email));


    res.json({
      ok: true,
      buckets: data.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('🔴 Health check Supabase KO:', error.message);
    res.status(500).json({
      ok: false,
      error: 'Supabase indisponible',
      details: error.message
    });
  }
});


// Deploiement Vercel voir la vrai IP
app.set('trust proxy', 1);

const SECRET_KEY = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

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
        "https://integora-backend.onrender.com"

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
app.use(express.json({ limit: '10kb' })); // Limite taille JSON
app.use(express.urlencoded({ extended: true, limit: '10kb' }));


// Appliquer les limiteurs
app.use(globalLimiter);
app.use('/login', authLimiter);
app.use('/inscription', authLimiter);
app.use('/api/verify-token', authLimiter);
app.use('/api/start-trial-invite', authLimiter);
app.use('/api/start-paid-checkout', authLimiter);
app.use('/api/resend-activation', authLimiter);





// ==================== STATIC PUBLIC / STATIC APP (PROPRE) ====================
const FRONTEND_DIR = path.join(__dirname, "../frontend");
const APP_DIR = path.join(FRONTEND_DIR, "app");


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

// CSS/JS : cache modéré (tu peux les modifier)
app.use("/app/css", express.static(path.join(APP_DIR, "css"), { maxAge: "7d", etag: true }));
app.use("/app/js", express.static(path.join(APP_DIR, "js"), { maxAge: "7d", etag: true }));

// Images "générales" (hors assets) : cache moyen
app.use(
  "/app/images",
  express.static(path.join(APP_DIR, "images"), {
    etag: false,
    lastModified: false,
    maxAge: 0,
    setHeaders(res) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
      res.setHeader("Surrogate-Control", "no-store");
    },
  })
);

// ✅ IMPORTANT : cache LONG uniquement pour le dossier logo
// => /app/assets/logo/logo.webp sera "figé" et instant en navigation
app.use(
  "/app/assets/logo",
  express.static(path.join(APP_DIR, "assets", "logo"), {
    etag: false,
    lastModified: false,
    maxAge: 0,
    setHeaders(res) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
      res.setHeader("Surrogate-Control", "no-store");
    },
  })
);


// ✅ Le reste de /app/assets (jeux, illustrations, etc.) : cache NORMAL
// => si tu remplaces une image sans changer son nom, elle se mettra à jour bien plus vite
app.use(
  "/app/assets",
  express.static(path.join(APP_DIR, "assets"), {
    etag: false,
    lastModified: false,
    maxAge: 0,
    setHeaders(res) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
      res.setHeader("Surrogate-Control", "no-store");
    },
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
const CURRENT_TERMS_VERSION = "2026-01-20"; // <-- mets TA date
const CGUV_FILENAME = `cguv_integora_v${CURRENT_TERMS_VERSION}.pdf`;

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
const __planRank = { trial: 0, standard: 1, premium: 2 };

// Pages qui demandent un plan minimal (clé = nom du fichier sans .html)
const PAGE_MIN_PLAN = {
  // PREMIUM

  //connaissance_des_collegues_irl
  "le_pantheon_des_talents": "premium",


  //creativite_irl
  "le_labo_bizarre": "premium",

  //manager autrement
  "carte_rh_express": "premium",
  "30_defis_pour_mieux_manager": "premium",

  //bien_etre_irl
  "instant_zen": "premium",
  "quiz_bien_etre": "premium",

  //competition_amicale
  "challenge_des_tribus": "premium",





  // STANDARD 

  //connaissance_des_collegues_irl
  "qui_est_qui": "standard",
  "si_j_etais": "standard",
  "c_est_moi_ou_pas": "standard",


  //creativite_irl
  "conference_absurde": "standard",
  "histoire_impossible": "standard",
  "a_vous_de_continuer": "standard",
  "7_secondes_chrono": "standard",


  //manager autrement
  "un_mot_pour_avancer": "standard",
  "la_boussole_en_main": "standard",
  "ce_qu_on_ne_dit_pas_assez": "standard",


  //bien_etre_irl
  "chasse_au_bonheur": "standard",


  //collaboration_irl
  "le_relai_des_mimes": "standard",
  "switch": "standard",


  // RECRUTEMENT 
  "fiche_de_poste": "standard",
  "rediger_offre_recrutement": "standard",
  "guide_recrutement": "standard",
  "recrutement_collectif": "standard",
  "communication_candidat": "standard",


  // INTEGRAION 
  "livret_accueil": "standard",
  "processus_integration": "standard",
  "parrain_marraine": "standard",
  "tableau_pilotage_des_formations": "standard",
  "intineraire_de_professionnalisation": "standard",




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
    // 1) Abonnement actif requis pour tout /app (comme avant)
    if (!req.user?.has_active_subscription) {
      return res.status(403).sendFile(path.join(FRONTEND_DIR, "subscription-expired.html"));
    }

    // 2) Contrôle plan par page
    const pageName = getPageNameFromAppPath(req.path);

    if (!canAccessPageServer(req.user, pageName)) {
      // ✅ Objectif: ne JAMAIS afficher la page premium, même si l'URL est tapée
      // On redirige vers 403.html (ton fichier est dans /frontend/403.html)
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

  // fallback app
  return res.sendFile(path.join(APP_DIR, "choix_irl_digital.html"));
});

//middleware empechant POST PUT, ect site externe

function enforceSameSiteForMutations(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();

  const origin = req.headers.origin || "";
  const referer = req.headers.referer || "";

  const allowed = (o) =>
    ALLOWED_ORIGINS.has(o) || /^https:\/\/integora-frontend-.*\.vercel\.app$/.test(o);

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
    } catch {
      return res.status(403).json({ error: "Referer invalide" });
    }
  }

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


// → 1. S'assurer qu'un token existe en cookie lisible


// → 2. Vérifier le token pour les méthodes mutantes
function validateCSRF(req, res, next) {
  // On protège uniquement les méthodes qui modifient
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();

  console.log("🧪 CSRF CHECK", {
    method: req.method,
    path: req.path,
    url: req.url,
    originalUrl: req.originalUrl,
  });

  // ✅ Routes publiques (signup / paiement) : pas de CSRF, sinon blocage
  const exempt = new Set([
    '/login',
    '/inscription',
    '/verify-token',

    // ✅ nouveau flow
    '/api/start-paid-checkout',
    '/api/complete-signup',
    '/api/start-trial-invite',
    '/api/resend-activation',
    '/api/finalize-pending',

    // (optionnel) si tu gardes encore l’ancienne route quelque part
    '/api/create-paid-checkout',

    // ✅ PUBLIC CONTACT 
    '/api/contact/ticket'
  ]);

  if (exempt.has(req.path)) return next();

  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies['XSRF-TOKEN'];

  if (!headerToken || !cookieToken || headerToken !== cookieToken) {
    console.log("🚨 CSRF Token invalide", {
      method: req.method,
      path: req.path,
      url: req.url,
      originalUrl: req.originalUrl,
      headerToken: headerToken ? "present" : "missing",
      cookieToken: cookieToken ? "present" : "missing",
    });
    return res.status(403).json({ error: "Token CSRF invalide" });
  }


  next();
}


function ensureCsrfToken(req, res, next) {
  try {
    // Si déjà présent, on ne régénère pas
    if (req.cookies && req.cookies["XSRF-TOKEN"]) return next();

    const token = crypto.randomBytes(32).toString("hex");

    // Render + Vercel = https => secure + SameSite=None
    const isProd = process.env.NODE_ENV === "production";
    res.cookie("XSRF-TOKEN", token, {
      httpOnly: false,                 // doit être lisible par le frontend si besoin
      secure: isProd,                  // true en prod (https), false en local
      sameSite: isProd ? "none" : "lax",
      path: "/"
    });

    return next();
  } catch (e) {
    console.error("❌ ensureCsrfToken error:", e);
    return next();
  }
}



// ➕ Monte-les AVANT tes routes protégées
app.use(ensureCsrfToken);
app.use(validateCSRF);


// API profil
//const profileRoutes = require('./routes/profile');
//app.use('/api', profileRoutes);


// Routes principales
const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";

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
  app.get("/dev/recovery-link", async (req, res) => {
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


// ✅ CONFIG FRONT 
app.get("/config.js", (req, res) => {
  res.setHeader("Content-Type", "application/javascript; charset=utf-8");

  // ✅ Autoriser explicitement le chargement cross-origin du script
  res.setHeader("Access-Control-Allow-Origin", "*");

  // ✅ Évite certains blocages CORP/COEP
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");

  // (optionnel mais safe)
  res.setHeader("Cache-Control", "no-store");

  const SUPABASE_URL = process.env.SUPABASE_URL || "";
  const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";

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
  "rediger-offre-recrutement": { fichier: "recrutement/rediger_offre_recrutement", public: false },
  "guide-recrutement": { fichier: "recrutement/guide_recrutement", public: false },
  "recrutement-collectif": { fichier: "recrutement/recrutement_collectif", public: false },
  "communication-candidat": { fichier: "recrutement/communication_candidat", public: false },
  "grille-entretien": { fichier: "recrutement/grille_entretien", public: false },

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
    console.log("ROUTE_SLUG_OK =>", req.path);

    const slug = String(req.params.page || "").replace(".html", "").toLowerCase();
    const config = ROUTES_PROPRES[slug];
    const RESERVED = new Set(["api", "app", "stripe", "health"]);
    if (RESERVED.has(slug)) return res.status(404).sendFile(path.join(__dirname, "../frontend/404.html"));


    // 1) slug inconnu => 404
    if (!config) {
      console.log(`🚨 Page inconnue: ${slug}`);
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
      console.log(`🚨 Accès non authentifié (aucun token): ${slug}`);
      return res.redirect(`/login?next=/${slug}`);
    }

    return authenticateToken(req, res, () => {
      if (!req.user) {
        console.log(`🚨 Accès non authentifié (token invalide/expiré): ${slug}`);
        return res.redirect(`/login?next=/${slug}`);
      }

      // 4) Abonnement actif requis
      if (!req.user.has_active_subscription) {
        console.log(`🚨 Abonnement inactif: ${slug} pour ${req.user.email}`);
        return res.status(403).sendFile(path.join(__dirname, "../frontend/subscription-expired.html"));
      }

      // 5) Contrôle plan (PAGE_MIN_PLAN)
      const pageName = String(fichier).split("/").pop();
      if (!canAccessPageServer(req.user, pageName)) {
        console.log(`🚨 Plan insuffisant (PAGE_MIN_PLAN): ${slug} pour ${req.user.email}`);
        return res.redirect(302, "/403.html");
      }

      // 6) Serve page privée
      const filePathPriv = path.join(__dirname, `../frontend/app/${fichier}.html`);
      if (!fs.existsSync(filePathPriv)) {
        console.log(`🚨 Fichier introuvable: ${filePathPriv}`);
        return res.status(404).sendFile(path.join(__dirname, "../frontend/404.html"));
      }

      console.log(`✅ Accès autorisé: ${slug} (${fichier}) pour ${req.user.email}`);
      return res.sendFile(filePathPriv);
    });


  } catch (error) {
    console.error("💥 Erreur route universelle:", error);
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
    console.warn("⚠️ syncStripeCustomerBillingFromDb: profiles read error:", profErr);
    if (requireComplete) throw new Error("Erreur lecture profil/entreprise");
    return { ok: false, reason: "db_read_error" };
  }

  const company = prof?.companies || null;

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
  const s = v.trim();
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
    .select('plan, status, started_at, created_at, current_period_end, trial_end')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  if (error || !sub) {
    console.log('❌ [SUBSCRIPTION] Aucun abonnement trouvé, fallback trial');
    return {
      plan: 'trial',
      hasActiveSubscription: false,
      status: 'inactive'
    };
  }

  const now = new Date();
  const plan = String(sub.plan || 'trial').toLowerCase();
  const status = String(sub.status || '').toLowerCase();



  const paidPlans = ['standard', 'premium'];

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


  const result = {
    plan,
    status,
    hasActiveSubscription: isPaidActive || isTrialActive,
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
      console.warn("⚠️ apply_pending_prepayment error:", error.message);
      return { ok: false, reason: "rpc_error" };
    }

    if (data?.ok) {
      console.log("✅ Prépayment appliqué automatiquement:", data);
    }

    return data ?? { ok: false, reason: "no_data" };
  } catch (e) {
    console.warn("⚠️ applyPendingPrepaymentIfNeeded exception:", e);
    return { ok: false, reason: "exception" };
  }
}

// recupérer contact depuis table profiles 
async function getContactNameFromProfiles(userId) {
  const { data, error } = await supabaseAdmin
    .from("profiles")
    .select("first_name, last_name")
    .eq("user_id", userId)
    .maybeSingle();

  if (error || !data) return null;

  const full = `${data.first_name ?? ""} ${data.last_name ?? ""}`.trim();
  return full.length ? full : null;
}


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


// Middleware d'authentification
// server.js - NOUVELLE VERSION authenticateToken
async function resolveUserFromCookie(req) {
  const token = req.cookies?.auth_token;
  if (!token) throw new Error("NO_TOKEN");

  // 1) JWT
  const decoded = jwt.verify(token, SECRET_KEY);

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
    console.warn("❌ INVALID_SESSION", {
      sessionError: sessionError?.message,
      user_id: decoded.id,
    });
    throw new Error("INVALID_SESSION");
  }

  // ✅ expires_at : si null => on ne bloque pas ici
  if (session.expires_at) {
    const expiresMs = Date.parse(session.expires_at);
    if (Number.isFinite(expiresMs) && expiresMs < Date.now()) {
      console.warn("⏳ Session expirée (token_sessions)", { expires_at: session.expires_at });
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
  const [profileResult, subscriptionResult] = await Promise.all([
    supabaseAdmin
      .from("profiles")
      .select("user_id, first_name, last_name, company_id, avatar_url, terms_accepted_at, terms_version")
      .eq("user_id", decoded.id)
      .maybeSingle(),
    getActiveSubscription(decoded.id),
  ]);


  if (profileResult.error || !profileResult.data) {
    console.warn("❌ PROFILE_NOT_FOUND", {
      error: profileResult.error?.message,
      user_id: decoded.id,
    });
    throw new Error("PROFILE_NOT_FOUND");
  }

  const user = {
    id: decoded.id,
    email: decoded.email,
    first_name: profileResult.data.first_name,
    last_name: profileResult.data.last_name,
    company_id: profileResult.data.company_id,
    avatar_url: profileResult.data.avatar_url,
    subscription_type: subscriptionResult.plan,
    has_active_subscription: subscriptionResult.hasActiveSubscription,
  };

  cacheSet(cacheKey, user, 15000);
  return user;
}


async function authenticateToken(req, res, next) {
  try {
    req.user = await resolveUserFromCookie(req);

    console.log(
      "✅ AUTH RÉUSSIE - User:",
      req.user.email,
      "Plan:",
      req.user.subscription_type,
      "Actif:",
      req.user.has_active_subscription
    );

    next();
  } catch (error) {
    handleAuthenticationError(req, res, error);
  }
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
  res.clearCookie("auth_token");

  const accept = req.headers.accept || "";
  const wantsHtml = accept.includes("text/html");

  if (wantsHtml) {
    // Affiche une belle page 401 (avec next)
    return res.redirect("/401.html?next=" + encodeURIComponent(req.originalUrl));
  }

  // API/fetch
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


// ✅ ENDPOINT PAIEMENT STRIPE POUR STANDARD/PREMIUM
// ==================== STRIPE CONFIG (TEST/LIVE) ====================
const STRIPE_MODE = (process.env.STRIPE_MODE ?? (process.env.NODE_ENV === "production" ? "live" : "test")).toLowerCase();

const STRIPE_SECRET_KEY =
  STRIPE_MODE === "live"
    ? (process.env.STRIPE_SECRET_KEY_LIVE || process.env.STRIPE_SECRET_KEY)
    : (process.env.STRIPE_SECRET_KEY_TEST || process.env.STRIPE_SECRET_KEY);

const STRIPE_PRICE_STANDARD =
  STRIPE_MODE === "live"
    ? (process.env.STRIPE_PRICE_STANDARD_LIVE || process.env.STRIPE_PRICE_STANDARD)
    : (process.env.STRIPE_PRICE_STANDARD_TEST || process.env.STRIPE_PRICE_STANDARD);

const STRIPE_PRICE_PREMIUM =
  STRIPE_MODE === "live"
    ? (process.env.STRIPE_PRICE_PREMIUM_LIVE || process.env.STRIPE_PRICE_PREMIUM)
    : (process.env.STRIPE_PRICE_PREMIUM_TEST || process.env.STRIPE_PRICE_PREMIUM);

const STANDARD_PREPAY_PRICE_ID =
  STRIPE_MODE === "live"
    ? (process.env.STANDARD_PREPAY_PRICE_ID_LIVE || "")
    : (process.env.STANDARD_PREPAY_PRICE_ID_TEST || "");

const PREMIUM_PREPAY_PRICE_ID =
  STRIPE_MODE === "live"
    ? (process.env.PREMIUM_PREPAY_PRICE_ID_LIVE || "")
    : (process.env.PREMIUM_PREPAY_PRICE_ID_TEST || "");

if (!STRIPE_SECRET_KEY) console.error("❌ Missing STRIPE secret key (resolved)");
if (!STRIPE_PRICE_STANDARD) console.error("❌ Missing STRIPE standard price (resolved)");
if (!STRIPE_PRICE_PREMIUM) console.error("❌ Missing STRIPE premium price (resolved)");
if (!STANDARD_PREPAY_PRICE_ID) console.error("❌ Missing STANDARD_PREPAY price id (resolved)");
if (!PREMIUM_PREPAY_PRICE_ID) console.error("❌ Missing PREMIUM_PREPAY price id (resolved)");

const stripe = require("stripe")(STRIPE_SECRET_KEY);



// ✅ ROUTE POUR RÉCUPÉRER L'ABONNEMENT UTILISATEUR
app.get('/api/my-subscription', authenticateToken, async (req, res) => {
  try {
    console.log('📡 [SERVER] Récupération abonnement pour user:', req.user.id);

    const userId = req.user.id;

    // Utiliser Supabase avec service role (pas de RLS)
    const { data: subscription, error } = await supabaseAdmin
      .from('subscriptions')
      .select('*')
      .eq('user_id', userId)
      .single();

    if (error) {
      if (error.code === 'PGRST116') { // Aucune ligne trouvée
        console.log('📭 [SERVER] Aucun abonnement trouvé pour user:', userId);
        return res.status(404).json({
          error: 'Aucun abonnement trouvé',
          user_id: userId
        });
      }
      console.error('❌ [SERVER] Erreur Supabase:', error);
      return res.status(500).json({ error: 'Erreur base de données' });
    }

    console.log('✅ [SERVER] Abonnement trouvé:', {
      user_id: userId,
      plan: subscription.plan,
      status: subscription.status,
      period_end: subscription.current_period_end
    });

    // ✅ info prépaiement (année suivante)
    const { data: prepaid, error: prepaidErr } = await supabaseAdmin
      .from("subscription_prepayments")
      .select("amount, currency, plan, created_at, checkout_session_id, effective_period_start, effective_period_end")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();


    if (prepaidErr) console.warn("⚠️ prepaid query:", prepaidErr);

    const period_end = subscription.current_period_end || subscription.trial_end || null;


    return res.json({
      ...subscription,
      period_end,
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
    console.error('❌ [SERVER] Erreur récupération abonnement:', error);
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
    console.error("❌ /api/payment-method/status:", e);
    return res.status(500).json({ error: "Erreur status paiement" });
  }
});






// ✅ ROUTE POUR CONFIRMER LA SUPPRESSION (via le lien email)
// Dans ta route /api/request-account-deletion
app.post('/api/request-account-deletion', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { email } = req.body;

    console.log('📧 [SERVER] Demande suppression compte user:', userId);

    // Vérifier l'email
    if (email !== req.user.email) {
      return res.status(400).json({ error: 'Email incorrect' });
    }

    // 🔥 GÉNÉRER UN TOKEN DE SUPPRESSION
    const deletionToken = jwt.sign(
      {
        user_id: userId,
        email: email,
        action: 'delete_account',
        timestamp: Date.now()
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 🔥 CONSTRUIRE LE LIEN DE CONFIRMATION
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const confirmationLink = `${frontendUrl}/confirm-deletion.html?token=${deletionToken}`;

    console.log('🔗 [SERVER] Lien généré:', confirmationLink);

    // 🔥 APPEL EDGE FUNCTION AVEC SERVICE ROLE KEY
    console.log('📡 [SERVER] Appel Edge Function...');

    const edgeResponse = await fetch(`${process.env.SUPABASE_URL}/functions/v1/send-deletion-email`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        user_id: userId,
        email: email,
        confirmation_link: confirmationLink
      })
    });

    console.log('📡 [SERVER] Réponse Edge Function status:', edgeResponse.status);

    const edgeResult = await edgeResponse.json();
    console.log('📡 [SERVER] Réponse Edge Function:', edgeResult);

    if (!edgeResponse.ok) {
      console.error('❌ [SERVER] Erreur Edge Function:', edgeResult);

      // ⚠️ MODE SECOURS : Retourner le lien directement
      return res.json({
        success: true,
        message: 'Lien de suppression généré (mode secours)',
        link: confirmationLink,
        test_mode: true
      });
    }

    console.log('✅ [SERVER] Email envoyé avec succès');

    res.json({
      success: true,
      message: 'Email de confirmation envoyé'
    });

  } catch (error) {
    console.error('❌ [SERVER] Erreur demande suppression:', error);

    // ⚠️ MODE SECOURS EN CAS D'ERREUR
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const confirmationLink = `${frontendUrl}/confirm-deletion.html?token=fallback_${Date.now()}`;

    res.json({
      success: true,
      message: 'Lien de suppression généré (mode erreur)',
      link: confirmationLink,
      test_mode: true,
      error: error.message
    });
  }
});

// ✅ ROUTE POUR CONFIRMER LA SUPPRESSION (AVEC ARCHIVAGE)
app.post('/api/confirm-account-deletion', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Token manquant' });
    }

    // 🔥 VÉRIFIER LE TOKEN
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.action !== 'delete_account') {
      return res.status(400).json({ error: 'Token invalide' });
    }

    const userId = decoded.user_id;
    const userEmail = decoded.email;

    console.log('🚨 [SERVER] Confirmation suppression user:', userId);

    // 🔥 1. RÉCUPÉRER TOUTES LES DONNÉES POUR ARCHIVAGE
    const { data: profileData } = await supabaseAdmin
      .from('profiles')
      .select(`
                *,
                companies (*)
            `)
      .eq('user_id', userId)
      .single();

    const { data: subscriptionData } = await supabaseAdmin
      .from('subscriptions')
      .select('*')
      .eq('user_id', userId)
      .single();

    const { data: companyData } = await supabaseAdmin
      .from('companies')
      .select('*')
      .eq('owner_id', userId)
      .single();

    // 🔥 2. ARCHIVAGE COMPLET
    const { error: archiveError } = await supabaseAdmin
      .from('deleted_users_archive')
      .insert({
        user_id: userId,
        email: userEmail,

        // Données profil
        profile_data: profileData,
        first_name: profileData?.first_name,
        last_name: profileData?.last_name,
        phone: profileData?.phone,
        avatar_url: profileData?.avatar_url,
        company_id: profileData?.company_id,

        // Données entreprise
        company_data: companyData,
        company_legal_name: companyData?.legal_name,
        company_display_name: companyData?.display_name,

        // Données abonnement
        subscription_data: subscriptionData,
        plan_type: subscriptionData?.plan,
        subscription_status: subscriptionData?.status,
        current_period_end: subscriptionData?.current_period_end,
        stripe_customer_id: subscriptionData?.stripe_customer_id,
        stripe_subscription_id: subscriptionData?.stripe_subscription_id
      });

    if (archiveError) {
      console.error('❌ [SERVER] Erreur archivage:', archiveError);
    }

    // 🔥 3. SUPPRIMER L'ABONNEMENT STRIPE
    try {
      if (subscriptionData && subscriptionData.stripe_subscription_id) {
        await stripe.subscriptions.cancel(subscriptionData.stripe_subscription_id);

        if (subscriptionData.stripe_customer_id) {
          await stripe.customers.del(subscriptionData.stripe_customer_id);
        }
      }
    } catch (stripeError) {
      console.warn('⚠️ [SERVER] Erreur nettoyage Stripe:', stripeError);
    }

    // 🔥 4. SUPPRESSION DES DONNÉES (dans l'ordre logique)

    // D'abord supprimer l'entreprise si elle existe
    if (companyData) {
      await supabaseAdmin.from('companies').delete().eq('owner_id', userId);
    }

    // Puis les abonnements
    await supabaseAdmin.from('subscriptions').delete().eq('user_id', userId);

    // Puis le profil
    await supabaseAdmin.from('profiles').delete().eq('user_id', userId);

    // 🔥 5. SUPPRIMER LE COMPTE AUTH
    const { error: deleteError } = await supabaseAdmin.auth.admin.deleteUser(userId);

    if (deleteError) {
      console.error('❌ [SERVER] Erreur suppression user auth:', deleteError);
      return res.status(500).json({ error: 'Erreur suppression compte' });
    }

    console.log('✅ [SERVER] Compte archivé et supprimé user:', userId);

    res.json({
      success: true,
      message: 'Compte supprimé définitivement',
      user_id: userId,
      archived: true
    });

  } catch (error) {
    console.error('❌ [SERVER] Erreur confirmation suppression:', error);

    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Lien expiré, veuillez refaire une demande' });
    }

    res.status(500).json({ error: 'Erreur lors de la suppression' });
  }
});


// ==========================================
// ✅ Validation serveur stricte
// ==========================================
// ✅ Whitelist stricte (doit matcher inscription.html)
const ALLOWED_COMPANY_SIZES = new Set(["1-10", "11-50", "51-200", "201-500", "501+"]);
const ALLOWED_PLANS = new Set(["trial", "standard", "premium"]);

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());
}

//verifier si compte payant existe mode standard & premium pour l'inscription
async function authEmailExists(emailNorm) {
  const target = String(emailNorm || "").toLowerCase().trim();
  if (!target) return false;

  const perPage = 1000;
  let page = 1;

  for (let i = 0; i < 20; i++) { // garde-fou (20k users max scannés)
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page, perPage });
    if (error) throw error;

    const users = data?.users || [];
    if (users.some(u => String(u?.email || "").toLowerCase().trim() === target)) return true;

    if (users.length < perPage) break;
    page += 1;
  }

  return false;
}







async function retrieveProrationPreview(stripe, {
  userId,
  customerId,
  subscriptionId,
  subscriptionItemId,
  newPriceId,
  currentPriceId,
}) {
  const now = Math.floor(Date.now() / 1000);

  console.log("🔍 CHANGE PLAN LIVE CHECK", {
    stripeMode: STRIPE_MODE,
    user_id: userId,
    customerId,
    subscriptionId,
    subscriptionItemId,
    currentPrice: currentPriceId || null,
    targetPrice: newPriceId,
    isLiveKey: STRIPE_SECRET_KEY?.startsWith("sk_live"),
  });

  const preview = await stripe.invoices.createPreview({
    customer: customerId,
    subscription: subscriptionId,
    subscription_details: {
      proration_behavior: "create_prorations",
      proration_date: now,
      items: [
        {
          id: subscriptionItemId,
          price: newPriceId,
          quantity: 1,
        },
      ],
    },
  });

  return preview;
}



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
      console.warn("⚠️ Stripe customer introuvable dans ce mode, on recrée", {
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
// 🔁 UPGRADE STANDARD → PREMIUM (Checkout prorata)
// ✅ Stripe calcule le prorata (retrieveUpcoming)
// ✅ l’utilisateur paye via Stripe Checkout (payment)
// ✅ après paiement, le webhook applique l’upgrade (sans prorata)
// ==========================================
app.post("/api/change-plan", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { newPlan } = req.body;

    if (newPlan !== "premium") {
      return res.status(400).json({ error: "Upgrade autorisé uniquement vers Premium" });
    }

    const { data: sub, error } = await supabaseAdmin
      .from("subscriptions")
      .select("stripe_subscription_id, stripe_customer_id, plan")
      .eq("user_id", userId)
      .single();

    if (error || !sub?.stripe_subscription_id || !sub?.stripe_customer_id) {
      return res.status(400).json({ error: "Aucun abonnement Stripe actif" });
    }

    if (sub.plan !== "standard") {
      return res.status(400).json({ error: "Upgrade possible uniquement depuis Standard" });
    }

    // ✅ garantir un customer valide dans le mode courant (test/live)
    const ensured = await ensureStripeCustomer({
      userId,
      email: req.user?.email ?? null,
      existingCustomerId: sub.stripe_customer_id,
    });




    const PREMIUM_PRICE_ID = STRIPE_PRICE_PREMIUM;
    if (!PREMIUM_PRICE_ID) {
      return res.status(500).json({ error: "STRIPE_PRICE_PREMIUM manquant (mode " + STRIPE_MODE + ")" });
    }


    const FRONTEND_URL = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";




    // 1) récupérer subscription + item courant
    const subscriptionId = sub.stripe_subscription_id;
    const customerId = sub.stripe_customer_id;

    // 1) Récup subscription Stripe
    const stripeSub = await stripe.subscriptions.retrieve(subscriptionId);

    // 2) Customer réel de la subscription
    const subCustomerId = typeof stripeSub.customer === "string" ? stripeSub.customer : null;
    if (!subCustomerId) {
      return res.status(400).json({ error: "Stripe subscription has no customer" });
    }

    // 3) Si DB customer != Stripe customer, on resync DB (optionnel mais top)
    if (customerId !== subCustomerId) {
      console.log("🛠️ Resync stripe_customer_id from subscription.customer", {
        dbCustomerId: customerId,
        stripeCustomerId: subCustomerId,
      });

      await supabaseAdmin
        .from("subscriptions")
        .update({ stripe_customer_id: subCustomerId })
        .eq("user_id", userId);
    }

    const customerIdForUpgrade = subCustomerId;

    const itemId = stripeSub?.items?.data?.[0]?.id;
    if (!itemId) {
      return res.status(400).json({ error: "Subscription Stripe invalide (item manquant)" });
    }

    // ✅ sync facturation avant de créer un checkout
    try {
      await syncStripeCustomerBillingFromDb({
        userId,
        stripeCustomerId: customerIdForUpgrade,
        requireComplete: true,
      });

    } catch (e) {
      if (e?.code === "BILLING_INCOMPLETE") {
        return res.status(400).json({ error: e.message, code: "BILLING_INCOMPLETE" });
      }
      console.error("❌ sync billing (change-plan) error:", e);
      return res.status(500).json({ error: "Erreur sync facturation (Stripe)" });
    }

    // 2) demander à Stripe le "prorata dû maintenant" (quote)
    // IMPORTANT: on simule l’update (nouveau price) sans la faire encore
    const now = Math.floor(Date.now() / 1000);

    const preview = await retrieveProrationPreview(stripe, {
      userId,
      customerId: customerIdForUpgrade,
      subscriptionId: sub.stripe_subscription_id,
      subscriptionItemId: itemId,
      newPriceId: PREMIUM_PRICE_ID,
      currentPriceId: stripeSub?.items?.data?.[0]?.price?.id,
    });


    const amountDue = typeof preview?.amount_due === "number" ? preview.amount_due : 0;
    const currency = (preview?.currency || "eur").toLowerCase();


    // Si Stripe dit 0 (rare mais possible), pas besoin de paiement → on peut appliquer direct via webhook-like
    // (je te conseille quand même de gérer ce cas)
    if (amountDue <= 0) {
      return res.json({
        url: `${FRONTEND_URL}/app/profile.html?upgrade=free`,
      });
    }

    let receiptEmail = null;
    try {
      const customer = await stripe.customers.retrieve(ensured.customerId);
      if (customer && !customer.deleted) {
        receiptEmail = customer.email || null;
      }
    } catch (e) {
      console.warn("⚠️ Unable to retrieve customer email for Stripe receipt:", e);
    }

    const contactName = await getContactNameFromProfiles(userId);
    // 3) Checkout Session (payment) = l’utilisateur paye UNIQUEMENT le prorata
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer: customerIdForUpgrade,
      locale: "fr",
      // ✅ TVA auto (Stripe Tax)
      automatic_tax: { enabled: true },
      billing_address_collection: "required",
      customer_update: { name: "auto", address: "auto" },


      payment_intent_data: receiptEmail
        ? { receipt_email: receiptEmail }
        : undefined,

      invoice_creation: {
        enabled: true,
        invoice_data: {
          description: "INTEGORA — Upgrade Standard → Premium (prorata)",
          metadata: {
            action: "upgrade_proration",
            user_id: userId,
            plan: "premium",
            subscription_id: sub.stripe_subscription_id,
          },
        },
      },


      line_items: [
        {
          price_data: {
            currency,
            unit_amount: amountDue,
            tax_behavior: "exclusive",
            product_data: {
              name: "INTEGORA — Prorata upgrade Standard → Premium",
              tax_code: "txcd_10103000",
            },
          },
          quantity: 1,
        },
      ],


      success_url: `${FRONTEND_URL}/app/profile.html?upgrade=success`,
      cancel_url: `${FRONTEND_URL}/app/profile.html?upgrade=cancel`,

      metadata: {
        action: "upgrade_proration",
        user_id: userId,
        subscription_id: sub.stripe_subscription_id,
        new_price_id: PREMIUM_PRICE_ID,
        subscription_item_id: itemId,
      },
    });



    return res.json({ url: session.url });
  } catch (e) {
    console.error("❌ change-plan checkout error", {
      message: e?.message,
      type: e?.type,
      code: e?.code,
      rawType: e?.rawType,
      param: e?.param,
      requestId: e?.requestId,
    });
    return res.status(500).json({ error: "stripe_error" });
  }


});






// ==========================================
// payer l’année suivante
// ==========================================

// 💰 Montants en centimes par plan


app.post("/api/prepay-next-year/session", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const { data: sub, error } = await supabaseAdmin
      .from("subscriptions")
      .select("plan, stripe_customer_id, current_period_end, trial_end")
      .eq("user_id", userId)
      .single();

    if (error || !sub?.stripe_customer_id) {
      return res.status(400).json({ error: "Aucun customer Stripe" });
    }

    // ✅ empêcher un 2e prépaiement en attente
    const { data: pendingPrepay, error: prepayErr } = await supabaseAdmin
      .from("subscription_prepayments")
      .select("id")
      .eq("user_id", userId)
      .is("consumed_at", null)
      .limit(1);

    if (prepayErr) {
      console.error("❌ prepay-next-year pending check error:", prepayErr);
      return res.status(500).json({ error: "Erreur vérification prépaiement" });
    }

    if (pendingPrepay?.length) {
      return res.status(409).json({
        error: "prepay_already_exists",
        message: "Vous avez déjà un prépaiement en attente. Il sera appliqué automatiquement au prochain renouvellement.",
      });
    }

    // ✅ 1) plan demandé
    const requestedPlan = String(req.body?.plan ?? "").trim().toLowerCase();
    if (requestedPlan !== "standard" && requestedPlan !== "premium") {
      return res.status(400).json({ error: "Plan invalide" });
    }
    const plan = requestedPlan;

    // ✅ 2) garantir un customer valide (test/live)
    const ensured = await ensureStripeCustomer({
      userId,
      email: req.user?.email ?? null,
      existingCustomerId: sub.stripe_customer_id,
    });

    // ✅ 3) sync facturation AVANT checkout (adresse + SIRET + raison sociale)
    try {
      await syncStripeCustomerBillingFromDb({
        userId,
        stripeCustomerId: ensured.customerId,
        requireComplete: true,
      });
    } catch (e) {
      if (e?.code === "BILLING_INCOMPLETE") {
        return res.status(400).json({ error: e.message, code: "BILLING_INCOMPLETE" });
      }
      console.error("❌ sync billing (prepay) error:", e);
      return res.status(500).json({ error: "Erreur sync facturation (Stripe)" });
    }


    const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

    // ==========================================
    // Page profil paiement règle moins de 366 jours
    // ==========================================
    const endStr = sub.current_period_end || sub.trial_end;
    if (endStr) {
      const end = new Date(endStr);
      const now = new Date();
      const ms = end.getTime() - now.getTime();
      const daysRemaining = Math.ceil(ms / (1000 * 60 * 60 * 24));

      if (daysRemaining > 366) {
        return res.status(400).json({
          error: "Le prépaiement est disponible uniquement à moins d’un an de l’échéance.",
          daysRemaining
        });
      }
    }

    // Email reçu Stripe (optionnel)


    let receiptEmail = null;
    try {
      const customer = await stripe.customers.retrieve(ensured.customerId);
      if (customer && !customer.deleted) {
        receiptEmail = customer.email || null;
      }
    } catch (e) {
      console.warn("⚠️ Unable to retrieve customer email for Stripe receipt:", e);
    }




    // 0) Bloquer si un prépaiement non consommé existe déjà
    const { data: pending, error: pendingErr } = await supabase
      .from("subscription_prepayments")
      .select("id, checkout_session_id, applied_invoice_id, created_at")
      .eq("user_id", userId)
      .is("consumed_at", null)
      .limit(1)
      .maybeSingle();

    if (pendingErr) {
      console.error("prepay_next_year: lookup pending error", pendingErr);
      return res.status(500).json({ error: "pending_lookup_failed" });
    }

    if (pending?.id) {
      return res.status(409).json({
        error: "prepay_already_exists",
        message: "Vous avez déjà un prépaiement en attente. Il sera appliqué automatiquement au prochain renouvellement.",
      });
    }

    const priceId = plan === "premium" ? STRIPE_PRICE_PREMIUM : STRIPE_PRICE_STANDARD;
    if (!priceId) return res.status(500).json({ error: "Missing Stripe price for plan" });



    // ✅ 1) stripe_customer_id depuis la DB
    const stripeCustomerId = sub?.stripe_customer_id || null;

    // ✅ 2) email : utilise celui du user (ou receiptEmail si c'est ton email fiable)
    const userEmail = receiptEmail ?? null; // ou req.user.email si tu l'as



    // ✅ 3) sync billing AVANT checkout (facture complète : raison sociale, SIRET, adresse)
    await syncStripeCustomerBillingFromDb({
      userId,
      stripeCustomerId: ensured.customerId,
      requireComplete: true,
    });

    const prepayPriceId =
      plan === "premium" ? PREMIUM_PREPAY_PRICE_ID : STANDARD_PREPAY_PRICE_ID;

    console.log("🧪 prepay resolved", { STRIPE_MODE, plan, prepayPriceId });

    if (!prepayPriceId) {
      return res.status(500).json({
        error: "Missing prepay price id",
        plan,
        STRIPE_MODE,
      });
    }

    const contactName = await getContactNameFromProfiles(userId);

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer: ensured.customerId,
      locale: "fr",
      automatic_tax: { enabled: true },
      billing_address_collection: "required",
      customer_update: { name: "auto", address: "auto" },

      invoice_creation: {
        enabled: true,
        invoice_data: {
          description: `INTEGORA — Pré-paiement année suivante (${plan})`,
          metadata: { action: "prepay_next_year", user_id: userId, plan },
        },
      },

      line_items: [
        {
          price: prepayPriceId,   // ✅ on utilise un Price Stripe existant (one-off)
          quantity: 1,
        },
      ],

      success_url: `${FRONTEND_URL}/app/profile.html?prepay=success`,
      cancel_url: `${FRONTEND_URL}/app/profile.html?prepay=cancel`,

      metadata: {
        action: "prepay_next_year",
        user_id: userId,
        plan,
      },
    });

    return res.json({ url: session.url });


  } catch (err) {
    console.error("❌ prepay-next-year error:", err);
    return res.status(500).json({ error: "Erreur création session Stripe" });
  }
});




// ==========================================
// 🔁 TOGGLE RENOUVELLEMENT (cancel_at_period_end)
// ==========================================
app.post('/api/subscription/toggle-renewal', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { autoRenew } = req.body; // boolean

    const { data: sub, error } = await supabaseAdmin
      .from('subscriptions')
      .select('stripe_subscription_id')
      .eq('user_id', userId)
      .single();

    if (error || !sub?.stripe_subscription_id) {
      return res.status(400).json({ error: "Aucun abonnement Stripe actif" });
    }

    const current = await stripe.subscriptions.retrieve(sub.stripe_subscription_id);

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
    console.error("❌ toggle-renewal error:", err);
    res.status(500).json({ error: "Erreur renouvellement" });
  }
});




// ==========================================
// ✅ TRIAL -> PAID : créer une nouvelle subscription Stripe via Checkout
// ==========================================
app.post("/api/subscribe/session", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const desiredPlan = req.body?.plan;

    if (!["standard", "premium"].includes(desiredPlan)) {
      return res.status(400).json({ error: "Plan invalide" });
    }

    // 1) récupérer infos locales (customer existant ?)
    const { data: subRow } = await supabaseAdmin
      .from("subscriptions")
      .select("stripe_customer_id, stripe_subscription_id, plan")
      .eq("user_id", userId)
      .maybeSingle();

    // Si déjà une subscription Stripe -> on ne passe pas ici
    if (subRow?.stripe_subscription_id) {
      return res.status(400).json({
        error: "Abonnement Stripe déjà actif, utilise change-plan."
      });
    }

    // 2) price mapping
    const PRICE_BY_PLAN = {
      standard: STRIPE_PRICE_STANDARD,
      premium: STRIPE_PRICE_PREMIUM,
    };

    const priceId = PRICE_BY_PLAN[desiredPlan];
    if (!priceId) return res.status(500).json({ error: "PriceId Stripe manquant" });

    const FRONTEND_URL = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";

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
      console.error("❌ sync billing (subscribe/session) error:", e);
      return res.status(500).json({ ok: false, error: "Erreur sync facturation (Stripe)" });
    }


    // 🧪 DEBUG
    console.log("🧪 SUBSCRIBE DEBUG (/api/subscribe/session)", {
      desiredPlan,
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
        plan: desiredPlan
      },

      subscription_data: {
        metadata: {
          action: "subscribe_paid",
          user_id: userId,
          plan: desiredPlan
        },

      },

      // ✅ si tu veux forcer la saisie d’un moyen de paiement à l’achat
      payment_method_collection: "always",

    });

    return res.json({ url: session.url });

  } catch (e) {
    console.error("❌ /api/subscribe/session:", e?.raw?.message || e);
    return res.status(500).json({
      error: "Erreur création session Stripe",
      details: e?.raw?.message || e.message
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
      console.log("🔐 Tentative de connexion (opaque) pour:", String(email).trim().toLowerCase());
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
        console.log("❌ Login refusé (opaque). Reason:", authError?.message || "no_user");
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
      .select("first_name, last_name, company_id")
      .eq("user_id", user_id)
      .single();

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
    const isProd = process.env.NODE_ENV === "production";
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
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
    console.error("💥 Erreur login:", error);
    return res.status(500).json({
      success: false,
      error: "Erreur serveur lors de la connexion.",
    });
  }
});


// ✅ ROUTE DE DEBUG COOKIES
app.get("/api/debug-cookies", (req, res) => {


  res.json({
    cookies: req.cookies,
    headers: req.headers,
    message: "Debug cookies"
  });
});

// 🧪 ROUTE DE TEST - À ajouter temporairement
app.post("/test-supabase", async (req, res) => {

  const { email, password } = req.body;

  try {
    // Test 1: Vérifier la configuration Supabase
    console.log("🔧 Configuration Supabase:", {
      url: process.env.SUPABASE_URL ? "✅ Définie" : "❌ Manquante",
      key: process.env.SUPABASE_SERVICE_ROLE_KEY ? "✅ Définie" : "❌ Manquante"
    });

    // Test 2: Tester l'authentification
    const { data, error } = await supabase.auth.signInWithPassword({
      email: email || "test@test.com",
      password: password || "test123"
    });

    console.log("📋 Résultat test auth:", {
      success: !error,
      error: error?.message,
      user_id: data?.user?.id
    });

    // Test 3: Vérifier si l'utilisateur existe dans auth.users
    if (email) {
      console.log("🔍 Recherche utilisateur dans auth.users...");
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
    console.log("💥 Erreur test:", error);
    res.status(500).json({ error: error.message });
  }
});


// 🧪 ROUTE TEST COOKIE - À AJOUTER AVANT /verify-token
app.post("/test-cookie", (req, res) => {

  if (req.cookies?.auth_token) {
    try {
      const decoded = jwt.verify(req.cookies.auth_token, SECRET_KEY);
      console.log('✅ [TEST] Token JWT valide:', decoded);
      return res.json({ valid: true, hasCookie: true, tokenValid: true });
    } catch (error) {
      console.log('❌ [TEST] Token JWT invalide:', error.message);
      return res.json({ valid: false, hasCookie: true, tokenValid: false });
    }
  }

  res.json({ valid: false, hasCookie: false, tokenValid: false });
});


// 📌 VÉRIFICATION DU TOKEN
// server.js - NOUVELLE VERSION /verify-token
app.post("/verify-token", async (req, res) => {
  try {
    const user = await resolveUserFromCookie(req);
    return res.json({ valid: true, user });
  } catch (error) {
    return res.json({ valid: false });
  }
});


// 🧪 TEST SERVICE ROLE
app.get('/api/test-service-role', async (req, res) => {
  try {
    // Test 1: Lecture simple
    const { data: testData, error: testError } = await supabase
      .from('token_sessions')
      .select('count')
      .limit(1);

    console.log('🔑 Test Service Role - Lecture:', testError ? '❌ ' + testError.message : '✅ Succès');

    // Test 2: Écriture
    const { error: insertError } = await supabase
      .from('token_sessions')
      .insert({
        user_id: '00000000-0000-0000-0000-000000000000', // UUID fictif pour test
        token_hash: 'test_hash',
        expires_at: new Date().toISOString(),
        is_active: true
      });

    console.log('🔑 Test Service Role - Écriture:', insertError ? '❌ ' + insertError.message : '✅ Succès');

    res.json({
      read: testError ? testError.message : 'OK',
      write: insertError ? insertError.message : 'OK'
    });

  } catch (error) {
    res.json({ error: error.message });
  }
});
// ---------------------------
// ROUTES PROTÉGÉES AVEC ABONNEMENTS
// ---------------------------

app.get("/test-supabase", async (req, res) => {
  try {
    const { data, error } = await supabase.auth.getUser();
    res.json({
      status: "OK",
      user: data.user,
      error: error?.message
    });
  } catch (error) {
    res.json({ error: error.message });
  }
});


// ==================== ROUTES API PROFIL INLINE ====================

// ✅ Route de santé pour debug
app.get('/api/health', (req, res) => {
  console.log('🔧 [API Health] Test route appelée');
  res.json({
    ok: true,
    scope: 'server.js-inline',
    timestamp: new Date().toISOString()
  });
});


// ✅ ROUTE MY-PROFILE - VÉRIFIEZ QU'ELLE RETOURNE avatar_url
app.get('/api/my-profile', authenticateToken, async (req, res) => {
  console.log('👤 [API My-Profile] Début - User ID:', req.user?.id);

  try {
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('first_name, last_name, phone, company_id, avatar_url')
      .eq('user_id', req.user.id)
      .single();

    console.log('📊 [API My-Profile] Résultat Supabase:', {
      hasData: !!profile,
      error: error?.message,
      avatar_url: profile?.avatar_url // ← Doit être présent
    });

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
      avatar_url: profile.avatar_url  // ⚠️ CRITIQUE : toujours inclure
    };

    console.log('✅ [API My-Profile] Succès - avatar_url:', responseData.avatar_url);
    res.json(responseData);

  } catch (error) {
    console.error('💥 [API My-Profile] Exception:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// ✅ Lecture des infos entreprise (companies) -> auto-remplissage profile.html
app.get("/api/my-company", authenticateToken, async (req, res) => {
  console.log("🏢 [API My-Company] User ID:", req.user?.id);

  try {
    const { data: company, error } = await supabase
      .from("companies")
      .select(
        "id, legal_name, display_name, company_size, company_siret, billing_street, billing_postal_code, billing_city, billing_country",
      )
      .eq("owner_id", req.user.id)
      .maybeSingle();

    if (error) {
      console.error("❌ [API My-Company] Supabase error:", error);
      return res.status(400).json({ ok: false, error: error.message });
    }

    // Si pas encore de company : on renvoie un objet vide (pas une 404)
    return res.json(company || {});
  } catch (e) {
    console.error("💥 [API My-Company] Exception:", e);
    return res.status(500).json({ ok: false, error: "Erreur serveur my-company" });
  }
});


// ✅ Mise à jour du profil (POST au lieu de PUT pour CSRF)
app.post('/api/update-profile', authenticateToken, async (req, res) => {
  console.log('✏️ [API Update-Profile] Début - User ID:', req.user?.id);
  console.log('📦 [API Update-Profile] Données reçues:', req.body);

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

    console.log('🔄 [API Update-Profile] Données à mettre à jour:', updateData);

    const { data, error } = await supabase
      .from('profiles')
      .update(updateData)
      .eq('user_id', req.user.id)
      .select() // Retourne les données mises à jour
      .single();

    if (error) {
      console.error('❌ [API Update-Profile] Erreur Supabase:', error);
      return res.status(400).json({
        ok: false,
        error: 'Échec de la mise à jour: ' + error.message
      });
    }

    console.log('✅ [API Update-Profile] Succès - Données mises à jour:', data);
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
    console.error('💥 [API Update-Profile] Exception:', error);
    res.status(500).json({
      ok: false,
      error: 'Erreur serveur lors de la mise à jour du profil'
    });
  }
});



app.post("/api/company/update-billing", authenticateToken, async (req, res) => {
  console.log("🏢 [API update-billing] User:", req.user?.id);
  console.log("📦 [API update-billing] Body:", req.body);

  try {
    const owner_id = req.user.id;

    const body = req.body || {};

    // 1) Nettoyage/validation (backend = source de vérité sécurité)
    const legal_name = cleanTextStrict(body.legal_name, { max: 120, allowEmpty: false });
    if (!legal_name) {
      return res.status(400).json({ ok: false, error: "Raison sociale invalide." });
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
        await syncStripeCustomerBillingFromDb(subRow.stripe_customer_id, owner_id);
        stripe_synced = true;
      }
    } catch (e) {
      console.warn("⚠️ Stripe sync skipped (update-billing):", e);
    }

    return res.json({ ok: true, message: "Entreprise mise à jour", company, stripe_synced });


    return res.json({ ok: true, message: "Entreprise mise à jour", company });
  } catch (e) {
    console.error("💥 [API update-billing] Exception:", e);
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
      return res.status(500).json({ ok: false, error: "Erreur serveur: " + error.message });
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
      return res.status(500).json({ ok: false, error: error.message });
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

    // ✅ IMPORTANT : ton fichier default est dans "default/default-avatar.png"
    const DEFAULT_AVATAR_PATH = "default/default-avatar.png";

    const path = normalizeAvatarPath(prof?.avatar_url) || DEFAULT_AVATAR_PATH;

    const { data: signed, error: signErr } = await supabase.storage
      .from("Avatars")
      .createSignedUrl(path, 60 * 60);

    if (signErr) {
      // 🔎 te donne un log explicite pour ne plus être dans le flou
      console.error("❌ /api/my-avatar-url createSignedUrl error:", signErr, "path:", path);
      return res.status(500).json({ ok: false, error: signErr.message, path });
    }

    return res.json({ ok: true, url: signed.signedUrl, path });
  } catch (e) {
    console.error("💥 /api/my-avatar-url exception:", e);
    return res.status(500).json({ ok: false, error: e.message });
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

    const { data, error } = await supabase.storage.from('public').download(pathInBucket);
    if (error || !data) {
      console.log('❌ [Public Preview] Fichier non trouvé:', pathInBucket);
      return res.status(404).send('Not found');
    }

    const mimeType = guessMime(pathInBucket);
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    return res.send(Buffer.from(await data.arrayBuffer()));
  } catch (e) {
    console.error('💥 [Public Preview] Erreur:', e);
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
      console.log('❌ [Protected Asset] Asset non trouvé ou inactif:', assetId);
      return serveFallbackImage(res);
    }

    // 🔄 RÉESSAI SUR LE TÉLÉCHARGEMENT
    const { data: file, error: dlErr } = await withRetry(
      () => supabase.storage
        .from(asset.bucket)
        .download(asset.path)
    );

    if (dlErr || !file) {
      console.log('❌ [Protected Asset] Erreur download:', dlErr);
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
    console.error('💥 [Protected Asset] Erreur finale:', error);
    return serveFallbackImage(res);
  }
});

// 🖼️ FONCTION FALLBACK MANQUANTE - AJOUTE-LA !
function serveFallbackImage(res) {
  console.log('🔄 Utilisation de l\'image de fallback');
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
  console.log("🟡 [START-PAID] Reçu:", JSON.stringify(req.body, null, 2));
  console.log("🧾 [START-PAID] STRIPE_MODE =", STRIPE_MODE);
  console.log("🧾 [START-PAID] STRIPE_SECRET_KEY starts live =", STRIPE_SECRET_KEY?.startsWith("sk_live"));
  console.log("🧾 [START-PAID] STRIPE_SECRET_KEY starts test =", STRIPE_SECRET_KEY?.startsWith("sk_test"));
  console.log("🧾 [START-PAID] HOST =", req.headers.host);
  console.log("🧾 [START-PAID] ORIGIN =", req.headers.origin);

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
    if (!["standard", "premium"].includes(desired_plan)) {
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
    if (!/^\d{4}-\d{2}-\d{2}$/.test(termsVersionRaw)) {
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
      console.error("❌ pending_signups select error:", existingErr);
      return res.status(500).json({ error: "Erreur lecture pending_signups", details: existingErr.message });
    }

    let pending_id;

    if (existingPending) {
      pending_id = existingPending.id;

      console.log("ℹ️ pending existant réutilisé:", pending_id);

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
        console.error("❌ pending_signups update error:", updErr);
        return res.status(500).json({ error: "Erreur update pending_signup", details: updErr.message });
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
        console.error("❌ pending_signups insert error:", pendingErr);
        return res.status(500).json({ error: "Impossible de créer pending_signup", details: pendingErr?.message });
      }

      pending_id = pending.id;
      console.log("✅ pending créé:", pending_id);
    }

    // ✅ 2) Price mapping (ENV)
    const priceIds = {
      standard: STRIPE_PRICE_STANDARD,
      premium: STRIPE_PRICE_PREMIUM,
    };
    const priceId = priceIds[desired_plan];


    if (!priceId) {
      return res.status(500).json({
        error: "PriceId Stripe manquant côté serveur (STRIPE_PRICE_STANDARD / STRIPE_PRICE_PREMIUM)"
      });
    }

    // ✅ 3) Créer session Stripe (nouvelle session à chaque tentative)
    const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";

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
      },

      subscription_data: {
        metadata: {
          pending_id,
          desired_plan,
          user_email: emailNorm,
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
      console.error("❌ pending_signups update stripe_session_id error:", sessUpdErr);
      return res.status(500).json({ error: "Erreur update stripe_session_id", details: sessUpdErr.message });
    }

    return res.json({
      checkoutUrl: session.url,
      pending_id,
      session_id: session.id
    });

  } catch (e) {
    console.error("❌ [START-PAID] error:", e);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});



app.post("/api/complete-signup", async (req, res) => {
  console.log("🟢 [COMPLETE] Reçu:", JSON.stringify(req.body, null, 2));

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

    if (!["standard", "premium"].includes(pending.desired_plan)) {
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
    const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";
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
        const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";
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
    console.error("❌ [COMPLETE] error:", e);
    return res.status(500).send(`Erreur complete-signup: ${e.message}`);
  }
});

//remplir table subscriptions quand la personne clique sur le mail
app.post("/api/finalize-pending", async (req, res) => {
  console.log("🟦 FINALIZE-PENDING HIT");
  console.log("🟦 FINALIZE body:", JSON.stringify(req.body));

  try {
    const pending_id = String(req.body?.pending_id || "").trim();
    if (!pending_id) return res.status(400).json({ error: "pending_id requis" });

    // 1) Vérifier session Supabase (user connecté via lien email)
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    console.log("🧪 FINALIZE auth header present:", Boolean(auth));
    console.log("🧪 FINALIZE token length:", token ? token.length : 0);
    console.log("🧪 FINALIZE token preview:", token ? token.slice(0, 20) + "..." : "null");

    if (!token) return res.status(401).json({ error: "Missing bearer token" });

    // ✅ AJOUT ICI
    const payload = decodeJwtPayload(token);
    console.log("🧪 FINALIZE jwt iss:", payload?.iss);
    console.log("🧪 FINALIZE jwt sub:", payload?.sub);
    console.log("🧪 FINALIZE jwt aud:", payload?.aud);
    console.log("🧪 FINALIZE jwt exp:", payload?.exp);

    // puis ton getUser existant
    const { data: userData, error: userErr } = await supabaseAdmin.auth.getUser(token);
    console.log("🧪 FINALIZE getUser has user:", Boolean(userData?.user));


    const user = userData?.user;
    if (userErr || !user) return res.status(401).json({ error: "Invalid session" });

    // 2) Charger pending
    const { data: pending, error: pErr } = await supabaseAdmin
      .from("pending_signups")
      .select("*")
      .eq("id", pending_id)
      .single();

    console.log("🟦 FINALIZE pending.desired_plan:", pending?.desired_plan);
    console.log("🟦 FINALIZE pending.user_id:", pending?.user_id);
    console.log("🟦 FINALIZE user.id (auth):", user.id);


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

      console.log("🟦 PAY GATE plan:", plan);
      console.log("🟦 PAY GATE stripe_customer_id:", pending.stripe_customer_id);
      console.log("🟦 PAY GATE stripe_subscription_id:", pending.stripe_subscription_id);
      console.log("🟦 PAY GATE pending.status:", pending.status);

      // ✅ Condition “READY” = IDs Stripe présents
      if (!hasStripeCustomer || !hasStripeSub) {
        return res.status(409).json({
          error: "Subscription not ready yet",
          code: "PAYMENT_PENDING",
          details: { hasStripeCustomer, hasStripeSub },
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
      console.error("❌ profiles upsert error:", profErr);
      return res.status(500).json({ error: `profiles: ${profErr.message}` });
    }



    // 4) Créer subscription AU MOMENT DU CLIC
    console.log("🟦 FINALIZE desired_plan:", pending.desired_plan);
    console.log("🟦 FINALIZE will create subscription?", pending.desired_plan === "trial");

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

      console.log("🟦 FINALIZE subscriptions upsert payload:", payload);

      const { data: subSaved, error: upErr } = await supabaseAdmin
        .from("subscriptions")
        .upsert(payload, { onConflict: "user_id" })
        .select("id, user_id, plan, status, trial_end")
        .single();

      if (upErr) {
        console.error("❌ subscriptions upsert error:", upErr);
        return res.status(500).json({ error: `subscriptions: ${upErr.message}` });
      }

      console.log("✅ subscriptions upsert OK:", subSaved);
    } else {

      // ✅ Payant (standard/premium) : la subscription doit déjà exister (créée par webhook Stripe)
      const { data: subRow, error: subErr } = await supabaseAdmin
        .from("subscriptions")
        .select("user_id, plan, status")
        .eq("user_id", user.id)
        .maybeSingle();

      if (subErr) return res.status(500).json({ error: subErr.message });

      if (!subRow) {
        console.log("🟧 FINALIZE no subscriptions row yet -> creating fallback from pending");

        const { data: createdSub, error: createErr } = await supabaseAdmin
          .from("subscriptions")
          .upsert(
            {
              user_id: user.id,
              plan: plan,                  // "standard" ou "premium"
              status: "active",            // ✅ dans ton enum sub_status
              stripe_customer_id: pending.stripe_customer_id,
              stripe_subscription_id: pending.stripe_subscription_id,
              started_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            },
            { onConflict: "user_id" }
          )
          .select("id, user_id, plan, status, stripe_subscription_id")
          .single();

        if (createErr) {
          console.error("❌ FINALIZE fallback subscriptions upsert error:", createErr);
          return res.status(500).json({ error: `subscriptions: ${createErr.message}` });
        }

        console.log("✅ FINALIZE fallback subscriptions created:", createdSub);
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
    const redirectTo = "https://integora-frontend.vercel.app/create-password.html";

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
    console.error("❌ /api/finalize-pending:", e);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});



app.post("/api/start-trial-invite", async (req, res) => {
  console.log("🟣 [TRIAL] Reçu:", JSON.stringify(req.body, null, 2));
  console.log("[ENV] NODE_ENV =", process.env.NODE_ENV);
  console.log("[ENV] FRONTEND_URL =", process.env.FRONTEND_URL);
  console.log("[ENV] SUPABASE_URL =", process.env.SUPABASE_URL);
  console.log("[ENV] SUPABASE_SERVICE_ROLE_KEY ?", !!process.env.SUPABASE_SERVICE_ROLE_KEY);

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

    if (!/^\d{4}-\d{2}-\d{2}$/.test(termsVersionRaw)) {
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
      console.error("❌ pending_signups select error:", existingErr);
      return res.status(500).json({ error: "Erreur lecture pending_signups", details: existingErr.message });
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
        console.error("❌ pending_signups update error:", updErr);
        return res.status(500).json({ error: "Erreur update pending_signup trial", details: updErr.message });
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
        console.error("❌ pending_signups insert error:", pendingErr);
        return res.status(500).json({
          error: "Impossible de créer pending_signup trial",
          details: pendingErr?.message
        });
      }

      pending_id = pending.id;
    }


    // 2) invite email
    const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";
    const redirectTo = `${FRONT}/welcome.html?pending_id=${pending_id}`;
    console.log("🧪 [TRIAL] pending_id =", pending_id);
    console.log("🧪 [TRIAL] redirectTo =", redirectTo);

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
      console.error("❌ inviteUserByEmail error:", inviteErr);

      if (msg.toLowerCase().includes("already been registered")) {
        const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";
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
    console.error("❌ [TRIAL] error:", e);
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

    const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";
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

      // ✅ Cas : user déjà créé -> on génère un lien "recovery" pour définir le mot de passe
      if (msg.toLowerCase().includes("already been registered")) {
        const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";
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

        return res.json({
          ok: true,
          account_exists: true,
          set_password_link: setPasswordLink,
        });
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
    return res.status(500).json({ error: e.message });
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
        console.error("❌ support_tickets insert error:", ticketErr);

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
          console.warn("PJ upload error:", upErr.message);
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
      const planBadge = (ticket.user_plan || "").toLowerCase() === "premium"
        ? { label: "Plan premium", bg: "#FFF4E5", bd: "#FFB84D", tx: "#7A4A0B" }
        : (ticket.user_plan || "").toLowerCase() === "standard"
          ? { label: "Plan standard", bg: "#EAF7EE", bd: "#7FE0A0", tx: "#0B5A2A" }
          : { label: `Plan ${prettyPlan}`, bg: "#EEF2F7", bd: "#AAB4C3", tx: "#223048" };

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
      console.error("❌ /api/support/ticket:", e);
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





// helper email
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());
}

app.post("/api/contact/ticket", contactPublicLimiter, async (req, res) => {
  try {
    // Si tu n'as pas déjà app.use(express.json()) plus haut, garde bodyParser
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
      console.error("❌ contact_tickets insert error:", ticketErr);
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
    console.error("❌ /api/contact/ticket:", e);
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
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/'
  });

  res.json({
    success: true,
    message: "Déconnexion réussie"
  });
});

// Démarrage du serveur
const FINAL_PORT = process.env.PORT || 3000;
app.listen(FINAL_PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${FINAL_PORT}`);
  console.log(`📊 Types d'abonnements gérés: ${Object.values(SUBSCRIPTION_TYPES).join(', ')}`);
  console.log('🛡️ Architecture invisible activée');
  console.log('🔒 Rate limiting: Activé');
  console.log('📡 Headers de sécurité: Activés');
});
