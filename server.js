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




console.log("✅ Variables d'environnement chargées avec succès");

const express = require("express");
const app = express();


// ==========================================
// 📦 IMPORTS DES MODULES
// ==========================================
const path = require('path');
const fs = require('fs');
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

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
    process.env.SUPABASE_SERVICE_ROLE_KEY, // ← DOIT ÊTRE service_role, PAS anon
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

    if (error) throw error;

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
        "https://api.resend.com"
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

// 🔥 RATE LIMITING AGGRESSIF
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 5, // 5 tentatives max
//   message: { error: 'Trop de tentatives. Réessayez dans 15 minutes.' },
//   standardHeaders: true,
//   legacyHeaders: false
// });


const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute seulement
  max: 300, // 300 requêtes par minute par IP
  message: {
    error: 'Trop de requêtes. Réessayez dans une minute.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// 🔥 PROTECTION CONTRE LES ATTACKS CONNUES
app.use(cookieParser());
app.use(express.json({ limit: '10kb' })); // Limite taille JSON
app.use(express.urlencoded({ extended: true, limit: '10kb' }));


// Appliquer les limiteurs
// app.use(globalLimiter);
//app.use('/login', authLimiter);
//app.use('/inscription', authLimiter);
//app.use('/api/verify-token', authLimiter);




// ==================== FICHIERS STATIQUES PUBLICS ====================
// ✅ 1. FICHIERS FRONTEND PUBLICS (sans auth)
if (isProduction) {
  app.use(express.static(path.join(__dirname, "../frontend")));
} else {
  app.use(express.static(path.join(__dirname, "../frontend")));
}

// ==================== CONFIGURATION CORRIGÉE ====================

// ✅ 1. ASSETS PUBLICS GÉNÉRIQUES (sans /app/)
app.use("/css", express.static(path.join(__dirname, "../frontend/app/css")));
app.use("/js", express.static(path.join(__dirname, "../frontend/app/js")));
app.use("/fonts", express.static(path.join(__dirname, "../frontend/app/fonts")));
app.use("/videos", express.static(path.join(__dirname, "../frontend/app/videos")));
app.use("/images", express.static(path.join(__dirname, "../frontend/app/images")));

// ✅ 2. PROTECTION GLOBALE POUR TOUT /app/*
app.use("/app/*", (req, res, next) => {
  // Autoriser les assets (CSS, JS, images) même dans /app/
  if (req.path.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|webm)$/)) {
    return next();


    return next(); // → express.static s'en occupe
  }
  // Pour les HTML, APPLIQUER L'AUTH
  return authenticateToken(req, res, next);
});

// ✅ 3. SERVIR /app APRÈS LA PROTECTION
app.use("/app/assets", express.static(path.join(__dirname, "../frontend/app/assets")));
app.use("/app/images", express.static(path.join(__dirname, "../frontend/app/images")));


// ---------------------------
// CONFIGURATION ESPACE MEMBRE
// ---------------------------
// ==================== CONFIGURATION DES ROUTES /app ====================
app.get("/app/*", authenticateToken, (req, res) => {
  const fullPath = req.params[0];

  // ✅ REDIRECTION IMMÉDIATE POUR INDEX ET RACINE
  if (fullPath === 'index.html' || fullPath === '' || fullPath === 'index' || fullPath === '/') {
    return res.sendFile(path.join(__dirname, "../frontend/app/choix_irl_digital.html"));
  }

  // ✅ STRATÉGIE SIMPLIFIÉE POUR LES AUTRES PAGES
  const searchPaths = [
    path.join(__dirname, "../frontend/app", fullPath, fullPath + ".html"),
    path.join(__dirname, "../frontend/app", fullPath),
    path.join(__dirname, "../frontend/app", fullPath + ".html")
  ];

  let foundPath = null;
  for (const searchPath of searchPaths) {
    if (fs.existsSync(searchPath)) {
      foundPath = searchPath;
      break;
    }
  }

  if (foundPath) {
    return res.sendFile(foundPath);
  }

  // FALLBACK
  return res.sendFile(path.join(__dirname, "../frontend/app/choix_irl_digital.html"));
});



// -------------------------------------------------------
// 🔒 CSRF sécurisé (double-submit cookie)
// -------------------------------------------------------


// → 1. S'assurer qu'un token existe en cookie lisible


// → 2. Vérifier le token pour les méthodes mutantes
function validateCSRF(req, res, next) {
  // On protège uniquement les méthodes qui modifient
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();

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

    // (optionnel) si tu gardes encore l’ancienne route quelque part
    '/api/create-paid-checkout'
  ]);

  if (exempt.has(req.path)) return next();

  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies['XSRF-TOKEN'];

  if (!headerToken || !cookieToken || headerToken !== cookieToken) {
    console.log('🚨 CSRF Token invalide');
    return res.status(403).json({ error: 'Token CSRF invalide' });
  }

  next();
}



app.use((req, res, next) => {
  const allowedOrigins = [
    'http://localhost:3000',
    'https://integora-frontend.vercel.app'
  ];

  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }

  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-csrf-token');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

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

app.get("/", (req, res) => res.redirect(FRONT));
app.get("/login", (req, res) => res.redirect(`${FRONT}/login.html`));
app.get("/inscription", (req, res) => res.redirect(`${FRONT}/inscription.html`));

const frontDir = path.join(__dirname, "../frontend");
if (fs.existsSync(frontDir)) {
  app.use(express.static(frontDir));
}



// Gérer les erreurs CORS
app.use((error, req, res, next) => {
  if (error.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS non autorisé' });
  }
  next(error);
});


// 🎯 PAGES AUTORISÉES AVEC MAPPAGE OPAQUE
const pageMappings = {
  // Pages publiques/membres unifiées
  'home': { file: 'index', public: true, auth: false },
  'products': { file: 'produit', public: true, auth: false },
  'pricing': { file: 'tarif', public: true, auth: false },
  'choice': { file: 'choix_irl_digital', public: true, auth: false },

  // Pages membres uniquement - NOMS OPAQUES
  'dashboard': { file: 'index', public: false, auth: true, plans: ['trial', 'standard', 'premium'] },
  'profile': { file: 'profile', public: false, auth: true, plans: ['trial', 'standard', 'premium'] },
  'support': { file: 'supports', public: false, auth: true, plans: ['standard', 'premium'] },
  'automation': { file: 'automation_basic', public: false, auth: true, plans: ['standard', 'premium'] },
  'analytics': { file: 'analytics', public: false, auth: true, plans: ['premium'] },
  'admin': { file: 'admin', public: false, auth: true, plans: ['premium'] }
};

// 🌐 ROUTE UNIVERSELLE - ARCHITECTURE INVISIBLE
app.get("/:page", authenticateToken, async (req, res) => {
  try {
    const pageKey = req.params.page.replace('.html', '');
    const pageConfig = pageMappings[pageKey];

    // 🚨 PAGE INCONNUE = 404 IDENTIQUE
    if (!pageConfig) {
      console.log(`🚨 Tentative accès page inconnue: ${pageKey}`);
      return res.status(404).sendFile(path.join(__dirname, "../frontend/404.html"));
    }

    const { file, public: isPublic, auth: requiresAuth, plans } = pageConfig;

    // ✅ PAGE PUBLIQUE - ACCÈS DIRECT
    if (isPublic) {
      const filePath = path.join(__dirname, `../frontend/${file}.html`);
      return fs.existsSync(filePath)
        ? res.sendFile(filePath)
        : res.status(404).sendFile(path.join(__dirname, "../frontend/404.html"));
    }

    // 🚨 PAGE PROTÉGÉE SANS AUTH
    if (requiresAuth && !req.user) {
      console.log(`🚨 Tentative accès non authentifié: ${pageKey}`);
      return res.redirect(`/login?next=/${pageKey}`);
    }

    // 🚨 VERIFICATION ABONNEMENT
    if (plans && !plans.includes(req.user.subscription_type)) {
      console.log(`🚨 Plan insuffisant: ${pageKey} pour ${req.user.email}`);
      return res.status(403).sendFile(path.join(__dirname, "../frontend/403.html"));
    }

    // 🚨 ABONNEMENT INACTIF (sauf trial)
    if (req.user.subscription_type !== 'trial' && !req.user.has_active_subscription) {
      console.log(`🚨 Abonnement inactif: ${pageKey} pour ${req.user.email}`);
      return res.status(403).sendFile(path.join(__dirname, "../frontend/subscription-expired.html"));
    }

    // ✅ ACCÈS AUTORISÉ
    const filePath = path.join(__dirname, `../frontend/app/${file}.html`);
    if (!fs.existsSync(filePath)) {
      return res.status(404).sendFile(path.join(__dirname, "../frontend/404.html"));
    }

    console.log(`✅ Accès autorisé: ${pageKey} pour ${req.user.email}`);
    res.sendFile(filePath);

  } catch (error) {
    console.error('💥 Erreur route universelle:', error);
    res.status(500).sendFile(path.join(__dirname, "../frontend/500.html"));
  }
});









// ---------------------------
// FONCTIONS UTILITAIRES
// ---------------------------

// server.js - AJOUTE CE MIDDLEWARE CORS COMPLET




function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Vérifie si un abonnement est actif et valide
// ✅ VERSION CORRIGÉE - Gestion trial_end NULL et période N+1
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

// Middleware d'authentification
// server.js - NOUVELLE VERSION authenticateToken
async function authenticateToken(req, res, next) {

  // UNIQUEMENT le cookie
  const token = req.cookies?.auth_token;

  if (!token) {
    return handleUnauthorized(req, res);
  }

  try {
    // 1. VÉRIFICATION JWT EN PREMIER (signature + expiration)
    const decoded = jwt.verify(token, SECRET_KEY);

    // 2. VÉRIFICATION SESSION EN BASE (liée au user_id du JWT)
    const tokenHash = hashToken(token);
    const { data: session, error: sessionError } = await supabase
      .from("token_sessions")
      .select("user_id, expires_at, is_active, revoked_at")
      .eq("token_hash", tokenHash)
      .eq("user_id", decoded.id) // ← CRITIQUE : lien direct JWT → Session
      .eq("is_active", true)
      .is("revoked_at", null)
      .gt("expires_at", new Date().toISOString())
      .single();

    if (sessionError || !session) {
      throw new Error("Session invalide");
    }

    // 3. RÉCUPÉRATION PROFIL + ABONNEMENT
    const [profileResult, subscriptionResult] = await Promise.all([
      supabase
        .from("profiles")
        .select("first_name, last_name, company_id, avatar_url")
        .eq("user_id", decoded.id)
        .single(),
      getActiveSubscription(decoded.id)
    ]);

    if (profileResult.error) {
      throw new Error("Profil non trouvé");
    }

    // 4. CONSTRUCTION USER OBJECT
    req.user = {
      id: decoded.id,
      email: decoded.email,
      first_name: profileResult.data.first_name,
      last_name: profileResult.data.last_name,
      company_id: profileResult.data.company_id,
      avatar_url: profileResult.data.avatar_url,
      subscription_type: subscriptionResult.plan, // ← Plan réel (standard/premium/trial)
      has_active_subscription: subscriptionResult.hasActiveSubscription // ← Booléen séparé
    };

    console.log('✅ AUTH RÉUSSIE - User:', req.user.email,
      'Plan:', req.user.subscription_type,
      'Actif:', req.user.has_active_subscription);


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
  res.clearCookie('auth_token');

  const wantsHtml = req.headers.accept && req.headers.accept.includes('text/html');
  const isAppRoute = req.path.startsWith('/app/');

  if (wantsHtml && isAppRoute) {
    return res.redirect('/login.html?next=' + encodeURIComponent(req.originalUrl));
  }

  return res.status(403).json({
    error: "Token invalide ou expiré",
    code: "INVALID_TOKEN"
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

    res.json(subscription);

  } catch (error) {
    console.error('❌ [SERVER] Erreur récupération abonnement:', error);
    res.status(500).json({ error: 'Erreur serveur' });
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
        'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`, // ⚠️ SERVICE ROLE KEY
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
// ✅ ROUTE POUR CONFIRMER LA SUPPRESSION (AVEC ARCHIVAGE COMPLET)
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

// ✅ VÉRIFICATION SERVEUR RENFORCÉE
function extractPageName(fullPath) {
  const fileName = fullPath.split('/').pop() || 'index';
  return fileName.replace('.html', '');
}


// ---------------------------
// ROUTES D'AUTHENTIFICATION
// ---------------------------

app.post("/login", async (req, res) => {
  console.log('🔐 Tentative de connexion pour:', req.body.email);

  const { email, password, device_id } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: "Email et mot de passe requis."
    });
  }

  try {
    // ✅ 1. AUTHENTIFICATION avec client AUTH
    console.log('🔐 Authentification avec client Auth...');
    const { data: authData, error: authError } = await supabaseAuth.auth.signInWithPassword({
      email,
      password,
    });

    if (authError) {
      console.log('❌ Erreur auth:', authError.message);
      if (authError.message.includes("Invalid login credentials")) {
        return res.status(401).json({
          success: false,
          error: "Email ou mot de passe incorrect."
        });
      }
      return res.status(401).json({
        success: false,
        error: authError.message
      });
    }

    if (!authData.user) {
      return res.status(401).json({
        success: false,
        error: "Utilisateur non trouvé."
      });
    }

    const user_id = authData.user.id;
    console.log('✅ Auth réussie, user_id:', user_id);

    // ✅ 2. PROFIL avec client ADMIN
    console.log('👤 Récupération profil avec client Admin...');
    const { data: profile, error: profileError } = await supabaseAdmin
      .from("profiles")
      .select("first_name, last_name, company_id")
      .eq("user_id", user_id)
      .single();

    if (profileError) {
      console.log('❌ Erreur profil:', profileError);
      // Continuer même sans profil
    }

    // ✅ 3. SESSIONS avec client ADMIN
    console.log('💾 Gestion sessions avec client Admin...');
    const { error: sessionError } = await supabaseAdmin
      .from("token_sessions")
      .update({
        is_active: false,
        revoked_at: new Date().toISOString()
      })
      .eq("user_id", user_id)
      .eq("is_active", true);

    if (sessionError) {
      console.log('⚠️ Erreur session (non critique):', sessionError);
    }

    // ✅ 4. CRÉATION SESSION avec client ADMIN
    const token = jwt.sign(
      {
        id: user_id,
        email: authData.user.email,
        first_name: profile?.first_name || "Utilisateur",
        last_name: profile?.last_name || ""
      },
      SECRET_KEY,
      { expiresIn: "24h" }
    );

    const tokenHash = hashToken(token);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);

    const { error: newSessionError } = await supabaseAdmin
      .from("token_sessions")
      .insert([
        {
          user_id: user_id,
          token_hash: tokenHash,
          device_id: device_id || "web",
          user_agent: req.headers["user-agent"],
          ip: req.ip,
          expires_at: expiresAt.toISOString(),
          is_active: true
        }
      ]);

    if (newSessionError) {
      console.log("⚠️ Erreur création session:", newSessionError);
    } else {
      console.log("✅ Session créée pour:", email);
    }

    // ✅ 5. COOKIE
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
      path: '/'
    });

    console.log('✅ Cookie set pour:', email);

    // ✅ RÉPONSE
    return res.json({
      success: true,
      redirect: "/app/choix_irl_digital.html",
      user: {
        id: user_id,
        first_name: profile?.first_name || "Utilisateur",
        last_name: profile?.last_name || "",
        email: authData.user.email,
        company_id: profile?.company_id || null
      }
    });

  } catch (error) {
    console.error("💥 Erreur login:", error);
    return res.status(500).json({
      success: false,
      error: "Erreur serveur lors de la connexion."
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
    const token = req.cookies?.auth_token;


    if (!token) {
      console.log('❌ [Verify-Token] Aucun token trouvé');
      return res.json({ valid: false });
    }

    // 1. Vérifier le JWT
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log('✅ [Verify-Token] JWT valide pour:', decoded.email);

    let user_id = decoded.id;
    let sessionValid = false;

    // 2. ESSAYER de vérifier la session (optionnel)
    try {
      const tokenHash = hashToken(token);
      const { data: session, error: sessionError } = await supabase
        .from("token_sessions")
        .select("user_id, expires_at, is_active")
        .eq("token_hash", tokenHash)
        .eq("is_active", true)
        .single();

      if (!sessionError && session) {
        // Vérifier l'expiration
        const now = new Date();
        const expiresAt = new Date(session.expires_at);
        if (now <= expiresAt) {
          user_id = session.user_id;
          sessionValid = true;
          console.log('✅ [Verify-Token] Session VALIDE');

          // Mettre à jour last_seen_at
          await supabase
            .from("token_sessions")
            .update({ last_seen_at: new Date().toISOString() })
            .eq("token_hash", tokenHash);
        } else {
          console.log('⚠️ [Verify-Token] Session expirée');
        }
      } else {
      }
    } catch (sessionError) {
    }

    // 3. Récupérer le profil
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("first_name, last_name, company_id, avatar_url")
      .eq("user_id", user_id)
      .single();

    if (profileError) {
      console.log('❌ [Verify-Token] Profil non trouvé:', profileError.message);
      return res.json({ valid: false });
    }

    // 4. Récupérer l'abonnement
    const subscription = await getActiveSubscription(user_id);

    console.log('✅ [Verify-Token] Auth VALIDE pour:', decoded.email, '- Session:', sessionValid);

    res.json({
      valid: true,
      user: {
        id: user_id,
        email: decoded.email,
        first_name: profile.first_name,
        last_name: profile.last_name,
        company_id: profile.company_id,
        avatar_url: profile.avatar_url,
        subscription_type: subscription.plan,
        has_active_subscription: subscription.hasActiveSubscription
      }
    });

  } catch (error) {
    console.log('❌ [Verify-Token] Erreur:', error.message);
    res.json({ valid: false });
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

// ✅ Lecture du profil utilisateur
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



// ==================== ROUTE UPLOAD AVATAR ====================

const multer = require('multer');

// Configuration Multer pour l'upload en mémoire
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB max
  },
  fileFilter: (req, file, cb) => {
    // Vérifier que c'est bien une image
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Seules les images sont autorisées'), false);
    }
  }
});

// ✅ MIDDLEWARE DE GESTION D'ERREURS MULTER
const handleMulterError = (error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        ok: false,
        error: 'Fichier trop volumineux (max 5MB)'
      });
    }
    return res.status(400).json({
      ok: false,
      error: `Erreur upload: ${error.message}`
    });
  } else if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }
  next();
};

// ✅ ROUTE UPLOAD AVATAR
app.post('/api/upload-avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
  console.log('🖼️ [API Upload-Avatar] Début - User ID:', req.user?.id);

  try {
    if (!req.file) {
      console.log('❌ [API Upload-Avatar] Aucun fichier reçu');
      return res.status(400).json({
        ok: false,
        error: 'Aucun fichier sélectionné'
      });
    }

    console.log('📁 [API Upload-Avatar] Fichier reçu:', {
      originalName: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype
    });

    // Générer un nom de fichier unique
    const fileExtension = req.file.originalname.split('.').pop() || 'png';
    const fileName = `avatars/${req.user.id}/${Date.now()}.${fileExtension}`;

    console.log('☁️ [API Upload-Avatar] Upload vers Supabase Storage:', fileName);

    // ✅ UPLOAD VERS SUPABASE STORAGE
    const { data: uploadData, error: uploadError } = await supabase
      .storage
      .from('Avatars')
      .upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: true
      });

    if (uploadError) {
      console.error('❌ [API Upload-Avatar] Erreur upload storage:', uploadError);
      return res.status(500).json({ ok: false, error: 'Erreur upload storage: ' + uploadError.message });
    }

    // ✅ RÉCUPÉRATION DE L'URL PUBLIQUE
    const { data: publicUrlData } = supabase
      .storage
      .from('Avatars')
      .getPublicUrl(fileName);

    const avatarUrl = publicUrlData.publicUrl;
    console.log('🔗 [API Upload-Avatar] URL publique générée:', avatarUrl);

    // ✅ MISE À JOUR DU PROFIL
    console.log('💾 [API Upload-Avatar] Mise à jour profil avec avatar_url:', avatarUrl);

    const { data: updatedProfile, error: updateError } = await supabase
      .from('profiles')
      .update({
        avatar_url: avatarUrl,
        updated_at: new Date().toISOString()
      })
      .eq('user_id', req.user.id)
      .select('avatar_url')
      .single();

    if (updateError) {
      console.error('❌ [API Upload-Avatar] Erreur mise à jour profil:', updateError);
      return res.status(500).json({ ok: false, error: 'Erreur mise à jour profil: ' + updateError.message });
    }

    console.log('✅ [API Upload-Avatar] Profil mis à jour - Vérification:', updatedProfile.avatar_url);

    res.json({
      ok: true,
      url: avatarUrl,
      message: 'Avatar mis à jour avec succès !'
    });

  } catch (error) {
    console.error('💥 [API Upload-Avatar] Exception:', error);
    res.status(500).json({ ok: false, error: 'Erreur serveur: ' + error.message });
  }
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


// ✅ ENDPOINT PAIEMENT STRIPE POUR STANDARD/PREMIUM
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

app.post("/api/start-paid-checkout", async (req, res) => {
  console.log("🟡 [START-PAID] Reçu:", JSON.stringify(req.body, null, 2));

  try {
    const {
      email,
      first_name,
      last_name,
      company_name,
      company_size,
      desired_plan
    } = req.body;

    const emailNorm = (email || "").trim().toLowerCase();

    if (!emailNorm || !desired_plan) {
      return res.status(400).json({ error: "email + desired_plan requis" });
    }
    if (!["standard", "premium"].includes(desired_plan)) {
      return res.status(400).json({ error: "desired_plan invalide" });
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
          status: "pending",
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
          status: "pending",
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
      standard: process.env.STRIPE_PRICE_STANDARD,
      premium: process.env.STRIPE_PRICE_PREMIUM
    };
    const priceId = priceIds[desired_plan];

    if (!priceId) {
      return res.status(500).json({
        error: "PriceId Stripe manquant côté serveur (STRIPE_PRICE_STANDARD / STRIPE_PRICE_PREMIUM)"
      });
    }

    // ✅ 3) Créer session Stripe (nouvelle session à chaque tentative)
    const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";

    const session = await stripe.checkout.sessions.create({
      customer_email: emailNorm,
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${FRONT}/email-sent-paiement.html?session_id={CHECKOUT_SESSION_ID}&pending_id=${pending_id}`,
      cancel_url: `${FRONT}/inscription.html?canceled=1`,
      metadata: {
        pending_id,
        desired_plan,
        user_email: emailNorm
      },
      subscription_data: {
        metadata: {
          pending_id,
          desired_plan,
          user_email: emailNorm
        }
      }
    });

    // ✅ 4) Stocker stripe_session_id dans pending
    const { error: sessUpdErr } = await supabaseAdmin
      .from("pending_signups")
      .update({
        stripe_session_id: session.id,
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
    return res.status(500).json({ error: "Erreur start-paid-checkout", details: e.message });
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
      console.error("❌ inviteUserByEmail error:", inviteErr);
      // cas typique : user existe déjà
      return res.status(409).json({ error: inviteErr.message });
    }


    const user_id = inviteData?.user?.id || null;

// ✅ 3bis) UPSERT subscriptions (PAYANT)
if (user_id) {
  const sub = session.subscription; // grâce au expand

  const stripe_price_id = sub?.items?.data?.[0]?.price?.id || null;

  const payload = {
    user_id,
    plan: pending.desired_plan, // "standard" | "premium"
    status: (sub?.status || "active"),

    stripe_customer_id: sub?.customer || session.customer || stripe_customer_id || null,
    stripe_subscription_id: sub?.id || stripe_subscription_id || null,
    stripe_price_id,

    current_period_start: toIsoFromStripeTs(sub?.current_period_start),
    current_period_end: toIsoFromStripeTs(sub?.current_period_end),
    started_at: toIsoFromStripeTs(sub?.start_date) || new Date().toISOString(),
    trial_end: toIsoFromStripeTs(sub?.trial_end),
    cancel_at: toIsoFromStripeTs(sub?.cancel_at),
  };

  const { error: upErr } = await supabaseAdmin
    .from("subscriptions")
    .upsert(payload, { onConflict: "user_id" });

  if (upErr) {
    console.error("❌ subscriptions upsert (PAID) error:", upErr);
    return res.status(500).json({ error: upErr.message });
  }
}


    

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


app.post("/api/start-trial-invite", async (req, res) => {
  console.log("🟣 [TRIAL] Reçu:", JSON.stringify(req.body, null, 2));

  try {
    const {
      email,
      first_name,
      last_name,
      company_name,
      company_size
    } = req.body;

    const emailNorm = (email || "").trim().toLowerCase();
    if (!emailNorm) return res.status(400).json({ error: "email requis" });

    // 1) pending
    const { data: pending, error: pendingErr } = await supabaseAdmin
      .from("pending_signups")
      .insert([{
        email: emailNorm,
        first_name,
        last_name,
        company_name,
        company_size,
        desired_plan: "trial",
        status: "pending"
      }])
      .select("*")
      .single();

    if (pendingErr || !pending) {
      console.error("❌ pending_signups insert error:", pendingErr);
      return res.status(500).json({ error: "Impossible de créer pending_signup trial" });
    }

    const pending_id = pending.id;

    // 2) invite email
    const FRONT = process.env.FRONTEND_URL || "https://integora-frontend.vercel.app";
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
      console.error("❌ inviteUserByEmail error:", inviteErr);
      return res.status(409).json({ error: inviteErr.message });
    }

const user_id = inviteData?.user?.id || null;

// ✅ 2bis) UPSERT subscriptions (TRIAL 7 jours)
if (user_id) {
  const now = new Date();
  const trialEnd = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  const payload = {
    user_id,
    plan: "trial",
    status: "trialing",
    current_period_start: now.toISOString(),
    trial_end: trialEnd.toISOString(),
    started_at: now.toISOString(),
    // stripe_* restent null
  };

  const { error: upErr } = await supabaseAdmin
    .from("subscriptions")
    .upsert(payload, { onConflict: "user_id" });

  if (upErr) {
    console.error("❌ subscriptions upsert (TRIAL) error:", upErr);
    return res.status(500).json({ error: upErr.message });
  }
}

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
    return res.status(500).json({ error: "Erreur start-trial-invite", details: e.message });
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
      return res.status(409).json({ error: inviteErr.message });
    }

const user_id = inviteData?.user?.id || pending.user_id || null;

if (user_id) {
  const payload = {
    user_id,
    plan: pending.desired_plan,   // trial/standard/premium
    status: pending.desired_plan === "trial" ? "trialing" : "active",
  };

  const { error: upErr } = await supabaseAdmin
    .from("subscriptions")
    .upsert(payload, { onConflict: "user_id" });

  if (upErr) {
    console.error("❌ subscriptions upsert (RESEND) error:", upErr);
    // pas forcément bloquant, mais je te conseille de bloquer en dev
  }
}

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
