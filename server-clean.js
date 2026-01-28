// server-clean.js - VERSION PROPRE ET FONCTIONNELLE
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
console.log("BOOT: server.js", new Date().toISOString());



// ==================== CONFIGURATION ====================

// Chargement .env
require('dotenv').config({ path: path.join(__dirname, '.env') });



if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  process.exit(1);
}

// ⚠️ CRÉATION GLOBALE DE SUPABASE ⚠️
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);


// Configuration Express
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "../frontend")));
app.use(cookieParser());

const SECRET_KEY = process.env.JWT_SECRET || "secret-par-defaut";

// ==================== ROUTE LOGIN SIMPLIFIÉE ====================

app.post("/login", async (req, res) => {

  try {
    // VÉRIFICATION QUE SUPABASE EST DÉFINI
    if (!supabase) {
      throw new Error("supabase non défini");
    }

    // Authentification Supabase
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email: req.body.email,
      password: req.body.password,
    });


    if (authError) {
      return res.status(401).json({
        success: false,
        error: "Email ou mot de passe incorrect"
      });
    }

    if (!authData.user) {
      return res.status(401).json({
        success: false,
        error: "Utilisateur non trouvé"
      });
    }

    // SUCCÈS - Générer un token simple
    const token = jwt.sign(
      {
        id: authData.user.id,
        email: authData.user.email
      },
      SECRET_KEY,
      { expiresIn: "24h" }
    );


    // ⚠️ RÉPONSE CORRECTE AVEC TOKEN ⚠️
    res.json({
      success: true,
      redirect: "/index.html",
      token: token, // ⬅️ ASSUREZ-VOUS QUE CE CHAMP EXISTE
      user: {
        id: authData.user.id,
        email: authData.user.email
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Erreur serveur: " + error.message
    });
  }
});

// ==================== ROUTES BASIQUES ====================

app.get("/", (req, res) => {
  res.send("✅ Serveur fonctionne !");
});

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

// ==================== DÉMARRAGE ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
});