// =============================================================
// gen-app-pages.js — Régénère app-pages.json (liste des pages /app + dossier).
// Utile car EN PROD le backend (Render) n'a PAS le dossier frontend (sur Vercel).
// Ce fichier figé sert à : catégories des pages + "pages non consultées".
//
// Quand le lancer : UNIQUEMENT si tu ajoutes / supprimes une page dans frontend/app.
//   npm run pages
// puis commit app-pages.json. (Si tu oublies : seules les NOUVELLES pages
//  apparaîtront en catégorie "Autre" — aucune stat n'est cassée.)
// =============================================================
const fs = require('fs');
const path = require('path');

const APP_DIR = path.resolve(__dirname, '../frontend/app');
const SKIP_DIRS = ['css', 'js', 'images', 'assets', 'fonts', 'videos'];
const pages = [];

function walk(dir, folder) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (e) { console.error('Dossier introuvable:', dir, '(lance cette commande en local, pas sur Render)'); process.exit(1); }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.includes(entry.name)) continue;
      walk(path.join(dir, entry.name), folder ? `${folder}/${entry.name}` : entry.name);
    } else if (entry.isFile() && entry.name.endsWith('.html')) {
      const name = entry.name.replace('.html', '');
      if (name.startsWith('admin')) continue; // pages admin exclues
      pages.push({ page: name, folder: folder || null });
    }
  }
}

walk(APP_DIR, '');
fs.writeFileSync(path.join(__dirname, 'app-pages.json'), JSON.stringify(pages));
console.log('✅ app-pages.json régénéré :', pages.length, 'pages. (pense à le commit + push)');
