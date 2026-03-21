// ==========================================
// 📧 TEMPLATES EMAIL — RAPPELS EXPIRATION
// ==========================================

const FRONT_URL = process.env.FRONTEND_URL || "https://integora.fr";
const PRIMARY = "#4a90e2";
const DARK = "#0f172a";
const GRAY = "#64748b";
const BG = "#f8fafc";
const CARD_BG = "#ffffff";

// ✅ Layout commun
function emailLayout(content) {
  return `
<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:${BG};font-family:Arial,sans-serif;">
  <div style="max-width:580px;margin:0 auto;padding:40px 20px;">
    <div style="background:${CARD_BG};border-radius:16px;padding:40px 32px;border:1px solid #e2e8f0;">
      ${content}
    </div>
    <p style="text-align:center;font-size:12px;color:${GRAY};margin-top:24px;">
      INTEGORA — Plateforme RH &amp; Cohesion d'equipe<br>
      Cet email a ete envoye automatiquement. Merci de ne pas y repondre.
    </p>
  </div>
</body>
</html>`;
}

// ✅ Bouton CTA
function ctaButton(text, url) {
  return `
  <div style="text-align:center;margin:28px 0 8px;">
    <a href="${url}" style="display:inline-block;background:${PRIMARY};color:#fff;text-decoration:none;padding:14px 32px;border-radius:50px;font-weight:600;font-size:15px;">
      ${text}
    </a>
  </div>`;
}

// ✅ Formatage date FR
function formatDateFR(isoStr) {
  if (!isoStr) return "—";
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric" });
}

// ✅ Label plan
function planLabel(plan) {
  const labels = { trial: "Essai gratuit", standard: "Standard", premium: "Premium" };
  return labels[plan] || plan;
}

// ──────────────────────────────────────────
// TEMPLATE J-30 (payant uniquement)
// ──────────────────────────────────────────
function reminderJ30({ firstName, plan, endDate }) {
  return {
    subject: "Votre abonnement INTEGORA expire dans 30 jours",
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        Votre abonnement <strong>${planLabel(plan)}</strong> arrive a echeance
        le <strong>${formatDateFR(endDate)}</strong>.
      </p>
      <p style="font-size:15px;color:${GRAY};line-height:1.7;margin:0 0 8px;">
        Pour continuer a profiter de toutes les fonctionnalites de la plateforme,
        pensez a renouveler votre abonnement avant cette date.
      </p>
      ${ctaButton("Renouveler mon abonnement", `${FRONT_URL}/app/profile.html`)}
    `),
  };
}

// ──────────────────────────────────────────
// TEMPLATE J-7 (payant uniquement)
// ──────────────────────────────────────────
function reminderJ7({ firstName, plan, endDate }) {
  return {
    subject: "Plus qu'une semaine — votre abonnement INTEGORA expire bientot",
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        Il ne reste plus que <strong>7 jours</strong> avant l'expiration de votre
        abonnement <strong>${planLabel(plan)}</strong> (le ${formatDateFR(endDate)}).
      </p>
      <p style="font-size:15px;color:${GRAY};line-height:1.7;margin:0 0 8px;">
        Sans renouvellement, vous perdrez l'acces aux activites, supports RH
        et outils de la plateforme.
      </p>
      ${ctaButton("Renouveler maintenant", `${FRONT_URL}/app/profile.html`)}
    `),
  };
}

// ──────────────────────────────────────────
// TEMPLATE J-3 (trial + payant)
// ──────────────────────────────────────────
function reminderJ3({ firstName, plan, endDate }) {
  const isTrial = plan === "trial";
  return {
    subject: isTrial
      ? "Votre essai INTEGORA expire dans 3 jours"
      : "3 jours restants — pensez a renouveler votre abonnement",
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        ${isTrial
          ? `Votre <strong>essai gratuit</strong> se termine dans <strong>3 jours</strong> (le ${formatDateFR(endDate)}).`
          : `Votre abonnement <strong>${planLabel(plan)}</strong> expire dans <strong>3 jours</strong> (le ${formatDateFR(endDate)}).`
        }
      </p>
      <p style="font-size:15px;color:${GRAY};line-height:1.7;margin:0 0 8px;">
        ${isTrial
          ? "Passez a un abonnement Standard ou Premium pour conserver votre acces a la plateforme."
          : "Renouvelez des maintenant pour eviter toute interruption de service."
        }
      </p>
      ${ctaButton(isTrial ? "Decouvrir les offres" : "Renouveler", isTrial ? `${FRONT_URL}/tarif.html` : `${FRONT_URL}/app/profile.html`)}
    `),
  };
}

// ──────────────────────────────────────────
// TEMPLATE J-1 (trial + payant)
// ──────────────────────────────────────────
function reminderJ1({ firstName, plan, endDate }) {
  const isTrial = plan === "trial";
  return {
    subject: isTrial
      ? "Dernier jour de votre essai INTEGORA"
      : "Derniere chance — votre abonnement expire demain",
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        ${isTrial
          ? `Votre <strong>essai gratuit</strong> expire <strong>demain</strong> (le ${formatDateFR(endDate)}).`
          : `Votre abonnement <strong>${planLabel(plan)}</strong> expire <strong>demain</strong> (le ${formatDateFR(endDate)}).`
        }
      </p>
      <p style="font-size:15px;color:#dc2626;font-weight:600;line-height:1.7;margin:0 0 8px;">
        ${isTrial
          ? "Apres demain, vous n'aurez plus acces a la plateforme."
          : "Sans renouvellement, votre acces sera suspendu des demain."
        }
      </p>
      ${ctaButton(isTrial ? "Choisir une offre" : "Renouveler maintenant", isTrial ? `${FRONT_URL}/tarif.html` : `${FRONT_URL}/app/profile.html`)}
    `),
  };
}

// ──────────────────────────────────────────
// TEMPLATE JOUR J — EXPIRÉ (trial + payant)
// ──────────────────────────────────────────
function reminderExpired({ firstName, plan, endDate }) {
  const isTrial = plan === "trial";
  return {
    subject: isTrial
      ? "Votre essai INTEGORA est termine"
      : "Votre abonnement INTEGORA a expire",
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        ${isTrial
          ? `Votre <strong>essai gratuit</strong> a pris fin le ${formatDateFR(endDate)}.`
          : `Votre abonnement <strong>${planLabel(plan)}</strong> a expire le ${formatDateFR(endDate)}.`
        }
      </p>
      <p style="font-size:15px;color:${GRAY};line-height:1.7;margin:0 0 8px;">
        Votre acces aux fonctionnalites de la plateforme est maintenant suspendu.
        ${isTrial
          ? "Souscrivez a une offre pour retrouver votre acces."
          : "Renouvelez votre abonnement pour retrouver votre acces immediatement."
        }
      </p>
      ${ctaButton(isTrial ? "Voir les offres" : "Renouveler mon abonnement", isTrial ? `${FRONT_URL}/tarif.html` : `${FRONT_URL}/app/profile.html`)}
    `),
  };
}

// ✅ Export
module.exports = {
  reminderJ30,
  reminderJ7,
  reminderJ3,
  reminderJ1,
  reminderExpired,
};
