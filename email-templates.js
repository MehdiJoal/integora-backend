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
    <div style="text-align:center;margin-top:24px;font-size:12px;color:#718096;line-height:1.6;">
      &copy; INTEGORA — Tous droits réservés.<br/>
      <a href="https://integora.fr" style="color:#718096;text-decoration:none;font-weight:600;">integora.fr</a><br/>
      Une question ? Écrivez-nous à <a href="mailto:contact@integora.fr" style="color:#718096;text-decoration:none;font-weight:600;">contact@integora.fr</a>
    </div>
  </div>
</body>
</html>`;
}

// ✅ Bouton CTA
function ctaButton(text, url, note) {
  return `
  <div style="text-align:center;margin:28px 0 8px;">
    <a href="${url}" style="display:inline-block;background:${PRIMARY};color:#fff;text-decoration:none;padding:14px 32px;border-radius:50px;font-weight:600;font-size:15px;">
      ${text}
    </a>
    ${note ? `<p style="font-size:12px;color:${GRAY};margin-top:10px;">${note}</p>` : ""}
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
  const contentItems = plan === "premium"
    ? `
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Activités d'équipe professionnelles prêtes à l'emploi</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Supports RH opérationnels</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Outils interactifs et ressources téléchargeables</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Contenus et thématiques Premium</td></tr>`
    : `
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Activités d'équipe professionnelles prêtes à l'emploi</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Supports RH opérationnels</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Outils interactifs et ressources téléchargeables</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Contenus et thématiques Standard</td></tr>`;

  return {
    subject: `Integora — Votre abonnement expire bientôt`,
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        Votre abonnement <strong>${planLabel(plan)}</strong> arrive à échéance
        le <strong>${formatDateFR(endDate)}</strong>.
      </p>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 4px;">
        D'ici là, vous conservez un accès complet à l'ensemble de la plateforme :
      </p>
      <table role="presentation" style="margin:0 0 20px 8px;border:none;">
        ${contentItems}
      </table>
      <p style="font-size:15px;color:${GRAY};line-height:1.7;margin:0 0 8px;">
        Vous pouvez le renouveler dès maintenant pour conserver tous vos accès.
      </p>
      ${ctaButton("Renouveler mon abonnement", `${FRONT_URL}/login.html?next=/app/profile.html`, "Vous serez dirigé vers votre profil pour renouveler votre abonnement.")}
    `),
  };
}

// ──────────────────────────────────────────
// TEMPLATE J-7 (payant uniquement)
// ──────────────────────────────────────────
function reminderJ7({ firstName, plan, endDate }) {
  const lostItems = plan === "premium"
    ? `
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Vos activités d'équipe professionnelles</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Vos supports RH opérationnels</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Vos outils interactifs et ressources téléchargeables</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Vos contenus et thématiques Premium</td></tr>`
    : `
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Vos activités d'équipe professionnelles</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Vos supports RH opérationnels</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Vos outils interactifs et ressources téléchargeables</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Vos contenus et thématiques Standard</td></tr>`;

  return {
    subject: `Integora — Votre abonnement expire dans 7 jours`,
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        Votre abonnement <strong>${planLabel(plan)}</strong> expire dans <strong>7 jours</strong>,
        le <strong>${formatDateFR(endDate)}</strong>.
      </p>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 4px;">
        Après cette date, vous perdrez l'accès à :
      </p>
      <table role="presentation" style="margin:0 0 20px 8px;border:none;">
        ${lostItems}
      </table>
      <p style="font-size:15px;color:${GRAY};line-height:1.7;margin:0 0 8px;">
        Vous pouvez le renouveler dès maintenant en quelques clics.
      </p>
      ${ctaButton("Renouveler mon abonnement", `${FRONT_URL}/login.html?next=/app/profile.html`, "Vous serez dirigé vers votre profil pour renouveler votre abonnement.")}
    `),
  };
}

// ──────────────────────────────────────────
// TEMPLATE J-3 (trial + payant)
// ──────────────────────────────────────────
function reminderJ3({ firstName, plan, endDate }) {
  const isTrial = plan === "trial";

  const listItems = isTrial
    ? `
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Activités d'équipe professionnelles prêtes à l'emploi</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Supports RH opérationnels</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Outils interactifs et ressources téléchargeables</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Contenus et thématiques de la plateforme</td></tr>`
    : `
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Activités d'équipe professionnelles prêtes à l'emploi</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Supports RH opérationnels</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Outils interactifs et ressources téléchargeables</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Contenus et thématiques ${planLabel(plan)}</td></tr>`;

  return {
    subject: isTrial
      ? `Integora — Votre essai gratuit se termine dans 3 jours`
      : `Integora — Votre abonnement expire dans 3 jours`,
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        ${isTrial
          ? `Votre <strong>essai gratuit</strong> se termine dans <strong>3 jours</strong>, le <strong>${formatDateFR(endDate)}</strong>.`
          : `Votre abonnement <strong>${planLabel(plan)}</strong> expire dans <strong>3 jours</strong>, le <strong>${formatDateFR(endDate)}</strong>.`
        }
      </p>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 4px;">
        ${isTrial
          ? "Après cette date, vous perdrez l'accès à :"
          : "Après cette date, votre accès sera suspendu :"
        }
      </p>
      <table role="presentation" style="margin:0 0 20px 8px;border:none;">
        ${listItems}
      </table>
      <p style="font-size:15px;color:${GRAY};line-height:1.7;margin:0 0 8px;">
        ${isTrial
          ? "Pour continuer à en profiter, choisissez votre formule en quelques clics."
          : "Vous pouvez le renouveler dès maintenant pour tout conserver."
        }
      </p>
      ${ctaButton(isTrial ? "Activer mon abonnement" : "Renouveler mon abonnement", `${FRONT_URL}/login.html?next=/app/profile.html`, isTrial ? "Vous serez dirigé vers votre profil pour activer votre abonnement." : "Vous serez dirigé vers votre profil pour renouveler votre abonnement.")}
    `),
  };
}

// ──────────────────────────────────────────
// TEMPLATE J-1 (trial + payant)
// ──────────────────────────────────────────
function reminderJ1({ firstName, plan, endDate }) {
  const isTrial = plan === "trial";

  const listItems = `
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Des activités d'équipe déployables en 10 minutes, sans préparation</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Des supports RH opérationnels, directement utilisables</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Des outils simples et rapides, pensés pour un gain de temps immédiat</td></tr>
      <tr><td style="padding:6px 0;font-size:15px;color:${DARK};">&#10022; Des ressources téléchargeables prêtes à être utilisées</td></tr>`;

  return {
    subject: isTrial
      ? `Integora — Votre essai gratuit expire demain`
      : `Integora — Votre abonnement expire demain`,
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        ${isTrial
          ? `Votre <strong>essai gratuit</strong> expire <strong>demain</strong>, le <strong>${formatDateFR(endDate)}</strong>.`
          : `Votre abonnement <strong>${planLabel(plan)}</strong> expire <strong>demain</strong>, le <strong>${formatDateFR(endDate)}</strong>.`
        }
      </p>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 4px;">
        ${isTrial
          ? "Pendant 7 jours, vous avez eu accès à une plateforme conçue pour simplifier votre quotidien :"
          : "Depuis votre souscription, vous bénéficiez d'une plateforme conçue pour simplifier votre quotidien :"
        }
      </p>
      <table role="presentation" style="margin:0 0 20px 8px;border:none;">
        ${listItems}
      </table>
      <p style="font-size:15px;color:${isTrial ? GRAY : '#dc2626'};${isTrial ? '' : 'font-weight:600;'}line-height:1.7;margin:0 0 8px;">
        ${isTrial
          ? "Pour que votre équipe continue à en profiter, il suffit de choisir votre formule."
          : "Tout cela sera suspendu demain sans renouvellement."
        }
      </p>
      ${ctaButton(isTrial ? "Activer mon abonnement" : "Renouveler maintenant", `${FRONT_URL}/login.html?next=/app/profile.html`, isTrial ? "Vous serez dirigé vers votre profil pour activer votre abonnement." : "Vous serez dirigé vers votre profil pour renouveler votre abonnement.")}
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
      ? `Integora — Votre essai gratuit est terminé`
      : `Integora — Votre abonnement a expiré`,
    html: emailLayout(`
      <h1 style="font-size:22px;color:${DARK};margin:0 0 16px;">Bonjour ${firstName},</h1>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        ${isTrial
          ? `Votre <strong>essai gratuit</strong> est arrivé à son terme. Votre accès à Integora est désormais suspendu.`
          : `Votre abonnement <strong>${planLabel(plan)}</strong> a expiré le <strong>${formatDateFR(endDate)}</strong>.`
        }
      </p>
      <p style="font-size:15px;color:${DARK};line-height:1.7;margin:0 0 20px;">
        ${isTrial
          ? "Votre compte est conservé, rien n'est perdu. Il vous suffit de choisir votre formule pour retrouver l'ensemble de la plateforme."
          : "Votre accès à la plateforme est désormais suspendu. Votre compte est conservé, rien n'est perdu."
        }
      </p>
      ${isTrial ? "" : `<p style="font-size:15px;color:${GRAY};line-height:1.7;margin:0 0 8px;">
        Vous pouvez le réactiver à tout moment pour reprendre là où vous en étiez.
      </p>`}
      ${ctaButton(isTrial ? "Activer mon abonnement" : "Réactiver mon abonnement", `${FRONT_URL}/login.html?next=/app/profile.html`, isTrial ? "Vous serez dirigé vers votre profil pour activer votre abonnement." : "Vous serez dirigé vers votre profil pour renouveler votre abonnement.")}
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
