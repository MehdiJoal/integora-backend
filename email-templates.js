// ==========================================
// 📧 TEMPLATES EMAIL — RAPPELS EXPIRATION
// ==========================================

const FRONT_URL = process.env.FRONTEND_URL || "https://integora.fr";
const PROFILE_URL = `${FRONT_URL}/login.html?next=/app/profile.html`;

// ✅ Formatage date FR
function formatDateFR(isoStr) {
  if (!isoStr) return "—";
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric" });
}

// ✅ Label plan
function planLabel(plan) {
  const labels = { trial: "essai gratuit", standard: "Standard", premium: "Premium" };
  return labels[plan] || plan;
}

// ✅ Bouton sobre — style lien discret (pas marketing, pas de lien brut)
function soberLink(text) {
  return `<p style="margin:20px 0;"><a href="${PROFILE_URL}" style="color:#1a1a1a;font-weight:600;text-decoration:underline;">${text}</a></p>`;
}

// ✅ Layout simple — style email personnel (évite l'onglet Promotions Gmail)
function simpleLayout(body) {
  return `
<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;font-size:15px;color:#1a1a1a;line-height:1.6;">
  <div style="max-width:560px;margin:0 auto;padding:32px 16px;">
    ${body}
    <hr style="border:none;border-top:1px solid #e2e8f0;margin:32px 0 16px;" />
    <p style="font-size:13px;color:#64748b;line-height:1.6;margin:0;">
      L'équipe <strong>Integora</strong><br/>
      <a href="https://integora.fr" style="color:#64748b;text-decoration:none;">integora.fr</a> · <a href="mailto:contact@integora.fr" style="color:#64748b;text-decoration:none;">contact@integora.fr</a>
    </p>
    <p style="font-size:11px;color:#94a3b8;margin-top:12px;">&copy; ${new Date().getFullYear()} Integora — Tous droits réservés.</p>
  </div>
</body>
</html>`;
}

// ──────────────────────────────────────────
// TEMPLATE J-30 (payant uniquement)
// ──────────────────────────────────────────
function reminderJ30({ firstName, plan, endDate }) {
  return {
    subject: `${firstName}, votre abonnement Integora expire le ${formatDateFR(endDate)}`,
    html: simpleLayout(`
      <p>Bonjour ${firstName},</p>
      <p>Votre abonnement <strong>${planLabel(plan)}</strong> arrive à échéance le <strong>${formatDateFR(endDate)}</strong>.</p>
      <p>D'ici là, vous conservez un accès complet à la plateforme. Si vous souhaitez renouveler, vous pouvez le faire depuis votre profil :</p>
      ${soberLink("Accéder à mon compte")}
      <p>N'hésitez pas à nous écrire si vous avez la moindre question.</p>
    `),
  };
}

// ──────────────────────────────────────────
// TEMPLATE J-7 (payant uniquement)
// ──────────────────────────────────────────
function reminderJ7({ firstName, plan, endDate }) {
  return {
    subject: `${firstName}, plus que 7 jours sur votre abonnement Integora`,
    html: simpleLayout(`
      <p>Bonjour ${firstName},</p>
      <p>Votre abonnement <strong>${planLabel(plan)}</strong> expire dans <strong>7 jours</strong>, le <strong>${formatDateFR(endDate)}</strong>.</p>
      <p>Après cette date, votre accès à la plateforme sera suspendu. Vous pouvez renouveler dès maintenant depuis votre profil :</p>
      ${soberLink("Accéder à mon compte")}
      <p>Si vous avez des questions, répondez simplement à cet email.</p>
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
      ? `${firstName}, votre essai gratuit Integora se termine dans 3 jours`
      : `${firstName}, votre abonnement Integora expire dans 3 jours`,
    html: simpleLayout(`
      <p>Bonjour ${firstName},</p>
      <p>${isTrial
        ? `Votre <strong>essai gratuit</strong> se termine dans <strong>3 jours</strong>, le <strong>${formatDateFR(endDate)}</strong>.`
        : `Votre abonnement <strong>${planLabel(plan)}</strong> expire dans <strong>3 jours</strong>, le <strong>${formatDateFR(endDate)}</strong>.`
      }</p>
      <p>${isTrial
        ? "Après cette date, votre accès sera suspendu. Pour continuer à utiliser Integora, il suffit de choisir votre formule :"
        : "Après cette date, votre accès sera suspendu. Vous pouvez renouveler depuis votre profil :"
      }</p>
      ${soberLink("Accéder à mon compte")}
      <p>Une question ? Répondez directement à cet email.</p>
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
      ? `${firstName}, votre essai Integora expire demain`
      : `${firstName}, votre abonnement Integora expire demain`,
    html: simpleLayout(`
      <p>Bonjour ${firstName},</p>
      <p>${isTrial
        ? `Votre <strong>essai gratuit</strong> expire <strong>demain</strong>, le <strong>${formatDateFR(endDate)}</strong>.`
        : `Votre abonnement <strong>${planLabel(plan)}</strong> expire <strong>demain</strong>, le <strong>${formatDateFR(endDate)}</strong>.`
      }</p>
      <p>${isTrial
        ? "Si vous souhaitez continuer à utiliser Integora, choisissez votre formule avant demain :"
        : "Pour conserver votre accès, renouvelez avant demain :"
      }</p>
      ${soberLink("Accéder à mon compte")}
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
      ? `${firstName}, votre essai Integora est terminé`
      : `${firstName}, votre abonnement Integora a expiré`,
    html: simpleLayout(`
      <p>Bonjour ${firstName},</p>
      <p>${isTrial
        ? "Votre <strong>essai gratuit</strong> est arrivé à son terme. Votre accès à Integora est maintenant suspendu."
        : `Votre abonnement <strong>${planLabel(plan)}</strong> a expiré le <strong>${formatDateFR(endDate)}</strong>. Votre accès est maintenant suspendu.`
      }</p>
      <p>Votre compte est conservé, rien n'est perdu. Vous pouvez réactiver votre accès à tout moment :</p>
      ${soberLink("Accéder à mon compte")}
      <p>Si vous avez besoin d'aide, répondez à cet email.</p>
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
