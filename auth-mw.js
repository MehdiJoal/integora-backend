// backend/auth-mw.js
module.exports.authenticateToken = async (req, res, next) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'Missing token' });

    // TODO: Vérifie ton JWT ici et récupère l'id utilisateur
    // Exemple: const decoded = verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'] });
    // req.user = { id: decoded.sub };

    // ⛔️ Pour test uniquement (remplace dès que possible)
    // req.user = { id: 'f4596768-4d9a-4dac-ac77-8ec6321dec6d' };

    if (!req.user?.id) return res.status(401).json({ error: 'Invalid token' });
    next();
  } catch (e) {
    console.error(e);
    return res.status(401).json({ error: 'Auth error' });
  }
};
