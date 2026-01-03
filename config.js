import express from "express";

const app = express();

// ✅ config.js dynamique (lu depuis .env)
app.get("/config.js", (req, res) => {
  const url = process.env.SUPABASE_URL;
  const anon = process.env.SUPABASE_ANON_KEY;

  if (!url || !anon) {
    return res.status(500).type("text/plain").send("Missing SUPABASE env vars");
  }

  res.setHeader("Content-Type", "application/javascript; charset=utf-8");
  res.setHeader("Cache-Control", "no-store, max-age=0"); // évite de cacher une vieille config
  res.send(
    `window.APP_CONFIG=${JSON.stringify({
      SUPABASE_URL: url,
      SUPABASE_ANON_KEY: anon,
    })};`
  );
});
