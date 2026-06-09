/**
 * Read the Bills — AI deep-dive Worker (Cloudflare) + paid credit packs
 * ---------------------------------------------------------------------
 * Holds the Anthropic key, runs the Claude analysis, and (optionally) gates each
 * run behind purchased credits sold via Stripe. The browser tool never sees the
 * Anthropic or Stripe secrets.
 *
 * ROUTES:
 *   POST  /            -> run an AI analysis (gated by credits when PAYWALL_ENABLED)
 *   GET   /balance     -> { paywall, credits, packCredits, buyUrl } for a token
 *   POST  /webhook     -> Stripe webhook (checkout.session.completed -> grant credits)
 *
 * SECRETS (wrangler secret put / CF API):
 *   ANTHROPIC_API_KEY      (required)
 *   STRIPE_WEBHOOK_SECRET  (required only once the paywall is on; whsec_...)
 * KV: binding RL  (rate-limit counters + credit balances + webhook idempotency)
 *
 * GO-LIVE: create a Stripe Payment Link, set PAYMENT_LINK below, add a webhook to
 *   <worker-url>/webhook (event checkout.session.completed) and store its signing
 *   secret as STRIPE_WEBHOOK_SECRET, then set PAYWALL_ENABLED = true and redeploy.
 */

const MODEL = "claude-opus-4-8";
const PAYWALL_ENABLED = false;                 // flip to true once Stripe is wired
const PAYMENT_LINK    = "";                     // your Stripe Payment Link URL (e.g. https://buy.stripe.com/xxx)
const CREDITS_PER_PACK = 100;                   // credits granted per completed checkout
const FREE_TRIAL       = 2;                      // free analyses per new visitor before they must buy
const PER_IP_HOURLY    = 20;                     // abuse backstop (per visitor/hour)
const GLOBAL_DAILY     = 2000;                   // abuse backstop (site-wide/day)

const ALLOW_ORIGINS = [
  "https://toresays.github.io",
  "https://toresays.com",
  "https://www.toresays.com",
  "http://localhost:8777",
  "http://127.0.0.1:8777"
];

const SCHEMA = {
  type: "object", additionalProperties: false,
  properties: {
    plainSummary: { type: "string", description: "2-4 sentences, 8th-grade reading level: what this bill actually does." },
    traps: { type: "array", items: { type: "object", additionalProperties: false,
      properties: {
        title: { type: "string" }, quote: { type: "string" }, why: { type: "string" },
        severity: { type: "string", enum: ["high", "medium", "low"] }
      }, required: ["title", "quote", "why", "severity"] } },
    whoBenefits: { type: "string" }, whoBurdened: { type: "string" },
    changesToLaw: { type: "string" }, watchList: { type: "array", items: { type: "string" } }
  },
  required: ["plainSummary", "traps", "whoBenefits", "whoBurdened", "changesToLaw", "watchList"]
};

function cors(origin) {
  const allow = ALLOW_ORIGINS.includes(origin) ? origin : ALLOW_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400"
  };
}
function json(obj, status, origin) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...cors(origin) } });
}

async function getCredits(env, token) {
  if (!env.RL || !token) return null;
  const v = await env.RL.get("credit:" + token);
  return v == null ? null : (+v || 0);
}
async function setCredits(env, token, n) { await env.RL.put("credit:" + token, String(n)); }

// Stripe webhook signature check (HMAC-SHA256, Web Crypto)
async function stripeVerify(payload, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  const parts = {};
  sigHeader.split(",").forEach(kv => { const i = kv.indexOf("="); parts[kv.slice(0, i)] = kv.slice(i + 1); });
  const t = parts.t, v1 = parts.v1;
  if (!t || !v1) return false;
  if (Math.abs(Date.now() / 1000 - (+t)) > 300) return false; // reject >5 min old
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(t + "." + payload));
  const hex = [...new Uint8Array(mac)].map(b => b.toString(16).padStart(2, "0")).join("");
  if (hex.length !== v1.length) return false;
  let diff = 0; for (let i = 0; i < hex.length; i++) diff |= hex.charCodeAt(i) ^ v1.charCodeAt(i);
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    if (request.method === "OPTIONS") return new Response(null, { headers: cors(origin) });

    // ---- balance / config ----
    if (path === "/balance" && request.method === "GET") {
      const token = url.searchParams.get("token") || "";
      let credits = await getCredits(env, token);
      if (credits == null) credits = FREE_TRIAL;
      return json({ paywall: PAYWALL_ENABLED, credits, packCredits: CREDITS_PER_PACK, buyUrl: PAYMENT_LINK }, 200, origin);
    }

    // ---- Stripe webhook ----
    if (path === "/webhook" && request.method === "POST") {
      const raw = await request.text();
      const ok = await stripeVerify(raw, request.headers.get("stripe-signature"), env.STRIPE_WEBHOOK_SECRET);
      if (!ok) return new Response("bad signature", { status: 400 });
      let evt; try { evt = JSON.parse(raw); } catch { return new Response("bad json", { status: 400 }); }
      if (evt.type === "checkout.session.completed") {
        const seenKey = "seen:" + evt.id;
        if (await env.RL.get(seenKey)) return new Response("ok (dup)", { status: 200 });
        const token = evt.data && evt.data.object && evt.data.object.client_reference_id;
        if (token) {
          const cur = (await getCredits(env, token)) || 0;
          await setCredits(env, token, cur + CREDITS_PER_PACK);
          await env.RL.put(seenKey, "1", { expirationTtl: 2592000 });
        }
      }
      return new Response("ok", { status: 200 });
    }

    // ---- AI analysis ----
    if (request.method !== "POST") return new Response("POST only", { status: 405, headers: cors(origin) });
    let body; try { body = await request.json(); } catch { return json({ error: "Bad JSON" }, 400, origin); }
    const token = body.token || "";

    // abuse backstop (always on)
    if (env.RL) {
      const ip = request.headers.get("CF-Connecting-IP") || "anon";
      const tnow = Date.now();
      const hourKey = "ip:" + ip + ":" + Math.floor(tnow / 3600000);
      const dayKey = "day:" + Math.floor(tnow / 86400000);
      const [ipc, gc] = await Promise.all([env.RL.get(hourKey), env.RL.get(dayKey)]);
      if ((+ipc || 0) >= PER_IP_HOURLY) return json({ error: "Too many requests from this connection — try again shortly." }, 429, origin);
      if ((+gc || 0) >= GLOBAL_DAILY) return json({ error: "The service is busy right now — please try again later." }, 429, origin);
      await Promise.all([
        env.RL.put(hourKey, String((+ipc || 0) + 1), { expirationTtl: 3600 }),
        env.RL.put(dayKey, String((+gc || 0) + 1), { expirationTtl: 86400 })
      ]);
    }

    // credit gate (only when paywall is on)
    let balBefore = null;
    if (PAYWALL_ENABLED) {
      balBefore = await getCredits(env, token);
      if (balBefore == null) balBefore = FREE_TRIAL;
      if (!token || balBefore <= 0) {
        return json({ error: "no_credits", message: "You're out of AI credits. Grab a pack to keep running deep-dives.", buyUrl: PAYMENT_LINK, packCredits: CREDITS_PER_PACK }, 402, origin);
      }
    }

    const { title = "", bill = "", policyArea = "", flagged = [], textSample = "" } = body;
    const flaggedText = (Array.isArray(flagged) ? flagged : []).slice(0, 40).join("\n• ");
    const system =
      "You are a sharp, nonpartisan legislative analyst writing for ordinary citizens on a public transparency site. " +
      "You read U.S. House bill text and explain — in plain English — what it really does, the traps and vague language " +
      "buried in it, who benefits, who is burdened, and what existing law it changes. Be specific and quote the bill. " +
      "Do not editorialize about a party. Flag real concerns; if the bill is clean, say so plainly. Never invent text " +
      "that is not in what you were given.";
    const user =
      `Bill: ${bill}\nTitle: ${title}\nPolicy area: ${policyArea}\n\n` +
      (flaggedText ? `Passages our keyword scanner flagged (quote from these where relevant):\n• ${flaggedText}\n\n` : "") +
      `Excerpt of the bill text:\n"""\n${String(textSample).slice(0, 18000)}\n"""\n\n` +
      `Analyze this bill for the public. Return your analysis as structured JSON.`;

    try {
      const r = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: MODEL, max_tokens: 4000, system, messages: [{ role: "user", content: user }], output_config: { format: { type: "json_schema", schema: SCHEMA } } })
      });
      if (!r.ok) { const t = await r.text(); return json({ error: "Anthropic API error", status: r.status, detail: t.slice(0, 500) }, 502, origin); }
      const data = await r.json();
      const textBlock = (data.content || []).find(b => b.type === "text");
      let analysis; try { analysis = JSON.parse(textBlock ? textBlock.text : "{}"); } catch { return json({ error: "Could not parse model output" }, 502, origin); }
      // success -> decrement one credit
      let creditsLeft = null;
      if (PAYWALL_ENABLED) { creditsLeft = Math.max(0, balBefore - 1); await setCredits(env, token, creditsLeft); }
      return json({ analysis, creditsLeft }, 200, origin);
    } catch (e) {
      return json({ error: String(e) }, 500, origin);
    }
  }
};
