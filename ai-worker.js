/**
 * Read the Bills — AI deep-dive Worker (Cloudflare)
 * --------------------------------------------------
 * A tiny proxy that holds the Anthropic API key server-side and turns a bill's
 * flagged passages into a plain-English "trap" analysis. The browser tool
 * (house-legislation.html) POSTs here; the key is NEVER exposed to the page.
 *
 * DEPLOY (one time, ~5 min):
 *   1. Create a free Cloudflare account → https://dash.cloudflare.com
 *   2. Install Wrangler:   npm i -g wrangler   &&   wrangler login
 *   3. In a folder with this file + the wrangler.toml below, set the secret:
 *        wrangler secret put ANTHROPIC_API_KEY      (paste your Anthropic key)
 *   4. Deploy:   wrangler deploy
 *   5. Copy the deployed URL (e.g. https://read-the-bills-ai.<you>.workers.dev)
 *      and paste it into AI_WORKER_URL at the top of house-legislation.html.
 *
 *   wrangler.toml:
 *     name = "read-the-bills-ai"
 *     main = "ai-worker.js"
 *     compatibility_date = "2026-01-01"
 *
 * COST CONTROL: only the rules-engine-flagged excerpts + a text sample are sent,
 * not the whole bill — so each analysis is small and cheap.
 */

const MODEL = "claude-opus-4-8";
const PER_IP_HOURLY = 10;   // max AI analyses per visitor per hour
const GLOBAL_DAILY  = 400;  // max AI analyses site-wide per day (protects your balance)
const ALLOW_ORIGINS = [
  "https://toresays.github.io",
  "https://toresays.com",
  "https://www.toresays.com",
  "http://localhost:8777",
  "http://127.0.0.1:8777"
];

const SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    plainSummary: { type: "string", description: "2-4 sentences, 8th-grade reading level: what this bill actually does." },
    traps: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          title: { type: "string", description: "Short name of the concern." },
          quote: { type: "string", description: "The exact phrase or sentence from the bill text that raises it." },
          why: { type: "string", description: "Plain-English explanation of why it matters and who it could affect." },
          severity: { type: "string", enum: ["high", "medium", "low"] }
        },
        required: ["title", "quote", "why", "severity"]
      }
    },
    whoBenefits: { type: "string", description: "Who gains from this bill, concretely." },
    whoBurdened: { type: "string", description: "Who pays, loses a protection, or carries the cost." },
    changesToLaw: { type: "string", description: "What existing law this changes, repeals, or creates — in plain terms." },
    watchList: { type: "array", items: { type: "string" }, description: "Specific things a citizen should watch for or ask their representative." }
  },
  required: ["plainSummary", "traps", "whoBenefits", "whoBurdened", "changesToLaw", "watchList"]
};

function cors(origin) {
  const allow = ALLOW_ORIGINS.includes(origin) ? origin : ALLOW_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400"
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") return new Response(null, { headers: cors(origin) });
    if (request.method !== "POST") return new Response("POST only", { status: 405, headers: cors(origin) });

    let body;
    try { body = await request.json(); } catch { return json({ error: "Bad JSON" }, 400, origin); }

    // ---- rate limiting (protects the account balance) ----
    if (env.RL) {
      const ip = request.headers.get("CF-Connecting-IP") || "anon";
      const t = Date.now();
      const hourKey = "ip:" + ip + ":" + Math.floor(t / 3600000);
      const dayKey  = "day:" + Math.floor(t / 86400000);
      const [ipc, gc] = await Promise.all([env.RL.get(hourKey), env.RL.get(dayKey)]);
      if ((+ipc || 0) >= PER_IP_HOURLY)
        return json({ error: "You've hit the hourly limit for AI deep-dives from this connection. Browsing and the trap detector still work — try the AI again in a bit." }, 429, origin);
      if ((+gc || 0) >= GLOBAL_DAILY)
        return json({ error: "The site's daily AI deep-dive limit has been reached. Everything else still works; the AI resets tomorrow." }, 429, origin);
      await Promise.all([
        env.RL.put(hourKey, String((+ipc || 0) + 1), { expirationTtl: 3600 }),
        env.RL.put(dayKey,  String((+gc  || 0) + 1), { expirationTtl: 86400 })
      ]);
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
        headers: {
          "content-type": "application/json",
          "x-api-key": env.ANTHROPIC_API_KEY,
          "anthropic-version": "2023-06-01"
        },
        body: JSON.stringify({
          model: MODEL,
          max_tokens: 4000,
          system,
          messages: [{ role: "user", content: user }],
          output_config: { format: { type: "json_schema", schema: SCHEMA } }
        })
      });
      if (!r.ok) {
        const t = await r.text();
        return json({ error: "Anthropic API error", status: r.status, detail: t.slice(0, 500) }, 502, origin);
      }
      const data = await r.json();
      const textBlock = (data.content || []).find(b => b.type === "text");
      let analysis;
      try { analysis = JSON.parse(textBlock ? textBlock.text : "{}"); }
      catch { return json({ error: "Could not parse model output" }, 502, origin); }
      return json({ analysis }, 200, origin);
    } catch (e) {
      return json({ error: String(e) }, 500, origin);
    }
  }
};

function json(obj, status, origin) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", ...cors(origin) }
  });
}
