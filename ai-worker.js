/**
 * Read the Bills — AI deep-dive Worker (Cloudflare)
 * -------------------------------------------------
 * Runs the Claude analysis and gates each run by ONE of three access modes:
 *   1) Credit packs   — one-off Stripe purchase, N credits per pack
 *   2) Subscription   — recurring Stripe sub, capped at SUB_MONTHLY_CAP / month
 *   3) Bring-your-own — caller passes their own Anthropic key; costs the owner $0
 *
 * ROUTES:
 *   POST  /         -> run analysis (body: {token, byokKey?, title, bill, ...})
 *   GET   /balance  -> { paywall, byok, credits, packCredits, buyUrl, subUrl, subCap, sub:{active,used,cap} }
 *   POST  /webhook  -> Stripe webhook (grants credits / activates subscriptions)
 *
 * SECRETS: ANTHROPIC_API_KEY (required), STRIPE_WEBHOOK_SECRET (once paywall on)
 * KV: binding RL  (rate limits + credit balances + subscriptions + idempotency)
 *
 * GO-LIVE: set PAYMENT_LINK (one-off) and/or SUB_PAYMENT_LINK (recurring), add a
 *   Stripe webhook to <worker>/webhook (events: checkout.session.completed,
 *   invoice.paid, customer.subscription.deleted), store its signing secret as
 *   STRIPE_WEBHOOK_SECRET, then set PAYWALL_ENABLED = true and redeploy.
 */

const MODEL = "claude-sonnet-4-6";              // strong on legal text, ~1/3 the cost of Opus
const PAYWALL_ENABLED  = false;                 // flip true once Stripe is wired
const BYOK_ALLOWED     = true;                  // allow callers to use their own Anthropic key
const PAYMENT_LINK     = "";                    // Stripe Payment Link — one-off credit pack
const SUB_PAYMENT_LINK = "";                    // Stripe Payment Link — recurring subscription
const CREDITS_PER_PACK = 100;                   // credits granted per pack purchase
const SUB_MONTHLY_CAP  = 200;                   // analyses/month for subscribers
const FREE_TRIAL       = 2;                     // free analyses per new visitor
const PER_IP_HOURLY    = 20;
const GLOBAL_DAILY     = 2000;

const ALLOW_ORIGINS = [
  "https://toresays.github.io", "https://toresays.com", "https://www.toresays.com",
  "http://localhost:8777", "http://127.0.0.1:8777"
];

const SCHEMA = {
  type: "object", additionalProperties: false,
  properties: {
    plainSummary: { type: "string" },
    traps: { type: "array", items: { type: "object", additionalProperties: false,
      properties: { title: { type: "string" }, quote: { type: "string" }, why: { type: "string" },
        severity: { type: "string", enum: ["high", "medium", "low"] } },
      required: ["title", "quote", "why", "severity"] } },
    whoBenefits: { type: "string" }, whoBurdened: { type: "string" },
    changesToLaw: { type: "string" }, watchList: { type: "array", items: { type: "string" } }
  },
  required: ["plainSummary", "traps", "whoBenefits", "whoBurdened", "changesToLaw", "watchList"]
};

function cors(o){const a=ALLOW_ORIGINS.includes(o)?o:ALLOW_ORIGINS[0];return{"Access-Control-Allow-Origin":a,"Access-Control-Allow-Methods":"POST, GET, OPTIONS","Access-Control-Allow-Headers":"Content-Type","Access-Control-Max-Age":"86400"};}
function json(obj,status,o){return new Response(JSON.stringify(obj),{status,headers:{"content-type":"application/json",...cors(o)}});}
function monthBucket(){const d=new Date();return ""+d.getUTCFullYear()+String(d.getUTCMonth()+1).padStart(2,"0");}
async function num(env,k){const v=await env.RL.get(k);return v==null?0:(+v||0);}
async function rawCredits(env,token){if(!env.RL||!token)return null;const v=await env.RL.get("credit:"+token);return v==null?null:(+v||0);}

async function stripeVerify(payload,sig,secret){
  if(!sig||!secret)return false;
  const p={};sig.split(",").forEach(kv=>{const i=kv.indexOf("=");p[kv.slice(0,i)]=kv.slice(i+1);});
  if(!p.t||!p.v1)return false;
  if(Math.abs(Date.now()/1000-(+p.t))>300)return false;
  const enc=new TextEncoder();
  const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const mac=await crypto.subtle.sign("HMAC",key,enc.encode(p.t+"."+payload));
  const hex=[...new Uint8Array(mac)].map(b=>b.toString(16).padStart(2,"0")).join("");
  if(hex.length!==p.v1.length)return false;
  let diff=0;for(let i=0;i<hex.length;i++)diff|=hex.charCodeAt(i)^p.v1.charCodeAt(i);
  return diff===0;
}

export default {
  async fetch(request, env){
    const origin=request.headers.get("Origin")||"";
    const url=new URL(request.url);
    const path=url.pathname.replace(/\/+$/,"")||"/";
    if(request.method==="OPTIONS")return new Response(null,{headers:cors(origin)});

    // ---- balance / config ----
    if(path==="/balance"&&request.method==="GET"){
      const token=url.searchParams.get("token")||"";
      let credits=await rawCredits(env,token); if(credits==null)credits=FREE_TRIAL;
      const subExp=await num(env,"sub:"+token);
      const subActive=subExp>Date.now();
      const subUsed=await num(env,"subused:"+token+":"+monthBucket());
      return json({paywall:PAYWALL_ENABLED,byok:BYOK_ALLOWED,credits,packCredits:CREDITS_PER_PACK,
        buyUrl:PAYMENT_LINK,subUrl:SUB_PAYMENT_LINK,subCap:SUB_MONTHLY_CAP,
        sub:{active:subActive,used:subUsed,cap:SUB_MONTHLY_CAP}},200,origin);
    }

    // ---- Stripe webhook ----
    if(path==="/webhook"&&request.method==="POST"){
      const raw=await request.text();
      if(!await stripeVerify(raw,request.headers.get("stripe-signature"),env.STRIPE_WEBHOOK_SECRET))
        return new Response("bad signature",{status:400});
      let evt;try{evt=JSON.parse(raw);}catch{return new Response("bad json",{status:400});}
      const obj=(evt.data&&evt.data.object)||{};
      if(evt.type==="checkout.session.completed"){
        const seen="seen:"+evt.id;
        if(await env.RL.get(seen))return new Response("dup",{status:200});
        const token=obj.client_reference_id;
        if(token){
          if(obj.mode==="subscription"||obj.subscription){
            await env.RL.put("sub:"+token,String(Date.now()+33*86400000));
            if(obj.subscription)await env.RL.put("subtoken:"+obj.subscription,token);
          }else{
            const cur=(await rawCredits(env,token))||0;
            await env.RL.put("credit:"+token,String(cur+CREDITS_PER_PACK));
          }
          await env.RL.put(seen,"1",{expirationTtl:2592000});
        }
      }else if(evt.type==="invoice.paid"){
        const subId=obj.subscription;
        if(subId){const tk=await env.RL.get("subtoken:"+subId);if(tk)await env.RL.put("sub:"+tk,String(Date.now()+33*86400000));}
      }else if(evt.type==="customer.subscription.deleted"){
        const tk=await env.RL.get("subtoken:"+obj.id);if(tk)await env.RL.put("sub:"+tk,"0");
      }
      return new Response("ok",{status:200});
    }

    // ---- AI analysis ----
    if(request.method!=="POST")return new Response("POST only",{status:405,headers:cors(origin)});
    let body;try{body=await request.json();}catch{return json({error:"Bad JSON"},400,origin);}
    const token=body.token||"";
    const byok=(body.byokKey||"").trim();
    const useByok=BYOK_ALLOWED&&/^sk-ant/.test(byok);

    // abuse backstop
    if(env.RL){
      const ip=request.headers.get("CF-Connecting-IP")||"anon";const t=Date.now();
      const hk="ip:"+ip+":"+Math.floor(t/3600000),dk="day:"+Math.floor(t/86400000);
      const [ipc,gc]=await Promise.all([env.RL.get(hk),env.RL.get(dk)]);
      if((+ipc||0)>=PER_IP_HOURLY)return json({error:"Too many requests from this connection — try again shortly."},429,origin);
      if(!useByok&&(+gc||0)>=GLOBAL_DAILY)return json({error:"The service is busy right now — please try again later."},429,origin);
      await Promise.all([env.RL.put(hk,String((+ipc||0)+1),{expirationTtl:3600}),env.RL.put(dk,String((+gc||0)+1),{expirationTtl:86400})]);
    }

    // access gate (skipped for BYOK and when paywall off)
    let mode=null,creditBal=null,subUsed=0;
    if(PAYWALL_ENABLED&&!useByok){
      const subActive=(await num(env,"sub:"+token))>Date.now()&&!!token;
      if(subActive){subUsed=await num(env,"subused:"+token+":"+monthBucket());if(subUsed<SUB_MONTHLY_CAP)mode="sub";}
      if(!mode){creditBal=await rawCredits(env,token);if(creditBal==null)creditBal=FREE_TRIAL;if(token&&creditBal>0)mode="credit";}
      if(!mode)return json({error:"no_credits",buyUrl:PAYMENT_LINK,subUrl:SUB_PAYMENT_LINK,byok:BYOK_ALLOWED,packCredits:CREDITS_PER_PACK,subCap:SUB_MONTHLY_CAP,subCapReached:subActive},402,origin);
    }

    const {title="",bill="",policyArea="",flagged=[],textSample=""}=body;
    const flaggedText=(Array.isArray(flagged)?flagged:[]).slice(0,40).join("\n• ");
    const system="You are a sharp, nonpartisan legislative analyst writing for ordinary citizens on a public transparency site. "+
      "You read U.S. House bill text and explain — in plain English — what it really does, the traps and vague language buried in it, "+
      "who benefits, who is burdened, and what existing law it changes. Be specific and quote the bill. Do not editorialize about a party. "+
      "Flag real concerns; if the bill is clean, say so plainly. Never invent text that is not in what you were given.";
    const user=`Bill: ${bill}\nTitle: ${title}\nPolicy area: ${policyArea}\n\n`+
      (flaggedText?`Passages our keyword scanner flagged (quote from these where relevant):\n• ${flaggedText}\n\n`:"")+
      `Excerpt of the bill text:\n"""\n${String(textSample).slice(0,18000)}\n"""\n\nAnalyze this bill for the public. Return your analysis as structured JSON.`;

    try{
      const r=await fetch("https://api.anthropic.com/v1/messages",{method:"POST",
        headers:{"content-type":"application/json","x-api-key":useByok?byok:env.ANTHROPIC_API_KEY,"anthropic-version":"2023-06-01"},
        body:JSON.stringify({model:MODEL,max_tokens:4000,system,messages:[{role:"user",content:user}],output_config:{format:{type:"json_schema",schema:SCHEMA}}})});
      if(!r.ok){const t=await r.text();return json({error:useByok?"Your Anthropic key was rejected or is out of credit.":"Anthropic API error",status:r.status,detail:t.slice(0,500)},useByok?400:502,origin);}
      const data=await r.json();
      const tb=(data.content||[]).find(b=>b.type==="text");
      let analysis;try{analysis=JSON.parse(tb?tb.text:"{}");}catch{return json({error:"Could not parse model output"},502,origin);}
      let creditsLeft=null;
      if(mode==="sub"){await env.RL.put("subused:"+token+":"+monthBucket(),String(subUsed+1),{expirationTtl:40*86400});}
      else if(mode==="credit"){creditsLeft=Math.max(0,creditBal-1);await env.RL.put("credit:"+token,String(creditsLeft));}
      return json({analysis,creditsLeft},200,origin);
    }catch(e){return json({error:String(e)},500,origin);}
  }
};
