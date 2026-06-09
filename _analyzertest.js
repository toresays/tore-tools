// Validate the detector against REAL bill text (no API key needed for text files).
const RULES=[
 {id:"notw",sev:"high",label:'notwithstanding any other provision of law',re:/notwithstanding any other provision of (law|this title|this Act)/gi},
 {id:"nojud",sev:"high",label:"blocks court review",re:/shall not be subject to judicial review|precludes? judicial review|not be reviewable in any court|no court shall have jurisdiction|not subject to review/gi},
 {id:"apa",sev:"high",label:"skips rulemaking/NEPA",re:/without regard to (the provisions of )?(chapter 5 of title 5|subchapter II of chapter 5|the Administrative Procedure Act|section 553|the National Environmental Policy Act)/gi},
 {id:"sums",sev:"med",label:"such sums as may be necessary",re:/such sums as (may be|are) necessary/gi},
 {id:"disc",sev:"med",label:"sole discretion",re:/(in|at) the sole discretion of|sole and (unreviewable|absolute) discretion|as the (Secretary|Administrator|Director|President|Attorney General|Commissioner)[^.]{0,45}(determines|considers|deems)[^.]{0,30}(appropriate|necessary)/gi},
 {id:"emerg",sev:"med",label:"emergency designation",re:/designated as (an emergency|emergency requirement)|emergency requirement pursuant to/gi},
 {id:"waive",sev:"med",label:"waiver",re:/may waive|is authorized to waive|waiver of (any|the|all) (requirement|provision|rule)/gi},
 {id:"retro",sev:"med",label:"retroactive",re:/effective as if (enacted|included)|shall (take effect|apply) (as if|retroactively)/gi},
 {id:"xfer",sev:"med",label:"transfer/reprogram funds",re:/may (transfer|reprogram)|authority to transfer|transferred (to|between) (any )?(other )?accounts?/gi},
 {id:"repeal",sev:"med",label:"repeal",re:/is (hereby )?repealed|are (hereby )?repealed|repeal of section/gi},
 {id:"auth",sev:"low",label:"authorized to be appropriated",re:/there (is|are) authorized to be appropriated/gi},
 {id:"other",sev:"low",label:"and for other purposes",re:/and for other purposes/gi},
 {id:"amend",sev:"info",label:"amends by reference",re:/is amended[—-]|by striking|by inserting|by adding at the end/gi},
 {id:"rule",sev:"info",label:"delegates to regulations",re:/shall (issue|prescribe|promulgate) (regulations|rules)|by regulation/gi},
 {id:"sunset",sev:"info",label:"sunset",re:/shall (cease to have effect|expire|terminate) (on|after|at)|sunset|termination date/gi},
 {id:"sense",sev:"info",label:"sense of Congress",re:/it is the sense of (the )?(congress|house|senate)/gi}
];
const VAGUE=/\b(reasonable|appropriate|practicable|substantial(ly)?|significant(ly)?|as necessary|from time to time|undue|good faith|adequate|excessive)\b/gi;
function strip(html){
  html=html.replace(/<(script|style)[\s\S]*?<\/\1>/gi," ");
  let txt=html.replace(/<\/(p|div|li|h\d|tr|section)>/gi,"\n").replace(/<[^>]+>/g," ");
  txt=txt.replace(/&nbsp;/g," ").replace(/&amp;/g,"&").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&#\d+;/g," ");
  return txt.replace(/[ \t]+/g," ").replace(/\n{3,}/g,"\n\n").trim();
}
(async()=>{
  const urls=[
    "https://www.congress.gov/119/bills/hr8312/BILLS-119hr8312ih.htm",
    "https://www.congress.gov/119/bills/hr8312/BILLS-119hr8312rh.htm"
  ];
  for(const url of urls){
    try{
      const r=await fetch(url);
      if(!r.ok){console.log("\n"+url+" -> HTTP "+r.status);continue;}
      const text=strip(await r.text());
      console.log("\n===== "+url.split("/").pop()+" ("+text.length+" chars plain) =====");
      let total=0;
      RULES.forEach(rule=>{const re=new RegExp(rule.re.source,rule.re.flags);let c=0,m;while((m=re.exec(text))){c++;if(m.index===re.lastIndex)re.lastIndex++;if(c>5000)break;}if(c){total+=c;console.log("  ["+rule.sev.toUpperCase().padEnd(4)+"] x"+String(c).padStart(3)+"  "+rule.label);}});
      let v=0,vm2;const vre=new RegExp(VAGUE.source,VAGUE.flags);while((vm2=vre.exec(text))){v++;if(vm2.index===vre.lastIndex)vre.lastIndex++;}
      console.log("  vague terms: "+v+"  | total rule hits: "+total);
    }catch(e){console.log(url+" -> ERROR "+e.message);}
  }
})();
