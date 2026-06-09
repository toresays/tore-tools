const fs=require("fs"),vm=require("vm");
const html=fs.readFileSync(process.argv[2],"utf8");
const re=/<script>([\s\S]*?)<\/script>/g;let m,i=0,bad=0;
while((m=re.exec(html))){i++;try{new vm.Script(m[1]);console.log("script #"+i+": OK ("+m[1].length+" chars)");}catch(e){bad++;console.log("script #"+i+": SYNTAX ERROR -> "+e.message);}}
console.log(bad?("FAIL: "+bad+" block(s) with errors"):"ALL "+i+" SCRIPT BLOCK(S) PARSE OK");
