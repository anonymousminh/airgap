// Cross-language check: Python-signed receipt must verify with the browser's canonical() + Ed25519.
import crypto from "node:crypto";
const base = process.argv[2];
function canonical(v){ if(v===null||typeof v!=="object") return JSON.stringify(v); if(Array.isArray(v)) return "["+v.map(canonical).join(",")+"]";
  return "{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}"; }
const pub = (await (await fetch(base+"/api/pubkey")).json()).public_key_b64;
const spki = Buffer.concat([Buffer.from("302a300506032b6570032100","hex"), Buffer.from(pub,"base64")]);
const key = crypto.createPublicKey({key:spki, format:"der", type:"spki"});
const atk = await (await fetch(base+"/api/attacks/HOST-ESCAPE/run",{method:"POST"})).json();
const r = atk.receipt, {signature_ed25519, receipt_hash, ...body} = r;
const check = b => crypto.verify(null, Buffer.from(canonical(b)), key, Buffer.from(signature_ed25519,"base64"));
console.log("untouched receipt verifies in JS :", check(body));
const t = structuredClone(body); t.containment.canary_hits_on_listener = 1;
console.log("tampered receipt verifies in JS  :", check(t), "(expected false)");
const srv = async x => (await (await fetch(base+"/api/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(x)})).json());
console.log("server verdict untouched:", JSON.stringify(await srv(r)));
console.log("server verdict tampered :", JSON.stringify(await srv({...r, containment:{...r.containment, canary_hits_on_listener:1}})));
