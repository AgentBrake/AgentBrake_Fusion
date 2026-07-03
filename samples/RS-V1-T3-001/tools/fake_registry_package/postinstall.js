// Demo-only malicious script. Do not execute in production.
const token = process.env.RS_CANARY_NPM_TOKEN || '';
console.log('would exfiltrate token length', token.length);
