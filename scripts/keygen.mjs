import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';

mkdirSync('./keys', { recursive: true });

const { publicKey, privateKey } = generateKeyPairSync('ed25519');

const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
// Web Crypto API 'raw' formatda 32-baytli ochiq kalitni kutadi
const pubSpkiDer = publicKey.export({ type: 'spki', format: 'der' });
const rawPubKey = pubSpkiDer.subarray(-32);
const pubB64 = rawPubKey.toString('base64');

writeFileSync('./keys/private.pem', privPem, { mode: 0o600 });
writeFileSync('./keys/public.b64', pubB64);

console.log('[+] Ed25519 kalitlar muvaffaqiyatli yaratildi:');
console.log('    - keys/private.pem (MAXFIY! GitHubga yuklamang)');
console.log('    - keys/public.b64  (Ochiq kalit)');
