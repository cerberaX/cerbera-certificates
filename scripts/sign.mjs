import { sign, createPrivateKey } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const privPem = readFileSync('./keys/private.pem', 'utf8');
const pubB64 = readFileSync('./keys/public.b64', 'utf8').trim();
const privateKey = createPrivateKey(privPem);

const db = JSON.parse(readFileSync('./data/certs.json', 'utf8'));
db.publicKey = pubB64;

db.certificates = db.certificates.map((cert) => {
  // Imzolanadigan qat'iy kanonik matn
  const payload = [
    cert.id,
    cert.holder,
    cert.program,
    cert.issueDate,
    cert.hours,
    cert.grade,
    cert.status,
    cert.skills.join(',')
  ].join('|');

  const sigBuffer = sign(null, Buffer.from(payload, 'utf8'), privateKey);
  return {
    ...cert,
    signature: sigBuffer.toString('base64')
  };
});

writeFileSync('./data/certs.json', JSON.stringify(db, null, 2));
console.log(`[+] ${db.certificates.length} ta sertifikat Ed25519 bilan imzolandi!`);
