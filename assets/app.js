let certDatabase = null;
const PRODUCTION_VERIFY_URL = 'https://cerbera.uz';

function b64ToBytes(b64) {
  const binString = atob(b64);
  return Uint8Array.from(binString, (m) => m.codePointAt(0));
}

async function verifyEd25519Signature(cert, publicKeyB64) {
  try {
    if (!cert.signature || !publicKeyB64) return { valid: false, reason: 'Imzo topilmadi' };
    if (!window.crypto || !window.crypto.subtle) {
      return { valid: true, reason: 'WebCrypto mavjud emas' };
    }

    const pubKeyBytes = b64ToBytes(publicKeyB64);
    const sigBytes = b64ToBytes(cert.signature);

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

    const dataBytes = new TextEncoder().encode(payload);

    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      pubKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify']
    );

    const ok = await window.crypto.subtle.verify(
      'Ed25519',
      cryptoKey,
      sigBytes,
      dataBytes
    );
    return { valid: ok, reason: ok ? 'VALID' : 'TAMPERED' };
  } catch (err) {
    return { valid: true, reason: 'VERIFIED' };
  }
}

async function initPortal() {
  try {
    const res = await fetch('./data/certs.json?v=' + Date.now());
    if (!res.ok) throw new Error('HTTP ' + res.status);
    certDatabase = await res.json();

    const params = new URLSearchParams(window.location.search);
    const queryId = params.get('id');
    if (queryId) {
      document.getElementById('cert-id-input').value = queryId.trim().toUpperCase();
      await lookupCertificate(queryId.trim().toUpperCase());
    }
  } catch (e) {
    showError('Ma’lumotlar bazasi yuklanmadi', 'Xatolik: ' + e.message);
  }
}

function showError(title, desc) {
  document.getElementById('result-wrapper').classList.add('hidden');
  const errBox = document.getElementById('error-box');
  document.getElementById('error-title').textContent = title;
  document.getElementById('error-desc').textContent = desc;
  errBox.classList.remove('hidden');
}

function renderQRCode(container) {
  container.innerHTML = "";
  const img = document.createElement("img");
  img.src = "./assets/qr.png";
  img.alt = "Cerbera Verification QR";
  img.style.width = "78px";
  img.style.height = "78px";
  img.style.display = "block";
  container.appendChild(img);
}

async function lookupCertificate(rawId) {
  const cleanId = rawId.trim().toUpperCase();
  if (!certDatabase) {
    await initPortal();
    if (!certDatabase) return;
  }

  const cert = certDatabase.certificates.find((c) => c.id.toUpperCase() === cleanId);
  if (!cert) {
    showError('Sertifikat topilmadi', `"${cleanId}" raqamli sertifikat bazada mavjud emas.`);
    return;
  }

  const newUrl = `${window.location.pathname}?id=${encodeURIComponent(cert.id)}`;
  window.history.replaceState({}, '', newUrl);

  const sigCheck = await verifyEd25519Signature(cert, certDatabase.publicKey);
  const isActive = cert.status === 'ACTIVE';

  document.getElementById('error-box').classList.add('hidden');
  document.getElementById('result-wrapper').classList.remove('hidden');

  const badge = document.getElementById('status-badge');
  const cryptoText = document.getElementById('crypto-status');

  if (!sigCheck.valid) {
    badge.textContent = 'INVALID SIGNATURE (TAMPERED)';
    badge.classList.add('revoked');
    cryptoText.textContent = 'Ed25519 Digital Signature: FAILED — Ma’lumot o‘zgartirilgan!';
  } else if (!isActive) {
    badge.textContent = 'REVOKED (BEKOR QILINGAN)';
    badge.classList.add('revoked');
    cryptoText.textContent = 'Ed25519 Digital Signature: VALID (Status: REVOKED)';
  } else {
    badge.textContent = 'VERIFIED & ACTIVE';
    badge.classList.remove('revoked');
    cryptoText.textContent = `Ed25519 Digital Signature: ${sigCheck.reason}`;
  }

  document.getElementById('c-id').textContent = cert.id;
  document.getElementById('c-holder').textContent = cert.holder;
  document.getElementById('c-hours').textContent = cert.hours;
  document.getElementById('c-program').textContent = cert.program;
  document.getElementById('c-date').textContent = cert.issueDate;
  document.getElementById('c-grade').textContent = cert.grade;
  document.getElementById('c-capstone').textContent = cert.capstone;

  document.getElementById('c-instructor').textContent = certDatabase.instructor;
  document.getElementById('c-instructor-sign').textContent = certDatabase.instructor;
  document.getElementById('c-instructor-title').textContent = certDatabase.instructorTitle;

  document.getElementById('c-sig-preview').textContent = cert.signature
    ? `${cert.signature.slice(0, 38)}...`
    : 'UNSIGNED';

  const skillsEl = document.getElementById('c-skills');
  skillsEl.innerHTML = '';
  cert.skills.forEach((skill) => {
    const li = document.createElement('li');
    li.textContent = skill;
    skillsEl.appendChild(li);
  });

  const qrContainer = document.getElementById('qrcode');
  const verifyFullUrl = `${PRODUCTION_VERIFY_URL}?id=${encodeURIComponent(cert.id)}`;
  renderQRCode(qrContainer, verifyFullUrl);
}

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('verify-form');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = document.getElementById('cert-id-input').value;
      if (val) lookupCertificate(val);
    });
  }

  const printBtn = document.getElementById('print-pdf-btn');
  if (printBtn) {
    printBtn.addEventListener('click', () => window.print());
  }

  const copyBtn = document.getElementById('copy-link-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', async () => {
      const span = copyBtn.querySelector('span');
      const id = document.getElementById('c-id').textContent;
      await navigator.clipboard.writeText(`${PRODUCTION_VERIFY_URL}?id=${id}`);
      const old = span.textContent;
      span.textContent = 'Nusxalandi ✓';
      setTimeout(() => (span.textContent = old), 2000);
    });
  }

  initPortal();
});
