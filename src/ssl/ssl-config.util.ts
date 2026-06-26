import * as fs   from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as tls    from 'tls';
import * as https  from 'https';
import { spawnSync } from 'child_process';

// ─── Detección de certificados SSL ────────────────────────────────────────────
// Prioridad 1: .pfx / .p12  (con password.txt opcional)
// Prioridad 2: *.key + *.crt / *.cer  (con password.txt opcional)
// Si el PFX no puede descifrarse, hace fallback a .key/.crt en la misma carpeta

function readPassphrase(certDir: string): string | undefined {
  try {
    const files  = fs.readdirSync(certDir);
    const pwFile = files.find(n => n.toLowerCase() === 'password.txt');
    if (!pwFile) return undefined;
    const raw   = fs.readFileSync(path.join(certDir, pwFile), 'utf8').trim();
    const match = raw.match(/^(?:password|passphrase)\s*:\s*(.+)$/i);
    return match ? match[1].trim() : raw;
  } catch { return undefined; }
}

export function detectCertFormat(certDir: string) {
  try {
    const files = fs.readdirSync(certDir);
    const pfxFile = files.find(f => /\.(pfx|p12)$/i.test(f));
    if (pfxFile) {
      return { type: 'pfx', pfx: path.join(certDir, pfxFile), passphrase: readPassphrase(certDir) };
    }
    const keyFile  = files.find(f => /\.key$/i.test(f));
    const certFile = files.find(f => /\.(crt|cer)$/i.test(f));
    if (keyFile && certFile) {
      return { type: 'pem', key: path.join(certDir, keyFile), cert: path.join(certDir, certFile), passphrase: readPassphrase(certDir) };
    }
  } catch { /* carpeta no accesible */ }
  return null;
}

export function isKeyEncrypted(keyPath: string): boolean | null {
  try {
    const c = fs.readFileSync(keyPath, 'utf8');
    if (c.includes('BEGIN ENCRYPTED PRIVATE KEY')) return true;
    if (c.includes('Proc-Type:') && c.includes('ENCRYPTED')) return true;
    return false;
  } catch { return null; }
}

export function logCertInfo(certBuffer: Buffer | string): void {
  try {
    const x509 = new crypto.X509Certificate(certBuffer);
    const cn   = (x509.subject.match(/CN=([^,\n]+)/) || [])[1] || '(no CN)';
    console.log('   Dominio (CN):', cn);
    if (x509.subjectAltName) {
      const sans = x509.subjectAltName.split(',').map(s => s.trim()).filter(s => s.startsWith('DNS:'));
      if (sans.length) console.log('   SANs:', sans.join(', '));
    }
    console.log('   Válido hasta:', x509.validTo);
  } catch (e: any) {
    console.log('   (no se pudo leer info del certificado:', e.message + ')');
  }
}

function logPfxInfo(pfxPath: string, passphrase?: string): void {
  try {
    const result = spawnSync('openssl',
      ['pkcs12', '-in', pfxPath, '-nokeys', '-clcerts', '-nodes', '-passin', `pass:${passphrase || ''}`],
      { encoding: 'utf8' },
    );
    if (result.status === 0 && result.stdout) {
      const pem = result.stdout.match(/(-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----)/);
      if (pem) logCertInfo(pem[1]);
    } else {
      console.log('   (openssl no disponible o no se pudo leer el PFX)');
    }
  } catch (e: any) {
    console.log('   (no se pudo leer info del PFX:', e.message + ')');
  }
}

export function buildHttpsOptions(): https.ServerOptions | null {
  if (process.env.USE_SSL !== 'true') return null;

  const certPathEnv = process.env.CERT_PATH?.trim();
  if (!certPathEnv) {
    console.warn('⚠️  USE_SSL=true pero CERT_PATH no está definido — continuando sin HTTPS');
    console.warn('   Define CERT_PATH en .env apuntando al directorio de certificados');
    return null;
  }
  // Rutas estilo Windows (C:\... o C:/...) son absolutas en Windows pero no en Linux
  const isWindowsAbsPath = /^[A-Za-z]:[\\\/]/.test(certPathEnv);
  if (isWindowsAbsPath && process.platform !== 'win32') {
    console.warn(`⚠️  CERT_PATH es una ruta de Windows ("${certPathEnv}") pero el proceso corre en Linux/Docker`);
    console.warn('   Define CERT_PATH con ruta Unix en docker-compose.dev.yml (ej: /app/certs)');
    return null;
  }
  const resolvedPaths: string[] = (path.isAbsolute(certPathEnv) || isWindowsAbsPath)
    ? [certPathEnv]
    : [
        path.join(process.cwd(), certPathEnv),
        path.join(__dirname, '..', certPathEnv),
        path.join(__dirname, certPathEnv),
      ];

  console.log('🔍 Buscando certificados SSL...');

  let certInfo: ReturnType<typeof detectCertFormat> = null;
  let certsPath: string | null = null;

  for (const p of resolvedPaths) {
    const detected = detectCertFormat(p);
    if (detected) { certInfo = detected; certsPath = p; console.log(`   ✔ ${p}  ← usada`); break; }
    console.log(`   ✘ ${p}  (${fs.existsSync(p) ? 'sin certificados' : 'no existe'})`);
  }

  if (!certInfo) {
    console.warn('⚠️  No se encontraron certificados SSL — continuando sin HTTPS');
    return null;
  }

  try {
    if (certInfo.type === 'pfx') {
      const pfxBuffer  = fs.readFileSync(certInfo.pfx!);
      const passphrase = certInfo.passphrase ?? '';
      try {
        tls.createSecureContext({ pfx: pfxBuffer, passphrase });
      } catch {
        console.warn('⚠️  PFX cifrado — buscando .key/.crt como fallback...');
        const files    = fs.readdirSync(certsPath!);
        const keyFile  = files.find(f => f.endsWith('.key'));
        const certFile = files.find(f => f.endsWith('.crt') || f.endsWith('.cer'));
        if (keyFile && certFile) {
          const certBuf = fs.readFileSync(path.join(certsPath!, certFile));
          console.log('🔒 HTTPS habilitado - .key/.crt (fallback)');
          logCertInfo(certBuf);
          return { key: fs.readFileSync(path.join(certsPath!, keyFile)), cert: certBuf };
        }
        throw new Error('PFX cifrado y no se encontró .key/.crt como alternativa');
      }
      console.log('🔒 HTTPS habilitado - PFX:', certsPath);
      logPfxInfo(certInfo.pfx!, certInfo.passphrase);
      return { pfx: pfxBuffer, passphrase };
    } else {
      const certBuf = fs.readFileSync(certInfo.cert!);
      const opts: https.ServerOptions = { key: fs.readFileSync(certInfo.key!), cert: certBuf };
      if (certInfo.passphrase) opts.passphrase = certInfo.passphrase;
      console.log('🔒 HTTPS habilitado - PEM:', certsPath);
      const enc = isKeyEncrypted(certInfo.key!);
      console.log('   Clave cifrada:', enc === true ? 'Sí' : enc === false ? 'No' : 'indeterminado');
      logCertInfo(certBuf);
      return opts;
    }
  } catch (e: any) {
    console.error('❌ Error al leer certificados:', e.message, '— continuando sin HTTPS');
    return null;
  }
}
