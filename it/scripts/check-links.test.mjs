import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { checkAllLinks } from './check-links.mjs';

test('HTTPS link checks verify certificates and keep retrying', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'gateway-tls-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
    '-keyout', keyPath, '-out', certPath,
  ], { stdio: 'ignore' });
  const cert = readFileSync(certPath);
  let requests = 0;
  let handshakeErrors = 0;
  const server = https.createServer({ key: readFileSync(keyPath), cert }, (_req, res) => {
    requests++;
    res.end('ok');
  });
  server.on('tlsClientError', () => { handshakeErrors++; });
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const url = `https://127.0.0.1:${server.address().port}/`;

  await t.test('rejects an untrusted certificate before sending HTTP requests', async t => {
    const setTimeout = globalThis.setTimeout;
    t.mock.method(globalThis, 'setTimeout', (callback, _delay, ...args) => setTimeout(callback, 0, ...args));
    const failures = await checkAllLinks([url]);
    assert.equal(failures.size, 1);
    assert.match(failures.get(url), /self.signed certificate/i);
    assert.equal(requests, 0);
    assert.ok(handshakeErrors >= 3, 'the checker should retry failed TLS handshakes');
  });

  await t.test('accepts a matching certificate from an explicitly trusted CA', async t => {
    const previousCA = https.globalAgent.options.ca;
    https.globalAgent.options.ca = cert;
    t.after(() => { https.globalAgent.options.ca = previousCA; });
    const failures = await checkAllLinks([url]);
    assert.equal(failures.size, 0);
    assert.equal(requests, 1);
  });
});
