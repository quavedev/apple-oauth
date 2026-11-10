// Run with Node 24 and 26: node tests/node-compat.cjs <installed-dependency-directory>
// Dependencies must be installed from this package's npm-shrinkwrap.json.
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const root = path.resolve(process.argv[2] || '.npm/package/node_modules');
const jwt = require(path.join(root, 'jsonwebtoken'));
require(path.join(root, 'jwks-rsa'));
assert.equal(require(path.join(root, 'jwa/package.json')).version, '1.4.2');
const issuer = 'https://appleid.apple.com';
const audience = 'test.example.apple-client';
const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const pem = key => key.export({ type: 'pkcs8', format: 'pem' });
const pub = key => key.export({ type: 'spki', format: 'pem' });
const identity = jwt.sign({ sub: 'synthetic-user' }, pem(rsa.privateKey), {
  algorithm: 'RS256', issuer, audience, expiresIn: 60, keyid: 'synthetic-key'
});
const options = { algorithms: ['RS256'], issuer, audience };
assert.equal(jwt.verify(identity, pub(rsa.publicKey), options).sub, 'synthetic-user');
assert.throws(() => jwt.verify(identity, pub(rsa.publicKey), { ...options, audience: 'wrong' }));
assert.throws(() => jwt.verify(identity, pub(rsa.publicKey), { ...options, issuer: 'wrong' }));
assert.throws(() => jwt.verify(identity, pub(rsa.publicKey), { ...options, clockTimestamp: Math.floor(Date.now() / 1000) + 120 }));
const wrong = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
assert.throws(() => jwt.verify(identity, pub(wrong.publicKey), options));
const secret = jwt.sign({ iss: 'synthetic-team', sub: audience, aud: issuer }, pem(ec.privateKey), {
  algorithm: 'ES256', keyid: 'synthetic-key', expiresIn: 60
});
assert.equal(jwt.verify(secret, pub(ec.publicKey), { algorithms: ['ES256'], audience: issuer }).sub, audience);
const hmac = jwt.sign({ sub: 'synthetic-user' }, 'synthetic-secret', { algorithm: 'HS256' });
assert.equal(jwt.verify(hmac, 'synthetic-secret', { algorithms: ['HS256'] }).sub, 'synthetic-user');
assert.throws(() => jwt.verify(hmac, 'wrong-secret', { algorithms: ['HS256'] }));
assert.ok(!Object.keys(require.cache).some(file => file.includes('buffer-equal-constant-time')));
console.log(`PASS ${process.version}: module load, RS256 identity, ES256 client secret, HS256, invalid signature/issuer/audience/expiry; legacy buffer module not loaded`);
