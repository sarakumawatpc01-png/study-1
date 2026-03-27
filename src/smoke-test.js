const http = require('http');
const crypto = require('crypto');
const app = require('./server');

function req(method, path, body) {
  const payload = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const r = http.request(
      {
        host: '127.0.0.1',
        port: global.__PORT__,
        method,
        path,
        headers: {
          'content-type': 'application/json',
          ...(payload ? { 'content-length': Buffer.byteLength(payload) } : {}),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          let json = {};
          try {
            json = data ? JSON.parse(data) : {};
          } catch (e) {}
          resolve({ status: res.statusCode, body: json });
        });
      }
    );
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

async function run() {
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  global.__PORT__ = server.address().port;

  const signup = await req('POST', '/api/auth/signup', {
    email: `user-${crypto.randomUUID()}@example.com`,
    password: 'StrongPass123',
    name: 'Rahul',
    exam: 'SSC CGL',
  });
  if (signup.status !== 201 || !signup.body.token) throw new Error('Signup failed');

  server.close();
  console.log('Smoke test passed');
}

run().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
