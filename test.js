process.env.DB_FILE = ":memory:";
const assert = require("assert");
const { app } = require("./server");

let logs = [];
const origLog = console.log;
console.log = (...a) => { logs.push(a.join(" ")); };
const lastOtp = () => logs.filter((l) => l.includes("[DEV EMAIL]")).pop().match(/code=(\d+)/)[1];

const server = app.listen(0, async () => {
  const base = `http://localhost:${server.address().port}`;
  const call = async (method, path, body, token) => {
    const r = await fetch(base + path, {
      method,
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: r.status, body: await r.json() };
  };
  const ok = (name) => origLog("PASS:", name);

  try {
    const a = (await call("POST", "/auth/register", { name: "Ali", email: "a@x.com", password: "123456" })).body;
    const b = (await call("POST", "/auth/register", { name: "Bob", email: "b@x.com", password: "123456" })).body;
    const c = (await call("POST", "/auth/register", { name: "Eve", email: "c@x.com", password: "123456" })).body;
    const tA = (await call("POST", "/auth/login", { email: "a@x.com", password: "123456" })).body.accessToken;
    const tB = (await call("POST", "/auth/login", { email: "b@x.com", password: "123456" })).body.accessToken;
    const tC = (await call("POST", "/auth/login", { email: "c@x.com", password: "123456" })).body.accessToken;
    assert(tA && tB && tC); ok("register + login without 2FA returns tokens directly");

    const m = (await call("POST", "/messages", { receiverId: b.id, content: "hi anon" }, tA)).body;
    let inbox = (await call("GET", "/messages/received", null, tB)).body;
    assert.equal(inbox.length, 1); assert.equal(inbox[0].senderId, null); assert.equal(inbox[0].senderName, null);
    ok("receiver can't see sender identity");

    assert.equal((await call("POST", `/messages/${m.id}/request-identity`, null, tC)).status, 404);
    const rq = (await call("POST", `/messages/${m.id}/request-identity`, null, tB)).body;
    assert.equal(rq.status, "pending"); ok("identity request pending");

    assert.equal((await call("GET", "/requests", null, tB)).body.length, 0);
    const reqs = (await call("GET", "/requests", null, tA)).body;
    assert.equal(reqs.length, 1);
    assert.equal((await call("PATCH", `/requests/${rq.id}`, { action: "accept" }, tB)).status, 404);
    ok("sender sees requests; others can't act");

    assert.equal((await call("PATCH", `/requests/${rq.id}`, { action: "reject" }, tA)).body.status, "rejected");
    inbox = (await call("GET", "/messages/received", null, tB)).body;
    assert.equal(inbox[0].senderId, null); ok("reject keeps identity hidden");

    const rq2 = (await call("POST", `/messages/${m.id}/request-identity`, null, tB)).body;
    const acc = (await call("PATCH", `/requests/${rq2.id}`, { action: "accept" }, tA)).body;
    assert.equal(acc.status, "accepted"); assert(acc.conversationId);
    inbox = (await call("GET", "/messages/received", null, tB)).body;
    assert.equal(inbox[0].senderName, "Ali"); ok("accept reveals identity + creates conversation");

    const cid = acc.conversationId;
    assert.equal((await call("POST", `/conversations/${cid}/messages`, { content: "hey" }, tB)).status, 201);
    assert.equal((await call("POST", `/conversations/${cid}/messages`, { content: "yo" }, tA)).status, 201);
    assert.equal((await call("GET", `/conversations/${cid}/messages`, null, tA)).body.messages.length, 2);
    assert.equal((await call("GET", `/conversations/${cid}/messages`, null, tC)).status, 404);
    assert.equal((await call("POST", `/conversations/${cid}/messages`, { content: "x" }, tC)).status, 404);
    ok("conversation authorization");

    await call("POST", "/auth/2fa/enable", null, tA);
    assert.equal((await call("POST", "/auth/2fa/verify", { otp: "000000" }, tA)).status, 401);
    assert.equal((await call("POST", "/auth/2fa/verify", { otp: lastOtp() }, tA)).status, 200);
    ok("enable 2FA via OTP");

    const l = (await call("POST", "/auth/login", { email: "a@x.com", password: "123456" })).body;
    assert(l.twoStepRequired && !l.accessToken); ok("login with 2FA sends OTP, no tokens");
    assert.equal((await call("POST", "/auth/login/confirm", { email: "a@x.com", otp: "000000" })).status, 401);
    assert((await call("POST", "/auth/login/confirm", { email: "a@x.com", otp: lastOtp() })).body.accessToken);
    ok("login confirm returns tokens");

    for (let i = 1; i <= 4; i++) assert.equal((await call("POST", "/auth/login", { email: "c@x.com", password: "bad" })).status, 401);
    assert.equal((await call("POST", "/auth/login", { email: "c@x.com", password: "bad" })).status, 429);
    assert.equal((await call("POST", "/auth/login", { email: "c@x.com", password: "123456" })).status, 429);
    ok("5 failures -> banned even with correct password");

    const { db } = require("./server");
    db.prepare("UPDATE users SET locked_until=? WHERE email='c@x.com'").run(Date.now() - 1);
    assert.equal((await call("POST", "/auth/login", { email: "c@x.com", password: "123456" })).status, 200);
    ok("ban expires after 5 minutes");
  } catch (e) {
    origLog("FAIL:", e);
    process.exitCode = 1;
  }
  server.close();
});
