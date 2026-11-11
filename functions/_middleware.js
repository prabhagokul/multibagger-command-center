// Cloudflare Pages Function — login gate + owner/viewer dual view.
// Credentials come from environment variables (set in the Pages dashboard, changeable anytime):
//   OWNER_USER, OWNER_PASS   -> full report (all amounts)
//   VIEWER_USER, VIEWER_PASS -> redacted report (holdings without quantities/amounts/P&L)
//   COOKIE_SECRET            -> any long random string (signs the login cookie)

const enc = new TextEncoder();

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function makeToken(role, secret) {
  const payload = role + "." + Date.now();
  return payload + "." + (await hmac(secret, payload));
}
async function roleFromCookie(cookieHeader, secret) {
  const m = /(?:^|;\s*)cc_auth=([^;]+)/.exec(cookieHeader || "");
  if (!m) return null;
  const parts = decodeURIComponent(m[1]).split(".");
  if (parts.length !== 3) return null;
  const [role, ts, sig] = parts;
  if (role !== "owner" && role !== "viewer") return null;
  const good = await hmac(secret, role + "." + ts);
  if (good !== sig) return null;
  if (Date.now() - Number(ts) > 1000 * 60 * 60 * 24 * 7) return null; // 7-day sessions
  return role;
}

function loginPage(msg) {
  const err = msg ? `<p style="color:#ff6b6b;font-size:13px;margin:0 0 10px">${msg}</p>` : "";
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Multibagger Command Center — Sign in</title>
<style>
  body{margin:0;background:linear-gradient(180deg,#0a0f15,#0b1016);color:#e7eef6;font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center}
  .box{background:#121a24;border:1px solid #1f2b38;border-radius:16px;padding:30px 28px;width:320px;box-shadow:0 10px 40px rgba(0,0,0,.45)}
  h1{font-size:19px;margin:0 0 4px} .sub{color:#8aa0b4;font-size:12.5px;margin:0 0 20px}
  label{display:block;font-size:12px;color:#8aa0b4;margin:12px 0 5px;text-transform:uppercase;letter-spacing:.4px}
  input{width:100%;box-sizing:border-box;background:#0f1620;border:1px solid #1f2b38;color:#e7eef6;border-radius:9px;padding:11px 12px;font-size:15px;outline:none}
  input:focus{border-color:#2dd4bf}
  button{width:100%;margin-top:20px;background:#2dd4bf;color:#06201c;border:0;border-radius:9px;padding:12px;font-size:15px;font-weight:800;cursor:pointer}
  button:hover{filter:brightness(1.05)}
</style></head><body>
  <form class="box" method="POST" action="/__login">
    <h1>Multibagger Command Center</h1>
    <div class="sub">Private — please sign in.</div>
    ${err}
    <label>Username</label>
    <input name="username" autocomplete="username" autofocus>
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</body></html>`;
  return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const secret = env.COOKIE_SECRET || "change-me";

  // Never allow the raw report files to be fetched directly.
  if (path === "/full.html" || path === "/viewer.html") {
    return new Response("Not found", { status: 404 });
  }

  // Logout
  if (path === "/__logout") {
    return new Response(null, { status: 302, headers: { "Location": "/", "Set-Cookie": "cc_auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" } });
  }

  // Login submit
  if (request.method === "POST" && path === "/__login") {
    const form = await request.formData();
    const u = (form.get("username") || "").toString();
    const p = (form.get("password") || "").toString();
    let role = null;
    if (u === env.OWNER_USER && p === env.OWNER_PASS) role = "owner";
    else if (u === env.VIEWER_USER && p === env.VIEWER_PASS) role = "viewer";
    if (!role) return loginPage("Wrong username or password.");
    const token = await makeToken(role, secret);
    return new Response(null, { status: 302, headers: {
      "Location": "/",
      "Set-Cookie": `cc_auth=${encodeURIComponent(token)}; Path=/; Max-Age=${60 * 60 * 24 * 7}; HttpOnly; Secure; SameSite=Lax`
    }});
  }

  // Everything else requires a valid session
  const role = await roleFromCookie(request.headers.get("Cookie"), secret);
  if (!role) return loginPage("");

  // Serve the correct report (fetched internally from static assets; never exposed as a URL)
  const file = role === "owner" ? "/full.html" : "/viewer.html";
  const asset = await env.ASSETS.fetch(new Request(new URL(file, url.origin), request));
  return new Response(asset.body, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}
