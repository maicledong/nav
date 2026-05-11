export async function onRequestPost({ env, request }) {
  try {
    const GITHUB_APP_ID = env.GITHUB_APP_ID;
    const PRIVATE_KEY = env.GITHUB_PRIVATE_KEY;

    if (!GITHUB_APP_ID || !PRIVATE_KEY) {
      return new Response(JSON.stringify({ err: "环境变量缺失" }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    // 解析前端传的参数
    const body = await request.json();
    const { owner, repo, branch, path, method, content, sha } = body;

    // 生成JWT
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: GITHUB_APP_ID,
      iat: now - 10,
      exp: now + 300
    };

    // 用私钥签名JWT
    const jwt = await signJWT(payload, PRIVATE_KEY);

    // 拿安装id
    const installRes = await fetch(`https://api.github.com/app/installations`, {
      headers: {
        "Authorization": `Bearer ${jwt}`,
        "Accept": "application/vnd.github.v3+json"
      }
    });
    const installs = await installRes.json();
    const installId = installs[0]?.id;
    if (!installId) throw new Error("未获取到GitHub安装ID");

    // 获取token
    const tokenRes = await fetch(`https://api.github.com/app/installations/${installId}/access_tokens`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${jwt}`,
        "Accept": "application/vnd.github.v3+json"
      }
    });
    const tokenData = await tokenRes.json();
    const token = tokenData.token;

    // 操作文件
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}?ref=${branch}`;
    const reqOpt = {
      method: method,
      headers: {
        "Authorization": `token ${token}`,
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: "更新配置",
        content: btoa(unescape(encodeURIComponent(content))),
        sha: sha || undefined
      })
    };

    const gitRes = await fetch(apiUrl, reqOpt);
    const gitJson = await gitRes.json();

    return new Response(JSON.stringify(gitJson), {
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });

  } catch (err) {
    return new Response(JSON.stringify({ err: err.message }), {
      status: 500,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }
}

// JWT 简易签名
async function signJWT(payload, privateKey) {
  const header = { alg: "RS256", typ: "JWT" };
  const enc = (obj) => btoa(JSON.stringify(obj)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const base = enc(header) + "." + enc(payload);
  
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pem2bin(privateKey),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(base)
  );

  const sigEnc = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return base + "." + sigEnc;
}

function pem2bin(pem) {
  const b64 = pem.replace(/-----BEGIN RSA PRIVATE KEY-----/g, "")
    .replace(/-----END RSA PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const raw = atob(b64);
  return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}

// 预检OPTIONS
export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}