/**
 * pgReviewer Token Vending Service
 *
 * Issues short-lived GitHub App installation tokens to verified GitHub Actions
 * workflows. Callers prove their identity via a GitHub OIDC token; this service
 * exchanges it for a pgreviewer-ci installation token scoped to their repo.
 *
 * Flow:
 *   1. Caller sends POST /token with GitHub OIDC token as Bearer
 *   2. We verify the OIDC token against GitHub's JWKS
 *   3. Extract `repository` claim → find pgreviewer-ci installation for that repo
 *   4. Generate a GitHub App JWT, exchange it for an installation token
 *   5. Return { token, expires_at }
 */

const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_API = "https://api.github.com";

export interface Env {
  APP_ID: string;
  APP_PRIVATE_KEY: string; // RSA private key, PEM format
}

// ── OIDC verification ────────────────────────────────────────────────────────

interface OIDCClaims {
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  repository: string;
  repository_owner: string;
  workflow_ref: string;
  job_workflow_ref: string;
}

async function fetchJWKS(): Promise<JsonWebKey[]> {
  const res = await fetch(`${GITHUB_OIDC_ISSUER}/.well-known/jwks`);
  if (!res.ok) throw new Error(`Failed to fetch JWKS: ${res.status}`);
  const { keys } = (await res.json()) as { keys: JsonWebKey[] };
  return keys;
}

function decodeBase64Url(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function parseJWTHeader(token: string): { kid?: string; alg: string } {
  const [headerB64] = token.split(".");
  return JSON.parse(new TextDecoder().decode(decodeBase64Url(headerB64)));
}

function parseJWTPayload(token: string): OIDCClaims {
  const [, payloadB64] = token.split(".");
  return JSON.parse(new TextDecoder().decode(decodeBase64Url(payloadB64)));
}

async function verifyGitHubOIDCToken(token: string): Promise<OIDCClaims> {
  const header = parseJWTHeader(token);
  const keys = await fetchJWKS();
  const jwk = keys.find((k) => k.kid === header.kid) ?? keys[0];
  if (!jwk) throw new Error("No matching JWK found");

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );

  const [headerB64, payloadB64, sigB64] = token.split(".");
  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = decodeBase64Url(sigB64);

  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, data);
  if (!valid) throw new Error("Invalid OIDC token signature");

  const claims = parseJWTPayload(token);
  if (claims.iss !== GITHUB_OIDC_ISSUER) throw new Error("Invalid issuer");
  if (claims.exp < Math.floor(Date.now() / 1000)) throw new Error("Token expired");

  return claims;
}

// ── GitHub App JWT ────────────────────────────────────────────────────────────

function pemToDer(pem: string): Uint8Array {
  // Strip headers/footers and ALL whitespace (handles \r\n and \n)
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const binary = atob(b64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * GitHub App private keys are PKCS#1 (BEGIN RSA PRIVATE KEY).
 * crypto.subtle.importKey only accepts PKCS#8 (BEGIN PRIVATE KEY).
 *
 * PKCS#8 PrivateKeyInfo = fixed 26-byte header + PKCS#1 DER:
 *   SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING { <pkcs1> } }
 * The only variable parts are the two 2-byte lengths, derived from pkcs1.length.
 */
function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  const L = pkcs1.length;
  // Inner length = 3 (version) + 15 (algId) + 4 (octet string header) + L
  const inner = 22 + L;
  const header = new Uint8Array([
    0x30, 0x82, (inner >> 8) & 0xff, inner & 0xff, // SEQUENCE
    0x02, 0x01, 0x00,                               // INTEGER 0 (version)
    0x30, 0x0d,                                     // SEQUENCE (algId, 13 bytes)
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
    0x05, 0x00,                                     // NULL
    0x04, 0x82, (L >> 8) & 0xff, L & 0xff,         // OCTET STRING
  ]);
  const result = new Uint8Array(header.length + L);
  result.set(header);
  result.set(pkcs1, header.length);
  return result;
}

function base64UrlEncode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateAppJWT(appId: string, privateKeyPem: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })),
  );
  const payload = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId })),
  );

  const isPkcs1 = privateKeyPem.includes("BEGIN RSA PRIVATE KEY");
  const der = isPkcs1 ? pkcs1ToPkcs8(pemToDer(privateKeyPem)) : pemToDer(privateKeyPem);

  const key = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const data = new TextEncoder().encode(`${header}.${payload}`);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data);
  return `${header}.${payload}.${base64UrlEncode(new Uint8Array(sig))}`;
}

// ── GitHub API ────────────────────────────────────────────────────────────────

async function getInstallationId(repository: string, appJwt: string): Promise<number | null> {
  const res = await fetch(`${GITHUB_API}/repos/${repository}/installation`, {
    headers: {
      Authorization: `Bearer ${appJwt}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "pgreviewer-token-service",
    },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GitHub API error: ${res.status}`);
  const { id } = (await res.json()) as { id: number };
  return id;
}

async function getInstallationToken(
  installationId: number,
  appJwt: string,
): Promise<{ token: string; expires_at: string }> {
  const res = await fetch(`${GITHUB_API}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${appJwt}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "pgreviewer-token-service",
    },
  });
  if (!res.ok) throw new Error(`Failed to get installation token: ${res.status}`);
  return res.json() as Promise<{ token: string; expires_at: string }>;
}

// ── Handler ───────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      return Response.json({ status: "ok" });
    }

    if (url.pathname !== "/token" || request.method !== "POST") {
      return new Response("Not Found", { status: 404 });
    }

    const authHeader = request.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return new Response("Missing Bearer token", { status: 401 });
    }
    const oidcToken = authHeader.slice(7);

    let claims: OIDCClaims;
    try {
      claims = await verifyGitHubOIDCToken(oidcToken);
    } catch (err) {
      return new Response(`Unauthorized: ${err}`, { status: 401 });
    }

    let appJwt: string;
    try {
      appJwt = await generateAppJWT(env.APP_ID, env.APP_PRIVATE_KEY);
    } catch (err) {
      console.error("Failed to generate App JWT:", err);
      return new Response("Internal Server Error", { status: 500 });
    }

    const installationId = await getInstallationId(claims.repository, appJwt).catch((err) => {
      console.error("Failed to get installation:", err);
      return null;
    });

    if (!installationId) {
      return new Response(
        `pgreviewer-ci is not installed on ${claims.repository}. ` +
          `Install it at https://github.com/apps/pgreviewer-ci`,
        { status: 403 },
      );
    }

    try {
      const { token, expires_at } = await getInstallationToken(installationId, appJwt);
      return Response.json({ token, expires_at });
    } catch (err) {
      console.error("Failed to get installation token:", err);
      return new Response("Internal Server Error", { status: 500 });
    }
  },
};
