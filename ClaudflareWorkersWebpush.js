/**
 * Web Push Proxy - Cloudflare Worker
 * @license The MIT License (MIT) - [https://github.com/subversivo58/subversivo58.github.io/blob/main/LICENSE]
 * @copyright Copyright (c) 2010-2026 Lauro Moraes - [https://github.com/subversivo58]
 * @version 0.1.0 [development stage] - [https://github.com/subversivo58/subversivo58.github.io/blob/main/VERSIONING.md]
 */

import { JWToken } from "./JWToken.mjs";

// ============================================================
// CONFIGURAÇÃO
// ============================================================

const ALLOWED_ORIGIN = "https://subversivo58.github.io";

const ALLOWED_HOSTS = [
  "fcm.googleapis.com",
  "updates.push.services.mozilla.com",
  "push.services.mozilla.com",
  "web.push.apple.com",
  "github.com"
];

const MAX_BODY = 4096;

const JWT_ISSUER = "Blog Subversivo58";
const JWT_SUBJECT = "https://subversivo58.github.io";
const JWT_DEFAULT_DURATION = "8h";

const JWT_KID_PATTERN = /^[a-f0-9]{32}$/i;

// ============================================================
// HANDLER PRINCIPAL
// ============================================================

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const url = new URL(request.url);

    // 1) Origem única
    if (origin !== ALLOWED_ORIGIN) {
      return new Response("Forbidden: origin não permitida", {
        status: 403,
        headers: corsHeaders(request)
      });
    }

    // 2) Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request)
      });
    }

    // 3) Só POST
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders(request)
      });
    }

    // 4) Rotas JWT identificadas antes do proxy
    if (url.pathname === "/jwt/create") {
      return handleJWTCreate(request, env);
    }

    if (url.pathname === "/jwt/refresh") {
      return handleJWTRefresh(request, env);
    }

    // ========================================================
    // PROXY ORIGINAL
    // ========================================================

    // 5) Destino = tudo depois da "/"
    const target = url.pathname.slice(1) + url.search;
    let targetUrl;

    try {
      targetUrl = new URL(target);
    } catch {
      return new Response("URL inválida", {
        status: 400,
        headers: corsHeaders(request)
      });
    }

    // 6) HTTPS obrigatório
    if (targetUrl.protocol !== "https:") {
      return new Response("Só HTTPS", {
        status: 400,
        headers: corsHeaders(request)
      });
    }

    // 7) Allowlist de hosts
    const hostOk = ALLOWED_HOSTS.some(
      (host) =>
        targetUrl.hostname === host ||
        targetUrl.hostname.endsWith("." + host)
    );

    if (!hostOk) {
      return new Response("Host não permitido", {
        status: 403,
        headers: corsHeaders(request)
      });
    }

    // 8) Limite inicial de tamanho do body
    const len = parseInt(
      request.headers.get("content-length") || "0",
      10
    );

    if (len > MAX_BODY) {
      return new Response("Payload muito grande", {
        status: 413,
        headers: corsHeaders(request)
      });
    }

    // 9) Headers encaminhados
    const headers = new Headers();

    for (const header of [
      "authorization",
      "content-encoding",
      "content-type",
      "accept",
      "ttl",
      "urgency",
      "topic"
    ]) {
      const value = request.headers.get(header);

      if (value) {
        headers.set(header, value);
      }
    }

    // 10) Corpo original, preservado por padrão
    let upstreamBody = request.body;

    // 11) Injeção temporária do Client Secret
    // Exclusivamente no endpoint de troca de token do GitHub.
    const isGitHubTokenEndpoint =
      targetUrl.hostname === "github.com" &&
      targetUrl.pathname === "/login/oauth/access_token";

    if (isGitHubTokenEndpoint) {
      if (!env.GITHUB_CLIENT_SECRET) {
        return new Response(
          "GITHUB_CLIENT_SECRET não configurado no Worker",
          {
            status: 500,
            headers: corsHeaders(request)
          }
        );
      }

      const contentType =
        request.headers.get("content-type") || "";

      if (
        !contentType.toLowerCase().startsWith(
          "application/x-www-form-urlencoded"
        )
      ) {
        return new Response(
          "Content-Type inválido para a requisição OAuth",
          {
            status: 400,
            headers: corsHeaders(request)
          }
        );
      }

      const formBody = await request.text();
      const params = new URLSearchParams(formBody);

      params.set(
        "client_secret",
        env.GITHUB_CLIENT_SECRET
      );

      upstreamBody = params.toString();

      const bodySize = new TextEncoder().encode(
        upstreamBody
      ).byteLength;

      if (bodySize > MAX_BODY) {
        return new Response("Payload muito grande", {
          status: 413,
          headers: corsHeaders(request)
        });
      }
    }

    // 12) Encaminha a requisição ao destino
    const controller = new AbortController();

    const timeout = setTimeout(
      () => controller.abort(),
      5000
    );

    let upstreamRes;

    try {
      upstreamRes = await fetch(targetUrl.toString(), {
        method: "POST",
        headers,
        body: upstreamBody,
        signal: controller.signal
      });
    } catch (err) {
      return new Response(
        `Erro no upstream: ${err.message}`,
        {
          status: 502,
          headers: corsHeaders(request)
        }
      );
    } finally {
      clearTimeout(timeout);
    }

    // 13) Devolve a resposta original + CORS
    const resHeaders = new Headers(corsHeaders(request));

    resHeaders.set(
      "Access-Control-Expose-Headers",
      "Location, TTL, Urgency, Topic"
    );

    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      statusText: upstreamRes.statusText,
      headers: resHeaders
    });
  }
};

// ============================================================
// JWT - CRIAÇÃO
// ============================================================

async function handleJWTCreate(request, env) {
  try {
    // 1) Valida OAuth GitHub
    const oauthError = await validateGitHubToken(request);

    if (oauthError) {
      return oauthError;
    }

    // 2) Lê o body
    const bodyResult = await readJSONBody(request);

    if (bodyResult.error) {
      return jsonResponse(
        request,
        { error: bodyResult.error },
        bodyResult.status
      );
    }

    const { kid, aud, expiresIn } = bodyResult.data;

    // 3) Valida parâmetros
    if (
      typeof kid !== "string" ||
      !JWT_KID_PATTERN.test(kid)
    ) {
      return jsonResponse(
        request,
        { error: "Identificador de chave inválido." },
        400
      );
    }

    if (
      typeof aud !== "string" ||
      !aud.trim()
    ) {
      return jsonResponse(
        request,
        { error: "Audience inválida." },
        400
      );
    }

    const duration = expiresIn === undefined
      ? JWT_DEFAULT_DURATION
      : expiresIn;

    if (
      typeof duration !== "string" ||
      !["8h", "6m", "1y"].includes(duration)
    ) {
      return jsonResponse(
        request,
        { error: "Duração do JWT inválida." },
        400
      );
    }

    // 4) Recupera a chave privada
    const privatePEM = env[`K_${kid}`];

    if (
      typeof privatePEM !== "string" ||
      !privatePEM
    ) {
      return jsonResponse(
        request,
        { error: "Chave privada não encontrada." },
        404
      );
    }

    // 5) Importa chave privada PKCS#8
    const jwt = new JWToken({
      issuer: JWT_ISSUER,
      audience: aud
    });

    const privateKey = await importPEMKey({
      jwt,
      keyId: kid,
      type: "private",
      pem: privatePEM,
      format: "pkcs8"
    });

    // 6) Calcula período de validade
    const now = new Date();
    const iat = Math.floor(now.getTime() / 1000);

    const exp = calculateExpiration(
      now,
      duration
    );

    // 7) Monta payload
    const payload = {
      iss: JWT_ISSUER,
      sub: JWT_SUBJECT,
      aud,
      iat,
      exp,
      jti: crypto.randomUUID()
    };

    // 8) Assina JWT
    const token = await jwt.sign({
      payload,
      keyId: kid,
      privateKey
    });

    return jsonResponse(
      request,
      { token },
      200
    );

  } catch (error) {
    return jsonResponse(
      request,
      {
        error: "Não foi possível criar o JWT.",
        detail: error.message
      },
      500
    );
  }
}

// ============================================================
// JWT - RENOVAÇÃO
// ============================================================

async function handleJWTRefresh(request, env) {
  try {
    // 1) Valida OAuth GitHub
    const oauthError = await validateGitHubToken(request);

    if (oauthError) {
      return oauthError;
    }

    // 2) Recupera JWT atual
    const authorization =
      request.headers.get("Authorization") || "";

    const bearerMatch = authorization.match(
      /^Bearer\s+(.+)$/i
    );

    if (!bearerMatch) {
      return jsonResponse(
        request,
        {
          error: "JWT atual não informado.",
          code: "INVALID_TOKEN"
        },
        401
      );
    }

    const currentToken = bearerMatch[1].trim();

    // 3) Recupera chave pública enviada pelo front-end
    const publicPEM =
      request.headers.get("X-JWT-Public-Key");

    if (!publicPEM) {
      return jsonResponse(
        request,
        { error: "Chave pública não informada." },
        400
      );
    }

    // 4) Valida body
    const bodyResult = await readJSONBody(request);

    if (bodyResult.error) {
      return jsonResponse(
        request,
        { error: bodyResult.error },
        bodyResult.status
      );
    }

    // 5) Decodifica JWT original
    const jwt = new JWToken();

    const decoded = jwt.decode(currentToken);

    const { header, payload } = decoded;

    // 6) Valida estrutura e claims
    if (
      header.alg !== "EdDSA" ||
      header.typ !== "JWT"
    ) {
      throw new Error("Algoritmo ou tipo de JWT inválido.");
    }

    if (
      typeof header.kid !== "string" ||
      !JWT_KID_PATTERN.test(header.kid)
    ) {
      throw new Error("Identificador de chave inválido.");
    }

    if (
      payload.iss !== JWT_ISSUER ||
      payload.sub !== JWT_SUBJECT ||
      typeof payload.aud !== "string" ||
      typeof payload.iat !== "number" ||
      !Number.isFinite(payload.iat) ||
      typeof payload.exp !== "number" ||
      !Number.isFinite(payload.exp) ||
      typeof payload.jti !== "string" ||
      !payload.jti
    ) {
      throw new Error("Claims do JWT inválidos.");
    }

    // 7) Recupera duração original
    const originalDuration = payload.exp - payload.iat;

    if (
      !Number.isFinite(originalDuration) ||
      originalDuration <= 0
    ) {
      throw new Error("Duração original do JWT inválida.");
    }

    // 8) Recupera chave privada pelo kid
    const privatePEM = env[`K_${header.kid}`];

    if (
      typeof privatePEM !== "string" ||
      !privatePEM
    ) {
      throw new Error("Chave privada não encontrada.");
    }

    // 9) Importa chave privada PKCS#8
    const privateKey = await importPEMKey({
      jwt,
      keyId: header.kid,
      type: "private",
      pem: privatePEM,
      format: "pkcs8"
    });

    // 10) Importa chave pública SPKI
    const publicKey = await importPEMKey({
      jwt,
      keyId: header.kid,
      type: "public",
      pem: publicPEM,
      format: "spki"
    });

    // ========================================================
    // 11) PROVA DE CORRESPONDÊNCIA DAS CHAVES
    // ========================================================

    const nowSeconds = Math.floor(
      Date.now() / 1000
    );

    // JWT temporário de teste
    const testPayload = {
      iss: payload.iss,
      sub: payload.sub,
      aud: payload.aud,
      iat: nowSeconds,
      exp: nowSeconds + 60,
      jti: crypto.randomUUID()
    };

    // Assina com a chave privada do Worker
    const testToken = await jwt.sign({
      payload: testPayload,
      keyId: header.kid,
      privateKey
    });

    // Verifica com a chave pública enviada pelo front-end
    await jwt.verify({
      token: testToken,
      publicKey,
      issuer: JWT_ISSUER,
      audience: payload.aud
    });

    // ========================================================
    // 12) VERIFICAÇÃO DA ASSINATURA ORIGINAL
    // ========================================================

    // Importante:
    // Não usamos jwt.verify() neste ponto porque ele rejeita
    // tokens expirados.
    //
    // A função abaixo verifica a autenticidade da assinatura
    // original e os demais requisitos de segurança, permitindo
    // que somente a expiração seja ignorada na renovação.

    await verifyOriginalTokenSignature({
      token: currentToken,
      publicKey,
      expectedKid: header.kid,
      expectedIssuer: JWT_ISSUER,
      expectedSubject: JWT_SUBJECT
    });

    // ========================================================
    // 13) EMISSÃO DO NOVO JWT
    // ========================================================

    const newIat = Math.floor(
      Date.now() / 1000
    );

    const newExp = newIat + originalDuration;

    const newPayload = {
      iss: payload.iss,
      sub: payload.sub,
      aud: payload.aud,
      iat: newIat,
      exp: newExp,
      jti: crypto.randomUUID()
    };

    const newToken = await jwt.sign({
      payload: newPayload,
      keyId: header.kid,
      privateKey
    });

    return jsonResponse(
      request,
      { token: newToken },
      200
    );

  } catch (error) {
    return jsonResponse(
      request,
      {
        error: "Não foi possível renovar o JWT.",
        code: "INVALID_TOKEN",
        detail: error.message
      },
      401
    );
  }
}

// ============================================================
// JWT - VERIFICAÇÃO DA ASSINATURA ORIGINAL
// ============================================================

async function verifyOriginalTokenSignature({
  token,
  publicKey,
  expectedKid,
  expectedIssuer,
  expectedSubject
}) {
  const jwt = new JWToken();

  // Decodificação e estrutura
  const { header, payload } = jwt.decode(token);

  const parts = token.split(".");

  if (
    parts.length !== 3 ||
    !parts[0] ||
    !parts[1] ||
    !parts[2]
  ) {
    throw new Error("Estrutura JWT inválida.");
  }

  // Header
  if (
    header.alg !== "EdDSA" ||
    header.typ !== "JWT" ||
    header.kid !== expectedKid
  ) {
    throw new Error("Header JWT inválido.");
  }

  // Claims obrigatórios
  if (
    payload.iss !== expectedIssuer ||
    payload.sub !== expectedSubject ||
    typeof payload.aud !== "string" ||
    typeof payload.iat !== "number" ||
    !Number.isFinite(payload.iat) ||
    typeof payload.exp !== "number" ||
    !Number.isFinite(payload.exp) ||
    typeof payload.jti !== "string" ||
    !payload.jti
  ) {
    throw new Error("Claims do JWT inválidos.");
  }

  // Verificação temporal, exceto expiração
  const nowSeconds = Math.floor(
    Date.now() / 1000
  );

  if (payload.iat > nowSeconds) {
    throw new Error("JWT emitido no futuro.");
  }

  if (payload.nbf !== undefined) {
    if (
      typeof payload.nbf !== "number" ||
      !Number.isFinite(payload.nbf)
    ) {
      throw new Error("Claim nbf inválida.");
    }

    if (payload.nbf > nowSeconds) {
      throw new Error("JWT ainda não está válido.");
    }
  }

  // Verificação criptográfica da assinatura
  const signingInput = `${parts[0]}.${parts[1]}`;

  const signature = JWToken.base64UrlDecode(
    parts[2]
  );

  const valid = await crypto.subtle.verify(
    {
      name: "Ed25519"
    },
    publicKey,
    signature,
    new TextEncoder().encode(signingInput)
  );

  if (!valid) {
    throw new Error("Assinatura JWT inválida.");
  }

  return true;
}

// ============================================================
// OAUTH - VALIDAÇÃO DO TOKEN GITHUB
// ============================================================

async function validateGitHubToken(request) {
  const accessToken =
    request.headers.get("X-GitHub-Access-Token");

  if (!accessToken) {
    return jsonResponse(
      request,
      {
        error: "Token OAuth GitHub não informado.",
        code: "OAUTH_EXPIRED"
      },
      401
    );
  }

  const controller = new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    5000
  );

  let response;

  try {
    response = await fetch(
      "https://api.github.com/user",
      {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Accept": "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "WebPush-Proxy"
        },
        signal: controller.signal
      }
    );

  } catch (error) {
    return jsonResponse(
      request,
      {
        error: "Falha ao validar o token OAuth GitHub."
      },
      502
    );

  } finally {
    clearTimeout(timeout);
  }

  if (
    response.status === 401 ||
    response.status === 403
  ) {
    return jsonResponse(
      request,
      {
        error: "A sessão OAuth GitHub expirou ou é inválida.",
        code: "OAUTH_EXPIRED"
      },
      401
    );
  }

  if (!response.ok) {
    return jsonResponse(
      request,
      {
        error: "Não foi possível validar o token OAuth GitHub."
      },
      502
    );
  }

  return null;
}

// ============================================================
// UTILITÁRIOS - IMPORTAÇÃO DE CHAVES PEM
// ============================================================

async function importPEMKey({
  jwt,
  keyId,
  type,
  pem,
  format
}) {
  const keyData = pemToBase64Url(
    pem,
    type === "private"
      ? "PRIVATE KEY"
      : "PUBLIC KEY"
  );

  return jwt.importKey({
    keyId,
    type,
    keyData,
    format,
    extractable: false
  });
}

function pemToBase64Url(pem, label) {
  if (
    typeof pem !== "string" ||
    !pem.trim()
  ) {
    throw new Error("Chave PEM não informada.");
  }

  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;

  if (
    !pem.includes(begin) ||
    !pem.includes(end)
  ) {
    throw new Error("Formato PEM inválido.");
  }

  const base64 = pem
    .replace(begin, "")
    .replace(end, "")
    .replace(/\s+/g, "");

  if (
    !base64 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)
  ) {
    throw new Error("Conteúdo Base64 da chave inválido.");
  }

  let binary;

  try {
    binary = atob(base64);
  } catch {
    throw new Error("Não foi possível decodificar a chave PEM.");
  }

  const bytes = Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );

  return JWToken.base64UrlEncode(bytes);
}

// ============================================================
// UTILITÁRIOS - EXPIRAÇÃO
// ============================================================

function calculateExpiration(date, duration) {
  const expiration = new Date(date.getTime());

  switch (duration) {
    case "8h":
      expiration.setUTCHours(
        expiration.getUTCHours() + 8
      );
      break;

    case "6m":
      expiration.setUTCMonth(
        expiration.getUTCMonth() + 6
      );
      break;

    case "1y":
      expiration.setUTCFullYear(
        expiration.getUTCFullYear() + 1
      );
      break;

    default:
      throw new Error("Duração de JWT não suportada.");
  }

  return Math.floor(
    expiration.getTime() / 1000
  );
}

// ============================================================
// UTILITÁRIOS - BODY JSON
// ============================================================

async function readJSONBody(request) {
  const contentType =
    request.headers.get("content-type") || "";

  if (
    !contentType.toLowerCase().startsWith(
      "application/json"
    )
  ) {
    return {
      error: "Content-Type deve ser application/json.",
      status: 400
    };
  }

  const contentLength = parseInt(
    request.headers.get("content-length") || "0",
    10
  );

  if (contentLength > MAX_BODY) {
    return {
      error: "Payload muito grande.",
      status: 413
    };
  }

  let text;

  try {
    text = await request.text();
  } catch {
    return {
      error: "Não foi possível ler o body.",
      status: 400
    };
  }

  if (
    new TextEncoder().encode(text).byteLength > MAX_BODY
  ) {
    return {
      error: "Payload muito grande.",
      status: 413
    };
  }

  let data;

  try {
    data = JSON.parse(text);
  } catch {
    return {
      error: "JSON inválido.",
      status: 400
    };
  }

  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data)
  ) {
    return {
      error: "O body deve conter um objeto JSON.",
      status: 400
    };
  }

  return {
    data,
    error: null
  };
}

// ============================================================
// UTILITÁRIOS - RESPOSTAS JSON
// ============================================================

function jsonResponse(request, data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        ...corsHeaders(request),
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store"
      }
    }
  );
}

// ============================================================
// CORS
// ============================================================

function corsHeaders(request) {
  const reqHeaders =
    request.headers.get("Access-Control-Request-Headers") || "*";

  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": reqHeaders,
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}