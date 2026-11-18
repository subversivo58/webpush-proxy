
// ============================================================
// CONFIGURAÇÃO
// ============================================================
const ALLOWED_ORIGIN = "https://subversivo58.github.io";

// Allowlist de hosts de webpush
const ALLOWED_HOSTS = [
  "fcm.googleapis.com",
  "updates.push.services.mozilla.com",
  "push.services.mozilla.com",
  "web.push.apple.com",
  "github.com"
];

const MAX_BODY = 4096; // limite prático do webpush (4KB)

// ============================================================
// HANDLER
// ============================================================
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const url = new URL(request.url);

    // 1) Origem única
    if (origin !== ALLOWED_ORIGIN) {
      return new Response("Forbidden: origin não permitida", {
        status: 403,
        headers: corsHeaders(request),
      });
    }

    // 2) Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request),
      });
    }

    // 3) Só POST
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders(request),
      });
    }

    // 4) Destino = tudo depois da "/"
    const target = url.pathname.slice(1) + url.search;
    let targetUrl;

    try {
      targetUrl = new URL(target);
    } catch {
      return new Response("URL inválida", {
        status: 400,
        headers: corsHeaders(request),
      });
    }

    // 5) HTTPS obrigatório
    if (targetUrl.protocol !== "https:") {
      return new Response("Só HTTPS", {
        status: 400,
        headers: corsHeaders(request),
      });
    }

    // 6) Allowlist de hosts
    const hostOk = ALLOWED_HOSTS.some(
      (h) =>
        targetUrl.hostname === h ||
        targetUrl.hostname.endsWith("." + h)
    );

    if (!hostOk) {
      return new Response("Host não permitido", {
        status: 403,
        headers: corsHeaders(request),
      });
    }

    // 7) Limite inicial de tamanho do body
    const len = parseInt(
      request.headers.get("content-length") || "0",
      10
    );

    if (len > MAX_BODY) {
      return new Response("Payload muito grande", {
        status: 413,
        headers: corsHeaders(request),
      });
    }

    // 8) Headers encaminhados
    const headers = new Headers();

    for (const h of [
      "authorization",
      "content-encoding",
      "content-type",
      "accept",
      "ttl",
      "urgency",
      "topic",
    ]) {
      const v = request.headers.get(h);
      if (v) headers.set(h, v);
    }

    // 9) Corpo original, preservado por padrão
    let upstreamBody = request.body;

    // 10) Injeção temporária do Client Secret
    // Exclusivamente no endpoint de troca de token do GitHub.
    // Nenhuma outra lógica OAuth é executada neste Worker.
    const isGitHubTokenEndpoint =
      targetUrl.hostname === "github.com" &&
      targetUrl.pathname === "/login/oauth/access_token";

    if (isGitHubTokenEndpoint) {
      if (!env.GITHUB_CLIENT_SECRET) {
        return new Response(
          "GITHUB_CLIENT_SECRET não configurado no Worker",
          {
            status: 500,
            headers: corsHeaders(request),
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
            headers: corsHeaders(request),
          }
        );
      }

      const formBody = await request.text();
      const params = new URLSearchParams(formBody);

      // O segredo configurado no Worker prevalece durante este teste.
      params.set("client_secret", env.GITHUB_CLIENT_SECRET);

      upstreamBody = params.toString();

      const bodySize = new TextEncoder().encode(
        upstreamBody
      ).byteLength;

      if (bodySize > MAX_BODY) {
        return new Response("Payload muito grande", {
          status: 413,
          headers: corsHeaders(request),
        });
      }
    }

    // 11) Encaminha a requisição ao destino
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
        signal: controller.signal,
      });
    } catch (err) {
      return new Response(
        `Erro no upstream: ${err.message}`,
        {
          status: 502,
          headers: corsHeaders(request),
        }
      );
    } finally {
      clearTimeout(timeout);
    }

    // 12) Devolve a resposta original + CORS
    const resHeaders = new Headers(corsHeaders(request));

    resHeaders.set(
      "Access-Control-Expose-Headers",
      "Location, TTL, Urgency, Topic"
    );

    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      statusText: upstreamRes.statusText,
      headers: resHeaders,
    });
  },
};

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
    "Vary": "Origin",
  };
}
