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
];

const MAX_BODY = 4096; // limite prático do webpush (4KB)

// ============================================================
// HANDLER
// ============================================================
export default {
  async fetch(request) {
    const origin = request.headers.get("Origin") || "";
    const url = new URL(request.url);

    // 1) Origem única
    if (origin !== ALLOWED_ORIGIN) {
      return new Response("Forbidden: origin não permitida", { status: 403 });
    }

    // 2) Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // 3) Só POST
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // 4) Destino = tudo depois da "/"
    const target = url.pathname.slice(1) + url.search;
    let targetUrl;
    try {
      targetUrl = new URL(target);
    } catch {
      return new Response("URL inválida", { status: 400 });
    }

    // 5) HTTPS obrigatório
    if (targetUrl.protocol !== "https:") {
      return new Response("Só HTTPS", { status: 400 });
    }

    // 6) Allowlist de hosts de webpush
    const hostOk = ALLOWED_HOSTS.some(
      (h) => targetUrl.hostname === h || targetUrl.hostname.endsWith("." + h)
    );
    if (!hostOk) {
      return new Response("Host não permitido", { status: 403 });
    }

    // 7) Limite de tamanho do body
    const len = parseInt(request.headers.get("content-length") || "0", 10);
    if (len > MAX_BODY) {
      return new Response("Payload muito grande", { status: 413 });
    }

    // 8) Headers de webpush repassados intactos
    const headers = new Headers();
    for (const h of [
      "authorization", // VAPID
      "content-encoding", // aes128gcm / aesgcm
      "content-type",
      "ttl",
      "urgency",
      "topic",
    ]) {
      const v = request.headers.get(h);
      if (v) headers.set(h, v);
    }

    // 9) Repassa com body binário intacto + timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    let upstreamRes;
    try {
      upstreamRes = await fetch(targetUrl.toString(), {
        method: "POST",
        headers,
        body: request.body,
        signal: controller.signal,
      });
    } catch (err) {
      return new Response(`Erro no upstream: ${err.message}`, {
        status: 502,
        headers: corsHeaders(request),
      });
    } finally {
      clearTimeout(timeout);
    }

    // 10) Resposta + CORS
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