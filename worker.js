
const MANIFEST = {
  id: "bitchord-tidal-addon",
  name: "TIDAL",
  version: "1.0.0",
  resources: ["search", "stream"]
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
    }

    if (url.pathname === "/manifest.json") {
      return json(MANIFEST);
    }

    if (url.pathname === "/health") {
      return json({ status: "ok" });
    }

    return json({
      error: "Endpoint not implemented yet"
    }, 404);
  }
};
        
