const CLIENT_ID = "ewgbhkBRUqcZbi3e";

const REDIRECT_URI =
  "https://bitchord-tidal.lakshyakanchan42.workers.dev/oauth/callback";

const SCOPES = [
  "search.read",
  "playback",
  "entitlements.read"
].join(" ");

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

function base64url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function createPKCE() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  const verifier = base64url(bytes);

  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );

  const challenge = base64url(new Uint8Array(hash));

  return {
    verifier,
    challenge
  };
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
      return json({
        status: "ok",
        kv: Boolean(env.KV)
      });
    }

    /*
     * Start TIDAL OAuth login
     */
    if (url.pathname === "/oauth/login") {
      const { verifier, challenge } = await createPKCE();

      const stateBytes = crypto.getRandomValues(
        new Uint8Array(32)
      );

      const state = base64url(stateBytes);

      const authURL = new URL(
        "https://login.tidal.com/authorize"
      );

      authURL.searchParams.set(
        "response_type",
        "code"
      );

      authURL.searchParams.set(
        "client_id",
        CLIENT_ID
      );

      authURL.searchParams.set(
        "redirect_uri",
        REDIRECT_URI
      );

      authURL.searchParams.set(
        "scope",
        SCOPES
      );

      authURL.searchParams.set(
        "code_challenge_method",
        "S256"
      );

      authURL.searchParams.set(
        "code_challenge",
        challenge
      );

      authURL.searchParams.set(
        "state",
        state
      );

      const headers = new Headers({
        "Location": authURL.toString(),
        "Access-Control-Allow-Origin": "*"
      });

      headers.append(
        "Set-Cookie",
        `tidal_verifier=${verifier}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
      );

      headers.append(
        "Set-Cookie",
        `tidal_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
      );

      return new Response(null, {
        status: 302,
        headers
      });
    }

    /*
     * TIDAL OAuth callback
     */
    if (url.pathname === "/oauth/callback") {
      const error = url.searchParams.get("error");

      if (error) {
        return json({
          success: false,
          error,
          description:
            url.searchParams.get("error_description")
        }, 400);
      }

      const code = url.searchParams.get("code");
      const returnedState =
        url.searchParams.get("state");

      if (!code || !returnedState) {
        return json({
          success: false,
          error:
            "Missing authorization code or state"
        }, 400);
      }

      const cookie =
        request.headers.get("Cookie") || "";

      const verifierMatch = cookie.match(
        /(?:^|;\s*)tidal_verifier=([^;]+)/
      );

      const stateMatch = cookie.match(
        /(?:^|;\s*)tidal_state=([^;]+)/
      );

      if (!verifierMatch || !stateMatch) {
        return json({
          success: false,
          error:
            "OAuth session expired. Start login again."
        }, 400);
      }

      const verifier =
        verifierMatch[1];

      const savedState =
        stateMatch[1];

      if (returnedState !== savedState) {
        return json({
          success: false,
          error: "Invalid OAuth state"
        }, 400);
      }

      const body = new URLSearchParams();

      body.set(
        "grant_type",
        "authorization_code"
      );

      body.set(
        "client_id",
        CLIENT_ID
      );

      body.set(
        "code",
        code
      );

      body.set(
        "redirect_uri",
        REDIRECT_URI
      );

      body.set(
        "code_verifier",
        verifier
      );

      const tokenResponse = await fetch(
        "https://auth.tidal.com/v1/oauth2/token",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/x-www-form-urlencoded"
          },
          body
        }
      );

      const tokenData =
        await tokenResponse.json();

      if (!tokenResponse.ok) {
        return json({
          success: false,
          error:
            "TIDAL token exchange failed",
          details: tokenData
        }, tokenResponse.status);
      }

      /*
       * Store TIDAL tokens in Cloudflare KV.
       *
       * The actual tokens are NOT returned
       * to the browser.
       */
      await env.KV.put(
        "tidal_tokens",
        JSON.stringify({
          access_token:
            tokenData.access_token,

          refresh_token:
            tokenData.refresh_token,

          token_type:
            tokenData.token_type,

          expires_in:
            tokenData.expires_in,

          saved_at:
            Date.now()
        })
      );

      /*
       * Clear temporary OAuth cookies.
       */
      const headers = new Headers({
        "Content-Type":
          "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*"
      });

      headers.append(
        "Set-Cookie",
        "tidal_verifier=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
      );

      headers.append(
        "Set-Cookie",
        "tidal_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
      );

      return new Response(
        JSON.stringify({
          success: true,
          message:
            "TIDAL authorization successful and token saved securely.",
          token_type:
            tokenData.token_type,
          expires_in:
            tokenData.expires_in,
          scope:
            tokenData.scope,
          access_token_saved:
            Boolean(tokenData.access_token),
          refresh_token_saved:
            Boolean(tokenData.refresh_token)
        }),
        {
          status: 200,
          headers
        }
      );
    }

    return json({
      error: "Endpoint not implemented yet"
    }, 404);
  }
};
