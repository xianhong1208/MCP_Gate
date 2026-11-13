"""Part of scripts/docker_smoke.sh: run inside the MCP Gate container (`docker exec -i <name> python - ...`).

Signs in to the console, issues a personal access token for a test service and verifies its RS256 signature against
the published JWKS. Prints the kid that signed it. Arguments: issuer, email, password.
Only the standard library and PyJWT (already in the image) are used.
"""

import http.cookiejar
import json
import sys
import urllib.request

import jwt

BASE = "http://127.0.0.1:4568"
ISSUER, EMAIL, PASSWORD = sys.argv[1:4]
SERVICE = "docker-smoke"

opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
headers = {"Content-Type": "application/json", "Origin": ISSUER}


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    with opener.open(request, timeout=30) as response:
        return json.load(response)


session = call("POST", "/api/session/login", {"email": EMAIL, "password": PASSWORD})
headers["X-Session-Binding"] = session["session_binding"]

service = next((s for s in call("GET", "/api/services")["services"] if s["name"] == SERVICE), None)
if service is None:
    service = call("POST", "/api/services", {"name": SERVICE, "host": "127.0.0.1", "port": 9, "mcp_path": "/mcp"})
token = call("POST", "/api/oauth/tokens/personal",
             {"service_id": service["id"], "expires_days": 1, "label": "docker smoke"})["access_token"]

kid = jwt.get_unverified_header(token)["kid"]
jwks = call("GET", "/.well-known/jwks.json")
key = next(k for k in jwks["keys"] if k["kid"] == kid)
claims = jwt.decode(token, jwt.PyJWK(key).key, algorithms=["RS256"], issuer=ISSUER, options={"verify_aud": False})
assert claims["sub"], "the token has no subject"
print(kid)
