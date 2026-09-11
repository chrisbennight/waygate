"""Disposable test issuer. Anyone can obtain the fixed demo identity.

This is not an OAuth authorization server and must never be used outside the
loopback-only tutorial. Keys exist only in this process and rotate on restart.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "http://demo-issuer:9000"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
PUBLIC_KEY.update(kid="demo", use="sig", alg="RS256")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # This disposable fixture emits no request data or credentials.
        pass

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            result = {"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks"}
        elif self.path == "/jwks":
            result = {"keys": [PUBLIC_KEY]}
        elif self.path == "/demo-token":
            now = int(time.time())
            result = {"access_token": jwt.encode({
                "iss": ISSUER, "aud": "gateway-demo", "sub": "demo-user",
                "iat": now, "exp": now + 300,
                "scope": "mcp:search mcp:invoke mcp:observe",
                "groups": ["demo-users"],
            }, KEY, algorithm="RS256", headers={"kid": "demo"})}
        else:
            self.send_error(404)
            return
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
