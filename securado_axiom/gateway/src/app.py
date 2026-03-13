from __future__ import annotations

import json
from wsgiref.simple_server import make_server

from .server import GatewayHTTPAPI


api = GatewayHTTPAPI()


def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    raw_body = environ["wsgi.input"].read(length) if length else b""
    body = json.loads(raw_body.decode("utf-8")) if raw_body else None
    headers = {"x-api-key": environ.get("HTTP_X_API_KEY", "")}

    status_code, payload = api.handle(method, path, body, headers)
    response = json.dumps(payload).encode("utf-8")
    status_text = {200: "200 OK", 400: "400 Bad Request", 401: "401 Unauthorized", 404: "404 Not Found"}.get(
        status_code, "500 Internal Server Error"
    )
    start_response(status_text, [("Content-Type", "application/json"), ("Content-Length", str(len(response)))])
    return [response]


def run() -> None:
    with make_server("0.0.0.0", 8080, application) as httpd:
        print("Securado Axiom API listening on :8080")
        httpd.serve_forever()


if __name__ == "__main__":
    run()
