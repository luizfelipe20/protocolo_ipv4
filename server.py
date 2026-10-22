#!/usr/bin/env python3
"""Servidor do simulador: entrega o frontend e expõe a API de simulação.

Uso: python3 server.py [--port 8000]
"""

from __future__ import annotations

import argparse
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from netsim import SimulationError, build_topology, simulate

STATIC = Path(__file__).parent / "static"
MAX_BODY = 4096


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC), **kwargs)

    def _json(self, status: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/topology":
            return self._json(200, build_topology().to_dict())
        return super().do_GET()

    def do_POST(self):
        if self.path != "/api/simulate":
            return self._json(404, {"erro": "Rota não encontrada."})
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY:
                return self._json(413, {"erro": "Requisição grande demais."})
            data = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return self._json(400, {"erro": "O corpo da requisição deve ser um objeto JSON."})
        try:
            return self._json(200, simulate(data.get("destino", ""), data.get("ttl", 64)))
        except SimulationError as exc:
            return self._json(400, {"erro": str(exc)})


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulador visual de uma requisição TCP/IP (IPv4)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Simulador disponível em http://{args.host}:{args.port}  (Ctrl+C para encerrar)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")


if __name__ == "__main__":
    main()
