#!/usr/bin/env python3
"""Build the cloudg documentation site into site/dist.

    python site/build.py                 # build
    python site/build.py --serve         # build, then serve on http://127.0.0.1:8000/cloudg/
    python site/build.py --strict        # fail on broken internal links (used in CI)
    python site/build.py --base /        # build for serving at the domain root

See site/AUTHORING.md for the page format. The generator itself lives in
site/docsgen/; this file is the command line around it.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

SITE = Path(__file__).resolve().parent
REPO = SITE.parent
sys.path.insert(0, str(SITE))
sys.path.insert(0, str(REPO))

from docsgen.site import Site  # noqa: E402


def serve(out: Path, base: str, port: int) -> None:
    class Handler(http.server.SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def translate_path(self, path):  # noqa: D401
            parsed = urlsplit(path).path
            if base != "/" and parsed.startswith(base):
                parsed = "/" + parsed[len(base) :]
            return str(out) + parsed

        def send_error(self, code, message=None, explain=None):
            if code == 404 and (out / "404.html").exists():
                body = (out / "404.html").read_bytes()
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            super().send_error(code, message, explain)

    handler = functools.partial(Handler, directory=str(out))
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), handler) as httpd:
        print(f"serving http://127.0.0.1:{port}{base}")
        httpd.serve_forever()


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--out", default=str(SITE / "dist"))
    ap.add_argument("--base", default=os.environ.get("DOCS_BASE", "/cloudg/"))
    ap.add_argument("--strict", action="store_true", help="exit non-zero on broken internal links")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    site = Site(args.base, args.strict)
    site.discover()
    site.render_all()
    out = Path(args.out)
    site.write(out)
    problems = site.check_links()
    for p in problems:
        print(f"link: {p}", file=sys.stderr)
    print(f"built {len(site.pages)} pages into {out} (base {site.base})")
    if problems and args.strict:
        return 1
    if args.serve:
        serve(out, site.base, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
