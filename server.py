import json
import os
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse
import cgi

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

DEFAULT_PORT = int(os.environ.get("PORT", "8000"))


class ReaderHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/upload":
            self.send_error(404, "Not Found")
            return

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers.get("Content-Type"),
                "CONTENT_LENGTH": self.headers.get("Content-Length"),
            },
        )

        file_item = form["report"] if "report" in form else None
        if file_item is None or not getattr(file_item, "file", None):
            self.respond_json({"error": "Файл не получен"}, status=400)
            return

        original_name = Path(file_item.filename or "report").name
        safe_name = f"{int(time.time() * 1000)}-{original_name}"
        safe_name = safe_name.replace(" ", "_")
        dest = UPLOAD_DIR / safe_name

        with dest.open("wb") as f:
            f.write(file_item.file.read())

        url = f"{self.server_origin()}/uploads/{dest.name}"
        self.respond_json({"url": url, "name": original_name, "storedAs": dest.name})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/reports":
            files = []
            for file in UPLOAD_DIR.iterdir():
                if file.suffix.lower() not in {".json", ".sarif", ".sarif.json"}:
                    continue
                files.append(
                    {
                        "name": file.name,
                        "url": f"{self.server_origin()}/uploads/{file.name}",
                        "created": file.stat().st_mtime,
                    }
                )
            files.sort(key=lambda f: f["created"], reverse=True)
            self.respond_json({"files": files})
            return

        # Strip query string so shared links like /?report=... return index.html
        self.path = parsed.path or "/"
        return super().do_GET()

    def do_DELETE(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/uploads/"):
            self.send_error(404, "Not Found")
            return

        target = UPLOAD_DIR / Path(parsed.path).name
        if not target.exists():
            self.respond_json({"error": "Файл не найден"}, status=404)
            return

        try:
            target.unlink()
            self.respond_json({"status": "deleted"})
        except OSError:
            self.respond_json({"error": "Не удалось удалить файл"}, status=500)

    def server_origin(self):
        host = self.headers.get("Host") or f"0.0.0.0:{DEFAULT_PORT}"
        scheme = "https" if self.server.server_address[1] == 443 else "http"
        return f"{scheme}://{host}"

    def respond_json(self, payload, status=200):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        # Log to stdout for container visibility
        super().log_message(format, *args)


def run():
    server = HTTPServer(("0.0.0.0", DEFAULT_PORT), ReaderHandler)
    print(f"Reader server running at http://0.0.0.0:{DEFAULT_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
