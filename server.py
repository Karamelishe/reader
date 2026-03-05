import json
import os
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import cgi

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

DEFAULT_PORT = int(os.environ.get("PORT", "8000"))
API_TOKEN = os.environ.get("API_TOKEN", "")


def parse_pagination(query):
    params = parse_qs(query or "")

    try:
        page = max(int(params.get("page", ["1"])[0]), 1)
    except (TypeError, ValueError):
        page = 1

    try:
        per_page = int(params.get("per_page", ["20"])[0])
    except (TypeError, ValueError):
        per_page = 20

    per_page = min(max(per_page, 1), 100)
    return page, per_page


class ReaderHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/reports":
            self.handle_ci_upload()
            return

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

    def handle_ci_upload(self):
        if API_TOKEN:
            token = self.headers.get("X-API-Token") or ""
            auth_header = self.headers.get("Authorization") or ""
            bearer = auth_header.removeprefix("Bearer ").strip()
            if token != API_TOKEN and bearer != API_TOKEN:
                self.respond_json({"error": "Unauthorized"}, status=401)
                return

        content_len = int(self.headers.get("Content-Length") or "0")
        if content_len <= 0:
            self.respond_json({"error": "Пустое тело запроса"}, status=400)
            return

        try:
            payload = self.rfile.read(content_len)
            parsed_json = json.loads(payload.decode("utf-8"))
            # Проверяем, что файл похож на Semgrep/SARIF для ранней валидации.
            if not isinstance(parsed_json, dict) or (
                "results" not in parsed_json and "runs" not in parsed_json
            ):
                raise ValueError("Ожидается Semgrep JSON или SARIF")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self.respond_json({"error": f"Некорректный JSON отчёт: {exc}"}, status=400)
            return

        query = parse_qs(urlparse(self.path).query)
        requested_name = (query.get("filename") or ["semgrep-report.json"])[0]
        original_name = Path(requested_name).name or "semgrep-report.json"
        safe_name = f"{int(time.time() * 1000)}-{original_name}".replace(" ", "_")
        if not safe_name.endswith((".json", ".sarif", ".sarif.json")):
            safe_name += ".json"

        dest = UPLOAD_DIR / safe_name
        with dest.open("wb") as file_handle:
            file_handle.write(payload)

        url = f"{self.server_origin()}/uploads/{dest.name}"
        self.respond_json(
            {
                "status": "ok",
                "url": url,
                "name": original_name,
                "storedAs": dest.name,
            },
            status=201,
        )

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
            page, per_page = parse_pagination(parsed.query)
            total = len(files)
            start = (page - 1) * per_page
            end = start + per_page
            self.respond_json(
                {
                    "files": files[start:end],
                    "pagination": {
                        "page": page,
                        "per_page": per_page,
                        "total": total,
                        "total_pages": max((total + per_page - 1) // per_page, 1),
                    },
                }
            )
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
