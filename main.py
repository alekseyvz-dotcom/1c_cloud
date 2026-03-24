import json
import threading
import traceback
import webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth
import tkinter as tk
from tkinter import ttk, messagebox


APP_TITLE = "1C Cloud Probe"
OUTPUT_ROOT = Path("probe_runs")


class ProbeLogger:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.lines = []

    def log(self, text=""):
        line = str(text)
        self.lines.append(line)
        if self.log_callback:
            self.log_callback(line)

    def save_to_file(self, path: Path):
        path.write_text("\n".join(self.lines), encoding="utf-8", errors="replace")


def mask_value(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def analyze_markers(text: str, url: str) -> list:
    markers = [
        "odata",
        "standard.odata",
        "e1cib",
        "webclient",
        "login",
        "password",
        "auth",
        "1c",
        "1cfresh",
        "hs",
        "__enter__",
    ]
    combined = f"{url}\n{text}".lower()
    return [m for m in markers if m in combined]


def response_to_dict(response: requests.Response) -> dict:
    return {
        "url": response.url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "history": [
            {
                "status_code": r.status_code,
                "url": r.url,
                "headers": dict(r.headers),
            }
            for r in response.history
        ],
    }


def try_get(session, url, timeout, verify_ssl, logger: ProbeLogger, label: str):
    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl,
        )
        logger.log(f"[OK] {label}: {url} -> {response.status_code} -> {response.url}")
        return response
    except Exception as e:
        logger.log(f"[ERR] {label}: {url} -> {e}")
        return None


def run_probe(base_url: str, username: str, password: str, verify_ssl: bool, timeout: int, logger: ProbeLogger) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = OUTPUT_ROOT / f"probe_{timestamp}"
    ensure_dir(run_dir)

    logger.log("=" * 80)
    logger.log(APP_TITLE)
    logger.log("=" * 80)
    logger.log(f"Base URL: {base_url}")
    logger.log(f"Username: {mask_value(username)}")
    logger.log(f"Password: {'*' * len(password) if password else ''}")
    logger.log(f"SSL verify: {verify_ssl}")
    logger.log(f"Timeout: {timeout}s")
    logger.log(f"Output dir: {run_dir}")

    report = {
        "started_at": datetime.now().isoformat(),
        "base_url": base_url,
        "username_masked": mask_value(username),
        "verify_ssl": verify_ssl,
        "timeout": timeout,
        "steps": {},
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 1C-Probe/1.0"
    })

    logger.log("")
    logger.log("=" * 80)
    logger.log("Шаг 1. Проверка стартовой страницы")
    logger.log("=" * 80)

    start_response = try_get(session, base_url, timeout, verify_ssl, logger, "START PAGE")
    if start_response is not None:
        report["steps"]["start_page"] = response_to_dict(start_response)

        logger.log(f"Финальный URL: {start_response.url}")
        logger.log(f"Статус: {start_response.status_code}")
        logger.log("Редиректы:")
        if start_response.history:
            for r in start_response.history:
                logger.log(f"  {r.status_code} -> {r.url}")
        else:
            logger.log("  (нет)")

        logger.log("Заголовки ответа:")
        for k, v in start_response.headers.items():
            logger.log(f"  {k}: {v}")

        start_html = start_response.text
        (run_dir / "start_page.html").write_text(start_html, encoding="utf-8", errors="replace")
        logger.log(f"Сохранен HTML: {run_dir / 'start_page.html'}")

        preview = start_html[:5000]
        logger.log("")
        logger.log("Первые 5000 символов HTML:")
        logger.log(preview)

        markers = analyze_markers(start_html, start_response.url)
        report["steps"]["start_page"]["markers"] = markers

        logger.log("")
        logger.log("Обнаруженные маркеры:")
        if markers:
            for m in markers:
                logger.log(f"  - {m}")
        else:
            logger.log("  (не найдены)")
    else:
        report["steps"]["start_page"] = {"error": "request_failed"}

    logger.log("")
    logger.log("=" * 80)
    logger.log("Шаг 2. Проверка типовых путей")
    logger.log("=" * 80)

    probe_paths = [
        "",
        "odata/",
        "odata/standard.odata/",
        "hs/",
        "api/",
        "e1cib/",
    ]
    report["steps"]["paths"] = {}

    for path in probe_paths:
        full_url = urljoin(base_url if base_url.endswith("/") else base_url + "/", path)
        resp = try_get(session, full_url, timeout, verify_ssl, logger, f"PATH [{path or '/'}]")
        if resp is not None:
            report["steps"]["paths"][path or "/"] = response_to_dict(resp)
        else:
            report["steps"]["paths"][path or "/"] = {"error": "request_failed"}

    logger.log("")
    logger.log("=" * 80)
    logger.log("Шаг 3. Проверка Basic Auth")
    logger.log("=" * 80)

    try:
        basic_session = requests.Session()
        basic_session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 1C-Probe/1.0"
        })

        basic_resp = basic_session.get(
            base_url,
            auth=HTTPBasicAuth(username, password),
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl,
        )
        logger.log(f"[OK] BASIC AUTH: {base_url} -> {basic_resp.status_code} -> {basic_resp.url}")

        report["steps"]["basic_auth"] = response_to_dict(basic_resp)
        basic_html = basic_resp.text
        (run_dir / "basic_auth_page.html").write_text(basic_html, encoding="utf-8", errors="replace")
        logger.log(f"Сохранен HTML: {run_dir / 'basic_auth_page.html'}")
    except Exception as e:
        logger.log(f"[ERR] BASIC AUTH: {base_url} -> {e}")
        report["steps"]["basic_auth"] = {"error": str(e)}

    report["finished_at"] = datetime.now().isoformat()
    (run_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
        errors="replace",
    )
    logger.log(f"Сохранен отчет JSON: {run_dir / 'report.json'}")

    logger.save_to_file(run_dir / "probe.log")
    return run_dir


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x650")
        self.minsize(820, 560)

        self.is_running = False
        self.last_run_dir = None

        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        top = ttk.LabelFrame(frm, text="Параметры проверки")
        top.pack(fill="x")

        ttk.Label(top, text="URL:").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        self.var_url = tk.StringVar()
        self.ent_url = ttk.Entry(top, textvariable=self.var_url, width=80)
        self.ent_url.grid(row=0, column=1, sticky="we", padx=6, pady=6, columnspan=3)

        ttk.Label(top, text="Логин:").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        self.var_username = tk.StringVar()
        self.ent_username = ttk.Entry(top, textvariable=self.var_username, width=30)
        self.ent
