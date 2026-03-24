import json
import re
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


APP_TITLE = "1C Cloud Probe"


class ProbeLogger:
    def __init__(self, log_widget: tk.Text, output_dir: Path):
        self.log_widget = log_widget
        self.output_dir = output_dir
        self.lines = []

    def log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {message}"
        self.lines.append(line)

        def append():
            self.log_widget.insert("end", line + "\n")
            self.log_widget.see("end")

        self.log_widget.after(0, append)

    def save(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / "probe.log"
        path.write_text("\n".join(self.lines), encoding="utf-8", errors="replace")
        return path


def mask_username(username: str) -> str:
    if not username:
        return ""
    if len(username) <= 2:
        return "*" * len(username)
    return username[:1] + "*" * (len(username) - 2) + username[-1]


def ensure_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)


def save_text_file(output_dir: Path, filename: str, content: str) -> Path:
    ensure_output_dir(output_dir)
    path = output_dir / filename
    path.write_text(content, encoding="utf-8", errors="replace")
    return path


def sanitize_filename(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9._-]+", "_", value)
    return value.strip("._-") or "file"


def detect_base_href(html: str) -> str | None:
    m = re.search(r'<base\s+href="([^"]+)"', html, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def detect_version(html: str) -> str | None:
    m = re.search(r'var\s+VERSION\s*=\s*"([^"]+)"', html)
    if m:
        return m.group(1).strip()
    return None


def analyze_markers(text: str, url: str) -> list[str]:
    markers = [
        "odata",
        "standard.odata",
        "e1cib",
        "webclient",
        "login",
        "password",
        "auth",
        "openid",
        "openidconnect",
        "oidc",
        "1c",
        "1cfresh",
        "hs",
        "__enter__",
        "openidrelyingparty",
    ]
    combined = f"{url}\n{text}".lower()
    return [m for m in markers if m in combined]


def response_summary(response: requests.Response) -> dict:
    return {
        "final_url": response.url,
        "status_code": response.status_code,
        "history": [{"status_code": r.status_code, "url": r.url} for r in response.history],
        "headers": dict(response.headers),
        "cookies": requests.utils.dict_from_cookiejar(response.cookies),
    }


def extract_interesting_headers(headers: dict) -> dict:
    interesting = {}
    for key in ["WWW-Authenticate", "Set-Cookie", "Location", "Content-Type", "Server"]:
        for h, v in headers.items():
            if h.lower() == key.lower():
                interesting[h] = v
    return interesting


def try_request(session: requests.Session, method: str, url: str, timeout: int, verify_ssl: bool, logger: ProbeLogger, label: str):
    try:
        response = session.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl,
        )
        logger.log(f"[OK] {label}: {method} {url} -> {response.status_code} -> {response.url}")
        return response, None
    except Exception as e:
        logger.log(f"[ERR] {label}: {method} {url} -> {e}")
        return None, str(e)


def build_url_variants(original_url: str, base_href: str | None) -> list[str]:
    variants = []
    normalized = original_url if original_url.endswith("/") else original_url + "/"
    variants.append(normalized)

    if base_href:
        parsed = urlparse(original_url)
        absolute_base = f"{parsed.scheme}://{parsed.netloc}{base_href}"
        if not absolute_base.endswith("/"):
            absolute_base += "/"
        if absolute_base not in variants:
            variants.append(absolute_base)

    return variants


def can_attempt_basic_auth(username: str, password: str) -> tuple[bool, str]:
    try:
        username.encode("latin-1")
        password.encode("latin-1")
        return True, ""
    except UnicodeEncodeError:
        return False, "Логин или пароль содержат символы вне latin-1; стандартный Basic Auth тест пропущен."


def save_http_body(output_dir: Path, prefix: str, response: requests.Response) -> Path:
    content_type = response.headers.get("Content-Type", "").lower()
    ext = ".txt"
    if "text/html" in content_type:
        ext = ".html"
    elif "application/json" in content_type:
        ext = ".json"
    elif "javascript" in content_type:
        ext = ".js"
    elif "xml" in content_type:
        ext = ".xml"

    filename = f"{sanitize_filename(prefix)}{ext}"
    return save_text_file(output_dir, filename, response.text)


def run_probe(base_url: str, username: str, password: str, verify_ssl: bool, timeout: int, output_dir: Path, logger: ProbeLogger):
    report = {
        "started_at": datetime.now().isoformat(),
        "base_url": base_url,
        "username_masked": mask_username(username),
        "verify_ssl": verify_ssl,
        "timeout_seconds": timeout,
        "start_page": None,
        "detected_base_href": None,
        "detected_version": None,
        "url_variants": [],
        "probes": [],
        "basic_auth": None,
        "notes": [],
    }

    logger.log("=" * 70)
    logger.log("Старт диагностики 1С")
    logger.log("=" * 70)
    logger.log(f"URL: {base_url}")
    logger.log(f"Логин: {mask_username(username)}")
    logger.log(f"Проверка SSL: {verify_ssl}")
    logger.log(f"Таймаут: {timeout} сек")
    logger.log(f"Папка вывода: {output_dir}")

    ensure_output_dir(output_dir)

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 1C-Probe/2.0"
    })

    logger.log("Шаг 1. Проверка стартовой страницы")
    start_response, start_error = try_request(session, "GET", base_url, timeout, verify_ssl, logger, "START PAGE")

    base_href = None
    version = None

    if start_response is not None:
        report["start_page"] = response_summary(start_response)
        preview = start_response.text[:5000]
        markers = analyze_markers(start_response.text, start_response.url)
        base_href = detect_base_href(start_response.text)
        version = detect_version(start_response.text)

        report["start_page"]["markers"] = markers
        report["start_page"]["html_preview"] = preview
        report["detected_base_href"] = base_href
        report["detected_version"] = version

        html_path = save_text_file(output_dir, "start_page.html", start_response.text)
        logger.log(f"Сохранен HTML стартовой страницы: {html_path}")

        if start_response.history:
            logger.log("Цепочка редиректов:")
            for r in start_response.history:
                logger.log(f"  {r.status_code} -> {r.url}")
        else:
            logger.log("Редиректов нет")

        logger.log(f"Финальный URL: {start_response.url}")
        logger.log(f"Статус: {start_response.status_code}")

        logger.log("Интересные заголовки ответа:")
        for k, v in extract_interesting_headers(dict(start_response.headers)).items():
            logger.log(f"  {k}: {v}")

        if base_href:
            logger.log(f"Обнаружен base href: {base_href}")
        else:
            logger.log("base href не найден")

        if version:
            logger.log(f"Обнаружена версия платформы: {version}")

        if markers:
            logger.log("Обнаружены маркеры:")
            for m in markers:
                logger.log(f"  - {m}")
        else:
            logger.log("Маркеры не найдены")
    else:
        report["start_page"] = {"error": start_error}
        report["notes"].append("Не удалось открыть стартовую страницу")

    url_variants = build_url_variants(base_url, base_href)
    report["url_variants"] = url_variants

    logger.log("Шаг 2. Проверка URL-вариантов и типовых путей")

    probe_paths = [
        "",
        "hs/",
        "odata/",
        "odata/standard.odata/",
        "api/",
        "e1cib/",
        "manifest.json",
    ]

    if version:
        probe_paths.append(f"scripts/mod_bootstrap_bootstrap.js?sysver={version}")
    else:
        probe_paths.append("scripts/mod_bootstrap_bootstrap.js")

    for base_variant in url_variants:
        logger.log(f"Базовый вариант: {base_variant}")

        for path in probe_paths:
            full_url = urljoin(base_variant, path)

            for method in ["GET", "HEAD", "OPTIONS"]:
                label = f"{method} [{path or '/'}]"
                resp, err = try_request(session, method, full_url, timeout, verify_ssl, logger, label)

                entry = {
                    "base_variant": base_variant,
                    "path": path or "/",
                    "method": method,
                    "url": full_url,
                    "error": err,
                }

                if resp is not None:
                    entry.update(response_summary(resp))
                    entry["interesting_headers"] = extract_interesting_headers(dict(resp.headers))

                    body_saved_to = None
                    if method == "GET":
                        body_saved_to = str(save_http_body(
                            output_dir,
                            prefix=f"{urlparse(base_variant).path}_{path}_{method}",
                            response=resp
                        ))
                    entry["body_saved_to"] = body_saved_to

                    if resp.status_code == 401:
                        logger.log("  -> Обнаружен 401 Unauthorized")
                        hdrs = extract_interesting_headers(dict(resp.headers))
                        if hdrs:
                            for k, v in hdrs.items():
                                logger.log(f"     {k}: {v}")

                report["probes"].append(entry)

    logger.log("Шаг 3. Проверка Basic Auth")
    can_basic, reason = can_attempt_basic_auth(username, password)
    if not can_basic:
        logger.log(f"[SKIP] BASIC AUTH: {reason}")
        report["basic_auth"] = {"skipped": True, "reason": reason}
    else:
        auth_session = requests.Session()
        auth_session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 1C-Probe/2.0"
        })
        try:
            response = auth_session.get(
                base_url,
                auth=(username, password),
                timeout=timeout,
                allow_redirects=True,
                verify=verify_ssl,
            )
            logger.log(f"[OK] BASIC AUTH: GET {base_url} -> {response.status_code} -> {response.url}")
            report["basic_auth"] = response_summary(response)
            report["basic_auth"]["interesting_headers"] = extract_interesting_headers(dict(response.headers))
            auth_path = save_http_body(output_dir, "basic_auth_response", response)
            report["basic_auth"]["body_saved_to"] = str(auth_path)
            logger.log(f"Сохранен ответ basic auth: {auth_path}")
        except Exception as e:
            logger.log(f"[ERR] BASIC AUTH: {e}")
            report["basic_auth"] = {"error": str(e)}

    report["finished_at"] = datetime.now().isoformat()

    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.log(f"Сохранен JSON-отчет: {report_path}")

    log_path = logger.save()
    logger.log(f"Сохранен лог-файл: {log_path}")
    logger.log("Диагностика завершена")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x760")
        self.minsize(860, 620)

        self.var_url = tk.StringVar()
        self.var_username = tk.StringVar()
        self.var_password = tk.StringVar()
        self.var_verify_ssl = tk.BooleanVar(value=True)
        self.var_timeout = tk.StringVar(value="20")
        self.var_output_dir = tk.StringVar(value=str(Path.cwd() / "output"))

        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        top = ttk.LabelFrame(frm, text="Параметры подключения")
        top.pack(fill="x", pady=(0, 10))

        ttk.Label(top, text="URL:").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(top, textvariable=self.var_url, width=90).grid(row=0, column=1, columnspan=2, sticky="we", padx=6, pady=6)

        ttk.Label(top, text="Логин:").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(top, textvariable=self.var_username, width=40).grid(row=1, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(top, text="Пароль:").grid(row=2, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(top, textvariable=self.var_password, show="*", width=40).grid(row=2, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(top, text="Таймаут (сек):").grid(row=3, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(top, textvariable=self.var_timeout, width=10).grid(row=3, column=1, sticky="w", padx=6, pady=6)

        ttk.Checkbutton(top, text="Проверять SSL сертификат", variable=self.var_verify_ssl).grid(
            row=4, column=1, sticky="w", padx=6, pady=6
        )

        ttk.Label(top, text="Папка результата:").grid(row=5, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(top, textvariable=self.var_output_dir, width=70).grid(row=5, column=1, sticky="we", padx=6, pady=6)
        ttk.Button(top, text="Выбрать...", command=self.choose_output_dir).grid(row=5, column=2, sticky="w", padx=6, pady=6)

        top.columnconfigure(1, weight=1)

        buttons = ttk.Frame(frm)
        buttons.pack(fill="x", pady=(0, 10))

        self.btn_run = ttk.Button(buttons, text="Запустить проверку", command=self.on_run)
        self.btn_run.pack(side="left")

        ttk.Button(buttons, text="Открыть папку результата", command=self.open_output_dir).pack(side="left", padx=6)
        ttk.Button(buttons, text="Очистить лог", command=self.clear_log).pack(side="left", padx=6)

        log_frame = ttk.LabelFrame(frm, text="Лог")
        log_frame.pack(fill="both", expand=True)

        self.txt_log = tk.Text(log_frame, wrap="word")
        self.txt_log.pack(side="left", fill="both", expand=True)

        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.txt_log.yview)
        scroll.pack(side="right", fill="y")
        self.txt_log.configure(yscrollcommand=scroll.set)

    def choose_output_dir(self):
        path = filedialog.askdirectory(title="Выберите папку для результатов")
        if path:
            self.var_output_dir.set(path)

    def open_output_dir(self):
        path = Path(self.var_output_dir.get().strip())
        path.mkdir(parents=True, exist_ok=True)
        try:
            import os
            os.startfile(path)
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Не удалось открыть папку:\n{e}")

    def clear_log(self):
        self.txt_log.delete("1.0", "end")

    def on_run(self):
        base_url = self.var_url.get().strip()
        username = self.var_username.get().strip()
        password = self.var_password.get()
        output_dir = Path(self.var_output_dir.get().strip())

        if not base_url:
            messagebox.showwarning(APP_TITLE, "Укажите URL")
            return

        try:
            timeout = int(self.var_timeout.get().strip())
            if timeout <= 0:
                raise ValueError
        except Exception:
            messagebox.showwarning(APP_TITLE, "Таймаут должен быть положительным целым числом")
            return

        self.btn_run.config(state="disabled")
        self.txt_log.delete("1.0", "end")

        logger = ProbeLogger(self.txt_log, output_dir)

        def worker():
            try:
                run_probe(
                    base_url=base_url,
                    username=username,
                    password=password,
                    verify_ssl=self.var_verify_ssl.get(),
                    timeout=timeout,
                    output_dir=output_dir,
                    logger=logger,
                )
                self.after(0, lambda: messagebox.showinfo(APP_TITLE, f"Проверка завершена.\nРезультаты сохранены в:\n{output_dir}"))
            except Exception as e:
                logger.log(f"[FATAL] {e}")
                logger.save()
                self.after(0, lambda: messagebox.showerror(APP_TITLE, f"Ошибка выполнения:\n{e}"))
            finally:
                self.after(0, lambda: self.btn_run.config(state="normal"))

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    app = App()
    app.mainloop()
