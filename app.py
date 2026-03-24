import base64
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
    keys = ["WWW-Authenticate", "Set-Cookie", "Location", "Content-Type", "Server", "Allow"]
    for key in keys:
        for h, v in headers.items():
            if h.lower() == key.lower():
                interesting[h] = v
    return interesting


def try_request(session: requests.Session, method: str, url: str, timeout: int, verify_ssl: bool, logger: ProbeLogger, label: str, headers: dict | None = None, auth=None):
    try:
        response = session.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl,
            headers=headers,
            auth=auth,
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


def parse_extra_paths(raw_text: str) -> list[str]:
    result = []
    for line in raw_text.splitlines():
        item = line.strip()
        if not item:
            continue
        if item.startswith("/"):
            item = item[1:]
        result.append(item)
    return result


def build_manual_basic_auth_header(username: str, password: str, encoding_name: str) -> tuple[dict | None, str | None]:
    try:
        raw = f"{username}:{password}".encode(encoding_name)
        token = base64.b64encode(raw).decode("ascii")
        return {"Authorization": f"Basic {token}"}, None
    except Exception as e:
        return None, str(e)


def log_interesting_response_info(logger: ProbeLogger, response: requests.Response):
    interesting = extract_interesting_headers(dict(response.headers))
    if interesting:
        logger.log("  Интересные заголовки:")
        for k, v in interesting.items():
            logger.log(f"    {k}: {v}")


def add_probe_entry(report: dict, category: str, base_variant: str, path: str, method: str, mode: str, url: str, resp, err, body_saved_to: str | None = None):
    entry = {
        "category": category,
        "base_variant": base_variant,
        "path": path or "/",
        "method": method,
        "mode": mode,
        "url": url,
        "error": err,
    }
    if resp is not None:
        entry.update(response_summary(resp))
        entry["interesting_headers"] = extract_interesting_headers(dict(resp.headers))
        entry["body_saved_to"] = body_saved_to
    report["probes"].append(entry)


def run_probe(base_url: str, username: str, password: str, verify_ssl: bool, timeout: int, output_dir: Path, logger: ProbeLogger, extra_paths: list[str], enable_requests_auth: bool, enable_manual_latin1: bool, enable_manual_utf8: bool):
    report = {
        "started_at": datetime.now().isoformat(),
        "base_url": base_url,
        "username_masked": mask_username(username),
        "verify_ssl": verify_ssl,
        "timeout_seconds": timeout,
        "extra_paths": extra_paths,
        "auth_modes": {
            "requests_auth": enable_requests_auth,
            "manual_basic_latin1": enable_manual_latin1,
            "manual_basic_utf8": enable_manual_utf8,
        },
        "start_page": None,
        "detected_base_href": None,
        "detected_version": None,
        "url_variants": [],
        "probes": [],
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
    logger.log(f"Дополнительные пути: {', '.join(extra_paths) if extra_paths else '(нет)'}")

    ensure_output_dir(output_dir)

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 1C-Probe/3.0"
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

        log_interesting_response_info(logger, start_response)

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

    default_probe_paths = [
        "",
        "hs/",
        "odata/",
        "odata/standard.odata/",
        "api/",
        "e1cib/",
        "manifest.json",
    ]

    if version:
        default_probe_paths.append(f"scripts/mod_bootstrap_bootstrap.js?sysver={version}")
    else:
        default_probe_paths.append("scripts/mod_bootstrap_bootstrap.js")

    all_custom_paths = list(dict.fromkeys(extra_paths))
    methods_common = ["GET", "HEAD", "OPTIONS"]

    logger.log("Шаг 2. Базовая проверка типовых путей без авторизации")
    for base_variant in url_variants:
        logger.log(f"Базовый вариант: {base_variant}")

        for path in default_probe_paths:
            full_url = urljoin(base_variant, path)

            for method in methods_common:
                label = f"DEFAULT {method} [{path or '/'}]"
                resp, err = try_request(session, method, full_url, timeout, verify_ssl, logger, label)

                body_saved_to = None
                if resp is not None:
                    if method == "GET":
                        body_saved_to = str(save_http_body(
                            output_dir,
                            prefix=f"default_{urlparse(base_variant).path}_{path}_{method}",
                            response=resp
                        ))
                    if resp.status_code in (200, 401, 403, 404, 405):
                        log_interesting_response_info(logger, resp)

                add_probe_entry(report, "default", base_variant, path, method, "no_auth", full_url, resp, err, body_saved_to)

    if all_custom_paths:
        logger.log("Шаг 3. Проверка пользовательских путей")

    for base_variant in url_variants:
        if not all_custom_paths:
            break

        logger.log(f"Пользовательские пути для базы: {base_variant}")

        for path in all_custom_paths:
            full_url = urljoin(base_variant, path)

            # 1) Без авторизации
            for method in methods_common:
                label = f"CUSTOM NO_AUTH {method} [{path}]"
                resp, err = try_request(session, method, full_url, timeout, verify_ssl, logger, label)

                body_saved_to = None
                if resp is not None:
                    if method == "GET":
                        body_saved_to = str(save_http_body(
                            output_dir,
                            prefix=f"custom_noauth_{urlparse(base_variant).path}_{path}_{method}",
                            response=resp
                        ))
                    log_interesting_response_info(logger, resp)

                add_probe_entry(report, "custom", base_variant, path, method, "no_auth", full_url, resp, err, body_saved_to)

            # 2) requests auth
            if enable_requests_auth:
                for method in ["GET"]:
                    label = f"CUSTOM REQ_AUTH {method} [{path}]"
                    try:
                        resp, err = try_request(
                            session,
                            method,
                            full_url,
                            timeout,
                            verify_ssl,
                            logger,
                            label,
                            auth=(username, password),
                        )
                    except Exception as e:
                        resp, err = None, str(e)

                    body_saved_to = None
                    if resp is not None:
                        body_saved_to = str(save_http_body(
                            output_dir,
                            prefix=f"custom_reqauth_{urlparse(base_variant).path}_{path}_{method}",
                            response=resp
                        ))
                        log_interesting_response_info(logger, resp)

                    add_probe_entry(report, "custom", base_variant, path, method, "requests_auth", full_url, resp, err, body_saved_to)

            # 3) Manual Basic latin-1
            if enable_manual_latin1:
                headers, auth_err = build_manual_basic_auth_header(username, password, "latin-1")
                if headers is None:
                    logger.log(f"[SKIP] CUSTOM MANUAL_BASIC_LATIN1 [${path}] -> {auth_err}")
                    add_probe_entry(report, "custom", base_variant, path, "GET", "manual_basic_latin1", full_url, None, auth_err, None)
                else:
                    label = f"CUSTOM MANUAL_BASIC_LATIN1 GET [{path}]"
                    resp, err = try_request(
                        session,
                        "GET",
                        full_url,
                        timeout,
                        verify_ssl,
                        logger,
                        label,
                        headers=headers,
                    )
                    body_saved_to = None
                    if resp is not None:
                        body_saved_to = str(save_http_body(
                            output_dir,
                            prefix=f"custom_manual_latin1_{urlparse(base_variant).path}_{path}_GET",
                            response=resp
                        ))
                        log_interesting_response_info(logger, resp)

                    add_probe_entry(report, "custom", base_variant, path, "GET", "manual_basic_latin1", full_url, resp, err, body_saved_to)

            # 4) Manual Basic UTF-8
            if enable_manual_utf8:
                headers, auth_err = build_manual_basic_auth_header(username, password, "utf-8")
                if headers is None:
                    logger.log(f"[SKIP] CUSTOM MANUAL_BASIC_UTF8 [{path}] -> {auth_err}")
                    add_probe_entry(report, "custom", base_variant, path, "GET", "manual_basic_utf8", full_url, None, auth_err, None)
                else:
                    label = f"CUSTOM MANUAL_BASIC_UTF8 GET [{path}]"
                    resp, err = try_request(
                        session,
                        "GET",
                        full_url,
                        timeout,
                        verify_ssl,
                        logger,
                        label,
                        headers=headers,
                    )
                    body_saved_to = None
                    if resp is not None:
                        body_saved_to = str(save_http_body(
                            output_dir,
                            prefix=f"custom_manual_utf8_{urlparse(base_variant).path}_{path}_GET",
                            response=resp
                        ))
                        log_interesting_response_info(logger, resp)

                    add_probe_entry(report, "custom", base_variant, path, "GET", "manual_basic_utf8", full_url, resp, err, body_saved_to)

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
        self.geometry("1050x840")
        self.minsize(900, 680)

        self.var_url = tk.StringVar()
        self.var_username = tk.StringVar()
        self.var_password = tk.StringVar()
        self.var_verify_ssl = tk.BooleanVar(value=True)
        self.var_timeout = tk.StringVar(value="20")
        self.var_output_dir = tk.StringVar(value=str(Path.cwd() / "output"))

        self.var_enable_requests_auth = tk.BooleanVar(value=True)
        self.var_enable_manual_latin1 = tk.BooleanVar(value=True)
        self.var_enable_manual_utf8 = tk.BooleanVar(value=True)

        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        top = ttk.LabelFrame(frm, text="Параметры подключения")
        top.pack(fill="x", pady=(0, 10))

        ttk.Label(top, text="URL:").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        ttk.Entry(top, textvariable=self.var_url, width=95).grid(row=0, column=1, columnspan=3, sticky="we", padx=6, pady=6)

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
        ttk.Entry(top, textvariable=self.var_output_dir, width=72).grid(row=5, column=1, columnspan=2, sticky="we", padx=6, pady=6)
        ttk.Button(top, text="Выбрать...", command=self.choose_output_dir).grid(row=5, column=3, sticky="w", padx=6, pady=6)

        auth_box = ttk.LabelFrame(top, text="Режимы авторизации для пользовательских путей")
        auth_box.grid(row=6, column=0, columnspan=4, sticky="we", padx=6, pady=8)

        ttk.Checkbutton(auth_box, text="requests auth (стандартный BasicAuth requests)", variable=self.var_enable_requests_auth).grid(
            row=0, column=0, sticky="w", padx=8, pady=4
        )
        ttk.Checkbutton(auth_box, text="manual basic latin-1", variable=self.var_enable_manual_latin1).grid(
            row=0, column=1, sticky="w", padx=8, pady=4
        )
        ttk.Checkbutton(auth_box, text="manual basic utf-8", variable=self.var_enable_manual_utf8).grid(
            row=0, column=2, sticky="w", padx=8, pady=4
        )

        extra_box = ttk.LabelFrame(frm, text="Дополнительные пути для проверки (по одному на строку)")
        extra_box.pack(fill="x", pady=(0, 10))

        self.txt_paths = tk.Text(extra_box, height=8, wrap="none")
        self.txt_paths.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)

        paths_scroll = ttk.Scrollbar(extra_box, orient="vertical", command=self.txt_paths.yview)
        paths_scroll.pack(side="right", fill="y", padx=(0, 6), pady=6)
        self.txt_paths.configure(yscrollcommand=paths_scroll.set)

        self.txt_paths.insert(
            "1.0",
            "hs/employees\n"
            "hs/integration/employees\n"
            "hs/staff\n"
            "hs/api/employees\n"
            "hs/catalog/employees\n"
            "hs/employee/list\n"
        )

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

        top.columnconfigure(1, weight=1)
        top.columnconfigure(2, weight=1)

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
        extra_paths = parse_extra_paths(self.txt_paths.get("1.0", "end"))

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
                    extra_paths=extra_paths,
                    enable_requests_auth=self.var_enable_requests_auth.get(),
                    enable_manual_latin1=self.var_enable_manual_latin1.get(),
                    enable_manual_utf8=self.var_enable_manual_utf8.get(),
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
