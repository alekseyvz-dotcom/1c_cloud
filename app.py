import json
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth
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


def analyze_markers(text: str, url: str) -> list[str]:
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


def response_summary(response: requests.Response) -> dict:
    return {
        "final_url": response.url,
        "status_code": response.status_code,
        "history": [{"status_code": r.status_code, "url": r.url} for r in response.history],
        "headers": dict(response.headers),
    }


def try_get(session: requests.Session, url: str, timeout: int, verify_ssl: bool, logger: ProbeLogger, label: str):
    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl,
        )
        logger.log(f"[OK] {label}: {url} -> {response.status_code} -> {response.url}")
        return response, None
    except Exception as e:
        logger.log(f"[ERR] {label}: {url} -> {e}")
        return None, str(e)


def run_probe(base_url: str, username: str, password: str, verify_ssl: bool, timeout: int, output_dir: Path, logger: ProbeLogger):
    report = {
        "started_at": datetime.now().isoformat(),
        "base_url": base_url,
        "username_masked": mask_username(username),
        "verify_ssl": verify_ssl,
        "timeout_seconds": timeout,
        "start_page": None,
        "path_probes": [],
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
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 1C-Probe/1.0"
    })

    logger.log("Шаг 1. Проверка стартовой страницы")
    start_response, start_error = try_get(session, base_url, timeout, verify_ssl, logger, "START PAGE")

    if start_response is not None:
        report["start_page"] = response_summary(start_response)
        preview = start_response.text[:5000]
        markers = analyze_markers(start_response.text, start_response.url)
        report["start_page"]["markers"] = markers
        report["start_page"]["html_preview"] = preview

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

        logger.log("Заголовки ответа:")
        for k, v in start_response.headers.items():
            logger.log(f"  {k}: {v}")

        if markers:
            logger.log("Обнаружены маркеры:")
            for m in markers:
                logger.log(f"  - {m}")
        else:
            logger.log("Маркеры не найдены")
    else:
        report["start_page"] = {"error": start_error}
        report["notes"].append("Не удалось открыть стартовую страницу")

    logger.log("Шаг 2. Проверка типовых путей")
    paths = [
        "",
        "odata/",
        "odata/standard.odata/",
        "hs/",
        "api/",
        "e1cib/",
    ]

    for path in paths:
        full_url = urljoin(base_url if base_url.endswith("/") else base_url + "/", path)
        resp, err = try_get(session, full_url, timeout, verify_ssl, logger, f"PATH [{path or '/'}]")
        entry = {
            "path": path or "/",
            "url": full_url,
            "error": err,
        }
        if resp is not None:
            entry.update(response_summary(resp))
        report["path_probes"].append(entry)

    logger.log("Шаг 3. Проверка Basic Auth")
    try:
        auth_response = session.get(
            base_url,
            auth=HTTPBasicAuth(username, password),
            timeout=timeout,
            allow_redirects=True,
            verify=verify_ssl,
        )
        logger.log(f"[OK] BASIC AUTH: {base_url} -> {auth_response.status_code} -> {auth_response.url}")
        report["basic_auth"] = response_summary(auth_response)

        auth_html_path = save_text_file(output_dir, "basic_auth_page.html", auth_response.text)
        logger.log(f"Сохранен HTML ответа basic auth: {auth_html_path}")
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
        self.geometry("900x700")
        self.minsize(820, 620)

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
        ttk.Entry(top, textvariable=self.var_url, width=80).grid(row=0, column=1, columnspan=2, sticky="we", padx=6, pady=6)

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
        ttk.Entry(top, textvariable=self.var_output_dir, width=65).grid(row=5, column=1, sticky="we", padx=6, pady=6)
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
