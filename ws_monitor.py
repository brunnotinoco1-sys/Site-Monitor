import http.client
import queue
import re
import threading
import time
import textwrap
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit, unquote
from urllib.request import Request, urlopen
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_NAME = "WS Monitor"
DEVELOPER = "WS Dev"
CHECK_INTERVAL_SECONDS = 30
LOG_POLL_SECONDS = 2
MAX_EVENTS = 5000
MAX_SAMPLES = 10000
LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\b'
)
AUTH_PATH_PATTERN = re.compile(r"(?:login|log-in|signin|sign-in|wp-login|/admin)", re.I)
SQLI_PATTERN = re.compile(
    r"(?:\bunion\s+(?:all\s+)?select\b|\bselect\b.{0,80}\bfrom\b|"
    r"\bor\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|"
    r"\b(?:sleep|benchmark)\s*\(|(?:--|/\*|\*/|;\s*drop\b))",
    re.I,
)
XSS_PATTERN = re.compile(
    r"(?:<\s*script\b|javascript\s*:|on(?:error|load|click)\s*=|<\s*svg\b)",
    re.I,
)
TRAVERSAL_PATTERN = re.compile(r"(?:\.\.[/\\]|%2e%2e)", re.I)
COMMAND_PATTERN = re.compile(
    r"(?:;\s*(?:cat|whoami|id|uname|curl|wget)\b|\|\s*(?:cat|whoami|id)\b|"
    r"`[^`]+`|\$\([^)]{1,100}\))",
    re.I,
)
SECURITY_HEADERS = (
    ("Content-Security-Policy", "Content-Security-Policy"),
    ("X-Content-Type-Options", "X-Content-Type-Options"),
    ("X-Frame-Options", "X-Frame-Options"),
    ("Referrer-Policy", "Referrer-Policy"),
)


@dataclass
class Sample:
    timestamp: datetime
    status: str
    latency_ms: float | None
    detail: str
    missing_headers: tuple[str, ...] = ()


@dataclass
class SecurityEvent:
    timestamp: datetime
    category: str
    source: str
    detail: str


def safe_text(value: str, limit: int = 300) -> str:
    return "".join(char if char.isprintable() else " " for char in value)[:limit]


def normalize_site(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Digite o endereço do site.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Informe um endereço HTTP ou HTTPS válido.")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("O endereço contém uma porta inválida.") from error
    if parsed.username or parsed.password:
        raise ValueError("Não inclua usuário ou senha no endereço do site.")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))


def report_site(site: str) -> str:
    parsed = urlsplit(site)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def classify_request(request: str) -> list[str]:
    decoded = unquote(unquote(request)).replace("\\", "/")
    categories = []
    if SQLI_PATTERN.search(decoded):
        categories.append("Possível SQL injection")
    if XSS_PATTERN.search(decoded):
        categories.append("Possível XSS")
    if TRAVERSAL_PATTERN.search(decoded):
        categories.append("Possível traversal de diretório")
    if COMMAND_PATTERN.search(decoded):
        categories.append("Possível injeção de comando")
    return categories


class LogAnalyzer:
    def __init__(self, path: str, emit_event):
        self.path = Path(path)
        self.emit_event = emit_event
        file_stat = self.path.stat()
        self.offset = file_stat.st_size
        self.file_identity = (file_stat.st_dev, file_stat.st_ino)
        self.recent_by_ip = defaultdict(deque)
        self.recent_all = deque()
        self.last_brute_alert = {}
        self.last_ddos_alert = {}
        self.last_cleanup = time.time()

    def poll(self):
        file_stat = self.path.stat()
        identity = (file_stat.st_dev, file_stat.st_ino)
        if identity != self.file_identity or file_stat.st_size < self.offset:
            self.offset = 0
            self.file_identity = identity
        with self.path.open("r", encoding="utf-8", errors="replace") as log_file:
            log_file.seek(self.offset)
            lines = log_file.readlines()
            self.offset = log_file.tell()
        for line in lines:
            self._analyze_line(line)

    def _analyze_line(self, line: str):
        match = LOG_PATTERN.match(line)
        if not match:
            return
        ip, log_time, request, status_text = match.groups()
        status = int(status_text)
        now = time.time()
        try:
            now = datetime.strptime(log_time, "%d/%b/%Y:%H:%M:%S %z").timestamp()
        except ValueError:
            pass
        if now - self.last_cleanup >= 60:
            for key, requests in list(self.recent_by_ip.items()):
                while requests and now - requests[0] > 60:
                    requests.popleft()
                if not requests:
                    del self.recent_by_ip[key]
                    if isinstance(key, str):
                        self.last_brute_alert.pop(key, None)
                    else:
                        self.last_ddos_alert.pop(key[1], None)
            self.last_cleanup = now
        request = safe_text(request)
        for category in classify_request(request):
            self.emit_event(
                SecurityEvent(datetime.now(), category, ip, f"Requisição: {request}")
            )

        endpoint = request.split(" ", 2)[1] if " " in request else request
        if status in (401, 403) and AUTH_PATH_PATTERN.search(endpoint):
            attempts = self.recent_by_ip[ip]
            attempts.append(now)
            while attempts and now - attempts[0] > 60:
                attempts.popleft()
            if len(attempts) >= 5 and now - self.last_brute_alert.get(ip, 0) >= 60:
                self.last_brute_alert[ip] = now
                self.emit_event(
                    SecurityEvent(
                        datetime.now(),
                        "Possível força bruta",
                        ip,
                        f"{len(attempts)} respostas 401/403 em rota de autenticação nos últimos 60 s.",
                    )
                )

        self.recent_all.append(now)
        ip_requests = self.recent_by_ip[("traffic", ip)]
        ip_requests.append(now)
        while self.recent_all and now - self.recent_all[0] > 60:
            self.recent_all.popleft()
        while ip_requests and now - ip_requests[0] > 60:
            ip_requests.popleft()
        if len(ip_requests) > 60 and now - self.last_ddos_alert.get(ip, 0) >= 60:
            self.last_ddos_alert[ip] = now
            self.emit_event(
                SecurityEvent(
                    datetime.now(),
                    "Possível pico de tráfego (DDoS)",
                    ip,
                    f"{len(ip_requests)} requisições deste IP nos últimos 60 s.",
                )
            )
        if len(self.recent_all) > 300 and now - self.last_ddos_alert.get("global", 0) >= 60:
            self.last_ddos_alert["global"] = now
            self.emit_event(
                SecurityEvent(
                    datetime.now(),
                    "Possível pico de tráfego (DDoS)",
                    "Múltiplos IPs",
                    f"{len(self.recent_all)} requisições no total nos últimos 60 s.",
                )
            )


class MonitorSession:
    def __init__(self, site: str, log_path: str | None, output_queue: queue.Queue):
        self.site = site
        self.log_path = log_path
        self.output_queue = output_queue
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.samples: list[Sample] = []
        self.events: list[SecurityEvent] = []
        self.started_at = datetime.now()
        self.finished_at: datetime | None = None
        self.worker = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.worker.start()

    def stop(self):
        self.stop_event.set()

    def snapshot(self):
        with self.lock:
            return list(self.samples), list(self.events), self.finished_at

    def _emit_event(self, event: SecurityEvent):
        with self.lock:
            self.events.append(event)
            del self.events[:-MAX_EVENTS]
        self.output_queue.put(("alert", event))

    def _run(self):
        analyzer = None
        if self.log_path:
            try:
                analyzer = LogAnalyzer(self.log_path, self._emit_event)
            except OSError as error:
                self.output_queue.put(("error", f"Não foi possível abrir o log: {error}"))

        next_check = 0.0
        next_log_poll = 0.0
        while not self.stop_event.is_set():
            now = time.monotonic()
            if analyzer and now >= next_log_poll:
                try:
                    analyzer.poll()
                except OSError as error:
                    self.output_queue.put(("error", f"Erro ao ler o log: {error}"))
                    analyzer = None
                next_log_poll = now + LOG_POLL_SECONDS
            if now >= next_check and not self.stop_event.is_set():
                self._check_site()
                next_check = time.monotonic() + CHECK_INTERVAL_SECONDS
            self.stop_event.wait(0.25)
        with self.lock:
            self.finished_at = datetime.now()
        self.output_queue.put(("stopped", None))

    def _check_site(self):
        started = time.monotonic()
        timestamp = datetime.now()
        status = "Erro"
        detail = ""
        latency = None
        missing_headers = ()
        request = Request(self.site, headers={"User-Agent": "WS-Monitor/1.0"})
        try:
            with urlopen(request, timeout=8) as response:
                response.read(65536)
                status = str(response.status)
                missing_headers = tuple(
                    name for name, header in SECURITY_HEADERS if not response.headers.get(header)
                )
                detail = "Resposta HTTP recebida."
        except HTTPError as error:
            status = str(error.code)
            missing_headers = tuple(
                name for name, header in SECURITY_HEADERS if not error.headers.get(header)
            )
            detail = f"Servidor respondeu HTTP {error.code}."
        except (URLError, TimeoutError, OSError, http.client.HTTPException) as error:
            detail = safe_text(str(error), 200)
        latency = (time.monotonic() - started) * 1000
        sample = Sample(timestamp, status, latency, detail, missing_headers)
        with self.lock:
            self.samples.append(sample)
            del self.samples[:-MAX_SAMPLES]
        self.output_queue.put(("sample", sample))


def _pdf_escape(text: str) -> bytes:
    encoded = text.encode("cp1252", errors="replace")
    escaped = bytearray()
    for byte in encoded:
        if byte in (ord("("), ord(")"), ord("\\")):
            escaped.append(ord("\\"))
            escaped.append(byte)
        elif byte < 32 or byte > 126:
            escaped.extend(f"\\{byte:03o}".encode("ascii"))
        else:
            escaped.append(byte)
    return bytes(escaped)


def write_pdf(path: Path, session: MonitorSession):
    samples, events, finished_at = session.snapshot()
    finished_at = finished_at or datetime.now()
    successful = sum(1 for sample in samples if sample.status.isdigit() and int(sample.status) < 400)
    errors = len(samples) - successful
    lines = [
        APP_NAME,
        f"Desenvolvedor: {DEVELOPER}",
        "",
        f"Site monitorado: {report_site(session.site)}",
        f"Log de acesso: {Path(session.log_path).name if session.log_path else 'não informado'}",
        f"Início: {session.started_at.strftime('%d/%m/%Y %H:%M:%S')}",
        f"Fim: {finished_at.strftime('%d/%m/%Y %H:%M:%S')}",
        f"Verificações HTTP: {len(samples)} | Respostas abaixo de 400: {successful} | Erros/HTTP 4xx-5xx: {errors}",
        f"Eventos de segurança detectados nos logs: {len(events)}",
        "",
        "VERIFICAÇÕES DO SITE",
    ]
    for sample in samples:
        latency = f"{sample.latency_ms:.0f} ms" if sample.latency_ms is not None else "n/d"
        lines.append(
            f"{sample.timestamp.strftime('%d/%m/%Y %H:%M:%S')} | HTTP {sample.status} | "
            f"{latency} | {sample.detail}"
        )
        if sample.missing_headers:
            lines.append("  Cabeçalhos de segurança ausentes: " + ", ".join(sample.missing_headers))
    lines.extend(("", "EVENTOS DE SEGURANÇA"))
    if events:
        for event in events:
            lines.append(
                f"{event.timestamp.strftime('%d/%m/%Y %H:%M:%S')} | {event.category} | "
                f"Origem: {event.source} | {event.detail}"
            )
    elif session.log_path:
        lines.append("Nenhum padrão de ataque foi identificado nos logs monitorados.")
    else:
        lines.append("Nenhum log foi configurado; não foi possível analisar tentativas de ataque.")
    lines.extend(
        (
            "",
            "LIMITAÇÕES",
            "As verificações HTTP observam apenas a resposta pública do site. Eventos de ataque são",
            "heurísticas baseadas em novas linhas de logs Apache/Nginx fornecidos pelo usuário.",
            "O monitor não bloqueia ataques, não substitui WAF/IDS e não garante detectar todas as",
            "tentativas. A análise de tráfego é limitada às últimas 60 segundos observadas no log.",
        )
    )

    page_lines = []
    for line in lines:
        wrapped = textwrap.wrap(line, width=100, replace_whitespace=True, drop_whitespace=True)
        page_lines.extend(wrapped or [""])
    pages = [page_lines[index:index + 55] for index in range(0, len(page_lines), 55)] or [[]]
    objects: list[bytes | None] = [None]

    def add_object(content: bytes) -> int:
        objects.append(content)
        return len(objects) - 1

    catalog_id = add_object(b"")
    pages_id = add_object(b"")
    font_id = add_object(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    )
    page_ids = []
    for page in pages:
        stream = bytearray(b"BT\n/F1 9 Tf\n48 790 Td\n12 TL\n")
        for line in page:
            stream.extend(b"(" + _pdf_escape(line) + b") Tj\nT*\n")
        stream.extend(b"ET\n")
        content_id = add_object(
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
            + bytes(stream) + b"endstream"
        )
        page_id = add_object(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 842] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
            f"/Contents {content_id} 0 R >>".encode("ascii")
        )
        page_ids.append(page_id)
    objects[catalog_id] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[pages_id] = (
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")
    )

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, content in enumerate(objects[1:], 1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(content or b"")
        pdf.extend(b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects)}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects)} /Root {catalog_id} 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pdf)


def default_report_path() -> Path:
    documents = Path.home() / "Documents" / "WS Monitor Reports"
    filename = datetime.now().strftime("WS-Monitor-%Y%m%d-%H%M%S-%f.pdf")
    return documents / filename


class WSMonitorApp:
    BACKGROUND = "#07111f"
    PANEL = "#101d2e"
    LIME = "#b7f34a"
    FOREGROUND = "#e8f0f8"
    MUTED = "#91a0b4"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} - {DEVELOPER}")
        self.root.geometry("900x650")
        self.root.minsize(760, 540)
        self.root.configure(bg=self.BACKGROUND)
        self.output_queue = queue.Queue()
        self.session: MonitorSession | None = None
        self.log_path = tk.StringVar()
        self.site = tk.StringVar()
        self.status_text = tk.StringVar(value="Pronto para iniciar.")
        self._closing = False
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(250, self._process_queue)

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=self.PANEL,
            fieldbackground=self.PANEL,
            foreground=self.FOREGROUND,
            rowheight=27,
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#1b2b40",
            foreground=self.LIME,
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", "#315126")])
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=self.PANEL,
            background=self.LIME,
            bordercolor=self.PANEL,
        )

        header = tk.Frame(self.root, bg=self.BACKGROUND)
        header.pack(fill="x", padx=24, pady=(20, 10))
        tk.Label(
            header, text=APP_NAME, bg=self.BACKGROUND, fg=self.LIME,
            font=("Segoe UI", 24, "bold"),
        ).pack(side="left")
        tk.Label(
            header, text=f"Desenvolvido por {DEVELOPER}", bg=self.BACKGROUND,
            fg=self.MUTED, font=("Segoe UI", 10),
        ).pack(side="right", anchor="s", pady=8)

        controls = tk.Frame(self.root, bg=self.PANEL, padx=16, pady=14)
        controls.pack(fill="x", padx=24, pady=8)
        tk.Label(
            controls, text="Site para monitorar", bg=self.PANEL, fg=self.FOREGROUND,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, sticky="w", columnspan=3)
        self.site_entry = tk.Entry(
            controls, textvariable=self.site, bg="#0b1624", fg=self.FOREGROUND,
            insertbackground=self.LIME, relief="flat", font=("Segoe UI", 11),
        )
        self.site_entry.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(6, 12), ipady=7)
        tk.Label(
            controls, text="Log Apache/Nginx (opcional)", bg=self.PANEL, fg=self.FOREGROUND,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=2, column=0, sticky="w", columnspan=3)
        self.log_entry = tk.Entry(
            controls, textvariable=self.log_path, bg="#0b1624", fg=self.MUTED,
            insertbackground=self.LIME, relief="flat", font=("Segoe UI", 9),
        )
        self.log_entry.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 12), ipady=6)
        self.browse_button = self._button(controls, "Selecionar log", self._choose_log, False)
        self.browse_button.grid(row=3, column=2, padx=(8, 0), pady=(6, 12))

        self.start_button = self._button(controls, "Iniciar monitoramento", self._start, True)
        self.start_button.grid(row=4, column=0, sticky="ew", padx=(0, 8))
        self.stop_button = self._button(controls, "Parar", self._stop, False)
        self.stop_button.grid(row=4, column=1, sticky="ew", padx=4)
        self.report_button = self._button(controls, "Gerar relatório PDF", self._generate_report, False)
        self.report_button.grid(row=4, column=2, sticky="ew", padx=(8, 0))
        self.stop_button.configure(state="disabled")
        self.report_button.configure(state="disabled")
        controls.columnconfigure(0, weight=1)
        controls.columnconfigure(1, weight=1)
        controls.columnconfigure(2, weight=1)

        self.status_label = tk.Label(
            self.root, textvariable=self.status_text, bg=self.BACKGROUND, fg=self.LIME,
            font=("Segoe UI", 10, "bold"), anchor="w",
        )
        self.status_label.pack(fill="x", padx=26, pady=(8, 4))
        self.table = ttk.Treeview(
            self.root, columns=("time", "status", "latency", "detail"),
            show="headings", height=10,
        )
        for column, title, width in (
            ("time", "Horário", 150),
            ("status", "HTTP", 75),
            ("latency", "Tempo", 90),
            ("detail", "Resultado", 480),
        ):
            self.table.heading(column, text=title)
            self.table.column(column, width=width, anchor="w")
        self.table.pack(fill="both", expand=True, padx=24, pady=(4, 6))
        tk.Label(
            self.root,
            text="A análise de ataques depende de um log do servidor; este programa não bloqueia invasões.",
            bg=self.BACKGROUND, fg=self.MUTED, font=("Segoe UI", 9),
        ).pack(fill="x", padx=26, pady=(4, 16), anchor="w")

    def _button(self, parent, text, command, primary):
        return tk.Button(
            parent, text=text, command=command, relief="flat",
            bg=self.LIME if primary else "#24364a",
            fg="#101a13" if primary else self.FOREGROUND,
            activebackground="#9cda35" if primary else "#314961",
            activeforeground="#101a13" if primary else self.FOREGROUND,
            font=("Segoe UI", 9, "bold"), padx=12, pady=8, cursor="hand2",
        )

    def _choose_log(self):
        path = filedialog.askopenfilename(
            title="Selecione o log de acesso do servidor",
            filetypes=(("Arquivos de log", "*.log *.txt"), ("Todos os arquivos", "*.*")),
        )
        if path:
            self.log_path.set(path)

    def _start(self):
        try:
            site = normalize_site(self.site.get())
            if self.log_path.get() and not Path(self.log_path.get()).is_file():
                raise ValueError("O arquivo de log selecionado não existe ou não pode ser acessado.")
        except (ValueError, OSError) as error:
            messagebox.showerror(APP_NAME, str(error), parent=self.root)
            return
        for item in self.table.get_children():
            self.table.delete(item)
        self.site.set(site)
        self.session = MonitorSession(site, self.log_path.get().strip() or None, self.output_queue)
        self.session.start()
        self.site_entry.configure(state="disabled")
        self.log_entry.configure(state="disabled")
        self.browse_button.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.report_button.configure(state="normal")
        self.status_text.set(f"Monitorando {report_site(site)}")

    def _stop(self):
        if self.session:
            self.session.stop()
            self.stop_button.configure(state="disabled")
            self.status_text.set("Encerrando monitoramento...")

    def _process_queue(self):
        try:
            while True:
                kind, value = self.output_queue.get_nowait()
                if kind == "sample":
                    sample = value
                    latency = f"{sample.latency_ms:.0f} ms" if sample.latency_ms is not None else "n/d"
                    self.table.insert(
                        "", 0,
                        values=(
                            sample.timestamp.strftime("%H:%M:%S"),
                            sample.status,
                            latency,
                            sample.detail,
                        ),
                    )
                    children = self.table.get_children()
                    for item in children[100:]:
                        self.table.delete(item)
                    if sample.missing_headers:
                        self.status_text.set(
                            "Cabeçalhos ausentes: " + ", ".join(sample.missing_headers)
                        )
                elif kind == "alert":
                    event = value
                    self.status_text.set(f"ALERTA: {event.category} — origem {event.source}")
                    messagebox.showwarning(
                        "WS Monitor - alerta de segurança",
                        f"{event.category}\nOrigem: {event.source}\n{event.detail}",
                        parent=self.root,
                    )
                elif kind == "error":
                    self.status_text.set(value)
                    messagebox.showerror(APP_NAME, value, parent=self.root)
                elif kind == "stopped":
                    self._finish_session()
        except queue.Empty:
            pass
        if self.root.winfo_exists():
            self.root.after(250, self._process_queue)

    def _finish_session(self):
        if not self.session:
            return
        self.site_entry.configure(state="normal")
        self.log_entry.configure(state="normal")
        self.browse_button.configure(state="normal")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_text.set("Monitoramento encerrado. Relatório final em PDF salvo.")
        try:
            path = default_report_path()
            write_pdf(path, self.session)
        except OSError as error:
            messagebox.showerror(APP_NAME, f"Não foi possível salvar o relatório: {error}", parent=self.root)
            return
        if self._closing:
            messagebox.showinfo(APP_NAME, f"Relatório final salvo em:\n{path}", parent=self.root)
            self.root.destroy()
        else:
            messagebox.showinfo(APP_NAME, f"Relatório final salvo em:\n{path}", parent=self.root)

    def _generate_report(self):
        if not self.session:
            messagebox.showinfo(APP_NAME, "Inicie um monitoramento antes de gerar o relatório.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(
            title="Salvar relatório PDF",
            initialdir=str(default_report_path().parent),
            initialfile=default_report_path().name,
            defaultextension=".pdf",
            filetypes=(("Documento PDF", "*.pdf"),),
        )
        if not path:
            return
        try:
            write_pdf(Path(path), self.session)
        except OSError as error:
            messagebox.showerror(APP_NAME, f"Não foi possível salvar o relatório: {error}", parent=self.root)
            return
        messagebox.showinfo(APP_NAME, f"Relatório salvo em:\n{path}", parent=self.root)

    def _close(self):
        if self.session and self.session.worker.is_alive():
            self._closing = True
            self.session.stop()
            self.stop_button.configure(state="disabled")
            self.status_text.set("Encerrando e salvando o relatório final...")
            return
        if self.session and self.session.snapshot()[0]:
            try:
                path = default_report_path()
                write_pdf(path, self.session)
            except OSError as error:
                messagebox.showerror(APP_NAME, f"Não foi possível salvar o relatório: {error}", parent=self.root)
                return
            messagebox.showinfo(APP_NAME, f"Relatório final salvo em:\n{path}", parent=self.root)
        self.root.destroy()


def main():
    root = tk.Tk()
    WSMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
