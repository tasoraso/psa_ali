#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hunter_full.py – All-in-one PSA Hunter
(Search → URLs → Certs → Validate → SQLite)

Patches:
- Robustere searx_search (nicht-dikt JSON / HTML-Fehlerseiten)
- Universeller JSON-Guard _json_as_dict
- validate_psa_json: Typ-Check
- validate_and_store: defensives JSON-Parsing, Vorschau bei Fehlern
- logger.exception statt logger.error für vollständige Stacktraces
"""

import argparse, os, re, sys, time, random, json, sqlite3, html, logging
from typing import List, Set, Dict, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urljoin, urlencode, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import certifi
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler

# ============================================================
# ENV laden (Projekt-Root .env)
# ============================================================
load_dotenv()

# --- PSA / Network ---
ENV_PSA_TOKEN        = os.getenv("PSA_TOKEN", "")
ENV_PSA_BASE_URL     = os.getenv("PSA_BASE_URL", "https://api.psacard.com/publicapi")
ENV_REQUESTS_CA      = os.getenv("REQUESTS_CA_BUNDLE") or certifi.where()

# --- Suche ---
ENV_SEARCH_ENGINE    = (os.getenv("SEARCH_ENGINE", "auto") or "auto").lower()  # ddg | searx | auto
ENV_SEARXNG_URL      = os.getenv("SEARXNG_URL", "")

# --- Pfade ---
ENV_DATA_DIR         = os.getenv("DATA_DIR", "./data")
ENV_DB_DIR           = os.getenv("DB_DIR",   "./db")
ENV_LOG_DIR          = os.getenv("LOG_DIR",  "./logs")

# --- Limits/Timeouts ---
ENV_DAILY_CAP        = int(os.getenv("DAILY_CAP", "80"))
ENV_CONNECT_TIMEOUT  = float(os.getenv("CONNECT_TIMEOUT", "10"))
ENV_READ_TIMEOUT     = float(os.getenv("READ_TIMEOUT", "25"))
ENV_RETRIES          = int(os.getenv("RETRIES", "3"))

# ============================================================
# Logger Setup
# ============================================================
def setup_logger(log_dir: str, name: str = "hunter", level: int = logging.INFO) -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    date = time.strftime("%Y-%m-%d")
    logfile = os.path.join(log_dir, f"{name}_{date}.log")

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers[:] = []  # doppelte Handler vermeiden

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    # Konsole
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # Datei (Rotating)
    fh = RotatingFileHandler(logfile, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    logger.info(f"Logging gestartet → {logfile}")
    return logger

# ============================================================
# Globale Puffer (Ctrl+C → Flush)
# ============================================================
COLLECT_BUFFER_URLS: List[str] = []
COLLECT_BUFFER_CERTS: List[str] = []

# ============================================================
# Defaults & Endpoints
# ============================================================
ROOT     = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(ENV_DATA_DIR)
DB_DIR   = os.path.abspath(ENV_DB_DIR)
LOG_DIR  = os.path.abspath(ENV_LOG_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(DB_DIR,  exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

logger = setup_logger(LOG_DIR, "hunter", level=logging.INFO)

DUCK_HTMLS = [
    "https://html.duckduckgo.com/html/",  # zuerst diese (oft stabil)
    "https://duckduckgo.com/html/",
    "https://lite.duckduckgo.com/lite/",
]

DEFAULT_DOMAINS = [
    "psacard.com", "www.psacard.com", "setregistry.psacard.com",
    "pwccmarketplace.com", "www.pwccmarketplace.com",
    "goldin.co", "www.goldin.co",
    "heritageauctions.com", "www.ha.com", "ha.com",
    "robertedwardauctions.com", "www.robertedwardauctions.com",
    "memorylaneinc.com", "www.memorylaneinc.com",
    "ebay.com", "www.ebay.com", "ebay.de", "www.ebay.de",
    "net54baseball.com", "www.net54baseball.com",
    "blowoutforums.com", "www.blowoutforums.com",
    "reddit.com", "www.reddit.com", "old.reddit.com",
    "beckett.com", "www.beckett.com",
    "sportscardinvestor.com", "www.sportscardinvestor.com",
]

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16 Safari/605.1.15",
]

# Lockeres Default-Pattern-Set
DEFAULT_INCLUDE_PATTERN = r"/setregistry|/sets?|/collection|/registry|/auction|/auctions?|/lot/|/item/|/listing|/thread|/topic|/forum|/discussion|/r/.*?/comments/|/card|/details|/catalog|/price|/pop|/population"

# ============================================================
# Utilities
# ============================================================
def make_session(retries: int) -> requests.Session:
    """Robuste Session (certifi + Retries/Backoff)"""
    s = requests.Session()
    s.verify = ENV_REQUESTS_CA
    retry = Retry(
        total=retries, connect=retries, read=retries,
        backoff_factor=0.8,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://",  adapter)
    return s

def load_lines(path: str) -> List[str]:
    if not os.path.isfile(path): return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.rstrip("\n") for ln in f]

def save_lines(path: str, lines: List[str], header: Optional[str] = None, append: bool = True) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    mode = "a" if append and os.path.exists(path) else "w"
    with open(path, mode, encoding="utf-8", newline="\n") as f:
        if mode == "w" and header:
            f.write(header + "\n")
        for ln in lines:
            f.write(ln + "\n")

def normalize_url(u: str, base_for_relative: str = "https://duckduckgo.com") -> str:
    """Entfernt DDG-Redirects (/l/?uddg=...), Tracking-Query, Fragments; normalisiert."""
    u = html.unescape(u.strip())
    if "duckduckgo.com/l/?" in u or u.startswith("/l/?"):
        try:
            qs = parse_qs(u.split("?", 1)[1])
            if "uddg" in qs and qs["uddg"]:
                u = qs["uddg"][0]
        except Exception:
            pass
    if u.startswith("/"):
        u = urljoin(base_for_relative, u)
    p = urlparse(u)
    p = p._replace(fragment="")
    q = parse_qs(p.query)
    for k in ["utm_source","utm_medium","utm_campaign","utm_term","utm_content","utm_id","mkt","fbclid","gclid","mc_cid","mc_eid"]:
        q.pop(k, None)
    new_query = urlencode({k: v[0] for k, v in q.items()})
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, ""))

def in_domains(u: str, allow: Set[str]) -> bool:
    if not allow:  # leer = alles erlauben
        return True
    host = urlparse(u).netloc.lower()
    return any(host == d or host.endswith("." + d) for d in allow)

def regex_or_none(pattern: str):
    return re.compile(pattern, re.IGNORECASE) if pattern else None

def match_allow_deny(u: str, allow_re, deny_re) -> bool:
    path = urlparse(u).path
    if deny_re and deny_re.search(path):
        return False
    if allow_re:
        return bool(allow_re.search(path))
    return True  # kein allow_re = alles ok

def _json_as_dict(resp) -> Dict:
    """Parse response JSON sicher; gib {} zurück, wenn nicht-JSON oder kein dict."""
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}

# ============================================================
# Such-Engines
# ============================================================
def duckduckgo_search(query: str, page: int, session: requests.Session,
                      per_page: int, timeout_tuple: Tuple[float,float]) -> List[str]:
    params = {"q": query, "s": page * per_page}
    headers = {
        "User-Agent": random.choice(UA_LIST),
        "Accept-Language": "de,en;q=0.9",
        "Referer": "https://duckduckgo.com/",
        "Cache-Control": "no-cache",
    }
    last_err = None
    for base in DUCK_HTMLS:
        try:
            r = session.get(base, params=params, headers=headers, timeout=timeout_tuple)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            anchors = soup.select("a.result__a, a.result__url") or soup.find_all("a", href=True)
            out = []
            for a in anchors:
                href = a.get("href")
                if not href:
                    continue
                out.append(normalize_url(href, base_for_relative=base))
            uniq, seen = [], set()
            for u in out:
                if u not in seen:
                    uniq.append(u); seen.add(u)
                if len(uniq) >= per_page:
                    break
            if uniq:
                return uniq
        except requests.RequestException as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    return []

def searx_search(query: str, page: int, session: requests.Session,
                 per_page: int, timeout_tuple: Tuple[float,float], base_url: str) -> List[str]:
    """SearXNG JSON API: /search?q=...&format=json&pageno=N (robust gegen Nicht-Objekt-JSON)"""
    if not base_url:
        return []
    params = {
        "q": query,
        "format": "json",
        "pageno": page + 1,  # searx ist 1-basiert
        "language": "de-DE",
        "safesearch": 1
    }
    headers = {
        "User-Agent": random.choice(UA_LIST),
        "Accept": "application/json",
        "Cache-Control": "no-cache",
    }
    try:
        r = session.get(base_url.rstrip("/") + "/search", params=params, headers=headers, timeout=timeout_tuple)
        r.raise_for_status()
    except requests.RequestException as e:
        logger.warning(f"SearXNG Request-Fehler: {e}")
        return []

    data = _json_as_dict(r)
    if not data:
        body_preview = (r.text or "")[:200].replace("\n", " ")
        logger.warning(f"SearXNG lieferte kein JSON-Objekt (status={r.status_code}). Preview: {body_preview}")
        return []

    results = data.get("results")
    if results is None:
        results = data.get("result") or data.get("items") or []

    if not isinstance(results, list):
        logger.warning("SearXNG 'results' ist kein Listentyp – überspringe.")
        return []

    out = []
    for item in results:
        url = None
        if isinstance(item, dict):
            url = item.get("url") or item.get("link")
        if url:
            out.append(normalize_url(url))

    uniq, seen = [], set()
    for u in out:
        if u not in seen:
            uniq.append(u); seen.add(u)
        if len(uniq) >= per_page:
            break
    return uniq

def dispatch_search(engine: str, searx_url: str, query: str, page: int, session: requests.Session,
                    per_page: int, timeout_tuple: Tuple[float,float]) -> List[str]:
    engine = (engine or "auto").lower()
    if engine == "ddg":
        logger.info(f"[🔎] Engine=DDG → '{query}' (page {page})")
        return duckduckgo_search(query, page, session, per_page, timeout_tuple)
    if engine == "searx":
        logger.info(f"[🔎] Engine=SearXNG ({searx_url}) → '{query}' (page {page})")
        return searx_search(query, page, session, per_page, timeout_tuple, searx_url)
    # auto: erst DDG, bei Fehler SearXNG
    try:
        logger.info(f"[🔎] Engine=Auto (Try DDG) → '{query}' (page {page})")
        return duckduckgo_search(query, page, session, per_page, timeout_tuple)
    except requests.RequestException as e:
        logger.warning(f"[⚠️] DDG fail: {e} → fallback zu SearXNG ({searx_url})")
        try:
            return searx_search(query, page, session, per_page, timeout_tuple, searx_url)
        except Exception as e2:
            logger.warning(f"[⚠️] SearXNG Fallback-Fehler: {e2}")
            return []

# ============================================================
# Suche → URLs
# ============================================================
def search_queries_to_urls(
    queries_path: str,
    out_urls: str,
    per_query: int,
    max_pages: int,
    sleep_s: float,
    domains: List[str],
    include_any: bool,
    allow_re,
    deny_re,
    retries: int,
    connect_timeout: float,
    read_timeout: float,
    engine: str,
    searx_url: str
) -> int:
    queries = [q for q in load_lines(queries_path) if q and not q.strip().startswith("#")]
    if not queries:
        logger.warning("⚠️ Keine Queries gefunden.")
        return 0

    allowed = set(d.strip().lower() for d in domains if d.strip())
    session = make_session(retries)
    timeout_tuple = (connect_timeout, read_timeout)

    existing = set()
    for ln in load_lines(out_urls):
        s = ln.strip()
        if s and not s.startswith("#"):
            if "#" in s: s = s.split("#", 1)[0].strip()
            existing.add(s)

    collected = []
    seen = set(existing)
    for qi, q in enumerate(queries, 1):
        logger.info(f"[{qi}/{len(queries)}] Suche: {q}")
        got = 0
        page = 0
        while page < max_pages and got < per_query:
            try:
                results = dispatch_search(engine, searx_url, q, page, session, per_page=30, timeout_tuple=timeout_tuple)
            except Exception as e:
                logger.warning(f"  !! Fehler Search: {e} – skip page")
                break

            if not results:
                logger.warning("  (keine Resultate auf dieser Seite)")
                break

            raw = list(results)
            dom_fail = 0; pat_fail = 0; kept = 0
            for u in raw:
                if not in_domains(u, allowed):
                    dom_fail += 1
                    continue
                if not include_any and not match_allow_deny(u, allow_re, deny_re):
                    pat_fail += 1
                    continue
                if u not in seen:
                    collected.append(u); seen.add(u); got += 1; kept += 1
                    COLLECT_BUFFER_URLS.append(u)
                    logger.info(f"   + {u}")
                    if got >= per_query:
                        break
            logger.info(f"   stats: raw={len(raw)} kept={kept} dom_fail={dom_fail} pat_fail={pat_fail}")

            page += 1
            time.sleep(sleep_s + random.random()*0.3)

    if collected:
        save_lines(out_urls, collected, header="# collected URLs (hunter_full)", append=True)
    logger.info(f"➡️  {len(collected)} neue URLs → {out_urls}")
    return len(collected)

# ============================================================
# URLs → Certs Scan
# ============================================================
def extract_certs_from_text(text: str) -> Set[str]:
    return set(re.findall(r"\b\d{7,9}\b", text))

def urls_to_certs(
    urls_path: str,
    out_certs: str,
    limit_per_url: int,
    sleep_each: float,
    retries: int,
    connect_timeout: float,
    read_timeout: float
) -> int:
    session = make_session(retries)
    timeout_tuple = (connect_timeout, read_timeout)

    urls = [u for u in load_lines(urls_path) if u and not u.startswith("#")]
    existing = {}
    for ln in load_lines(out_certs):
        s = ln.strip()
        if s and not s.startswith("#"):
            num = s.split("#", 1)[0].strip()
            num = re.sub(r"\D+", "", num)
            if num:
                existing[num] = True

    new_certs = {}
    for i, u in enumerate(urls, 1):
        logger.info(f"[{i}/{len(urls)}] scan: {u}")
        try:
            r = session.get(u, headers={"User-Agent": random.choice(UA_LIST)}, timeout=timeout_tuple)
            r.raise_for_status()
            nums = extract_certs_from_text(r.text)
            if limit_per_url > 0:
                nums = set(list(nums)[:limit_per_url])
            added_here = 0
            for n in nums:
                if n not in existing and n not in new_certs:
                    new_certs[n] = ""  # desc unbekannt
                    existing[n] = True
                    COLLECT_BUFFER_CERTS.append(n)
                    added_here += 1
            if added_here:
                logger.info(f"   + {added_here} neue Certs")
        except requests.RequestException as e:
            logger.warning(f"   !! {e}")
        time.sleep(sleep_each + random.random()*0.2)

    if new_certs:
        lines = [f"{c}" + (f"   # {d}" if d else "") for c, d in sorted(new_certs.items(), key=lambda x: x[0])]
        save_lines(out_certs, lines, header="# certs (hunter_full)", append=True)
    logger.info(f"➡️  {len(new_certs)} neue Certs → {out_certs}")
    return len(new_certs)

# ============================================================
# SQLite Vollschema & Mapping
# ============================================================
def ensure_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
CREATE TABLE IF NOT EXISTS psa_certs (
    cert_number                     TEXT PRIMARY KEY,
    spec_id                         INTEGER,
    spec_number                     TEXT,
    label_type                      TEXT,
    reverse_barcode                 INTEGER,
    year                            INTEGER,
    brand                           TEXT,
    category                        TEXT,
    card_number                     TEXT,
    subject                         TEXT,
    variety                         TEXT,
    is_psadna                       INTEGER,
    is_dual_cert                    INTEGER,
    grade_description               TEXT,
    card_grade                      TEXT,
    total_population                INTEGER,
    total_population_with_qualifier INTEGER,
    population_higher               INTEGER,
    description                     TEXT,
    http_status                     INTEGER,
    server_message                  TEXT,
    payload_json                    TEXT,
    updated_at                      TEXT
);
""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_updated_at ON psa_certs(updated_at);")
    return conn

def db_has_cert(conn: sqlite3.Connection, cert: str) -> bool:
    cur = conn.execute("SELECT 1 FROM psa_certs WHERE cert_number=? LIMIT 1", (cert,))
    return cur.fetchone() is not None

def validate_psa_json(j: Dict) -> Tuple[bool, Dict]:
    if not isinstance(j, dict):
        return (False, {})
    c = j.get("PSACert") or {}
    if not c or not c.get("CertNumber"):
        return (False, {})
    # Year 4-stellig?
    year = c.get("Year")
    year_int = None
    if isinstance(year, (str, int)):
        m = re.search(r"\d{4}", str(year))
        if m: year_int = int(m.group(0))
    if not year_int:
        return (False, {})
    # Mindestens Brand oder Subject
    if not (c.get("Brand") or c.get("Subject")):
        return (False, {})
    mapped = {
        "cert_number": c.get("CertNumber"),
        "spec_id": c.get("SpecID"),
        "spec_number": c.get("SpecNumber"),
        "label_type": c.get("LabelType"),
        "reverse_barcode": int(bool(c.get("ReverseBarCode"))) if "ReverseBarCode" in c else None,
        "year": year_int,
        "brand": c.get("Brand"),
        "category": c.get("Category"),
        "card_number": c.get("CardNumber"),
        "subject": c.get("Subject"),
        "variety": c.get("Variety"),
        "is_psadna": int(bool(c.get("IsPSADNA"))) if "IsPSADNA" in c else None,
        "is_dual_cert": int(bool(c.get("IsDualCert"))) if "IsDualCert" in c else None,
        "grade_description": c.get("GradeDescription"),
        "card_grade": c.get("CardGrade"),
        "total_population": c.get("TotalPopulation"),
        "total_population_with_qualifier": c.get("TotalPopulationWithQualifier"),
        "population_higher": c.get("PopulationHigher"),
    }
    return (True, mapped)

def upsert_cert(conn: sqlite3.Connection, mapped: Dict, desc: str, http_status: int, server_message: Optional[str], payload_json: str, updated_at: str):
    mapped_full = dict(mapped)
    mapped_full.update({
        "description": desc,
        "http_status": http_status,
        "server_message": server_message,
        "payload_json": payload_json,
        "updated_at": updated_at
    })
    cols = ",".join(mapped_full.keys())
    qs   = ",".join(["?"]*len(mapped_full))
    set_clause = ",".join([f"{k}=excluded.{k}" for k in mapped_full.keys() if k != "cert_number"])
    sql = f"""
INSERT INTO psa_certs ({cols}) VALUES ({qs})
ON CONFLICT(cert_number) DO UPDATE SET
  {set_clause}
"""
    conn.execute(sql, tuple(mapped_full.values()))

# ============================================================
# Validation via PSA API
# ============================================================
def validate_and_store(
    certs_path: str,
    daily_cap: int,
    base_url: str,
    token: str,
    verify,
    db_path: str,
    sleep_ms: int,
    retries: int,
    connect_timeout: float,
    read_timeout: float
) -> Tuple[int,int,int]:
    conn = ensure_db(db_path)
    session = make_session(retries)
    session.verify = verify
    timeout_tuple = (connect_timeout, read_timeout)

    headers = {"Authorization": f"bearer {token}", "Content-Type": "application/json"}
    saved = 0; ignored = 0; calls = 0
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")

    lines = [ln for ln in load_lines(certs_path) if ln and not ln.startswith("#")]
    for ln in lines:
        if daily_cap and calls >= daily_cap:
            logger.info(f"⛔ Daily-Cap erreicht ({daily_cap}).")
            break
        s = ln.strip()
        num_part = s.split("#", 1)[0].strip()
        desc = s.split("#", 1)[1].strip() if "#" in s and s.split("#", 1)[1].strip() else ""
        cert = re.sub(r"\D+", "", num_part)
        if not cert:
            continue
        if db_has_cert(conn, cert):
            logger.info(f"skip (DB): {cert}")
            continue
        url = f"{base_url.rstrip('/')}/cert/GetByCertNumber/{cert}"
        try:
            r = session.get(url, headers=headers, timeout=timeout_tuple)
            calls += 1
            code = r.status_code

            j = _json_as_dict(r)
            if not j:
                body_preview = (r.text or "")[:200].replace("\n", " ")
                logger.warning(f"PSA API gab kein JSON-Objekt zurück (cert={cert}, status={code}). Preview: {body_preview}")

            ok, mapped = validate_psa_json(j)
            logger.debug(f"[API] {url} → {code} body_len={len(r.text)}")
            if ok:
                upsert_cert(conn, mapped, desc, code, j.get("ServerMessage") if isinstance(j, dict) else None, json.dumps(j or {}, ensure_ascii=False), now_iso)
                conn.commit()
                saved += 1
                logger.info(f"OK  {cert}")
            else:
                ignored += 1
                logger.info(f"IGN {cert} (keine gültigen Daten)")
        except requests.RequestException as e:
            logger.error(f"ERR {cert}: {e}")
        time.sleep(max(0, sleep_ms) / 1000.0)

    conn.close()
    logger.info(f"➡️ gespeichert={saved}, ignoriert={ignored}, api_calls={calls}")
    return saved, ignored, calls

# ============================================================
# CLI
# ============================================================
def main():
    ap = argparse.ArgumentParser(description="Dein PSA Hunter (Search → URLs → Certs → Validate → DB)")

    # Pfade
    ap.add_argument("--queries", default=os.path.join(DATA_DIR, "queries.txt"))
    ap.add_argument("--urls",    default=os.path.join(DATA_DIR, "urls.txt"))
    ap.add_argument("--certs",   default=os.path.join(DATA_DIR, "certs.txt"))
    ap.add_argument("--db",      default=os.path.join(DB_DIR,  "psa.db"))

    # Suche: Domains/Regex
    ap.add_argument("--domains", default=",".join(DEFAULT_DOMAINS), help="Kommagetrennte Domain-Whitelist; leer ('') = keine Restriktion")
    ap.add_argument("--allow",   default=DEFAULT_INCLUDE_PATTERN,  help="Regex-Whitelist für Pfade (wenn leer, alles erlaubt)")
    ap.add_argument("--deny",    default="",                        help="Regex-Blacklist für Pfade")
    ap.add_argument("--include-any", action="store_true", help="Ignoriert allow/deny, nur Domain-Filter (oder gar keinen, wenn --domains '')")

    # Suche: Mengen & Pace
    ap.add_argument("--per-query", type=int, default=20)
    ap.add_argument("--max-pages", type=int, default=2)
    ap.add_argument("--sleep",     type=float, default=1.0, help="Sekunden Pause zwischen Queries")

    # Scan
    ap.add_argument("--scan-limit-per-url", type=int, default=0, help="max Certs je URL (0 = unbegrenzt)")
    ap.add_argument("--scan-sleep",         type=float, default=0.5, help="Sekunden Pause zwischen Seitenabrufen (Scan)")

    # Validation
    ap.add_argument("--validate", action="store_true", help="fehlende Certs via PSA API prüfen & speichern")
    ap.add_argument("--daily-cap", type=int, default=ENV_DAILY_CAP)
    ap.add_argument("--sleep-ms",  type=int, default=250, help="Pause zwischen API-Calls (ms)")

    # Timeouts/Retries
    ap.add_argument("--connect-timeout", type=float, default=ENV_CONNECT_TIMEOUT)
    ap.add_argument("--read-timeout",    type=float, default=ENV_READ_TIMEOUT)
    ap.add_argument("--retries",         type=int,   default=ENV_RETRIES)

    # Engine + SearXNG
    ap.add_argument("--engine",    choices=["ddg","searx","auto"], default=ENV_SEARCH_ENGINE,
                    help="Suchmaschine: ddg, searx oder auto (ddg→searx Fallback)")
    ap.add_argument("--searx-url", default=ENV_SEARXNG_URL, help="SearXNG Base URL (z.B. https://searxng.yourhost)")

    args = ap.parse_args()

    # Domains & Regex vorbereiten
    domains = [d for d in (args.domains or "").split(",")] if args.domains is not None else []
    if len(domains) == 1 and domains[0].strip() == "":
        domains = []  # keine Restriktion

    allow_re = None
    deny_re  = None
    if not args.include_any:
        allow_re = regex_or_none(args.allow)
        deny_re  = regex_or_none(args.deny)

    # Puffer-Flush Helper
    def flush_buffers():
        if COLLECT_BUFFER_URLS:
            try:
                save_lines(args.urls, COLLECT_BUFFER_URLS, header="# collected URLs (hunter_full)", append=True)
                logger.info(f"📝 URLs gepuffert gespeichert: {len(COLLECT_BUFFER_URLS)} → {args.urls}")
            except Exception as e:
                logger.error(f"‼️ Konnte URL-Puffer nicht speichern: {e}")
            COLLECT_BUFFER_URLS.clear()
        if COLLECT_BUFFER_CERTS:
            try:
                lines = [f"{c}" for c in sorted(set(COLLECT_BUFFER_CERTS))]
                save_lines(args.certs, lines, header="# certs (hunter_full)", append=True)
                logger.info(f"📝 Certs gepuffert gespeichert: {len(lines)} → {args.certs}")
            except Exception as e:
                logger.error(f"‼️ Konnte Cert-Puffer nicht speichern: {e}")
            COLLECT_BUFFER_CERTS.clear()

    try:
        # Schritt 1: Suche → URLs
        added_urls = search_queries_to_urls(
            queries_path=args.queries,
            out_urls=args.urls,
            per_query=args.per_query,
            max_pages=args.max_pages,
            sleep_s=args.sleep,
            domains=domains,
            include_any=args.include_any,
            allow_re=allow_re,
            deny_re=deny_re,
            retries=args.retries,
            connect_timeout=args.connect_timeout,
            read_timeout=args.read_timeout,
            engine=args.engine,
            searx_url=args.searx_url
        )

        # Schritt 2: URLs → Certs
        added_certs = urls_to_certs(
            urls_path=args.urls,
            out_certs=args.certs,
            limit_per_url=args.scan_limit_per_url,
            sleep_each=args.scan_sleep,
            retries=args.retries,
            connect_timeout=args.connect_timeout,
            read_timeout=args.read_timeout,
        )

        # Schritt 3: Validation (optional)
        if args.validate:
            token = ENV_PSA_TOKEN
            if not token:
                logger.error("❌ PSA_TOKEN fehlt (.env/ENV). Abbruch Validate.")
                sys.exit(1)
            base_url = ENV_PSA_BASE_URL
            verify   = ENV_REQUESTS_CA

            validate_and_store(
                certs_path=args.certs,
                daily_cap=args.daily_cap,
                base_url=base_url,
                token=token,
                verify=verify,
                db_path=args.db,
                sleep_ms=args.sleep_ms,
                retries=args.retries,
                connect_timeout=args.connect_timeout,
                read_timeout=args.read_timeout,
            )

    except KeyboardInterrupt:
        logger.warning("⛔ Abgebrochen (Ctrl+C) – speichere Zwischenergebnisse ...")
        flush_buffers()
        sys.exit(130)
    except Exception as e:
        logger.exception(f"❌ Unerwarteter Fehler: {e}")
        flush_buffers()
        sys.exit(1)
    else:
        flush_buffers()

if __name__ == "__main__":
    main()
