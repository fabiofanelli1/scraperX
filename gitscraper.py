"""
X.com Vulnerability Monitor
============================================================
Monitora automaticamente X.com per tweet su vulnerabilità di sicurezza
di prodotti a scelta. Esegue query predefinite ogni
X minuti e mostra solo i tweet nuovi nel terminale.

Requisiti:
    pip install selenium rich cryptography

Setup:
    1. Installa l'estensione 'Get cookies.txt LOCALLY' nel tuo browser
    2. Vai su x.com e accedi normalmente
    3. Esporta i cookie e salva il file come 'cookies.txt' nella cartella dello script
    4. Cripta il file:  python x_search.py --encrypt cookies.txt
       → genera 'cookies.enc' protetto da password e cancella 'cookies.txt'
    5. Da ora in poi lo script usa 'cookies.enc' e chiede la password all'avvio

Sicurezza:
    - Cookie crittografati con AES-256-GCM (via Fernet/PBKDF2)
    - Controllo permessi file (chmod 600) su cookies.enc
    - Pulizia cookie dal browser e garbage collection all'uscita
    - Nessun dato sensibile nei log

Uso:
    python x_search.py --encrypt cookies.txt              # cripta i cookie
    python x_search.py                                    # monitor automatico
    python x_search.py --vendor fortinet cisco            # solo Fortinet e Cisco
    python x_search.py --headless                         # senza interfaccia grafica
    python x_search.py --mode single "FortiGate CVE"      # ricerca singola
"""

import argparse
import gc
import getpass
import os
import signal
import stat
import sys
import time
import random
import json
import re
from datetime import datetime

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import (
        TimeoutException, NoSuchElementException, WebDriverException
    )
except ImportError:
    print("❌ Selenium non installato. Esegui:")
    print("   pip install selenium")
    sys.exit(1)

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    console = Console()
    USE_RICH = True
except ImportError:
    USE_RICH = False


# ─── Configurazione ──────────────────────────────────────────────────────────

SCROLL_PAUSE = 2.5     # secondi tra uno scroll e l'altro
MAX_SCROLLS = 15        # numero massimo di scroll per raccogliere tweet
REQUEST_TIMEOUT = 15    # secondi di attesa per il caricamento pagina


# ─── Utilità di output ────────────────────────────────────────────────────────

def print_header(text: str):
    if USE_RICH:
        console.print(f"\n[bold cyan]{'═' * 60}[/]")
        console.print(f"[bold white]  {text}[/]")
        console.print(f"[bold cyan]{'═' * 60}[/]\n")
    else:
        print(f"\n{'═' * 60}")
        print(f"  {text}")
        print(f"{'═' * 60}\n")


def print_tweet(index: int, tweet: dict):
    """Stampa un singolo tweet nel terminale."""
    if USE_RICH:
        header = Text()
        header.append(f"@{tweet['username']}", style="bold green")
        header.append(f"  •  {tweet['date']}", style="dim")

        body = Text(tweet["text"])

        stats = Text()
        stats.append(f"💬 {tweet['replies']}  ", style="dim")
        stats.append(f"🔁 {tweet['retweets']}  ", style="dim")
        stats.append(f"❤️  {tweet['likes']}  ", style="dim")
        stats.append(f"👁 {tweet['views']}", style="dim")

        link = Text(tweet["url"], style="underline blue")

        content = Text.assemble(header, "\n\n", body, "\n\n", stats, "\n", link)
        console.print(Panel(content, title=f"[bold]#{index}[/]", box=box.ROUNDED))
    else:
        print(f"--- Tweet #{index} ---")
        print(f"👤 @{tweet['username']}  •  {tweet['date']}")
        print(f"\n{tweet['text']}\n")
        print(f"💬 {tweet['replies']}  🔁 {tweet['retweets']}  ❤️  {tweet['likes']}  👁 {tweet['views']}")
        print(f"🔗 {tweet['url']}")
        print()


def print_info(msg: str):
    if USE_RICH:
        console.print(f"[yellow]ℹ️  {msg}[/]")
    else:
        print(f"ℹ️  {msg}")


def print_success(msg: str):
    if USE_RICH:
        console.print(f"[green]✅ {msg}[/]")
    else:
        print(f"✅ {msg}")


def print_error(msg: str):
    if USE_RICH:
        console.print(f"[red]❌ {msg}[/]")
    else:
        print(f"❌ {msg}")


def print_warning(msg: str):
    if USE_RICH:
        console.print(f"[orange1]⚠️  {msg}[/]")
    else:
        print(f"⚠️  {msg}")


# ─── Browser Setup ────────────────────────────────────────────────────────────

def create_driver(headless: bool = False) -> webdriver.Chrome:
    """Crea e configura il browser Chrome/Chromium."""
    options = Options()

    if headless:
        options.add_argument("--headless=new")

    # Rileva automaticamente il binario di Chromium su Fedora/Linux
    import shutil
    chromium_paths = [
        shutil.which("chromium-browser"),
        shutil.which("chromium"),
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        "/usr/sbin/chromium-browser",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
    ]
    for path in chromium_paths:
        if path and os.path.isfile(path):
            options.binary_location = path
            print_info(f"Browser trovato: {path}")
            break

    # Impostazioni anti-detection di base
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--window-size=1920,1080")
    options.add_argument(
        "--user-agent=Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
    )
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    # Selenium 4.10+ gestisce automaticamente il download del chromedriver corretto
    # Non serve più webdriver-manager
    driver = webdriver.Chrome(options=options)

    # Rimuove flag webdriver
    driver.execute_cdp_cmd(
        "Page.addScriptToEvaluateOnNewDocument",
        {"source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"},
    )

    return driver


# ─── Sicurezza: Crittografia Cookie ──────────────────────────────────────────

SALT_SIZE = 16  # bytes per il salt PBKDF2
ENCRYPTED_EXT = ".enc"


def _derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una chiave AES-256 dalla password con PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,  # OWASP 2023 recommendation
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_cookie_file(plain_path: str, enc_path: str | None = None) -> str:
    """
    Cripta un file cookies.txt con password.
    Ritorna il percorso del file crittografato.
    """
    if not HAS_CRYPTO:
        print_error("Libreria 'cryptography' non installata.")
        print_info("Esegui: pip install cryptography")
        sys.exit(1)

    if not os.path.isfile(plain_path):
        print_error(f"File non trovato: {plain_path}")
        sys.exit(1)

    if enc_path is None:
        enc_path = os.path.splitext(plain_path)[0] + ENCRYPTED_EXT

    # Chiedi password (doppia conferma)
    print_info("Scegli una password per proteggere i cookie.")
    password = getpass.getpass("🔐 Password: ")
    confirm = getpass.getpass("🔐 Conferma password: ")
    if password != confirm:
        print_error("Le password non coincidono.")
        sys.exit(1)
    if len(password) < 8:
        print_error("La password deve essere di almeno 8 caratteri.")
        sys.exit(1)

    # Leggi, cripta, scrivi
    with open(plain_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    key = _derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(plaintext)

    with open(enc_path, "wb") as f:
        f.write(salt + encrypted)

    # Imposta permessi restrittivi (solo owner)
    _enforce_permissions(enc_path)

    # Cancella il file in chiaro in modo sicuro (sovrascrittura)
    _secure_delete(plain_path)

    print_success(f"Cookie crittografati salvati in: {enc_path}")
    print_success(f"File originale '{plain_path}' eliminato in modo sicuro.")
    print_info("Da ora usa lo script normalmente: ti chiederà la password all'avvio.")

    # Pulizia variabili sensibili dalla memoria
    del password, confirm, plaintext, key
    gc.collect()

    return enc_path


def decrypt_cookie_file(enc_path: str) -> str:
    """
    Decripta il file cookie in memoria e ritorna il contenuto come stringa.
    Non scrive MAI il contenuto decriptato su disco.
    """
    if not HAS_CRYPTO:
        print_error("Libreria 'cryptography' non installata.")
        print_info("Esegui: pip install cryptography")
        sys.exit(1)

    if not os.path.isfile(enc_path):
        print_error(f"File crittografato non trovato: {enc_path}")
        sys.exit(1)

    password = getpass.getpass("🔐 Password cookie: ")

    with open(enc_path, "rb") as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    encrypted = data[SALT_SIZE:]

    try:
        key = _derive_key(password, salt)
        fernet = Fernet(key)
        plaintext = fernet.decrypt(encrypted).decode("utf-8")
    except Exception:
        print_error("Password errata o file corrotto.")
        del password
        gc.collect()
        sys.exit(1)

    # Pulizia
    del password, key
    gc.collect()

    return plaintext


# ─── Sicurezza: Permessi File ────────────────────────────────────────────────

def _enforce_permissions(filepath: str):
    """Imposta i permessi del file a 600 (solo owner read/write)."""
    try:
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # chmod 600
        print_info(f"Permessi impostati a 600 su: {filepath}")
    except OSError as e:
        print_warning(f"Impossibile impostare permessi su {filepath}: {e}")


def _check_permissions(filepath: str) -> bool:
    """Verifica che il file abbia permessi sicuri (non leggibile da altri)."""
    try:
        file_stat = os.stat(filepath)
        mode = file_stat.st_mode
        # Controlla che group e others non abbiano permessi
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            print_warning(f"⚠️  ATTENZIONE: '{filepath}' è leggibile da altri utenti!")
            print_warning(f"   Permessi attuali: {oct(mode)[-3:]}")
            print_info(f"   Correggo automaticamente...")
            _enforce_permissions(filepath)
            return False
        return True
    except OSError:
        return True  # non bloccare se non riesce a leggere i permessi


# ─── Sicurezza: Cancellazione Sicura ─────────────────────────────────────────

def _secure_delete(filepath: str):
    """Sovrascrive il file con dati casuali prima di eliminarlo."""
    try:
        size = os.path.getsize(filepath)
        with open(filepath, "wb") as f:
            # 3 passate di sovrascrittura
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(filepath)
    except OSError as e:
        print_warning(f"Impossibile cancellare in modo sicuro {filepath}: {e}")
        # Fallback: eliminazione normale
        try:
            os.remove(filepath)
        except OSError:
            pass


# ─── Sicurezza: Pulizia all'uscita ───────────────────────────────────────────

def secure_cleanup(driver: webdriver.Chrome | None):
    """Pulisce cookie, sessione browser e forza garbage collection."""
    print_info("🧹 Pulizia sicura in corso...")

    if driver:
        try:
            # Cancella tutti i cookie dal browser
            driver.delete_all_cookies()
            print_info("   Cookie rimossi dal browser.")
        except Exception:
            pass

        try:
            # Cancella storage del browser
            driver.execute_script("window.localStorage.clear();")
            driver.execute_script("window.sessionStorage.clear();")
            print_info("   Storage browser svuotato.")
        except Exception:
            pass

        try:
            driver.quit()
            print_info("   Browser chiuso.")
        except Exception:
            pass

    # Forza garbage collection per rimuovere dati sensibili dalla memoria
    gc.collect()
    print_success("🧹 Pulizia completata.")


# ─── Login tramite Cookie ──────────────────────────────────────────────────────

def _parse_cookies_text(cookie_text: str) -> list[dict]:
    """Parsa il contenuto di un cookies.txt (formato Netscape) in lista di dict."""
    cookies = []
    for line in cookie_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        parts = line.split("\t")
        if len(parts) < 7:
            continue

        domain, _, path, secure, expires, name, value = parts[:7]

        # Solo cookie di x.com / twitter.com
        if not any(d in domain for d in [".x.com", "x.com", ".twitter.com", "twitter.com"]):
            continue

        cookie = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": path,
            "secure": secure.lower() == "true",
        }

        try:
            exp = int(expires)
            if exp > 0:
                cookie["expiry"] = exp
        except ValueError:
            pass

        cookies.append(cookie)

    return cookies


def load_cookies(driver: webdriver.Chrome, cookie_source: str) -> bool:
    """
    Carica i cookie nel browser. Supporta:
    - File .enc (crittografato) → chiede password, decripta in memoria
    - File .txt (plaintext) → carica direttamente + avvisa di crittografare
    """
    # Determina il tipo di sorgente
    if cookie_source.endswith(ENCRYPTED_EXT):
        # File crittografato → decripta in memoria
        _check_permissions(cookie_source)
        print_info("File cookie crittografato rilevato.")
        cookie_text = decrypt_cookie_file(cookie_source)
    elif os.path.isfile(cookie_source):
        # File plaintext → avvisa
        print_warning("⚠️  Stai usando un file cookie NON crittografato!")
        print_warning("   Chiunque abbia accesso al file può impersonare il tuo account.")
        print_info("   Cripta i cookie con:  python x_search.py --encrypt " + cookie_source)
        print()
        with open(cookie_source, "r") as f:
            cookie_text = f.read()
    else:
        print_error(f"File cookie non trovato: {cookie_source}")
        return False

    # Parsa i cookie
    cookies = _parse_cookies_text(cookie_text)

    # Pulizia immediata del testo in chiaro dalla memoria
    del cookie_text
    gc.collect()

    if not cookies:
        print_error("Nessun cookie valido di X.com trovato.")
        return False

    # Naviga su x.com per impostare i cookie sul dominio corretto
    print_info("Caricamento pagina iniziale di X.com...")
    driver.get("https://x.com")
    time.sleep(3)

    # Inietta i cookie
    cookie_count = 0
    for cookie in cookies:
        try:
            driver.add_cookie(cookie)
            cookie_count += 1
        except Exception:
            pass

    # Pulizia lista cookie dalla memoria
    del cookies
    gc.collect()

    if cookie_count == 0:
        print_error("Nessun cookie caricato nel browser.")
        return False

    print_success(f"{cookie_count} cookie caricati.")

    # Ricarica la pagina con i cookie attivi
    print_info("Verifica sessione...")
    driver.get("https://x.com/home")
    time.sleep(4)

    # Controlla se siamo loggati
    if "/home" in driver.current_url:
        print_success("Login tramite cookie riuscito!")
        return True
    elif "login" in driver.current_url.lower():
        print_error("Cookie scaduti o non validi. Riesporta i cookie dal browser.")
        return False
    else:
        print_warning("Stato login incerto, continuo comunque...")
        return True


# ─── Scraping ──────────────────────────────────────────────────────────────────

def extract_tweets(driver: webdriver.Chrome) -> list[dict]:
    """Estrae i tweet visibili nella pagina corrente."""
    tweets = []
    seen_texts = set()

    try:
        articles = driver.find_elements(By.CSS_SELECTOR, 'article[data-testid="tweet"]')
    except Exception:
        return tweets

    for article in articles:
        try:
            tweet = {}

            # Username
            try:
                user_el = article.find_element(By.CSS_SELECTOR, 'div[data-testid="User-Name"]')
                links = user_el.find_elements(By.TAG_NAME, "a")
                tweet["username"] = "sconosciuto"
                for link in links:
                    href = link.get_attribute("href") or ""
                    if href.startswith("https://x.com/") and "/status/" not in href:
                        tweet["username"] = href.split("https://x.com/")[-1].strip("/")
                        break
            except NoSuchElementException:
                tweet["username"] = "sconosciuto"

            # Testo del tweet
            try:
                text_el = article.find_element(By.CSS_SELECTOR, 'div[data-testid="tweetText"]')
                tweet["text"] = text_el.text.strip()
            except NoSuchElementException:
                tweet["text"] = "[media/senza testo]"

            # Evita duplicati
            fingerprint = f"{tweet['username']}:{tweet['text'][:80]}"
            if fingerprint in seen_texts:
                continue
            seen_texts.add(fingerprint)

            # Data
            try:
                time_el = article.find_element(By.TAG_NAME, "time")
                tweet["date"] = time_el.get_attribute("datetime")[:16].replace("T", " ")
            except NoSuchElementException:
                tweet["date"] = "N/D"

            # URL del tweet
            try:
                all_links = article.find_elements(By.CSS_SELECTOR, 'a[href*="/status/"]')
                tweet["url"] = "N/D"
                for link in all_links:
                    href = link.get_attribute("href") or ""
                    if "/status/" in href and "/analytics" not in href:
                        tweet["url"] = href
                        break
            except NoSuchElementException:
                tweet["url"] = "N/D"

            # Metriche (risposte, retweet, like, visualizzazioni)
            tweet["replies"] = "0"
            tweet["retweets"] = "0"
            tweet["likes"] = "0"
            tweet["views"] = "0"

            try:
                reply_btn = article.find_element(By.CSS_SELECTOR, 'button[data-testid="reply"]')
                tweet["replies"] = reply_btn.text.strip() or "0"
            except NoSuchElementException:
                pass
            try:
                rt_btn = article.find_element(By.CSS_SELECTOR, 'button[data-testid="retweet"]')
                tweet["retweets"] = rt_btn.text.strip() or "0"
            except NoSuchElementException:
                pass
            try:
                like_btn = article.find_element(By.CSS_SELECTOR, 'button[data-testid="like"]')
                tweet["likes"] = like_btn.text.strip() or "0"
            except NoSuchElementException:
                pass
            try:
                # Le views sono nell'ultimo link dentro il gruppo analytics
                analytics_el = article.find_element(By.CSS_SELECTOR, 'a[href*="/analytics"]')
                tweet["views"] = analytics_el.text.strip() or "0"
            except NoSuchElementException:
                pass

            tweets.append(tweet)

        except Exception:
            continue

    return tweets


def search_x(
    driver: webdriver.Chrome,
    query: str,
    max_results: int = 20,
    lang: str | None = None,
    max_days_ago: int = 2,
) -> list[dict]:
    """Cerca tweet su X.com per parola chiave (limitati agli ultimi N giorni)."""
    from datetime import timedelta

    # Costruisci la query di ricerca con filtro temporale
    since_date = (datetime.now() - timedelta(days=max_days_ago)).strftime("%Y-%m-%d")
    search_query = f"{query} since:{since_date}"

    if lang:
        search_query += f" lang:{lang}"

    from urllib.parse import quote
    encoded = quote(search_query)
    search_url = f"https://x.com/search?q={encoded}&src=typed_query&f=live"

    print_info(f"Ricerca: \"{search_query}\"")
    driver.get(search_url)
    time.sleep(4)

    all_tweets: list[dict] = []
    seen_fingerprints: set[str] = set()
    scrolls = 0
    no_new_count = 0

    while len(all_tweets) < max_results and scrolls < MAX_SCROLLS:
        new_tweets = extract_tweets(driver)
        added = 0

        for tw in new_tweets:
            fp = f"{tw['username']}:{tw['text'][:80]}"
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                all_tweets.append(tw)
                added += 1
                if len(all_tweets) >= max_results:
                    break

        if added == 0:
            no_new_count += 1
            if no_new_count >= 3:
                print_info("Nessun nuovo tweet trovato, fermo lo scroll.")
                break
        else:
            no_new_count = 0

        # Scroll verso il basso
        driver.execute_script("window.scrollBy(0, 800);")
        time.sleep(SCROLL_PAUSE + random.uniform(0.5, 1.5))
        scrolls += 1

        print_info(f"  Scroll {scrolls}/{MAX_SCROLLS} — {len(all_tweets)} tweet raccolti")

    return all_tweets[:max_results]


# ─── Query Predefinite — Vulnerabilità ────────────────────────────────────────

VULN_QUERIES = [
    
]

MONITOR_INTERVAL = 300  # secondi (5 minuti)
RESULTS_PER_QUERY = 10  # tweet per ogni query


# ─── Deduplicazione globale ──────────────────────────────────────────────────

class TweetTracker:
    """Tiene traccia dei tweet già visti per evitare duplicati tra i cicli."""

    def __init__(self, max_history: int = 5000):
        self.seen: set[str] = set()
        self.max_history = max_history

    def fingerprint(self, tweet: dict) -> str:
        return f"{tweet['username']}:{tweet['text'][:100]}"

    def is_new(self, tweet: dict) -> bool:
        fp = self.fingerprint(tweet)
        if fp in self.seen:
            return False
        self.seen.add(fp)
        # Evita che il set cresca all'infinito
        if len(self.seen) > self.max_history:
            to_remove = list(self.seen)[:1000]
            for item in to_remove:
                self.seen.discard(item)
        return True

    def filter_new(self, tweets: list[dict]) -> list[dict]:
        return [tw for tw in tweets if self.is_new(tw)]


# ─── Ciclo di Monitoraggio ───────────────────────────────────────────────────

def run_monitor_cycle(
    driver: webdriver.Chrome,
    queries: list[str],
    tracker: TweetTracker,
    max_per_query: int,
    lang: str | None,
    cycle_num: int,
):
    """Esegue un ciclo completo di ricerca su tutte le query."""
    cycle_start = datetime.now()
    total_new = 0
    total_scanned = 0

    print_header(
        f"🔄 CICLO #{cycle_num}  —  {cycle_start.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    print_info(f"Query da eseguire: {len(queries)}")
    print()

    for i, query in enumerate(queries, 1):
        if USE_RICH:
            console.rule(f"[bold magenta]  [{i}/{len(queries)}]  {query}  [/]")
        else:
            print(f"\n{'─' * 60}")
            print(f"  [{i}/{len(queries)}]  {query}")
            print(f"{'─' * 60}")

        try:
            tweets = search_x(driver, query, max_results=max_per_query, lang=lang)
            total_scanned += len(tweets)

            # Filtra solo tweet nuovi (mai visti)
            new_tweets = tracker.filter_new(tweets)

            if new_tweets:
                total_new += len(new_tweets)
                print_success(f"{len(new_tweets)} nuovi tweet trovati (su {len(tweets)} totali)")
                for j, tweet in enumerate(new_tweets, 1):
                    print_tweet(j, tweet)
            else:
                print_info(f"Nessun nuovo tweet ({len(tweets)} già visti)")

        except Exception as e:
            print_error(f"Errore nella query '{query}': {e}")

        # Pausa tra le query per evitare rate-limiting
        pause = random.uniform(3, 6)
        print_info(f"Pausa {pause:.1f}s prima della prossima query...")
        time.sleep(pause)

    # Riepilogo ciclo
    elapsed = (datetime.now() - cycle_start).total_seconds()
    print()
    print_header(f"📊 RIEPILOGO CICLO #{cycle_num}")
    print_success(f"🆕 Nuovi tweet trovati: {total_new}")
    print_info(f"📋 Tweet totali analizzati: {total_scanned}")
    print_info(f"🔍 Query eseguite: {len(queries)}")
    print_info(f"⏱️  Durata ciclo: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print_info(f"🗃️  Tweet in memoria: {len(tracker.seen)}")

    return total_new


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🛡️ X.com Vulnerability"
    )
    parser.add_argument(
        "--mode",
        choices=["monitor", "single"],
        default="monitor",
        help="'monitor' = loop automatico ogni 5 min (default), 'single' = ricerca singola",
    )
    parser.add_argument("query", nargs="?", help="Parola chiave (solo in mode=single)")
    parser.add_argument("--max", type=int, default=RESULTS_PER_QUERY, help=f"Risultati per query (default: {RESULTS_PER_QUERY})")
    parser.add_argument("--interval", type=int, default=MONITOR_INTERVAL, help="Intervallo in secondi tra i cicli (default: 300)")
    parser.add_argument("--lang", type=str, default=None, help="Lingua dei tweet (es: en, it)")
    parser.add_argument("--headless", action="store_true", help="Esegui senza interfaccia grafica")
    parser.add_argument("--cookies", type=str, default=None, help="Percorso file cookie (.enc o .txt)")
    parser.add_argument("--no-login", action="store_true", help="Senza login (risultati limitati)")
    parser.add_argument("--encrypt", type=str, metavar="FILE", help="Cripta un file cookies.txt ed esci")
    parser.add_argument(
        "--vendor",
        nargs="+",
        choices=["fortinet", "microsoft", "cisco", "all"],
        default=["all"],
        help="Filtra query per vendor (default: all)",
    )
    args = parser.parse_args()

    # ── Modalità crittografia (utility) ──
    if args.encrypt:
        print_header("🔐 Crittografia Cookie")
        encrypt_cookie_file(args.encrypt)
        sys.exit(0)

    # ── Banner ──
    if USE_RICH:
        console.print(Panel(
            "[bold white]🛡️  X.com Vulnerability Monitor[/]\n"
            "[dim]Monitoraggio automatico vulnerabilità Fortinet / Microsoft / Cisco[/]\n\n"
            f"[cyan]Modalità:[/] {args.mode}   "
            f"[cyan]Intervallo:[/] {args.interval}s   "
            f"[cyan]Headless:[/] {'Sì' if args.headless else 'No'}",
            title="[bold red]VulnWatch[/]",
            box=box.DOUBLE,
        ))
    else:
        print_header("🛡️  X.com Vulnerability Monitor")
        print(f"  Modalità: {args.mode}  |  Intervallo: {args.interval}s  |  Headless: {args.headless}\n")

    # ── Filtra query per vendor ──
    if args.mode == "monitor":
        selected_vendors = [v.lower() for v in args.vendor]
        if "all" in selected_vendors:
            queries = VULN_QUERIES
        else:
            queries = []
            vendor_keywords = {
                "fortinet": ["fortinet"],
                "microsoft": ["microsoft"],
                "cisco": ["cisco"],
            }
            for q in VULN_QUERIES:
                q_lower = q.lower()
                for vendor in selected_vendors:
                    if any(kw in q_lower for kw in vendor_keywords.get(vendor, [])):
                        queries.append(q)
                        break

        print_info(f"Query attive: {len(queries)}")
        for q in queries:
            print_info(f"  • {q}")
        print()

    # ── Modalità single (ricerca singola) ──
    if args.mode == "single":
        query = args.query
        if not query:
            query = input("🔎 Inserisci la parola chiave da cercare: ").strip()
            if not query:
                print_error("Nessuna parola chiave inserita.")
                sys.exit(1)

    # ── Auto-detect file cookie ──
    cookie_source = args.cookies
    if not args.no_login and cookie_source is None:
        # Cerca prima .enc, poi .txt
        if os.path.isfile("cookies.enc"):
            cookie_source = "cookies.enc"
        elif os.path.isfile("cookies.txt"):
            cookie_source = "cookies.txt"
        else:
            print_warning("Nessun file cookie trovato (cookies.enc / cookies.txt).")
            print_info("Per ottenere risultati completi:")
            print_info("  1. Esporta i cookie da x.com come 'cookies.txt'")
            print_info("  2. Crittografali:  python x_search.py --encrypt cookies.txt\n")
            risposta = input("Vuoi continuare senza login? (s/n): ").strip().lower()
            if risposta != "s":
                sys.exit(0)
            args.no_login = True

    # ── Verifica permessi file cookie ──
    if not args.no_login and cookie_source:
        _check_permissions(cookie_source)

    # ── Avvia browser ──
    print_info("Avvio del browser...")
    driver = None
    try:
        driver = create_driver(headless=args.headless)
    except WebDriverException as e:
        print_error(f"Impossibile avviare Chrome/Chromium: {e}")
        sys.exit(1)

    # Registra handler per SIGINT/SIGTERM per pulizia sicura
    def _signal_handler(signum, frame):
        print_warning("\n\n🛑 Segnale ricevuto, pulizia in corso...")
        secure_cleanup(driver)
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    try:
        # Login tramite cookie
        if not args.no_login:
            if not load_cookies(driver, cookie_source):
                print_warning("Login tramite cookie fallito. Continuo comunque...")

        # ══════════════════════════════════════════════════════════
        #  MODALITÀ MONITOR — Loop automatico
        # ══════════════════════════════════════════════════════════
        if args.mode == "monitor":
            tracker = TweetTracker()
            cycle = 0

            print_success("Monitor avviato. Premi Ctrl+C per fermare.\n")

            while True:
                cycle += 1
                try:
                    new_count = run_monitor_cycle(
                        driver, queries, tracker, args.max, args.lang, cycle
                    )
                except Exception as e:
                    print_error(f"Errore nel ciclo #{cycle}: {e}")
                    print_info("Riprovo al prossimo ciclo...")

                # Countdown al prossimo ciclo
                next_run = datetime.now().strftime("%H:%M:%S")
                mins = args.interval // 60
                secs = args.interval % 60
                print_info(
                    f"⏳ Prossimo ciclo tra {mins}m {secs}s "
                    f"(alle ~{next_run})... Ctrl+C per uscire."
                )
                time.sleep(args.interval)

        # ══════════════════════════════════════════════════════════
        #  MODALITÀ SINGLE — Ricerca singola
        # ══════════════════════════════════════════════════════════
        else:
            tweets = search_x(driver, query, max_results=args.max, lang=args.lang)

            if not tweets:
                print_warning("Nessun tweet trovato.")
                return

            print_header(f"Risultati per \"{query}\"  ({len(tweets)} tweet)")
            for i, tweet in enumerate(tweets, 1):
                print_tweet(i, tweet)

            print_header("📊 Riepilogo")
            print_success(f"Tweet trovati: {len(tweets)}")
            print_info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    except KeyboardInterrupt:
        print_warning("\n\n🛑 Monitor fermato dall'utente.")
    except Exception as e:
        print_error(f"Errore imprevisto: {e}")
    finally:
        secure_cleanup(driver)


if __name__ == "__main__":
    main()
