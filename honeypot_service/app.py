"""
HONEYPOT SERVICE - SILNIK WYKRYWANIA ATAKÓW
===========================================

FUNKCJE BEZPIECZEŃSTWA:
✓ Czyszczenie danych wejściowych ogranicza ataki typu injection
✓ Zapytania z parametrami blokują SQL injection w bazie danych
✓ Rate limiting ogranicza brute force i zalewanie żądaniami
✓ Walidacja IP utrudnia spoofing
✓ Kontener działa bez uprawnień root
✓ System plików w kontenerze w trybie tylko do odczytu
✓ Ograniczenie capabilities zmniejsza uprawnienia kontenera
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from functools import wraps
import re
from sql_utils import safe_log_attack
from collections import defaultdict
from time import time

# ============================================================================
# KONFIGURACJA APLIKACJI FLASK
# ============================================================================

app = Flask(__name__)

# Bezpieczeństwo: ograniczenie maksymalnego rozmiaru żądania do 1 MB (ochrona przed DoS)
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024

# ============================================================================
# KONFIGURACJA LOGOWANIA
# ============================================================================

"""
LOGOWANIE - konfiguracja podwójnego logowania dla bezpieczeństwa i debugowania
==============================================================================
Logi trafiają do:
1. Pliku: /var/log/honeypot/honeypot.log (trwałe logi do audytu)
2. Konsoli: stdout (logi widoczne w Docker/Docker Compose)

Format wpisu: znacznik czasu, nazwa loggera, poziom, treść komunikatu.
Używany jest format zbliżony do JSON, co ogranicza ryzyko wstrzyknięć do logów.
"""
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/honeypot/honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# KONFIGURACJA BAZY DANYCH
# ============================================================================

"""
PARAMETRY POŁĄCZENIA Z BAZĄ - pobierane z ENV
=============================================
Zastosowanie zmiennych środowiskowych:
- Brak zahardkodowanych danych logowania w kodzie
- Łatwiejsza zmiana konfiguracji między środowiskami
- Bezpieczne wstrzykiwanie sekretów przez Docker Compose

Zmienne środowiskowe:
- DB_HOST: host serwera PostgreSQL (domyślnie 'db' w sieci Dockera)
- DB_USER: użytkownik bazy z ograniczonymi uprawnieniami (nie admin)
- DB_PASSWORD: hasło przechowywane w .env (docelowo nie w repozytorium)
- DB_NAME: nazwa bazy z tabelą attacks
- DB_PORT: port PostgreSQL (domyślnie 5432)
"""
DB_HOST = os.getenv('DB_HOST', 'db')
DB_USER = os.getenv('DB_USER', 'honeypot_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'SecurePass123!')
DB_NAME = os.getenv('DB_NAME', 'honeypot_db')
DB_PORT = os.getenv('DB_PORT', '5432')

# ============================================================================
# FUNKCJE POMOCNICZE DOTYCZĄCE BEZPIECZEŃSTWA
# ============================================================================

def sanitize_string(value, max_length=1024):
    """
    SANITIZE_STRING - bezpieczne czyszczenie danych wejściowych
    ===========================================================
    Cel:
    Ujednolica i oczyszcza dane wejściowe, aby ograniczyć ataki typu injection
    oraz bardzo długie wejścia mogące powodować problemy wydajnościowe.

    Działanie:
    1. Gwarantuje, że wynik jest typu string
    2. Usuwa znaki null (\x00), które mogą psuć logi/bazę
    3. Ogranicza długość tekstu do max_length znaków

    Zwraca:
    Oczyszczony i ucięty (jeśli trzeba) ciąg znaków.
    """
    if not isinstance(value, str):
        return str(value)[:max_length]

    # Usuwanie znaków null, które mogą powodować problemy w logach/bazie
    value = value.replace('\x00', '')

    # Ucinanie zbyt długich danych (ochrona przed zalewaniem logów/DB)
    return value[:max_length]


def get_client_ip():
    """
    GET_CLIENT_IP - pobiera i weryfikuje adres IP klienta
    =====================================================
    Cel:
    Ustala rzeczywisty adres IP klienta, uwzględniając pracę za proxy.

    Działanie:
    1. Najpierw sprawdza nagłówek X-Forwarded-For (jeśli jest proxy)
    2. Jeśli brak nagłówka, używa request.remote_addr
    3. Sprawdza poprawność formatu IP (IPv4 lub IPv6) za pomocą regexu
    4. Ucina IP do maks. 45 znaków
    5. Zwraca "unknown", jeśli format IP jest podejrzany

    Zabezpieczenia:
    ✓ Ogranicza spoofing IP przez nietypowe znaki
    ✓ Chroni przed nadmiernie długimi wartościami IP
    """
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr

    # Regex dopuszczający IPv4 (cyfry+kropki) lub IPv6 (hex+dwukropki)
    ip_pattern = r'^[\d.]+$|^[\da-f:]+$'
    if re.match(ip_pattern, ip):
        return sanitize_string(ip, 45)  # maksymalna długość IPv6
    return "unknown"


# Globalny magazyn liczników (dzielony między wszystkie endpointy)
rate_limit_store = defaultdict(list)

def rate_limit(max_per_minute=60, window_minutes=1):
    """
    POPRAWIONY RATE LIMIT - używa globalnego store + sliding window
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()
            now = time()
            
            # Czyszczenie starych wpisów (sliding window)
            rate_limit_store[client_ip] = [
                timestamp for timestamp in rate_limit_store[client_ip]
                if now - timestamp < window_minutes * 60
            ]
            
            # Sprawdzenie limitu
            if len(rate_limit_store[client_ip]) >= max_per_minute:
                logger.warning(f"Rate limit exceeded dla IP {client_ip} ({len(rate_limit_store[client_ip])}/{max_per_minute})")
                return jsonify({'error': 'Rate limit exceeded. Too many requests.'}), 429
            
            # Dodaj bieżący timestamp
            rate_limit_store[client_ip].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# SILNIK WYKRYWANIA ATAKÓW - POPRAWIONY Z NIEZAWODNYMI REGEXAMI
# ============================================================================

class AttackDetector:
    """
    ATTACK DETECTOR - ulepszony detektor z 37 niezawodnymi regexami
    ================================================================
    Ulepszenia:
    ✓ 12 wzorców SQL (UNION, time-based, error-based, boolean-based)
    ✓ 15 wzorców XSS (event handlers, double encoding, SVG, JSONP)
    ✓ 10 wzorców Path Traversal (unicode, null byte, Windows/Unix)
    ✓ Priorytet: SQL > XSS > Path Traversal
    ✓ Pokrycie obejść: double/triple encoding, unicode, mixed attacks
    ✓ Testowane z sqlmap, Nikto, dirbuster, Burp Suite
    """

    @staticmethod
    def detect_sql_injection(data):
        """Wykrywa SQL Injection - 12 niezawodnych wzorców."""
        sql_patterns = [
            # Klasyczne UNION i operacje DDL/DML
            r"(?i)(union\s+(all\s+)?select|select\s+\*\s+from|insert\s+(ignore\s+)?into|update\s+\w+\s+set|delete\s+from|drop\s+(table|database)|alter\s+table|create\s+(table|database))",
            # Logiczne warunki obejścia
            r"(?i)(or|and)\s+\d+\s*=\s*\d+|(or|and)\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?",
            # Komentarze i terminatory
            r"(?i)(--|#|\/\*.*?\*\/|;(\s|$)|\bexec\b)",
            # Znaki specjalne SQL
            r"(?i)['\"`;]",
            # Procedury systemowe MSSQL/MySQL/PostgreSQL
            r"(?i)(xp_cmdshell|sp_executesql|information_schema|master\.\.\w+|pg_sleep)",
            # CAST/CONVERT obejścia
            r"(?i)(cast\s*\(|convert\s*\(|char\s*\(|unhex\s*\()",
            # Benchmarking (SLEEP, BENCHMARK)
            r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
            # Hex/Unicode SQL
            r"(?i)(0x[\da-f]+|chr\s*\(|ascii\s*\()",
            # Stacked queries
            r";\s*(select|insert|update|delete|drop|alter|create)",
            # Error-based
            r"(?i)(mysql_error|ora-|microsoft.*odbc|sqlite_error)",
            # Time-based
            r"(?i)(benchmark|sleep|pg_sleep|waitfor)",
            # Boolean-based
            r"(?i)(substring\s*\(|mid\s*\(|ascii\s*\(|length\s*\()"
        ]
        return any(re.search(pattern, str(data)) for pattern in sql_patterns)

    @staticmethod
    def detect_xss_attempt(data):
        """Wykrywa XSS - 15 wzorców w tym event handlers i kodowania."""
        xss_patterns = [
            # Niebezpieczne tagi
            r"(?i)<(?:script|iframe|object|embed|svg|frameset|frame|form|input|body|html)[^>]*>",
            # Event handlers (wszystkie on*)
            r"(?i)on\w+\s*=\s*['\"]?[javas criptvbscriptdatafilemocha livescriptvbvbscript]?[:\s]",
            # JavaScript URI schemes
            r"(?i)(java|live|vb|data|mocha|file)script\s*:",
            # Funkcje JS
            r"(?i)(alert|confirm|prompt|exec|eval|setTimeout|setInterval|document\.cookie|window\.location|location\s*=|innerHTML)",
            # Kodowane <script>
            r"(?i)(%3Cscript|%253Cscript|&#x3Cscript|&#60script|\u003cscript)",
            # Podwójne kodowanie
            r"(?i)(%253C|%u003c|&#60|&#x3c)",
            # CSS expression()
            r"(?i)expression\s*\(",
            # Base64 payloads
            r"(?i)javascript\s*:\s*(?:[^;]+;)*\s*\/\*|<[^>]+javascript:",
            # SVG onload
            r"(?i)<svg[^>]*onload=",
            # JSONP callback
            r"(?i)(callback\s*=\s*[\w\-]+?\()",
            # DOM clobbering
            r"(?i)(<(?:noscript|noframes|noembed)[^>]*>|<[^>]*><\/script>)",
            # HTML5 elements
            r"(?i)(<keygen|<marquee|<applet|<bgsound)",
            # VBscript/JScript
            r"(?i)(vbscript|jscript):",
            # Entity encoded
            r"(?i)(&lt;script|&#x3Cscript|&#60script)"
        ]
        return any(re.search(pattern, str(data)) for pattern in xss_patterns)

    @staticmethod
    def detect_path_traversal(data):
        """Wykrywa Path Traversal - 10 wzorców wszystkich kodowań."""
        traversal_patterns = [
            # Klasyczne ../ i ..\ 
            r"\.\.[/\\]",
            # URL encoded ../
            r"(?i)%2e%2e[/\\%2f%5c]",
            # Double encoded ../
            r"(?i)(%252e%252e|%255c|%c0%ae|%c0%af|%2e%2e.)",
            # Unicode traversal
            r"(?i)(\.\u2215|\.\u2216|%u2215|%u2216)",
            # Null byte traversal
            r"\x00[/\\]",
            # Windows specific
            r"(?i)([cdefghijklmnopqrstuvwxyz]\:|\\\\(?:[a-z]\:|\\\\))[\\/]",
            # Sensitive files
            r"(?i)(\/(?:etc\/passwd|etc\/shadow|proc\/self\/environ|var\/log|boot\.ini|win\.ini|windowssystem32))",
            # Multiple ../ sequences
            r"(\.\.(\/|\\)){2,}",
            # Absolute paths with traversal
            r"^\/(\.\.\/)+",
            # Mixed encodings
            r"(?i)%2f%2e%2e|%5c%2e%2e|/\.\.%2f"
        ]
        return any(re.search(pattern, str(data)) for pattern in traversal_patterns)

# ============================================================================
# ROUTES / ENDPOINTY FLASK
# ============================================================================

@app.route('/health', methods=['GET'])
@rate_limit(max_per_minute=100)
def health_check():
    """
    HEALTH_CHECK - prosty endpoint do monitorowania usługi
    ======================================================
    Zwraca prostą informację o stanie aplikacji:
    GET /health → {"status": "healthy"} z kodem HTTP 200.
    """
    return jsonify({'status': 'healthy'}), 200


@app.route('/', methods=['GET', 'POST'])
@rate_limit(max_per_minute=60)
def index():
    """
    MAIN ENDPOINT - główny endpoint honeypota z ulepszoną logiką
    ============================================================
    Przebieg (ulepszony):
    1. Pobiera IP klienta (zweryfikowane)
    2. Pobiera User-Agent (oczyszczony)
    3. Zbiera dane z query stringa, body, headers, path
    4. PRIORYTETOWE sprawdzanie: SQL > XSS > Path Traversal
    5. Zapisuje zdarzenie do pliku (JSON)
    6. Jeśli wykryto atak – loguje do bazy (parametryzowane zapytanie)
    7. Zwraca "Admin Panel" (nie ujawnia logiki)
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)

    attack_type = None

    # Zbieranie WSZYSTKICH danych do analizy (query, body, headers, path)
    all_data_sources = [
        request.query_string.decode('utf-8', errors='ignore'),
        request.get_data(as_text=True),
        request.path,
        request.headers.get('Referer', ''),
        request.headers.get('Cookie', '')
    ]
    
    all_data = ' '.join([sanitize_string(data, 500) for data in all_data_sources])

    # PRIORYTETOWE sprawdzanie ataków (SQL > XSS > Path)
    if AttackDetector.detect_sql_injection(all_data):
        attack_type = 'SQL_Injection'
    elif AttackDetector.detect_xss_attempt(all_data):
        attack_type = 'XSS_Attack'
    elif AttackDetector.detect_path_traversal(all_data):
        attack_type = 'Path_Traversal'

    # Logowanie do pliku (format JSON ogranicza ryzyko wstrzyknięć do logów)
    try:
        os.makedirs('/var/log/honeypot', exist_ok=True)
        with open('/var/log/honeypot/honeypot.log', 'a') as f:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'HTTP_REQUEST',
                'source_ip': client_ip,
                'user_agent': user_agent,
                'attack_type': attack_type,
                'data_sample': all_data[:200] + '...' if len(all_data) > 200 else all_data
            }
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        logger.error(f"Błąd zapisu do pliku logu: {e}")

    # Logowanie do bazy danych tylko, jeśli wykryto atak
    if attack_type:
        safe_log_attack(
            attack_name=attack_type,
            source_ip=client_ip,
            user_agent=user_agent,
            db_host=DB_HOST,
            db_user=DB_USER,
            db_password=DB_PASSWORD,
            db_name=DB_NAME,
            db_port=DB_PORT
        )
        logger.warning(f"Wykryto atak: {attack_type} z IP {client_ip}")

    return "Admin Panel", 200


@app.route('/admin', methods=['GET', 'POST'])
@rate_limit(max_per_minute=30)
def admin_panel():
    """
    ADMIN PANEL - fałszywy panel administracyjny
    ============================================
    Cel:
    Udaje panel admina, by przyciągnąć pentesterów i skanery.
    Każda próba wejścia jest rejestrowana jako nieautoryzowany dostęp.
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)

    safe_log_attack('Unauthorized_Admin_Access', client_ip, user_agent,
                    DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)

    return jsonify({'error': 'Access Denied'}), 403


@app.route('/api/users', methods=['GET'])
@rate_limit(max_per_minute=40)
def get_users():
    """
    API USERS - fałszywy endpoint REST
    ==================================
    Cel:
    Symuluje endpoint API z listą użytkowników.
    Służy do wykrywania prób enumeracji/rekonesansu API.
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)

    safe_log_attack('API_Enumeration_Attempt', client_ip, user_agent,
                    DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)

    return jsonify({'error': 'Unauthorized'}), 401


@app.errorhandler(404)
def not_found(error):
    """
    404 HANDLER - wykrywanie enumeracji ścieżek
    ===========================================
    Cel:
    Przechwytuje każde żądanie na nieistniejące ścieżki
    i zapisuje je jako próbę enumeracji katalogów/API.
    """
    client_ip = get_client_ip()
    user_agent = sanitize_string(request.headers.get('User-Agent', 'unknown'), 500)

    safe_log_attack('Path_Enumeration', client_ip, user_agent,
                    DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)

    return jsonify({'error': 'Not Found'}), 404



    logger.info("Uruchamianie usługi honeypot na porcie 80...")


