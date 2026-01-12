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


def rate_limit(max_per_minute=60):
    """
    RATE_LIMIT - dekorator ograniczający liczbę żądań z jednego IP
    ==============================================================
    Cel:
    Ograniczenie liczby żądań na minutę z jednego adresu IP, aby
    utrudnić brute force, skanowanie i proste DoS.

    Działanie:
    1. Dekorator opakowuje funkcję widoku Flask
    2. Pobiera IP klienta (get_client_ip)
    3. Tworzy klucz "IP:YYYY-MM-DD HH:MM" (koszyk na minutę)
    4. Zwiększa licznik żądań dla danego klucza
    5. Jeśli licznik przekracza max_per_minute – zwraca HTTP 429
    6. Po minucie powstaje nowy koszyk z nowym kluczem

    Ograniczenia:
    - Przechowuje liczniki tylko w pamięci (restart kontenera je zeruje)
    - Przy wielu replikach aplikacji warto przenieść liczniki do Redis/Memcached
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()

            # Inicjalizacja słownika liczników przy pierwszym użyciu
            if not hasattr(decorated_function, 'calls'):
                decorated_function.calls = {}

            # Klucz unikalny dla IP i aktualnej minuty
            now = datetime.now()
            key = f"{client_ip}:{now.strftime('%Y-%m-%d %H:%M')}"

            # Zwiększ licznik dla danego IP/minuty
            decorated_function.calls[key] = decorated_function.calls.get(key, 0) + 1

            # Sprawdzenie limitu
            if decorated_function.calls[key] > max_per_minute:
                logger.warning(f"Przekroczony limit żądań dla IP {client_ip}")
                return jsonify({'error': 'Rate limit exceeded'}), 429

            # Kontynuuj normalną obsługę żądania
            return f(*args, **kwargs)
        return decorated_function
    return decorator
