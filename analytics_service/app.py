import os
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request
import psycopg2
from psycopg2 import sql
from functools import wraps
from threading import Thread
import time

app = Flask(__name__)

# ============================================================================
# KONFIGURACJA BAZY DANYCH
# ============================================================================

DB_HOST = os.getenv('DB_HOST', 'db')
DB_USER = os.getenv('DB_USER', 'honeypot_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'SecurePass123!')
DB_NAME = os.getenv('DB_NAME', 'honeypot_db')
DB_PORT = os.getenv('DB_PORT', '5432')

# ============================================================================
# KONFIGURACJA LOGOWANIA
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/analytics/analytics.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# SYSTEM CACHE - pamięciowy cache dla wyników statystyk
# ============================================================================

"""
DLACZEGO CACHE?
- Zapytania do bazy (agregacje) są relatywnie kosztowne
- Dashboard w przeglądarce odświeża dane co 10 sekund
- Bez cache baza byłaby zasypana identycznymi zapytaniami
- Cache odświeżany co 30 sekund jest dobrym kompromisem

EFEKT: istotne zmniejszenie obciążenia bazy (znacznie mniej zapytań).
"""
dashboard_cache = {
    'last_update': None,
    'data': {}
}

# ============================================================================
# FUNKCJE DOSTĘPU DO BAZY I AGREGACJI STATYSTYK
# ============================================================================

def get_db_connection():
    """
    GET_DB_CONNECTION - nawiązuje połączenie z bazą PostgreSQL

    Zwraca:
    - obiekt połączenia przy sukcesie
    - None w przypadku błędu (aplikacja degraduje się łagodnie)
    """
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT,
            connect_timeout=5
        )
        return conn
    except Exception as e:
        logger.error(f"Błąd połączenia z bazą: {e}")
        return None


def get_attack_stats():
    """
    GET_ATTACK_STATS - pobiera i agreguje statystyki ataków z tabeli attacks
    =========================================================================

    Wykonywane zapytania:
      1. Liczba wszystkich ataków
      2. Liczba ataków w podziale na typ (TOP 10)
      3. Najczęstsze IP źródłowe (TOP 20)
      4. Najczęstsze user‑agenty (TOP 15)
      5. Lista ostatnich ataków (50 najnowszych)

    Zwraca:
    Słownik z kompletem statystyk lub None przy błędzie.
    """
    try:
        conn = get_db_connection()
        if not conn:
            return None

        cursor = conn.cursor()

        # 1. Łączna liczba ataków
        cursor.execute("SELECT COUNT(*) FROM attacks")
        total_attacks = cursor.fetchone()[0]

        # 2. Ataki wg typu (TOP 10)
        cursor.execute("""
            SELECT attack_name, COUNT(*) as count
            FROM attacks
            GROUP BY attack_name
            ORDER BY count DESC
            LIMIT 10
        """)
        attacks_by_type = [
            {'name': row[0], 'count': row[1]}
            for row in cursor.fetchall()
        ]

        # 3. Najczęstsze IP (TOP 20)
        cursor.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM attacks
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 20
        """)
        top_ips = [
            {'ip': row[0], 'count': row[1]}
            for row in cursor.fetchall()
        ]

        # 4. Najczęstsze user‑agenty (TOP 15)
        cursor.execute("""
            SELECT user_agent, COUNT(*) as count
            FROM attacks
            WHERE user_agent IS NOT NULL
            GROUP BY user_agent
            ORDER BY count DESC
            LIMIT 15
        """)
        top_agents = [
            {'agent': row[0], 'count': row[1]}
            for row in cursor.fetchall()
        ]

        # 5. Ostatnie ataki (50 najnowszych)
        cursor.execute("""
            SELECT id, attack_name, source_ip, user_agent, timestamp
            FROM attacks
            ORDER BY timestamp DESC
            LIMIT 50
        """)
        recent = [
            {
                'id': row[0],
                'attack_name': row[1],
                'source_ip': row[2],
                'user_agent': row[3],
                'timestamp': str(row[4])
            }
            for row in cursor.fetchall()
        ]

        cursor.close()
        conn.close()

        return {
            'total_attacks': total_attacks,
            'attacks_by_type': attacks_by_type,
            'top_ips': top_ips,
            'top_agents': top_agents,
            'recent_attacks': recent,
            'last_update': datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Błąd pobierania statystyk ataków: {e}")
        return None


def update_cache():
    """
    UPDATE_CACHE - wątek w tle odświeżający cache co 30 sekund
    ===========================================================
    Założenia:
    - Dane na dashboardzie mogą być opóźnione maks. o ~30 sekund
    - Przeglądarka odświeża dane co 10 sekund, ale czyta z cache
    - Baza dostaje tylko jedno zapytanie agregujące co 30 s,
      zamiast wielu zapytań z każdej przeglądarki
    """
    while True:
        try:
            data = get_attack_stats()
            if data:
                dashboard_cache['data'] = data
                dashboard_cache['last_update'] = datetime.utcnow().isoformat()
                logger.info("Zaktualizowano cache dashboardu")
        except Exception as e:
            logger.error(f"Błąd podczas aktualizacji cache: {e}")

        time.sleep(30)


# Uruchomienie wątku aktualizującego cache w tle
cache_thread = Thread(target=update_cache, daemon=True)
cache_thread.start()
