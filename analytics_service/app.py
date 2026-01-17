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

# Tworzymy instancję aplikacji Flask
app = Flask(__name__)

# ============================================================================
# KONFIGURACJA BAZY DANYCH
# ============================================================================

# Dane konfiguracyjne bazy pobierane z zmiennych środowiskowych
# (z sensownymi wartościami domyślnymi na potrzeby środowiska developerskiego)
DB_HOST = os.getenv('DB_HOST', 'db')
DB_USER = os.getenv('DB_USER', 'honeypot_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'SecurePass123!')
DB_NAME = os.getenv('DB_NAME', 'honeypot_db')
DB_PORT = os.getenv('DB_PORT', '5432')

# ============================================================================
# KONFIGURACJA LOGOWANIA
# ============================================================================

# Konfiguracja globalnego loggera:
# - poziom INFO
# - logowanie do pliku w /var/log/analytics/analytics.log
# - oraz na standardowe wyjście (np. logi kontenera)
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
# Prosta struktura słownikowa przechowująca:
# - last_update: znacznik czasu ostatniego odświeżenia
# -  ostatnio policzone statystyki
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
        # Inicjalizacja połączenia z bazą przy użyciu danych konfiguracyjnych
        conn = psycopg2.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT,
            connect_timeout=5  # maksymalny czas oczekiwania na połączenie
        )
        return conn
    except Exception as e:
        # Logowanie błędu połączenia (bez przerywania działania serwera HTTP)
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
        # Nawiązanie połączenia z bazą
        conn = get_db_connection()
        if not conn:
            # Jeżeli nie udało się połączyć, zwracamy None
            return None

        cursor = conn.cursor()

        # 1. Łączna liczba ataków
        cursor.execute("SELECT COUNT(*) FROM attacks")
        total_attacks = cursor.fetchone()[0]

        # 2. Ataki wg typu (TOP 10)
        # Grupowanie po nazwie ataku i sortowanie malejąco po liczbie wystąpień
        cursor.execute("""
            SELECT attack_name, COUNT(*) as count
            FROM attacks
            GROUP BY attack_name
            ORDER BY count DESC
            LIMIT 10
        """)
        # Przekształcenie wyników w listę słowników przyjazną dla JSON
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
        # Sortowanie po timestamp malejąco, aby mieć najnowsze rekordy
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
                # Konwersja timestampa na string, aby był serializowalny do JSON
                'timestamp': str(row[4])
            }
            for row in cursor.fetchall()
        ]

        # Zamykamy kursor i połączenie, aby nie trzymać zasobów bazy
        cursor.close()
        conn.close()

        # Zwracamy komplet danych dla dashboardu
        return {
            'total_attacks': total_attacks,
            'attacks_by_type': attacks_by_type,
            'top_ips': top_ips,
            'top_agents': top_agents,
            'recent_attacks': recent,
            'last_update': datetime.utcnow().isoformat()
        }

    except Exception as e:
        # Logowanie błędu związanego z zapytaniami / agregacją
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
    # Pętla nieskończona – wątek działa przez cały czas życia aplikacji
    while True:
        try:
            # Pobranie najnowszych statystyk z bazy
            data = get_attack_stats()
            if 
                # Aktualizacja pamięciowego cache
                dashboard_cache['data'] = data
                dashboard_cache['last_update'] = datetime.utcnow().isoformat()
                logger.info("Zaktualizowano cache dashboardu")
        except Exception as e:
            # W razie błędu logujemy i próbujemy ponownie po 30 sekundach
            logger.error(f"Błąd podczas aktualizacji cache: {e}")

        # Odczekanie 30 sekund przed kolejną aktualizacją
        time.sleep(30)


# Uruchomienie wątku aktualizującego cache w tle
# daemon=True oznacza, że wątek zakończy się automatycznie
# po zatrzymaniu głównego procesu (nie blokuje wyłączenia aplikacji)
cache_thread = Thread(target=update_cache, daemon=True)
cache_thread.start()

# ============================================================================
# SZABLON HTML - ciemny dashboard z auto‑odświeżaniem
# ============================================================================

# HTML_TEMPLATE zawiera cały front-end dashboardu:
# - proste CSS (ciemny motyw)
# - sekcje kart ze statystykami
# - tabelę z ostatnimi atakami
# - JS, który co 10 sekund odpytuje /api/stats i aktualizuje widok
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot Analytics Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        h1 {
            margin-bottom: 30px;
            color: #38bdf8;
        }
        h2 {
            margin-top: 30px;
            margin-bottom: 20px;
            font-size: 1.3em;
            border-bottom: 2px solid #38bdf8;
            padding-bottom: 10px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
        }
        .card-title {
            font-size: 0.9em;
            color: #94a3b8;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .card-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #38bdf8;
        }
        .stat-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #334155;
        }
        .stat-item:last-child {
            border-bottom: none;
        }
        .stat-label {
            flex: 1;
            word-break: break-word;
            margin-right: 10px;
        }
        .stat-count {
            font-weight: bold;
            color: #38bdf8;
            white-space: nowrap;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }
        th {
            background: #1e293b;
            font-weight: 600;
            color: #38bdf8;
        }
        tr:hover {
            background: #1e293b;
        }
        .update-time {
            color: #94a3b8;
            font-size: 0.9em;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍯 Honeypot Analytics Dashboard</h1>
        
        <div class="grid">
            <div class="card">
                <div class="card-title">Total Attacks</div>
                <div class="card-value" id="total-attacks">-</div>
            </div>
            <div class="card">
                <div class="card-title">Unique Attack Types</div>
                <div class="card-value" id="unique-types">-</div>
            </div>
            <div class="card">
                <div class="card-title">Unique IPs</div>
                <div class="card-value" id="unique-ips">-</div>
            </div>
        </div>
        
        <h2>Attack Types</h2>
        <div class="card">
            <div id="attacks-by-type"></div>
        </div>
        
        <h2>Top Source IPs</h2>
        <div class="card">
            <div id="top-ips"></div>
        </div>
        
        <h2>Top User Agents</h2>
        <div class="card">
            <div id="top-agents"></div>
        </div>
        
        <h2>Recent Attacks</h2>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Attack Type</th>
                        <th>Source IP</th>
                        <th>User Agent</th>
                    </tr>
                </thead>
                <tbody id="recent-attacks">
                    <tr><td colspan="4">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="update-time">
            Last updated: <span id="last-update">-</span>
        </div>
    </div>
    
    <script>
        // Pomocnicza funkcja formatująca datę w czytelnej formie
        function formatDate(dateStr) {
            return new Date(dateStr).toLocaleString();
        }
        
        // Funkcja pobierająca dane z backendu i aktualizująca dashboard
        function updateDashboard() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    if (data.error) {
                        console.error(data.error);
                        return;
                    }
                    
                    // Ustawienie wartości w kafelkach
                    document.getElementById('total-attacks').textContent = data.total_attacks;
                    document.getElementById('unique-types').textContent = data.attacks_by_type.length;
                    document.getElementById('unique-ips').textContent = data.top_ips.length;
                    
                    // Lista typów ataków
                    let html = '';
                    data.attacks_by_type.forEach(item => {
                        html += `<div class="stat-item"><div class="stat-label">${item.name}</div><div class="stat-count">${item.count}</div></div>`;
                    });
                    document.getElementById('attacks-by-type').innerHTML = html;
                    
                    // Najczęstsze IP
                    html = '';
                    data.top_ips.forEach(item => {
                        html += `<div class="stat-item"><div class="stat-label">${item.ip}</div><div class="stat-count">${item.count}</div></div>`;
                    });
                    document.getElementById('top-ips').innerHTML = html;
                    
                    // Najczęstsze user-agenty (obcięte do 60 znaków, pełny w tooltipie)
                    html = '';
                    data.top_agents.forEach(item => {
                        let agent = item.agent.substring(0, 60) + (item.agent.length > 60 ? '...' : '');
                        html += `<div class="stat-item"><div class="stat-label" title="${item.agent}">${agent}</div><div class="stat-count">${item.count}</div></div>`;
                    });
                    document.getElementById('top-agents').innerHTML = html;
                    
                    // Ostatnie ataki (tabela)
                    html = '';
                    data.recent_attacks.forEach(item => {
                        html += `<tr><td>${formatDate(item.timestamp)}</td><td>${item.attack_name}</td><td>${item.source_ip}</td><td>${item.user_agent ? item.user_agent.substring(0, 40) + '...' : 'N/A'}</td></tr>`;
                    });
                    if (html === '') html = '<tr><td colspan="4">No attacks recorded</td></tr>';
                    document.getElementById('recent-attacks').innerHTML = html;
                    
                    // Ustawienie informacji o czasie ostatniej aktualizacji
                    document.getElementById('last-update').textContent = formatDate(data.last_update);
                })
                .catch(err => console.error('Error fetching stats:', err));
        }
        
        // Pierwsze wywołanie po załadowaniu strony
        updateDashboard();
        // Odświeżanie co 10 sekund
        setInterval(updateDashboard, 10000);
    </script>
</body>
</html>
"""

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def dashboard():
    """
    DASHBOARD ROUTE - główny widok panelu analitycznego

    Endpoint:
      GET /

    Zwraca:
      Wyrenderowany szablon HTML dashboardu.
    """
    # render_template_string renderuje szablon przekazany jako string (HTML_TEMPLATE)
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/stats')
def get_stats():
    """
    STATISTICS API - endpoint REST zwracający statystyki ataków

    Endpoint:
      GET /api/stats

    Zwraca:
      JSON z zagregowanymi statystykami, najczęściej z cache.
    """
    try:
        # Jeżeli cache ma dane, zwracamy je bez odpytywania bazy
        if dashboard_cache['data']:
            return jsonify(dashboard_cache['data'])
        else:
            # Fallback: bezpośrednie pobranie statystyk z bazy
            data = get_attack_stats()
            if 
                # Zapisanie do cache na przyszłość
                dashboard_cache['data'] = data
                dashboard_cache['last_update'] = datetime.utcnow().isoformat()
                return jsonify(data)
            else:
                # W przypadku braku danych zwracamy błąd 500 z informacją
                return jsonify({'error': 'Unable to fetch stats', 'total_attacks': 0}), 500
    except Exception as e:
        # Obsługa nieprzewidzianych wyjątków
        logger.error(f"Błąd w /api/stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/health')
def health():
    """
    HEALTH CHECK ENDPOINT

    Endpoint:
      GET /health

    Zwraca:
      {"status": "healthy"} z kodem 200 – do monitoringu kontenera.
    """
    # Prosta odpowiedź JSON informująca, że serwis działa
    return jsonify({'status': 'healthy'}), 200


# Upewniamy się, że katalog na logi istnieje (jeśli nie, zostanie utworzony)
os.makedirs('/var/log/analytics', exist_ok=True)
# Informacja startowa w logach po uruchomieniu serwisu
logger.info("Starting analytics service...")
