"""
BEZPIECZNE NARZĘDZIA BAZODANOWE - moduł zapytań z parametrami
=============================================================
Moduł dostarcza BEZPIECZNE operacje na bazie z użyciem zapytań parametryzowanych.
To podstawowa linia obrony przed atakami SQL injection.

ZASADA KLUCZOWA:
Nigdy nie łącz bezpośrednio danych użytkownika z tekstem SQL!
Zawsze używaj placeholderów (%s) i osobnego przekazania parametrów.
"""

import psycopg2
from psycopg2 import sql
import logging

logger = logging.getLogger(__name__)


def init_database(db_host, db_user, db_password, db_name, db_port='5432'):
    """
    INIT_DATABASE - inicjalizacja schematu bazy przy pierwszym uruchomieniu
    =========================================================================
    Cel:
    Tworzy wymaganą tabelę oraz indeksy w PostgreSQL.
    Funkcja jest idempotentna – można ją bezpiecznie uruchamiać wielokrotnie.

    Schemat:
    Tabela attacks:
      - id (SERIAL PRIMARY KEY)
      - attack_name (VARCHAR 100)  – typ ataku
      - source_ip (VARCHAR 45)     – adres IP atakującego
      - user_agent (VARCHAR 1024)  – informacje o kliencie/skanerze
      - timestamp (TIMESTAMP)      – czas zdarzenia
      - created_at (TIMESTAMP)     – czas utworzenia rekordu

    Indeksy:
      - idx_attacks_timestamp (zapytania po czasie)
      - idx_attacks_source_ip (analiza źródeł ataków)
      - idx_attacks_attack_name (statystyki typów ataków)

    Bezpieczeństwo:
      - Z góry ograniczone długości pól
      - Timestamp ustawiany po stronie bazy (nie przez klienta)
    """
    try:
        conn = psycopg2.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            port=db_port,
            connect_timeout=5
        )
        cursor = conn.cursor()

        # Tworzenie tabeli attacks, jeśli nie istnieje
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id SERIAL PRIMARY KEY,
                attack_name VARCHAR(100) NOT NULL,
                source_ip VARCHAR(45) NOT NULL,
                user_agent VARCHAR(1024),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Indeks po czasie (nowsze rekordy łatwiej wyszukiwać)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_attacks_timestamp 
            ON attacks(timestamp DESC);
        """)
        # Indeks po IP
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_attacks_source_ip 
            ON attacks(source_ip);
        """)
        # Indeks po typie ataku
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_attacks_attack_name 
            ON attacks(attack_name);
        """)

        conn.commit()
        cursor.close()
        conn.close()

        logger.info("Baza danych została poprawnie zainicjalizowana")
        return True

    except Exception as e:
        logger.error(f"Błąd inicjalizacji bazy danych: {e}")
        return False


def safe_log_attack(attack_name, source_ip, user_agent, db_host, db_user,
                    db_password, db_name, db_port='5432'):
    """
    SAFE_LOG_ATTACK - bezpieczne logowanie ataków do bazy
    =====================================================
    Cel:
    Zapisuje wykryte ataki przy użyciu zapytań parametryzowanych, co
    minimalizuje ryzyko SQL injection nawet przy logowaniu złośliwych danych.

    Niebezpieczny sposób (PRZYKŁAD, CZEGO NIE ROBIĆ):
        query = f"INSERT INTO attacks VALUES ('{attack_name}', '{source_ip}')"
        cursor.execute(query)  # podatne na SQL injection

    Bezpieczny sposób (stosowany tutaj):
        query = "INSERT INTO attacks (attack_name, source_ip, user_agent) VALUES (%s, %s, %s)"
        cursor.execute(query, (attack_name, source_ip, user_agent))

    Dlaczego to działa:
    - Struktura zapytania SQL jest zdefiniowana statycznie
    - Dane są przekazywane osobno i odpowiednio escapowane przez driver
    - Nawet jeśli wartości zawierają słowa kluczowe SQL, są traktowane jak tekst

    Dodatkowa sanityzacja:
    - attack_name: ucięte do 100 znaków
    - source_ip: ucięte do 45 znaków (IPv6)
    - user_agent: ucięte do 1024 znaków lub None

    Chroni przed:
    ✓ SQL injection w logowaniu
    ✓ Przepełnieniem pól
    ✓ Nadmiernym rozrostem danych w bazie
    """
    try:
        conn = psycopg2.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            port=db_port,
            connect_timeout=5
        )
        cursor = conn.cursor()

        # Zapytanie parametryzowane - struktura i dane rozdzielone
        query = sql.SQL("""
            INSERT INTO attacks (attack_name, source_ip, user_agent)
            VALUES (%s, %s, %s)
        """)

        # Parametry przekazywane osobno (kluczowe z punktu widzenia bezpieczeństwa)
        cursor.execute(query, (
            str(attack_name)[:100],            # dopasowanie do wielkości kolumny
            str(source_ip)[:45],               # maksymalna długość IPv6
            str(user_agent)[:1024] if user_agent else None
        ))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Zalogowano atak: {attack_name} z IP {source_ip}")
        return True

    except Exception as e:
        logger.error(f"Błąd logowania ataku do bazy: {e}")
        return False


def get_attacks(db_host, db_user, db_password, db_name, limit=100, db_port='5432'):
    """
    GET_ATTACKS - pobieranie zarejestrowanych ataków z bazy
    =======================================================
    Cel:
    Zwraca listę ostatnich ataków na potrzeby panelu analitycznego lub
    raportowania. Zapytania są parametryzowane (również LIMIT).

    Zapytanie:
        SELECT id, attack_name, source_ip, user_agent, timestamp
        FROM attacks
        ORDER BY timestamp DESC
        LIMIT %s

    Zwraca:
    Listę słowników z danymi ataków; w przypadku błędu – pustą listę.

    Wydajność:
    - Wykorzystuje indeks po timestamp
    - Parametryzowany LIMIT uniemożliwia wstrzyknięcie SQL

    Obsługa błędów:
    - Wyjątki są logowane
    - Funkcja zwraca pustą listę, aby nie zatrzymywać aplikacji
    """
    try:
        conn = psycopg2.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            port=db_port,
            connect_timeout=5
        )
        cursor = conn.cursor()

        query = sql.SQL("""
            SELECT id, attack_name, source_ip, user_agent, timestamp
            FROM attacks 
            ORDER BY timestamp DESC 
            LIMIT %s
        """)

        cursor.execute(query, (limit,))

        columns = [desc[0] for desc in cursor.description]
        attacks = [dict(zip(columns, row)) for row in cursor.fetchall()]

        cursor.close()
        conn.close()

        return attacks

    except Exception as e:
        logger.error(f"Błąd pobierania ataków z bazy: {e}")
        return []
