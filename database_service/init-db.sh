#!/bin/bash
# Skrypt inicjalizacji bazy danych dla honeypota
# Tworzy użytkownika z ograniczonymi uprawnieniami, tabelę attacks i indeksy

set -e  # Zakończ skrypt natychmiast, jeśli którekolwiek polecenie zwróci błąd

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL

    -- Utworzenie użytkownika aplikacyjnego z ograniczonymi uprawnieniami
    -- Ten użytkownik będzie używany przez honeypot_service oraz analytics_service
    CREATE USER honeypot_user WITH PASSWORD 'SecurePass123!';
    -- Upewnienie się, że hasło jest ustawione (idempotentne nadanie hasła)
    ALTER USER honeypot_user WITH PASSWORD 'SecurePass123!';
    
    -- Nadanie minimalnych uprawnień zgodnie z zasadą najmniejszych uprawnień
    -- Pozwalamy użytkownikowi jedynie łączyć się z bazą i korzystać ze schematu public
    GRANT CONNECT ON DATABASE $POSTGRES_DB TO honeypot_user;
    GRANT USAGE ON SCHEMA public TO honeypot_user;
    -- Zezwalamy na tworzenie obiektów (tabel) w schemacie public, jeśli będzie to potrzebne
    GRANT CREATE ON SCHEMA public TO honeypot_user;
    
    -- Utworzenie głównej tabeli do logowania ataków, jeśli jeszcze nie istnieje
    CREATE TABLE IF NOT EXISTS attacks (
        id SERIAL PRIMARY KEY,                       -- unikalny identyfikator rekordu
        attack_name VARCHAR(100) NOT NULL,          -- nazwa/typ ataku (SQLi, XSS itd.)
        source_ip VARCHAR(45) NOT NULL,             -- adres IP źródła ataku (IPv4/IPv6)
        user_agent VARCHAR(1024),                   -- identyfikator klienta / skanera
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- czas wykrycia ataku
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- czas utworzenia rekordu
    );
    
    -- Utworzenie indeksów przyspieszających typowe zapytania analityczne
    -- Indeks po czasie zdarzenia: szybkie zapytania typu "najświeższe ataki"
    CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp DESC);
    -- Indeks po IP: analizy najaktywniejszych adresów / korelacja z SIEM
    CREATE INDEX IF NOT EXISTS idx_attacks_source_ip ON attacks(source_ip);
    -- Indeks po typie ataku: statystyki i agregacje per attack_name
    CREATE INDEX IF NOT EXISTS idx_attacks_attack_name ON attacks(attack_name);
    
    -- Nadanie ograniczonych uprawnień do tabeli attacks
    -- Ustawiamy właściciela tabeli na honeypot_user, aby uniknąć nadmiarowych uprawnień innych kont
    ALTER TABLE attacks OWNER TO honeypot_user;
    -- Użytkownik aplikacyjny może tylko odczytywać, wstawiać i aktualizować rekordy (bez DELETE/DDL)
    GRANT SELECT, INSERT, UPDATE ON attacks TO honeypot_user;
    -- Zezwalamy na korzystanie z sekwencji klucza głównego (id) przy wstawianiu rekordów
    GRANT USAGE, SELECT ON SEQUENCE attacks_id_seq TO honeypot_user;

EOSQL

# Informacyjny komunikat na stdout – ułatwia debug w logach kontenera
echo "Database initialization complete"
