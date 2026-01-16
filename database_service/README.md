# Database Service – PostgreSQL dla Honeypota

Ten serwis dostarcza instancję PostgreSQL oraz skrypt inicjalizacyjny `init-db.sh`, który tworzy użytkownika aplikacyjnego z ograniczonymi uprawnieniami oraz tabelę `attacks` wykorzystywaną przez `honeypot_service` i `analytics_service`.

---

## 1. Rola serwisu

`database_service` pełni funkcję centralnego magazynu danych dla całego rozwiązania honeypot:

- przechowuje wszystkie zarejestrowane ataki HTTP w tabeli `attacks`,  
- udostępnia konto `honeypot_user` z minimalnym zakresem uprawnień,  
- automatycznie tworzy schemat i indeksy potrzebne do analityki.

Dzięki oddzieleniu bazy od serwisów aplikacyjnych można łatwiej zarządzać backupami, retencją logów oraz polityką dostępu.

---

## 2. Skrypt `init-db.sh`

Skrypt jest uruchamiany wewnątrz kontenera PostgreSQL (np. przez mechanizm `docker-entrypoint-initdb.d`), kiedy baza startuje po raz pierwszy.

Główne kroki:

1. **Tworzenie użytkownika aplikacyjnego**  
   - `CREATE USER honeypot_user WITH PASSWORD 'SecurePass123!'`  
   - użytkownik ten służy wyłącznie do obsługi aplikacji honeypot/analytics, a nie do administrowania bazą.

2. **Nadanie minimalnych uprawnień**  
   - `GRANT CONNECT ON DATABASE ...` – pozwala na samo połączenie z bazą.  
   - `GRANT USAGE ON SCHEMA public` – umożliwia korzystanie ze schematu `public`.  
   - `GRANT CREATE ON SCHEMA public` – opcjonalnie pozwala tworzyć obiekty w schemacie (można usunąć, jeśli aplikacja nie tworzy tabel).

3. **Tworzenie tabeli `attacks`**  
   Tabela przechowuje podstawowe informacje o każdym ataku:

id SERIAL PRIMARY KEY

attack_name VARCHAR(100) NOT NULL

source_ip VARCHAR(45) NOT NULL

user_agent VARCHAR(1024)

timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP


Pola i ich rozmiary są dobrane pod typowe dane ruchu HTTP (IP, UA, nazwa ataku).

4. **Tworzenie indeksów**  
- `idx_attacks_timestamp` – przyspiesza zapytania „ostatnie ataki” używane w dashboardzie.  
- `idx_attacks_source_ip` – ułatwia analizy źródeł ataków.  
- `idx_attacks_attack_name` – ułatwia statystyki wg typu ataku.

5. **Nadawanie uprawnień do tabeli**  
- `ALTER TABLE attacks OWNER TO honeypot_user` – ustawienie właściciela.  
- `GRANT SELECT, INSERT, UPDATE ON attacks TO honeypot_user` – aplikacja może czytać, wstawiać i aktualizować, ale nie kasować rekordów ani modyfikować struktury tabeli (zasada najmniejszych uprawnień).[web:19]  
- `GRANT USAGE, SELECT ON SEQUENCE attacks_id_seq` – umożliwia korzystanie z sekwencji klucza głównego przy INSERT.[web:15]

---

## 3. Zmiana hasła i użytkownika

W środowisku produkcyjnym zalecane jest:

- użycie innego hasła niż domyślne `SecurePass123!`,  
- przechowywanie hasła w mechanizmie secretów Dockera / Kubernetesa,  
- utrzymywanie spójności między:
- wartością hasła w `init-db.sh`,  
- zmiennymi `DB_USER` / `DB_PASSWORD` w `honeypot_service` i `analytics_service`.[web:19]

Aby zmienić użytkownika lub hasło:

1. Zaktualizuj odpowiednie linie w `init-db.sh`.  
2. Zaktualizuj zmienne środowiskowe w pozostałych serwisach.  
3. Przy pierwszym starcie nowej instancji bazy skrypt utworzy użytkownika z nową konfiguracją.

---

## 4. Uruchomienie w Dockerze


Przy pierwszym starcie bazy skrypt utworzy użytkownika, tabelę i indeksy, a kolejne restarty nie będą duplikować obiektów dzięki `IF NOT EXISTS`.

---

## 5. Bezpieczeństwo

Najważniejsze założenia bezpieczeństwa w `database_service`:

- rozdzielenie kont admina (`POSTGRES_USER`) i konta aplikacyjnego (`honeypot_user`),  
- minimalne uprawnienia dla aplikacji (brak DDL, brak DELETE),  
- brak twardo zakodowanych poświadczeń w kodzie aplikacji – aplikacje korzystają z `DB_USER` i `DB_PASSWORD` przekazywanych przez zmienne środowiskowe.

W połączeniu z parametryzowanymi zapytaniami w warstwie aplikacji (`psycopg2` + placeholdery `%s`) zapewnia to rozsądną podstawę do obrony przed SQL injection i nadużyciami po stronie bazy.
