# Honeypot Service – Attack Detection Engine

Python/Flask‑owy honeypot HTTP z logowaniem do PostgreSQL i prostym silnikiem wykrywania ataków opartym na regexach.

---

## 1. Architektura i przegląd

Honeypot składa się z lekkiej aplikacji Flask uruchamianej w kontenerze Docker oraz bazy PostgreSQL do przechowywania zarejestrowanych zdarzeń. 
Aplikacja nasłuchuje na porcie `8080` i udostępnia kilka endpointów imitujących panel administracyjny oraz API, których głównym celem jest przyciąganie skanerów i pentesterów.

**Główne komponenty:**

- `app.py` – serwis webowy (Flask), silnik wykrywania ataków, rate limiting, logowanie do pliku i bazy.  
- `sql_utils.py` – bezpieczne funkcje dostępu do PostgreSQL (zapytania parametryzowane). 
- `Dockerfile` – obraz aplikacji z dobrymi praktykami bezpieczeństwa kontenera (non‑root, fs read‑only). 
- `requirements.txt` – zależności Pythona (Flask, psycopg2 itd.).

---

## 2. Funkcjonalności bezpieczeństwa

Serwis implementuje kilka warstw ochrony, które łącznie zwiększają wiarygodność honeypota i utrudniają nadużycia.

**Mechanizmy:**

- **Wykrywanie ataków:**
  - SQL injection – wzorce fragmentów zapytań SQL, komentarzy i konstrukcji typu `OR 1=1`.
  - XSS – wykrywanie tagów `<script>`, zdarzeń JS (`onload`, `onclick`), schematów `javascript:` oraz typowych funkcji JS.
  - Path traversal – sekwencje `../` i ich zakodowane odpowiedniki oraz odwołania do wrażliwych plików systemowych.
- **Rate limiting** – ograniczanie liczby żądań na minutę z jednego IP, z odpowiedzią HTTP `429` po przekroczeniu limitu.
- **Walidacja danych wejściowych** – funkcja `sanitize_string` usuwa bajty null i ucina zbyt długie ciągi, ograniczając ryzyko DoS i problemów z logami/bazą.
- **Walidacja IP** – proste regexy dopuszczają tylko podstawowe formaty IPv4/IPv6, reszta jest mapowana na `unknown`.  
- **Bezpieczne logowanie do bazy** – wszystkie zapytania SQL używają placeholderów i osobnych parametrów, co jest standardem ochrony przed SQL injection. W praktyce bezpiecznego logowania do bazy, jak opisano w podanym przykładzie, wszystkie zapytania SQL używają placeholderów z osobnymi parametrami – np. SELECT * FROM users WHERE login = ? AND password = ?, gdzie ? to placeholdery, a login i hasło przekazywane są jako oddzielne parametry. Serwer bazy danych (np. PostgreSQL, MySQL z PDO) automatycznie escapuje i waliduje te wartości, blokując próby wstrzyknięcia złośliwego kodu typu SQL injection.
- **Hardening kontenera** – uruchamianie bez uprawnień root i ograniczanie capabilities zgodnie z zaleceniami bezpieczeństwa Pythona i Dockera.

---

## 3. Endpointy HTTP

| Endpoint      | Metody      | Limit/min/IP | Opis                                                                 |
|--------------|------------|-------------|----------------------------------------------------------------------|
| `/health`    | `GET`      | 100         | Prosty check zdrowia serwisu, używany w monitoringu.                |
| `/`          | `GET,POST` | 60          | Główny honeypot; wykrywa SQLi/XSS/path traversal, loguje do pliku/DB. |
| `/admin`     | `GET,POST` | 30          | Fałszywy panel administracyjny; wszystkie próby wejścia są logowane.|
| `/api/users` | `GET`      | 40          | Fałszywe API REST do wykrywania enumeracji API.                     |
| `*` (404)    | dowolna    | —           | Każda nieistniejąca ścieżka jest logowana jako próba enumeracji.    |

Każde żądanie przechodzące przez endpoint chroniony dekoratorem `rate_limit` jest liczone w słowniku w pamięci per klucz `IP:YYYY-MM-DD HH:MM`.
Wykryte ataki oraz wybrane podejrzane akcje (np. wejście na `/admin`) trafiają do tabeli `attacks` w bazie PostgreSQL, skąd można je analizować w zewnętrznych narzędziach.

---

## 4. Model danych i baza

Baza PostgreSQL zawiera główną tabelę:

TABLE attacks

id SERIAL PRIMARY KEY

attack_name VARCHAR(100) NOT NULL

source_ip VARCHAR(45) NOT NULL

user_agent VARCHAR(1024)

timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP


Tworzone są indeksy:

- `idx_attacks_timestamp` na `timestamp DESC` – szybkie zapytania po czasie.  
- `idx_attacks_source_ip` – analizy źródeł ataków i korelacja z SIEM.  
- `idx_attacks_attack_name` – statystyki typów ataków.  

Funkcja `init_database()` w `sql_utils.py` tworzy tabelę i indeksy w sposób idempotentny, więc może być bezpiecznie wywoływana przy starcie systemu.

---

## 5. Konfiguracja i uruchomienie

### Zmienne środowiskowe

Aplikacja używa następujących zmiennych środowiskowych:

- `DB_HOST` – host PostgreSQL (np. `db`).  
- `DB_USER` – użytkownik z ograniczonymi uprawnieniami.  
- `DB_PASSWORD` – hasło (z pliku `.env` lub managera sekretów).  
- `DB_NAME` – nazwa bazy (np. `honeypot_db`).  
- `DB_PORT` – port PostgreSQL (domyślnie `5432`).  

Taki sposób konfiguracji jest zgodny z dobrymi praktykami bezpieczeństwa i ułatwia deploy w różnych środowiskach.

---

## 6. Logowanie i analiza

Serwis zapisuje logi w dwóch miejscach:

- **Plik**: `/var/log/honeypot/honeypot.log` – logi tekstowe w formacie zbliżonym do JSON (jeden wpis na linię).  
- **Baza danych**: tabela `attacks` – dane do analityki, raportów, korelacji z SIEM i budowy dashboardów (np. w Grafanie/Kibanie).


---
