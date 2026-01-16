# Analytics Service – Honeypot Dashboard

Serwis analityczny wyświetlający statystyki z honeypota HTTP w formie prostego dashboardu WWW, zasilanego danymi z bazy PostgreSQL (tabela `attacks`).

---

## 1. Cel i architektura

Analytics Service jest lekką aplikacją Flask, która:

- Łączy się z tą samą bazą PostgreSQL, z której korzysta `honeypot_service`.  
- Cyklowo agreguje statystyki ataków (w tle, w osobnym wątku).  
- Udostępnia:
  - ciemny dashboard HTML pod `/`,  
  - API JSON pod `/api/stats`,  
  - prosty health‑check pod `/health`.  

Dzięki cache’owaniu danych w pamięci dashboard można odświeżać w przeglądarce co 10 sekund bez nadmiernego obciążania bazy.

Struktura katalogu:

- `app.py` – aplikacja Flask, logika cache, agregacja statystyk i szablon HTML.  
- `Dockerfile` – kontener z serwisem analitycznym.  
- `requirements.txt` – zależności Pythona.  

---

## 2. Dane wejściowe – tabela `attacks`

Serwis zakłada istnienie tabeli `attacks` w bazie (tworzonej przez `sql_utils.py` z honeypot_service). Struktura:

TABLE attacks

id SERIAL PRIMARY KEY

attack_name VARCHAR(100) NOT NULL

source_ip VARCHAR(45) NOT NULL

user_agent VARCHAR(1024)

timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP


Na tej tabeli wykonywane są zapytania agregujące (COUNT, GROUP BY, ORDER BY, LIMIT), zgodne z typowym podejściem do analizy logów ataków.

---

## 3. Funkcje i agregacje

### 3.1. Łączenie z bazą

Funkcja `get_db_connection()` używa `psycopg2` oraz zmiennych środowiskowych `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_PORT` do nawiązania połączenia z PostgreSQL.

### 3.2. Statystyki ataków

Funkcja `get_attack_stats()` wykonuje pięć głównych zapytań:

1. **Łączna liczba ataków** – `SELECT COUNT(*) FROM attacks`.  
2. **Ataki wg typu** (TOP 10) – `GROUP BY attack_name ORDER BY count DESC`.  
3. **Najczęstsze IP** (TOP 20) – `GROUP BY source_ip ORDER BY count DESC`.  
4. **Najczęstsze user‑agenty** (TOP 15) – `GROUP BY user_agent ORDER BY count DESC WHERE user_agent IS NOT NULL`.  
5. **Ostatnie ataki** (50 ostatnich rekordów) – sortowanie po `timestamp DESC`.  

Wynik zwracany jest jako słownik, który następnie jest cache’owany i serwowany jako JSON do dashboardu.

### 3.3. Cache w pamięci

Obiekt `dashboard_cache` przechowuje:

- `data` – ostatnio obliczone statystyki,  
- `last_update` – znacznik czasu aktualizacji.  

Wątek tła (`update_cache`) odświeża te dane co 30 sekund. Przeglądarka wywołuje `/api/stats` co 10 sekund, ale w większości przypadków dane są zwracane prosto z cache, co znacząco zmniejsza liczbę realnych zapytań do bazy.

---

## 4. Endpointy HTTP

| Endpoint      | Metody | Opis                                                                 |
|--------------|--------|----------------------------------------------------------------------|
| `/`          | GET    | Główny dashboard HTML (ciemny motyw, auto‑odświeżanie JS).           |
| `/api/stats` | GET    | API zwracające dane w formacie JSON dla dashboardu.                  |
| `/health`    | GET    | Proste sprawdzenie zdrowia serwisu (status 200, `{"status":"healthy"}`). |

Dashboard używa wbudowanego szablonu HTML/CSS (bez zewnętrznych bibliotek) i prostego skryptu JS do cyklicznego pobierania danych z `/api/stats` i odświeżania widoku tabel oraz kart.

---

## 5. Konfiguracja i uruchomienie

### 5.1. Zmienne środowiskowe

Serwis korzysta z tych samych zmiennych co honeypot:

- `DB_HOST` – host PostgreSQL (np. `db`).  
- `DB_USER` – użytkownik bazy (najlepiej z ograniczonymi uprawnieniami tylko do odczytu).  
- `DB_PASSWORD` – hasło do bazy.  
- `DB_NAME` – nazwa bazy (np. `honeypot_db`).  
- `DB_PORT` – port PostgreSQL (domyślnie `5432`).  

Stosowanie zmiennych środowiskowych ułatwia współpracę z Dockerem i narzędziami orkiestracji.

### 5.2. Uruchomienie

Wejdź na `http://localhost:5000/` aby zobaczyć dashboard (lub inny port, jeśli zmieniony w konfiguracji Flask/Docker).

W środowisku kontenerowym typowy scenariusz to jeden serwis `honeypot_service` zapisujący do bazy i drugi `analytics_service`, który z tej samej bazy czyta dane do wizualizacji.

---

## 6. Logowanie i monitoring

- Logi aplikacji zapisywane są do pliku `/var/log/analytics/analytics.log` oraz na stdout (widoczne w logach Dockera).  
- Endpoint `/health` ułatwia integrację z systemem monitoringu / orkiestratorem (np. Kubernetes liveness/readiness probe).

---
