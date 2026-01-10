# Architektura Analytics Service – Honeypot Dashboard

Serwis analityczny dostarcza prosty dashboard WWW do wizualizacji statystyk ataków z honeypota HTTP, korzystając z danych przechowywanych w bazie PostgreSQL.

## Użyte Technologie

- **Język programowania**: Python 3.x – lekki i elastyczny do budowania serwisów webowych i przetwarzania danych.
- **Framework webowy**: Flask – minimalny framework do tworzenia API i stron HTML z routingiem.
- **Klient bazy**: psycopg2 – adapter Pythona do połączeń z PostgreSQL via zmienne środowiskowe (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT).
- **Serwer WSGI**: Gunicorn – do produkcyjnego uruchamiania Flask w kontenerach Docker.
- **Konteneryzacja**: Docker – do pakowania serwisu z zależnościami (requirements.txt: Flask==3.0.0, psycopg2-binary==2.9.9, Werkzeug==3.0.1, gunicorn==22.0.0).

## Komponenty Architektury

Analytics Service składa się z trzech głównych endpointów obsługujących dashboard, API i health-check:

| Endpoint     | Opis                                      |
|--------------|-------------------------------------------|
| `/`          | Dashboard HTML (ciemny motyw, auto-odświeżanie JS). |
| `/api/stats` | Dane JSON ze statystykami ataków.         |
| `/health`    | Sprawdzenie stanu serwisu.                |

Dashboard odczytuje dane z tej samej bazy PostgreSQL co honeypot_service, agregując statystyki bez bezpośredniego obciążania bazy dzięki cache w pamięci RAM.

## Logika Przepływu Danych

1. Serwis łączy się z PostgreSQL i cyklicznie (wątek tła) pobiera/agreguje statystyki ataków: liczba całkowita, top typy ataków, IP źródłowe, user-agenty, ostatnie zdarzenia.
2. Dane cache'owane w pamięci (słownik z timestampem) – odświeżanie co 30s, serwowanie co 10s z cache bez zapytań do bazy.
3. Frontend JS pobiera JSON z `/api/stats`, renderuje karty i tabele na dashboardzie.
4. Logi zapisywane na stdout i do pliku dla monitoringu.

## Deployment i Skalowalność

- Uruchomienie lokalne: `python app.py` (port 5000).
- Produkcyjne: Docker + Gunicorn, zmienne środowiskowe dla konfiguracji DB.
- Skalowalność: Read-only user DB, cache minimalizuje zapytania.

## Aspekty bezpieczeństwa

- Serwis dostepny tylko z dozwolonych adresów IP na dedykowanym porcie
- Serwis nie korzysta z urzytkownika root bazy danych
