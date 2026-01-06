### Architektura bazy danych

Użyte technologie: Python, PostgreSQL

W rozwiązaniu honeypotowym centralnym komponentem warstwy danych jest serwis `database_service`, który udostępnia instancję bazy PostgreSQL. Pełni on rolę wspólnego magazynu danych dla pozostałych usług, w szczególności dla `honeypot_service` (rejestracja ataków) oraz `analytics_service` (analiza i raportowanie).

Oddzielenie bazy danych od serwisów aplikacyjnych pozwala niezależnie zarządzać kopiami zapasowymi, retencją i politykami dostępu, a także skalować część aplikacyjną bez ingerencji w warstwę danych.

### Model danych (wysokopoziomowo)

W bazie danych utrzymywana jest głównie jedna, domenowa tabela zdarzeń ataków, wykorzystywana przez wszystkie serwisy:

- Tabela zdarzeń ataków (np. `attacks`) – przechowuje metadane każdego zarejestrowanego ataku HTTP (typ ataku, adres IP źródła, nagłówek User-Agent, znaczniki czasu).
- Indeksy wspierające analitykę – tworzone są indeksy na kolumnach czasowych, źródłach ataków i nazwach ataków, aby przyspieszyć zapytania wykorzystywane przez dashboard i raporty.

Dzięki temu zarówno komponent honeypota, jak i analityka operują na wspólnym, spójnym modelu danych.

### Wybrane technologie

- System bazodanowy: PostgreSQL jako relacyjna baza danych typu open-source.
- Konteneryzacja: Uruchomienie bazy w kontenerze (np. Docker), z wykorzystaniem mechanizmu inicjalizacji (`docker-entrypoint-initdb.d`) do automatycznego tworzenia struktury danych.
- Skrypt inicjalizacyjny: Prosty skrypt powłoki (np. `init-db.sh`) realizujący:
  - utworzenie odrębnego użytkownika aplikacyjnego,
  - przygotowanie schematu i tabel,
  - założenie indeksów niezbędnych do analizy.
- Integracja aplikacyjna: Dostęp aplikacji do bazy poprzez typowe biblioteki klienckie PostgreSQL, z wykorzystaniem parametryzowanych zapytań.
