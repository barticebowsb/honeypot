Python/Flask‑owy honeypot HTTP z logowaniem do PostgreSQL i prostym silnikiem wykrywania ataków opartym na regexach.
## Funkcjonalności bezpieczeństwa

Serwis implementuje kilka warstw ochrony, które łącznie zwiększają wiarygodność honeypota i utrudniają nadużycia.

- **Rate limiting** – ograniczanie liczby żądań na minutę z jednego IP, z odpowiedzią HTTP `429` po przekroczeniu limitu.
- **Walidacja danych wejściowych** – funkcja `sanitize_string` usuwa bajty null i ucina zbyt długie ciągi, ograniczając ryzyko DoS i problemów z logami/bazą.
- **Walidacja IP** – proste regexy dopuszczają tylko podstawowe formaty IPv4/IPv6, reszta jest mapowana na `unknown`.  
- **Bezpieczne logowanie do bazy** – wszystkie zapytania SQL używają placeholderów i osobnych parametrów, co jest standardem ochrony przed SQL injection. W praktyce bezpiecznego logowania do bazy, jak opisano w podanym przykładzie, wszystkie zapytania SQL używają placeholderów z osobnymi parametrami – np. SELECT * FROM users WHERE login = ? AND password = ?, gdzie ? to placeholdery, a login i hasło przekazywane są jako oddzielne parametry. Serwer bazy danych (np. PostgreSQL, MySQL z PDO) automatycznie escapuje i waliduje te wartości, blokując próby wstrzyknięcia złośliwego kodu typu SQL injection.
- **Hardening kontenera** – uruchamianie bez uprawnień root i ograniczanie capabilities zgodnie z zaleceniami bezpieczeństwa Pythona i Dockera.


**Mechanizmy:**

- **Wykrywanie ataków:**
  - SQL injection – wzorce fragmentów zapytań SQL, komentarzy i konstrukcji typu `OR 1=1`.
  - XSS – wykrywanie tagów `<script>`, zdarzeń JS (`onload`, `onclick`), schematów `javascript:` oraz typowych funkcji JS.
  - Path traversal – sekwencje `../` i ich zakodowane odpowiedniki oraz odwołania do wrażliwych plików systemowych.


---

## Endpointy HTTP

| Endpoint      | Metody      | Limit/min/IP | Opis                                                                 |
|--------------|------------|-------------|----------------------------------------------------------------------|
| `/health`    | `GET`      | 100         | Prosty check zdrowia serwisu, używany w monitoringu.                |
| `/`          | `GET,POST` | 60          | Główny honeypot; wykrywa SQLi/XSS/path traversal, loguje do pliku/DB. |
| `/admin`     | `GET,POST` | 30          | Fałszywy panel administracyjny; wszystkie próby wejścia są logowane.|
| `/api/users` | `GET`      | 40          | Fałszywe API REST do wykrywania enumeracji API.                     |
| `*` (404)    | dowolna    | —           | Każda nieistniejąca ścieżka jest logowana jako próba enumeracji.    |

Każde żądanie przechodzące przez endpoint chroniony dekoratorem `rate_limit` jest liczone w słowniku w pamięci per klucz `IP:YYYY-MM-DD HH:MM`.
Wykryte ataki oraz wybrane podejrzane akcje (np. wejście na `/admin`) trafiają do tabeli `attacks` w bazie PostgreSQL, skąd można je analizować w zewnętrznych narzędziach.

## Logowanie i analiza

Serwis zapisuje logi w dwóch miejscach:

- **Plik**: `/var/log/honeypot/honeypot.log` – logi tekstowe w formacie zbliżonym do JSON (jeden wpis na linię).  
- **Baza danych**: tabela `attacks` – dane do analityki, raportów, korelacji z SIEM i budowy dashboardów (np. w Grafanie/Kibanie).

