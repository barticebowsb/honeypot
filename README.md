# 🛡️ Projekt Laboratorium Honeypot

**Pelny system honeypot** z detekcja atakow, logowaniem PostgreSQL, i panel analityczny.

![Analytics Dashboard](./analytics.jpg)
---

## 🏗️ Przeglad Architektury

| Usluga | Port | Cel | Status |
|---------|------|---------|--------|
| **Honeypot** | 80 | Detekcja atakow + logowanie | 🟢 Aktywny |
| **Baza danych** | 5432 | Magazyn atakow PostgreSQL | 🟢 Aktywny |
| **Analityka** | 5000 | Panel czasu rzeczywistego | 🟢 Aktywny |

---

## 🧪 Komendy testowania atakow

### 🔪 SQL Injection (3/3 ✅)

| # | Payload | Regex | Komenda |
|---|---------|-------|---------|
| 1 | UNION SELECT | `regex[0]` | `curl -s \"http://localhost/?id=1'+UNION+SELECT+1\\,2\\,3--\"` |
| 2 | OR 1=1 | `regex[1]` | `curl -s \"http://localhost/?login=admin'+OR+'1'='1'\"` |
| 3 | SLEEP() | `regex[7]` | `curl -s \"http://localhost/?id=1;+SLEEP\\(5\\)--\"` |

### 🕷️ Ataki XSS (2/3 ✅)

| # | Payload | Regex | Komenda |
|---|---------|-------|---------|
| 1 | `<img onerror>` | `regex[1]` | `curl -s \"http://localhost/?name=%3Cimg%20src=x%20onerror=alert(1)%3E\"` |
| 2 | `<svg onload>` | `regex[9]` | `curl -s \"http://localhost/?input=%3Csvg%20onload=alert(1)%3E\"` |
| 3 | `%3Cscript` | `regex[4]` | `curl -s \"http://localhost/?data=%3Cscript%3Ealert(1)%3C/script%3E\"` |

### 📁 Path Traversal (5/5 ✅)

| # | Payload | Regex | Komenda |
|---|---------|-------|---------|
| 1 | `../` | `regex[0]` | `curl -s \"http://localhost/?file=../../../etc/passwd\"` |
| 2 | `%2e%2e/` | `regex[1]` | `curl -s \"http://localhost/?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd\"` |
| 3 | `/etc/passwd` | `regex[6]` | `curl -s \"http://localhost/?file=/etc/passwd\"`
