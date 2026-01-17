# Przewodnik wdrożenia produkcyjnego

## Konfiguracja Ubuntu 24.04 LTS

sudo apt update && sudo apt upgrade -y


### Instalacja Dockera

curl -fsSL https://get.docker.com -o get-docker.sh

sudo sh get-docker.sh

sudo usermod -aG docker $USER

newgrp docker


### Konfiguracja zapory (firewall) (opcjonalnie)

sudo ufw enable

sudo ufw allow 22/tcp

sudo ufw allow 8080/tcp

sudo ufw allow 5000/tcp

sudo ufw deny 5432/tcp # Database internal only

sudo ufw status


### Wdrożenie honeypota

git clone https://github.com/barticebowsb/honeypot.git

cd honeypot-project

nano .env # Change all passwords!

docker-compose up -d

### Logi

docker-compose logs <service_name>


**Dostęp do dashboardu**

Otwórz w przeglądarce:

Open: http://localhost:

(albo `http://<adres_serwera>:5000` z innej maszyny)

### Utrzymanie

- Codziennie: sprawdzenie health‑checków, szybki przegląd logów.  
- Tygodniowo: weryfikacja wykrytych ataków, kontrola zajętości dysku.  
- Miesięcznie: test odtwarzania z backupu, aktualizacje systemu i obrazów, audyt konfiguracji bezpieczeństwa.

