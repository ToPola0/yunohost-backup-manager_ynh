# YunoHost Backup Manager — 0.5~ynh7 (wersja testowa)

**BIEŻĄCA WERSJA PAKIETU: 0.5~ynh7**

Natywna aplikacja YunoHost 12.1, wykonująca i weryfikująca kopie na udziałach SMB1/SMB2/SMB3.

## Nowości w wersji 0.5~ynh7

- Panel **Aktualizacje aplikacji** pokazuje wersję zainstalowaną i sprawdza wersję w repozytorium GitHub (`main/manifest.toml`).
- Przycisk **Sprawdź aktualizacje**, komunikat o nowej wersji i przycisk **Aktualizuj aplikację** z potwierdzeniem.
- Aktualizacja uruchamia natywne `yunohost app upgrade` z repozytorium GitHub, bez potrzeby ponownego korzystania z PuTTY.
- Aktualizator działa w odrębnym, *tymczasowym* zadaniu systemd wywoływanym przez aplikację, aby przetrwać restart usługi WWW podczas aktualizacji. Nie instaluje dodatkowego stałego serwisu i nie zmienia konfiguracji systemu.
- Aktualizator zapisuje postęp i wynik w katalogu danych aplikacji, obsługuje błędy i zabezpiecza żądanie aktualizacji tokenem CSRF.
- Nie wykonuje aktualizacji w trakcie tworzenia kopii zapasowej.
- Zachowano wszystkie funkcje 0.5~ynh6, w tym obsługę SMB przez `tailscale nc` w ramach aplikacji.

## Jednorazowa aktualizacja z wersji 0.5~ynh5

1. Rozpakuj całe archiwum ZIP i zastąp pliki w gałęzi `main`: https://github.com/ToPola0/yunohost-backup-manager_ynh
2. W PuTTY na YunoHost wykonaj:

   `sudo yunohost app upgrade yunohost-backup-manager --url https://github.com/ToPola0/yunohost-backup-manager_ynh`

3. Otwórz panel `https://strona.rpkj.ovh/backup-manager/` i znajdź sekcję **Aktualizacje aplikacji**.

**Kolejne aktualizacje będą dostępne z poziomu panelu** po publikacji nowej wersji w tym samym repozytorium.

## Uwagi

- Dostęp do aplikacji i jej aktualizatora jest przeznaczony wyłącznie dla administratorów YunoHost.
- Aktualizacja korzysta z istniejącego mechanizmu kopii bezpieczeństwa YunoHost i nie usuwa katalogu danych ani zaszyfrowanych haseł magazynów.
- Żadnych zmian w konfiguracji Proxmox, kontenera, OMV, Tailscale ani sieci.
- Automatyczna aktualizacja nie została jeszcze sprawdzona na docelowym serwerze; należy wykonać pierwszą próbę, gdy pojawi się następna wersja.
