# YunoHost Backup Manager — 0.5~ynh10 (wersja testowa)

**BIEŻĄCA WERSJA PAKIETU: 0.5~ynh10**

## Co nowego w 0.5~ynh10

- W panelu aktualizacji wyświetla się **podgląd prawdziwego logu YunoHost na żywo**, z możliwością skopiowania komunikatów.
- Podczas instalacji aktualizacji działa **animowany pasek aktywności**. Nie pokazuje fikcyjnego procentu; po zakończeniu zmienia się w komunikat sukcesu lub błędu.
- Podgląd aktualizacji odtwarza stan i historię po restarcie usługi WWW. Log jest przechowywany wyłącznie w katalogu danych aplikacji.
- Panel wyświetla przygotowaną ikonę aplikacji, dołączoną do pakietu. Nie wymaga modyfikacji konfiguracji YunoHost.
- Zachowano magazyny SMB, szyfrowane hasła oraz aktualizator YunoHost.

**Aktualizacja:** wgraj wszystkie pliki archiwum do gałęzi `main` w repozytorium `https://github.com/ToPola0/yunohost-backup-manager_ynh`, następnie wybierz w zainstalowanym panelu **Sprawdź aktualizacje → Aktualizuj aplikację**.

**Uwaga:** log na żywo i pasek aktywności będą dostępne od uruchomienia wersji 0.5~ynh10, czyli podczas *następnej* aktualizacji. Przy przejściu z 0.5~ynh9 stary panel nadal korzysta ze starego mechanizmu wyświetlania.

## Historia zmian

## Poprawka w wersji 0.5~ynh9

- Naprawiono zapisywanie magazynu SMB2/SMB3, gdy wskazany podkatalog już istnieje. Wcześniej `smbclient.mkdir()` zgłaszał `SMBOSError: [Errno 17] File exists`, mimo poprawnego testu odczytu i zapisu.
- Kod akceptuje jedynie błąd `EEXIST`, następnie sprawdza dostęp do katalogu; inne błędy nadal przerywają operację.
- Poprawiono numer wersji wyświetlany w nagłówku panelu.
- Zachowano dane magazynów, hasła i mechanizm aktualizacji aplikacji.
- Poprawki obejmują tylko pliki wtyczki, bez zmiany systemu, sieci, Tailscale, Proxmoxa ani OMV.

## Poprawka w wersji 0.5~ynh8

- Poprawiono test odczytu i zapisu SMB2/SMB3 na serwerach dostępnych przez Tailscale `userspace-networking`.
- Każde wywołanie biblioteki `smbclient` używa portu lokalnego przekierowania zamiast domyślnego `127.0.0.1:445` (również tworzenie katalogów, zapis, odczyt, usuwanie i zamknięcie sesji).
- Zachowano obsługę SMB1, zapisane magazyny, dane, automatyczny aktualizator i szyfrowane hasła.
- Nie zmieniono konfiguracji systemowej, Proxmoxa, OMV, sieci ani Tailscale.

## Funkcje wbudowane od wersji 0.5~ynh7

- Panel **Aktualizacje aplikacji** pokazuje wersję zainstalowaną i sprawdza wersję w repozytorium GitHub (`main/manifest.toml`).
- Przycisk **Sprawdź aktualizacje**, komunikat o nowej wersji i przycisk **Aktualizuj aplikację** z potwierdzeniem.
- Aktualizacja uruchamia natywne `yunohost app upgrade` z repozytorium GitHub, bez potrzeby ponownego korzystania z PuTTY.
- Aktualizator działa w odrębnym, *tymczasowym* zadaniu systemd wywoływanym przez aplikację, aby przetrwać restart usługi WWW podczas aktualizacji. Nie instaluje dodatkowego stałego serwisu i nie zmienia konfiguracji systemu.
- Aktualizator zapisuje postęp i wynik w katalogu danych aplikacji, obsługuje błędy i zabezpiecza żądanie aktualizacji tokenem CSRF.
- Nie wykonuje aktualizacji w trakcie tworzenia kopii zapasowej.
- Zachowano wszystkie funkcje 0.5~ynh6, w tym obsługę SMB przez `tailscale nc` w ramach aplikacji.

## Aktualizacja z wersji 0.5~ynh8

1. Rozpakuj całe archiwum ZIP i zastąp pliki w gałęzi `main`: https://github.com/ToPola0/yunohost-backup-manager_ynh
2. W panelu wtyczki wybierz **Sprawdź aktualizacje**, a następnie **Aktualizuj aplikację**. Nie odinstalowuj jej.

3. Otwórz panel `https://strona.rpkj.ovh/backup-manager/` i znajdź sekcję **Aktualizacje aplikacji**.

**Kolejne aktualizacje są dostępne z poziomu panelu** po publikacji nowej wersji w tym samym repozytorium.

## Uwagi

- Dostęp do aplikacji i jej aktualizatora jest przeznaczony wyłącznie dla administratorów YunoHost.
- Aktualizacja korzysta z istniejącego mechanizmu kopii bezpieczeństwa YunoHost i nie usuwa katalogu danych ani zaszyfrowanych haseł magazynów.
- Żadnych zmian w konfiguracji Proxmox, kontenera, OMV, Tailscale ani sieci.
- Automatyczna aktualizacja nie została jeszcze sprawdzona na docelowym serwerze; należy wykonać pierwszą próbę, gdy pojawi się następna wersja.
