# YunoHost Backup Manager — 0.5~ynh13 (wersja testowa)

**BIEŻĄCA WERSJA PAKIETU: 0.5~ynh13**

## Zmiany w 0.5~ynh13

1. **Postęp tworzenia kopii:** animowany pasek pracy podczas szacowania i tworzenia archiwum YunoHost; przy wysyłaniu i weryfikacji danych SMB rzeczywisty procent oraz liczba przetworzonych MiB.
2. **Dziennik kopii:** widoczny pod przyciskiem „Wykonaj kopię”, automatycznie uzupełniany o nazwy plików i etapy. Po zakończeniu pasek jest zielony, przy błędzie czerwony.
3. **Aktualizacja z menu aplikacji:** ulepszona weryfikacja numeru wersji na dysku i w działającym panelu. Fałszywy sukces lub niepodmienione pliki zostaną zgłoszone jako błąd.
4. **Weryfikacja SHA256:** sumy kontrolne danych wysłanych i odczytanych z SMB są porównywane przed usunięciem kopii lokalnej.
5. **Bez zmian poza wtyczką:** konfiguracja Proxmoxa, kontenera, Tailscale i OMV pozostaje nienaruszona.

### Aktualizacja

Po opublikowaniu całej paczki w gałęzi `main` repozytorium użyj w panelu **Sprawdź aktualizacje → Aktualizuj aplikację**. Sprawdź w panelu numer wersji po ukończeniu operacji; sam komunikat YunoHost „SUCCESS” nie jest dowodem, że uruchomiony panel został zmieniony.

## Zmiany w 0.5~ynh11

1. **Ikona YunoHost:** pliki `icon.png` i `doc/logo.png` znajdują się w repozytorium; skrypty instalacji i aktualizacji rejestrują ikonę w uprawnieniu `yunohost-backup-manager.main` przez oficjalne polecenie YunoHost. Ikona jest także widoczna w nagłówku panelu aplikacji.
2. **Ścieżka magazynu:** lista magazynów i wybór miejsca docelowego pokazują `Udział/Podkatalog`, np. `Archiwum/yunohost` (o ile podkatalog jest podany).
3. **Postęp importu:** przy imporcie listy aplikacji z JSON panel wyświetla animowany pasek pracy i log rzeczywistych etapów (liczba wczytanych wpisów, walidacja na serwerze, wynik, odświeżenie). Bez fikcyjnego procentu.
4. **Rozpoznawalna nazwa archiwum:** nowo tworzone archiwa YunoHost zawierają czytelne nazwy wybranych aplikacji, datę oraz krótki identyfikator unikatowy, np. `ybm_Balchan-KGW_20261024_061000_9a5c32.tar`. Nazwy są pobierane z listy aplikacji YunoHost; identyfikatory aplikacji zapisuje również plik metadanych `.info.json`. Długie listy otrzymują skróconą nazwę z liczbą dodatkowych aplikacji i sumą kontrolną. Plik `.info.json` ma taką samą nazwę bazową.

**Dotychczasowe archiwa pozostają bez zmian.** Dane magazynów i hasła nie są usuwane podczas aktualizacji.

### Aktualizacja

Rozpakuj ZIP i wgraj wszystkie jego pliki do głównego katalogu repozytorium `https://github.com/ToPola0/yunohost-backup-manager_ynh` (gałąź `main`). Następnie w panelu aplikacji wybierz **Sprawdź aktualizacje → Aktualizuj aplikację**.

Żadna poprawka nie wymaga ręcznych zmian w konfiguracji YunoHost, Proxmox, OMV ani Tailscale. Skrypty pakietu modyfikują jedynie zasoby i metadane własnej aplikacji w ramach standardowej instalacji/aktualizacji YunoHost.

---

## Poprzednie zmiany

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
