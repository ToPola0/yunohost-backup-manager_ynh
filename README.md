# YunoHost Backup Manager **0.5~ynh21**

## Postęp pojedynczych części archiwum

- Każda kopia ma **jeden** katalog na udziale SMB; wszystkie `tar.000000.part`, `tar.000001.part` itd., metadane oraz raport znajdują się bezpośrednio w tym samym katalogu.
- Zakładka „Kopie zapasowe” pokazuje nazwę katalogu, każdą część, jej rozmiar, bieżący etap i rzeczywisty procent transferu lub odczytu SHA256.
- Po wznowieniu poprawne części są oznaczone jako „Już poprawna — pominięta”, a brakujące lub uszkodzone jako „Wysyłanie” i następnie „Wysłana i sprawdzona”.
- Przycisk anulowania, raporty, przywracanie i obsługa archiwów starszego typu pozostają bez zmian.
- Nie dokonano żadnych zmian poza kodem wtyczki.

Przykład katalogu na SMB:

```text
Archiwum/yunohost/ybm_KGW_20261024_120739_7fc92b/
  tar.000000.part
  tar.000001.part
  tar.000002.part
  info.000000.part
  report.json
  complete.json
```

`pending.json` jest przejściowym plikiem stanu, usuwanym po poprawnym zakończeniu operacji. `complete.json` powstaje dopiero po sprawdzeniu całej kopii.

---

# YunoHost Backup Manager **0.5~ynh20**

## Nowość: niezawodne przesyłanie dużych kopii w częściach

- Każda nowa kopia trafia do osobnego folderu na udział SMB.
- Archiwum jest przesyłane w częściach po **256 MiB**, bez tworzenia lokalnych duplikatów `.tar`.
- Po zerwaniu połączenia wtyczka **automatycznie ponawia próby** (5–60 s) i za każdym razem weryfikuje części SHA256 przed pominięciem lub ponownym przesłaniem.
- Stan zadania zapisuje wyłącznie w katalogu danych wtyczki i automatycznie wznawia transfer po restarcie usługi.
- Dopiero po pełnym odczycie kontrolnym wszystkich części i zapisaniu raportu publikuje `complete.json`. Wcześniej kopia nie pojawia się na liście gotowych archiwów.
- W panelu znajduje się przycisk **„Przerwij przesyłanie kopii”**. Anulowanie zatrzymuje próby, ale pozostawia lokalne archiwum do kontroli.
- Przywracanie pobiera części z kontrolą SHA256 i składa je w oryginalne pliki `.tar` oraz `.info.json` YunoHost.
- Przywracanie, przeglądanie raportów i usuwanie kopii obsługuje zarówno nowy format, jak i starsze archiwa `.tar`.
- Nie zmienia konfiguracji YunoHost, Tailscale, OMV, Proxmoxa ani systemowego crona.

### Układ pojedynczej nowej kopii na SMB

```text
Archiwum/yunohost/ybm_Balchan_20261024_113000_abcdef/
  tar.000000.part
  tar.000001.part
  ...
  info.000000.part
  report.json
  complete.json   # pojawia się wyłącznie po pełnej weryfikacji
```

### Ważne ograniczenia

- YunoHost najpierw tworzy lokalne `.tar`, dlatego konieczne jest miejsce na jedno archiwum lokalne; nie powstaje drugi plik podczas dzielenia.
- Automatyczne wznowienie po restarcie dotyczy **etapu transferu gotowego archiwum**. Przerwanej w połowie operacji `yunohost backup create` nie uruchamia się automatycznie ponownie, aby nie ryzykować uszkodzenia archiwum.
- Przywracanie nadal wymaga wolnego miejsca na pełne archiwum, a działania wewnątrz YunoHost nie są automatycznie ponawiane po błędzie.
- Pliki częściowo przesłane pozostają na SMB jako robocze dane do wznowienia, ale **nie są prezentowane jako kompletne kopie**.

---

# YunoHost Backup Manager **0.5~ynh19**

## Nowość: odnośnik powrotny do YunoHost

- Kliknięcie napisu **YunoHost** w górnym lewym rogu panelu otwiera panel administracyjny pod adresem `/yunohost/admin/` na tej samej domenie.
- Link jest dostępny z klawiatury, ma wyraźne wyróżnienie po najechaniu i działa także na telefonie.
- Pozostałe funkcje kopii, przywracania, magazynów, harmonogramów oraz aktualizacji nie zostały zmienione.

---

# YunoHost Backup Manager **0.5~ynh18**

## Nowości: usuwanie archiwów bezpośrednio z panelu

- W zakładce **Kopie zapasowe** wybierz magazyn i zaznacz archiwum; przycisk **Usuń wybraną kopię** jest obok **Przywróć wybraną kopię**.
- Pojawia się okno potwierdzenia z nazwą archiwum i magazynu. Operacja wymaga wpisania **USUŃ**.
- Usuwane są **tylko pliki wybranego archiwum** na wskazanym magazynie: `.report.json`, `.info.json` i `.tar` (o ile występują). Nie są usuwane inne kopie, aplikacje YunoHost ani dane magazynu.
- Gdy trwa backup, przywracanie albo aktualizacja, usuwanie jest blokowane. Dodatkowa ochrona CSRF, walidacja nazwy archiwum i jednorazowy token żądania.
- Jeśli na SMB wystąpi błąd przy usuwaniu, operacja zostaje przerwana i wyświetla szczegóły. Archiwum `.tar` jest usuwane jako ostatnie, aby wcześniejszy błąd nie skasował właściwej zawartości kopii.
- Funkcja korzysta z istniejących połączeń SMB1/SMB2/SMB3 i przekierowania Tailscale wewnątrz wtyczki. Nie zmienia konfiguracji systemu, OMV, sieci ani Tailscale.
- Pozostałe możliwości wersji 0.5~ynh17 pozostają bez zmian.

---

# YunoHost Backup Manager **0.5~ynh17**

## Nowości: raport wykonania każdej kopii

- Dla nowo tworzonych kopii na SMB obok plików `<archiwum>.tar` i `<archiwum>.info.json` zapisywany jest **`<archiwum>.report.json`** — zapisany wraz z danym archiwum raport wykonania.
- Raport zawiera aplikacje, datę, historię etapów tworzenia, przesyłania i weryfikacji, rozmiar obu plików oraz ich **rzeczywiste sumy SHA256** potwierdzone przez ponowny odczyt z SMB. Także plik raportu jest odczytywany po wysłaniu i porównywany sumą SHA256.
- Kliknięcie archiwum w zakładce **Kopie zapasowe** otwiera okno jego raportu bez pobierania całego `.tar`. Można też zaznaczyć archiwum do przywrócenia radioprzyciskiem.
- Lokalna kopia YunoHost jest usuwana dopiero po zapisaniu i weryfikacji raportu na SMB. Jeśli publikacja raportu nie powiedzie się, operacja kończy się błędem, a lokalne archiwum nie jest celowo usuwane.
- Przy nieudanych operacjach raport błędu zapisywany jest lokalnie w katalogu **danych wtyczki**, jeżeli nadano już nazwę archiwum; brak łączności z SMB może uniemożliwić dołączenie go do zdalnej kopii.
- **Archiwa z poprzednich wersji nie otrzymują sztucznego potwierdzenia**: panel pokazuje „Brak raportu. Nie można potwierdzić historycznej weryfikacji SHA256”.
- Raport potwierdza integralność w chwili wykonania kopii, a **nie aktualną integralność w momencie przywracania**. Bez zmian pozostaje standardowa procedura przywracania YunoHost.
- Modyfikacje są ograniczone wyłącznie do plików wtyczki; bez zmian systemowych, sieci, OMV, Tailscale i Proxmoxa.

---

## Historia: 0.5~ynh16 — poprzednia wersja

**BIEŻĄCA WERSJA PAKIETU: 0.5~ynh20**

## Zmiany w 0.5~ynh16 — ponowna instalacja i Harmonogram (cron)

- **Aktualizacja / naprawa:** panel pozwala ponownie zainstalować dokładnie tę samą wersję z repozytorium GitHub, nawet gdy aplikacja jest aktualna. Wykorzystywana jest natywna komenda YunoHost `app upgrade --force` i dotychczasowy log oraz kontrola wyniku. Starsze wersje nie są instalowane automatycznie. Aktualizacja nowszej wersji działa jak dotychczas.
- **Nowa kategoria „Harmonogram (cron)”** w lewym menu. Obsługuje wiele zadań, zapis pięciopolowy cron, wygodne ustawienia codziennie/tygodniowo/miesięcznie, wybór istniejącego magazynu i aplikacji, włączanie, wyłączanie, edycję i usuwanie zadań.
- **Wbudowany harmonogram** działa wewnątrz działającej usługi aplikacji, nie edytuje crontaba systemowego, nie modyfikuje innych usług ani konfiguracji systemu. Zadania są zapisywane w istniejącej bazie SQLite w katalogu danych wtyczki. Aktualizacja ich nie kasuje.
- **Bezpieczne pomijanie kolizji:** jeżeli trwa tworzenie lub przywracanie kopii albo aktualizacja, zaplanowana kopia nie startuje. Wynik ostatniego uruchomienia/pominięcia i termin następnego są widoczne w tabeli. Ponowny start panelu w tej samej minucie nie uruchamia zadania dwukrotnie.
- Harmonogram działa, gdy usługa aplikacji jest uruchomiona; pominięte terminy w czasie wyłączenia nie są uruchamiane wstecz. Czas to lokalna strefa serwera YunoHost. Wersja nadal wymaga testu na docelowym serwerze.

## Zmiany w 0.5~ynh15 — kopie i przywracanie jak w Proxmox

W zakładce **Kopie zapasowe** znajduje się jeden wspólny panel:

1. Wybór magazynu SMB/CIFS, odświeżanie i przegląd jego istniejących archiwów.
2. Tabela kopii z nazwą, datą, rzeczywistym rozmiarem, nazwami aplikacji z `.info.json` i stanem kompletności.
3. **+ Nowa kopia** otwiera formularz wyboru aplikacji, a **Przywróć wybraną kopię** otwiera podgląd archiwum z listą aplikacji.
4. Przywracanie wymaga świadomego potwierdzenia `PRZYWRÓĆ`. Pobiera oba pliki (`.tar` i `.info.json`) z wybranego magazynu, pokazuje postęp pobierania i rzeczywisty log przywracania YunoHost. Nie usuwa zdalnego archiwum.
5. Tworzenie i przywracanie korzystają ze wspólnej blokady — nie mogą działać równolegle ani z aktualizacją wtyczki.
6. YunoHost **nie przywraca aplikacji na już zainstalowaną instancję**. Takie aplikacje są oznaczone na liście, a przywracanie jest bezpiecznie blokowane. Wtyczka nigdy nie odinstalowuje ich automatycznie.
7. Po udanej operacji lokalnie pobrane pliki są usuwane, a w razie niepowodzenia zostają do analizy/próby naprawy. Żadne istniejące lokalne archiwum nie jest nadpisywane.
8. Zachowano trzy kategorie w menu: Magazyn, Kopie zapasowe, Aktualizacja. Ikona pozostaje dołączona do pakietu.

**Uwaga:** To wersja testowa. Przeprowadzono testy lokalne z emulowanym SMB oraz symulowane interakcje w przeglądarce. Przywracania prawdziwej instalacji YunoHost nie testowano i należy je najpierw przeprowadzić na środowisku testowym. Wtyczka nie zmienia konfiguracji Proxmoxa, Tailscale, OMV ani systemu poza operacjami wykonywanymi przez YunoHost na żądanie użytkownika.

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
