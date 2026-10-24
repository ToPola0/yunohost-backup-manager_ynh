# YunoHost Backup Manager — 0.5~ynh5 (wersja testowa)

**BIEŻĄCA WERSJA PAKIETU: 0.5~ynh5**

Natywny pakiet aplikacji YunoHost Backup Manager dla YunoHost 12.1, instalowany z repozytorium GitHub poprzez panel YunoHost.

## Zmiany w tej wersji (0.5~ynh5)

- Poprawiono skrypty instalacji, aktualizacji, usuwania i przywracania: zastąpiono wywołania `ynh_add_nginx_config` / `ynh_add_systemd_config` funkcjami `ynh_config_add_nginx` / `ynh_config_add_systemd` oraz odpowiednikami do usuwania.
- Zachowano instalację w podkatalogu istniejącej domeny, np. `/backup-manager` (wprowadzoną w 0.5~ynh4).
- Port usługi: tylko lokalne `127.0.0.1:5051`.

## Instalacja

W panelu YunoHost wybierz instalację aplikacji z niestandardowego repozytorium Git:

https://github.com/ToPola0/yunohost-backup-manager_ynh

Ustaw domenę, ścieżkę `/backup-manager` i dostęp wyłącznie dla grupy administratorów.

## Ważne

- Panel wykonuje operacje administracyjne YunoHost jako `root`; **nie udostępniaj go publicznie**.
- Dane i zaszyfrowane poświadczenia SMB przechowywane są w katalogu danych zarządzanym przez YunoHost.
- Nowa instalacja nie importuje automatycznie magazynów SMB z wcześniejszej instalacji ręcznej.
- Pakiet sprawdzono pod względem składni, ale **nie potwierdzono jeszcze pomyślnej instalacji na działającym YunoHost**.
