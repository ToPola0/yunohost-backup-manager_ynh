# YunoHost Backup Manager — 0.5~ynh3 (wersja testowa)

Pakiet przeznaczony do instalacji przez YunoHost 12.1 z repozytorium Git.

Ważne: aplikacja wykonuje komendy YunoHost jako root. Nie wystawiaj jej publicznie.
Dostęp do panelu ogranicz do administratorów YunoHost.

Panel wymaga osobnej domeny lub wolnej domeny z URL /.
Backend nasłuchuje na 127.0.0.1:5051, aby nie kolidować z ręczną wersją na 5050.
Nowa instalacja tworzy nową bazę magazynów SMB; nie importuje danych z ręcznej instalacji.
Dane trzymane są w katalogu data_dir zarządzanym przez YunoHost.

Skrypty sprawdzono składniowo, nie przetestowano instalacji na żywym YunoHost.
