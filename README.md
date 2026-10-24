# YunoHost Backup Manager – pakiet YunoHost

Pakiet eksperymentalny (nieprzetestowany na działającym YunoHost).

W panelu YunoHost: Aplikacje → Zainstaluj → Niestandardowy adres URL.
Panel YunoHost nie zawsze obsługuje lokalne archiwa ZIP jako źródło.
W takim przypadku pakiet wymaga umieszczenia w repozytorium Git.

Instalacja wymaga oddzielnej domeny (ścieżka /), nie instaluj na domenie
z działającymi już stronami. Usługa działa jako root, ponieważ wywołuje
polecenia tworzenia kopii YunoHost. Nie udostępniaj jej publicznie bez
weryfikacji autoryzacji i zabezpieczeń. Zachowuje istniejące pliki data/
w /opt/yunohost-backup-manager podczas instalacji, ale usunięcie aplikacji
przez YunoHost może usunąć katalog instalacyjny i zapisane hasła.
