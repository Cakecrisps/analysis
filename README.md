# analysis

Скрипты для форензик-анализа журналов событий Windows (`.evtx`) и дампов сетевого трафика (`.pcap`/`.pcapng`).

## Структура репозитория

```
analysis/
├── windowsevents/
│   ├── evtx_to_csv.py     # выгрузка событий EVTX в CSV
│   └── general_scan.py    # расширенный анализ EVTX с поиском аномалий
└── traffic/
    └── general_scan.py    # расширенный анализ PCAP с поиском аномалий
```

## Требования

- Python 3
- [`python-evtx`](https://github.com/williballenthin/python-evtx) (модуль `Evtx`) — для скриптов из `windowsevents/`
- [`pyshark`](https://github.com/KimiNewt/pyshark) (обвязка над `tshark`/Wireshark) — для `traffic/general_scan.py`; для его работы нужен установленный **Wireshark/tshark**

```bash
pip install python-evtx pyshark
```

## windowsevents/evtx_to_csv.py

Разбирает один `.evtx`-файл или все `.evtx`-файлы в папке (рекурсивно) и выгружает записи в единый CSV.

Для каждой записи извлекаются: `EventID`, `TimeCreated`, `Channel`, `Level`, `Computer`, `Provider`, `EventRecordID`, данные о субъекте/цели входа (`SubjectUserName`, `TargetUserName`, `IpAddress`, `LogonID` и т. д.), `ProcessName`, `CommandLine`, а также «сырой» очищенный XML записи.

```bash
python windowsevents/evtx_to_csv.py <путь_к_.evtx_или_папке> <путь_к_.csv>

# Примеры
python windowsevents/evtx_to_csv.py Security.evtx output.csv
python windowsevents/evtx_to_csv.py /path/to/evtx/files/ output.csv
```

## windowsevents/general_scan.py

Более глубокий анализ EVTX-файлов с формированием текстового и JSON-отчётов. Обрабатывает, в частности, следующие категории событий:

| Категория | Event ID |
|---|---|
| Очистка журналов | `1102`, `104`, `108`, `1104` |
| SmartScreen / загрузки файлов | `1003` |
| RDP-сессии | `1149`, `21`–`25` |
| Успешные/неуспешные входы | `4624`, `4625`, `4648`, `4776` |
| Доступ к SMB | `4656`, `4663`, `5140`, `5145` |
| Файловые операции | `4658`, `4660`, `4670`, `4674` |
| WinRM | `4194`, `4195`, `4197`, `4198` |
| WMI | `5857`, `5858`, `5861`, `5862` |
| PowerShell (Script Block Logging) | `4103`, `4104` |
| Создание процессов | `4688` |
| Сетевые подключения | `5156` |

Дополнительно скрипт:

- ищет подозрительные команды PowerShell (`IEX`, `DownloadString`, `-EncodedCommand`, `certutil`, `bitsadmin`, обфускация Base64 и т. п.) и подозрительные паттерны в командных строках (`\Windows\Temp\`, `rundll32`, `mshta`, `regsvr32 scrobj.dll`, `psexec` и др.);
- сопоставляет сетевые подключения со списком известных подозрительных IP (`SUSPICIOUS_IPS` в коде, список нужно адаптировать под себя);
- строит топ-5 IP и пользователей по числу входов, карту «пользователь → IP», с которых он логинился;
- события, которые не удалось разобрать по ожидаемой схеме, попадают в `unhandled_events` — для последующего ручного разбора.

Результат: `evtx_report.txt` (человекочитаемый отчёт) и JSON-файл с полными структурированными данными.

```bash
python windowsevents/general_scan.py <путь_к_.evtx_или_папке> <путь_к_.json>

# Примеры
python windowsevents/general_scan.py Security.evtx output.json
python windowsevents/general_scan.py /path/to/evtx/files/ output.json
```

## traffic/general_scan.py

Анализ одного или нескольких `.pcap`/`.pcapng`-файлов через `pyshark`. Формирует текстовый и JSON-отчёты, включая:

- топ-5 IP-отправителей/получателей, статистику по протоколам, общее число пакетов;
- DNS- и NBNS-запросы, с эвристиками поиска подозрительных доменов (хэшеподобные поддомены `hex_32/40/64`, длинные случайные строки, домены с расширениями `.exe/.dll/.js/.ps1/...`, base64-подобные строки, IP в имени домена, двойные точки, подчёркивания);
- сопоставление IP-адресов трафика со списком известных подозрительных IP (`SUSPICIOUS_IPS`);
- HTTP-запросы к подозрительным доменам;
- попытки входа (login attempts), захваченные в трафике;
- опциональную детализацию по выбранным протоколам.

```bash
python traffic/general_scan.py [-l] [-p http,tcp,nbns] <путь_к_.pcap_или_папке> <путь_к_.json>
```

Флаги:

- `-l` — игнорировать локальные IP-адреса (сети `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) при подсчёте уникальных внешних IP;
- `-p protocol1,protocol2,...` — вывести детализацию по указанным протоколам (например, `http,tcp,nbns`).

```bash
# Примеры
python traffic/general_scan.py capture.pcap output.json
python traffic/general_scan.py -l capture.pcap output.json
python traffic/general_scan.py -p http,tcp,nbns capture.pcap output.json
python traffic/general_scan.py /path/to/pcap/files/ output.json
```

Результат: `pcap_report.txt` и JSON-файл с полными данными (IP, DNS/NBNS-запросы, подозрительные домены/IP, HTTP-запросы, статистика протоколов и т. д.).

## Замечания

- Списки `SUSPICIOUS_IPS` и паттерны подозрительных доменов/команд захардкожены в коде — перед использованием в реальном расследовании их стоит адаптировать под актуальные индикаторы компрометации (IOC).
- Оба `general_scan.py` при обработке множества файлов объединяют данные по всем найденным `.evtx`/`.pcap` файлам в один отчёт.
- Скрипты рассчитаны на построчный / потоковый разбор больших дампов, но не имеют встроенных ограничений по объёму — для очень больших `.pcap`/`.evtx` учитывайте время выполнения и потребление памяти.

## Лицензия

Не указана.
