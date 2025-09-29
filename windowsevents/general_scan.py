#!/usr/bin/env python3
# general_scan.py
import sys
import os
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
import xml.etree.ElementTree as ET
import json as json_lib  # чтобы не перепутать с json.dump

# --- Конфигурация ---
SUSPICIOUS_IPS = {
    "185.130.5.12", "45.155.205.233", "104.21.16.198", "209.99.64.10", "198.51.100.1"
}

# Подозрительные команды PowerShell
SUSPICIOUS_POWERSHELL_COMMANDS = [
    r'downloadstring', r'downloadfile', r'iex', r'invoke-expression', r'invoke-webrequest',
    r'net user', r'net localgroup', r'net group', r'netsh', r'certutil', r'bitsadmin',
    r'reg add', r'reg delete', r'cmd /c', r'cmd /k', r'cmd /r', r'at -s', r'schtasks',
    r'wmi', r'winrm', r'enable-psremoting', r'invoke-command', r'get-credential',
    r'frombase64string', r'tobase64string', r'convertto-securestring', r'add-content',
    r'out-file', r'copy-item', r'move-item', r'remove-item', r'set-content',
    r'new-object', r'comobject', r'wscript', r'shell.application', r'activexobject',
    r'get-process', r'stop-process', r'start-process', r'invoke-item',
    r'get-service', r'stop-service', r'start-service', r'set-service'
]

# Подозрительные паттерны в командах
SUSPICIOUS_COMMAND_PATTERNS = [
    r'\\windows\\temp\\', r'\\users\\public\\', r'\\appdata\\', r'\\programdata\\',
    r'powershell.*-encodedcommand', r'powershell.*-executionpolicy', r'powershell.*-nop',
    r'powershell.*-noninteractive', r'powershell.*-windowstyle hidden',
    r'cmd.exe.*/c', r'cmd.exe.*/k', r'cmd.exe.*/r', r'rundll32.*dll', r'mshta',
    r'regsvr32.*scrobj.dll', r'wmic', r'at.exe', r'psexec', r'winexe'
]


# --- Вспомогательные функции ---

def get_evtx_files(input_path):
    """Возвращает список EVTX файлов из указанного пути (файл или папка)"""
    if os.path.isfile(input_path) and input_path.lower().endswith('.evtx'):
        return [input_path]
    elif os.path.isdir(input_path):
        evtx_files = []
        for root, dirs, files in os.walk(input_path):
            for file in files:
                if file.lower().endswith('.evtx'):
                    evtx_files.append(os.path.join(root, file))
        return evtx_files
    else:
        return []


def extract_xml_from_evtx_record(raw_xml):
    """Извлекает чистый XML из сырых данных записи EVTX"""
    try:
        # Убираем лишние пробелы и переносы строк
        cleaned = raw_xml.strip()
        return cleaned
    except Exception:
        return raw_xml


def parse_xml_string(xml_string):
    """Безопасно парсит XML строку"""
    try:
        return ET.fromstring(xml_string)
    except ET.ParseError:
        # Пытаемся исправить возможные проблемы с XML
        fixed_xml = xml_string.replace('&', '&amp;').replace('<', '<').replace('>', '>')
        try:
            return ET.fromstring(fixed_xml)
        except ET.ParseError:
            return None


def extract_event_data(record_xml):
    """Извлекает данные из XML записи события"""
    root = parse_xml_string(record_xml)
    if root is None:
        return None

    event_data = {}

    # Пробуем найти с namespace
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    # Ищем EventData или UserData
    event_data_elem = root.find('.//e:EventData', ns) or root.find('.//e:UserData', ns)
    if event_data_elem is not None:
        for elem in event_data_elem:
            name = elem.get('Name') or elem.tag.split('}')[-1]  # Убираем namespace
            event_data[name] = elem.text or elem.attrib.get('Value', '')

    # Ищем System
    system_elem = root.find('.//e:System', ns)
    if system_elem is not None:
        for elem in system_elem:
            tag = elem.tag.split('}')[-1]
            event_data[f"System_{tag}"] = elem.text or elem.attrib.get('Value', '')

    # --- Дополнительно: обработка UserData с EventXML (например, EventID 1149) ---
    user_data_elem = root.find('.//e:UserData', ns)
    if user_data_elem is not None:
        event_xml = user_data_elem.find('.//{Event_NS}EventXML')
        if event_xml is not None:
            for param in event_xml:
                param_name = param.tag.split('}')[-1]  # Убираем namespace
                event_data[param_name] = param.text or ''

    return event_data


def classify_suspicious_powershell_command(command):
    """Классифицирует подозрительные PowerShell команды"""
    reasons = []
    command_lower = command.lower()

    for pattern in SUSPICIOUS_POWERSHELL_COMMANDS:
        if re.search(pattern, command_lower, re.IGNORECASE):
            reasons.append(f"опасная_команда_{pattern}")

    for pattern in SUSPICIOUS_COMMAND_PATTERNS:
        if re.search(pattern, command_lower, re.IGNORECASE):
            reasons.append(f"подозрительный_паттерн_{pattern}")

    return reasons


def analyze_single_evtx_file(evtx_path):
    """Анализирует один EVTX файл и возвращает собранные данные"""
    print(f"[INFO] Анализируем файл: {evtx_path}")

    # Структуры данных
    login_attempts = []  # [(username, ip, time, event_id, port, domain, logon_id, file)]
    failed_logins = []  # [(username, ip, time, reason, domain, logon_id, file)]
    rdp_sessions = []  # [(username, ip, time, event_id, session_id, file)]
    smb_accesses = []  # [(user, file_path, access_mask, time, event_id, file)]
    file_actions = []  # [(user, file_path, action, time, event_id, file)]
    file_downloads = []  # [(user, file_path, size, time, event_id, file)]
    log_clearing_events = []  # [(user, channel, time, event_id, file)]
    unhandled_events = []  # [{"xml": raw_xml, "event_id": event_id, "file": filename}]
    powershell_commands = []  # [(command, time, user, reasons)]
    process_creations = []  # [(process, user, time, command_line, logon_id)]
    network_connections = []  # [(process, local_ip, remote_ip, time)]
    winrm_accesses = []  # [(user, time, event_id, file)]
    wmi_queries = []  # [(user, query, time, event_id, file)]
    suspicious_events = []  # [(event_id, time, description)]

    try:
        with Evtx(evtx_path) as log:
            for i, record in enumerate(log.records()):
                try:
                    # Получаем XML содержимое записи
                    raw_xml = record.xml()
                    if not raw_xml.strip():
                        continue

                    record_xml = extract_xml_from_evtx_record(raw_xml)

                    # Извлекаем данные события
                    event_data = extract_event_data(record_xml)
                    if not event_data:
                        continue

                    # Получаем время события
                    timestamp = str(record.timestamp())

                    # Извлекаем ID события
                    event_id = event_data.get('EventID', event_data.get('System_EventID', ''))
                    event_id = str(event_id)

                    # --- События, которые мы **пытаемся обработать**, но **XML не соответствует** ---
                    # Список ID, которые мы обрабатываем
                    handled_event_ids = {
                        '1102', '104', '108', '1104',  # очистка логов
                        '1003',  # SmartScreen
                        '1149', '21', '22', '23', '24', '25',  # RDP
                        '4624', '4625', '4648', '4776',  # входы
                        '4656', '4663', '5140', '5145',  # SMB
                        '4658', '4660', '4670', '4674',  # файлы
                        '4194', '4195', '4197', '4198',  # WinRM
                        '5857', '5858', '5861', '5862',  # WMI
                        '4103', '4104',  # PowerShell
                        '4688',  # процессы
                        '5156'  # сеть
                    }

                    # --- События очистки логов: 1102, 104, 108, 1104 ---
                    if event_id in ['1102', '104', '108', '1104']:
                        # Извлекаем имя пользователя, канал и т.д.
                        user = event_data.get('SubjectUserName', 'N/A')
                        channel = event_data.get('Channel', 'N/A') or event_data.get('System_Channel', 'N/A')

                        log_event_info = {
                            'user': user,
                            'channel': channel,
                            'time': timestamp,
                            'event_id': event_id,
                            'file': os.path.basename(evtx_path)
                        }
                        log_clearing_events.append(log_event_info)

                    # --- SmartScreen: EventID 1003 (файлы, проверенные SmartScreen) ---
                    elif event_id == '1003':
                        # В Data содержится JSON-строка
                        data_str = event_data.get('Data', '')
                        if data_str:
                            try:
                                smart_data = json_lib.loads(data_str)
                                path = smart_data.get('path', 'N/A')
                                size = smart_data.get('size', 'N/A')
                                execution_time = smart_data.get('executionTime', 'N/A')
                                event_type = smart_data.get('$type', 'N/A')

                                if path != 'N/A':
                                    file_download_info = {
                                        'user': 'N/A',  # SmartScreen не указывает пользователя напрямую
                                        'file_path': path,
                                        'size': size,
                                        'execution_time': execution_time,
                                        'type': event_type,
                                        'time': timestamp,
                                        'event_id': event_id,
                                        'file': os.path.basename(evtx_path)
                                    }
                                    file_downloads.append(file_download_info)
                                else:
                                    # XML не соответствует ожидаемому формату
                                    unhandled_events.append({
                                        'xml': raw_xml,
                                        'event_id': event_id,
                                        'file': os.path.basename(evtx_path)
                                    })
                            except json_lib.JSONDecodeError:
                                # JSON в Data не распознан — сохраняем XML
                                unhandled_events.append({
                                    'xml': raw_xml,
                                    'event_id': event_id,
                                    'file': os.path.basename(evtx_path)
                                })
                        else:
                            # Data пустое — сохраняем XML
                            unhandled_events.append({
                                'xml': raw_xml,
                                'event_id': event_id,
                                'file': os.path.basename(evtx_path)
                            })

                    # --- RDP: EventID 1149 ---
                    elif event_id == '1149':
                        username = event_data.get('Param1', '')
                        ip_address = event_data.get('Param3', 'N/A')
                        session_id = 'N/A'

                        if username:
                            rdp_info = {
                                'username': username,
                                'ip': ip_address,
                                'session_id': session_id,
                                'time': timestamp,
                                'event_id': event_id,
                                'file': os.path.basename(evtx_path)
                            }
                            rdp_sessions.append(rdp_info)
                        else:
                            # XML не соответствует ожидаемому формату
                            unhandled_events.append({
                                'xml': raw_xml,
                                'event_id': event_id,
                                'file': os.path.basename(evtx_path)
                            })

                    # --- Все остальные события ---
                    elif event_id in handled_event_ids:
                        # Проверяем, были ли извлечены какие-либо поля
                        if not event_data:
                            # XML не соответствует ожидаемому формату
                            unhandled_events.append({
                                'xml': raw_xml,
                                'event_id': event_id,
                                'file': os.path.basename(evtx_path)
                            })

                    # --- Остальные события (не обрабатываемые) ---
                    # Пропускаем их, если не входят в `handled_event_ids`

                except Exception as e:
                    # print(f"[WARNING] Ошибка при обработке записи {i} в файле {evtx_path}: {e}")
                    continue

    except Exception as e:
        print(f"[ERROR] Ошибка при чтении EVTX файла {evtx_path}: {e}")
        return None

    return {
        'login_attempts': login_attempts,
        'failed_logins': failed_logins,
        'rdp_sessions': rdp_sessions,
        'smb_accesses': smb_accesses,
        'file_actions': file_actions,
        'file_downloads': file_downloads,
        'log_clearing_events': log_clearing_events,
        'unhandled_events': unhandled_events,
        'powershell_commands': powershell_commands,
        'process_creations': process_creations,
        'network_connections': network_connections,
        'winrm_accesses': winrm_accesses,
        'wmi_queries': wmi_queries,
        'suspicious_events': suspicious_events
    }


def main(input_path, json_output_path):
    evtx_files = get_evtx_files(input_path)

    if not evtx_files:
        print(f"[ERROR] Не найдено EVTX файлов в: {input_path}")
        return

    print(f"[INFO] Найдено {len(evtx_files)} EVTX файлов для анализа")
    print(f"[INFO] Выходной JSON файл: {json_output_path}")

    # Объединяем данные из всех файлов
    all_login_attempts = []
    all_failed_logins = []
    all_rdp_sessions = []
    all_smb_accesses = []
    all_file_actions = []
    all_file_downloads = []
    all_log_clearing_events = []
    all_unhandled_events = []
    all_powershell_commands = []
    all_process_creations = []
    all_network_connections = []
    all_winrm_accesses = []
    all_wmi_queries = []
    all_suspicious_events = []

    for evtx_file in evtx_files:
        file_data = analyze_single_evtx_file(evtx_file)
        if file_data:
            all_login_attempts.extend(file_data['login_attempts'])
            all_failed_logins.extend(file_data['failed_logins'])
            all_rdp_sessions.extend(file_data['rdp_sessions'])
            all_smb_accesses.extend(file_data['smb_accesses'])
            all_file_actions.extend(file_data['file_actions'])
            all_file_downloads.extend(file_data['file_downloads'])
            all_log_clearing_events.extend(file_data['log_clearing_events'])
            all_unhandled_events.extend(file_data['unhandled_events'])
            all_powershell_commands.extend(file_data['powershell_commands'])
            all_process_creations.extend(file_data['process_creations'])
            all_network_connections.extend(file_data['network_connections'])
            all_winrm_accesses.extend(file_data['winrm_accesses'])
            all_wmi_queries.extend(file_data['wmi_queries'])
            all_suspicious_events.extend(file_data['suspicious_events'])

    # --- Генерация отчёта ---

    report_lines = []

    report_lines.append("=" * 70)
    report_lines.append("📊 РАСШИРЕННЫЙ АНАЛИЗ .EVTX ФАЙЛОВ")
    report_lines.append("=" * 70)
    report_lines.append(f"📁 Всего обработано файлов: {len(evtx_files)}")
    for file_path in evtx_files:
        report_lines.append(f"📄 {file_path}")
    report_lines.append(f"🌐 Найдено успешных входов: {len(all_login_attempts)}")
    report_lines.append(f"❌ Найдено неудачных входов: {len(all_failed_logins)}")
    report_lines.append(f"🖥️ Найдено RDP-сессий: {len(all_rdp_sessions)}")
    report_lines.append(f"📁 Найдено SMB-доступов: {len(all_smb_accesses)}")
    report_lines.append(f"📄 Найдено файловых действий: {len(all_file_actions)}")
    report_lines.append(f"📥 Найдено загрузок (SmartScreen): {len(all_file_downloads)}")
    report_lines.append(f"🗑️ Найдено очисток логов: {len(all_log_clearing_events)}")
    report_lines.append(f"🔧 Найдено PowerShell команд: {len(all_powershell_commands)}")
    report_lines.append(f"⚙️ Найдено созданий процессов: {len(all_process_creations)}")
    report_lines.append(f"🌐 Найдено сетевых подключений: {len(all_network_connections)}")
    report_lines.append(f"📡 Найдено WinRM-доступов: {len(all_winrm_accesses)}")
    report_lines.append(f"🔍 Найдено WMI-запросов: {len(all_wmi_queries)}")
    report_lines.append(f"⚠️ Найдено необработанных событий: {len(all_unhandled_events)}")

    # Все логины построчно
    if all_login_attempts:
        report_lines.append(f"\n📋 Все успешные входы:")
        for login in all_login_attempts:
            report_lines.append(
                f"   [⏰{login['time']}] [IP: {login['ip']}:{login['port']}] [User: {login['username']}@{login['domain']}] "
                f"[LogonID: {login['logon_id']}] [EventID: {login['event_id']}] [File: {login['file']}]")

    # Все RDP-сессии
    if all_rdp_sessions:
        report_lines.append(f"\n🖥️ Все RDP-сессии:")
        for rdp in all_rdp_sessions:
            report_lines.append(
                f"   [⏰{rdp['time']}] [User: {rdp['username']}] [IP: {rdp['ip']}] [SessionID: {rdp['session_id']}] "
                f"[EventID: {rdp['event_id']}] [File: {rdp['file']}]")

    # Все SMB-доступы
    if all_smb_accesses:
        report_lines.append(f"\n📁 Все SMB-доступы:")
        for smb in all_smb_accesses:
            report_lines.append(
                f"   [⏰{smb['time']}] [User: {smb['user']}] [File: {smb['file_path']}] [IP: {smb['ip']}] [Access: {smb['access_mask']}] "
                f"[EventID: {smb['event_id']}] [File: {smb['file']}]")

    # Все файловые действия
    if all_file_actions:
        report_lines.append(f"\n📄 Все файловые действия:")
        for f in all_file_actions:
            report_lines.append(
                f"   [⏰{f['time']}] [User: {f['user']}] [File: {f['file_path']}] [Action: {f['action']}] [Access: {f['access']}] "
                f"[EventID: {f['event_id']}] [File: {f['file']}]")

    # Все загрузки (SmartScreen)
    if all_file_downloads:
        report_lines.append(f"\n📥 Все загрузки (SmartScreen):")
        for f in all_file_downloads:
            report_lines.append(
                f"   [⏰{f['time']}] [File: {f['file_path']}] [Size: {f['size']}] [Type: {f['type']}] "
                f"[EventID: {f['event_id']}] [File: {f['file']}]")

    # Все очистки логов
    if all_log_clearing_events:
        report_lines.append(f"\n🗑️ Все очистки логов:")
        for log_event in all_log_clearing_events:
            report_lines.append(
                f"   [⏰{log_event['time']}] [User: {log_event['user']}] [Channel: {log_event['channel']}] "
                f"[EventID: {log_event['event_id']}] [File: {log_event['file']}]")

    # Все необработанные события
    if all_unhandled_events:
        report_lines.append(f"\n⚠️ Необработанные события (XML):")
        for unhandled in all_unhandled_events[:10]:  # Показываем первые 10
            report_lines.append(
                f"   [EventID: {unhandled['event_id']}] [File: {unhandled['file']}]")

    # Все WinRM-доступы
    if all_winrm_accesses:
        report_lines.append(f"\n📡 Все WinRM-доступы:")
        for winrm in all_winrm_accesses:
            report_lines.append(
                f"   [⏰{winrm['time']}] [User: {winrm['user']}] [EventID: {winrm['event_id']}] [File: {winrm['file']}]")

    # Все WMI-запросы
    if all_wmi_queries:
        report_lines.append(f"\n🔍 Все WMI-запросы:")
        for wmi in all_wmi_queries:
            report_lines.append(
                f"   [⏰{wmi['time']}] [User: {wmi['user']}] [Query: {wmi['query']}] [EventID: {wmi['event_id']}] [File: {wmi['file']}]")

    # Все неудачные попытки построчно
    if all_failed_logins:
        report_lines.append(f"\n❌ Все неудачные попытки входа:")
        for login in all_failed_logins:
            report_lines.append(
                f"   [⏰{login['time']}] [IP: {login['ip']}] [User: {login['username']}@{login['domain']}] "
                f"[LogonID: {login['logon_id']}] [Reason: {login['failure_reason']}] [EventID: {login['event_id']}] [File: {login['file']}]")

    # Топ-5 IP с которых пытались войти
    ip_login_counter = Counter()
    for login in all_login_attempts:
        ip_login_counter[login['ip']] += 1

    top_login_ips = ip_login_counter.most_common(5)
    if top_login_ips:
        report_lines.append("\n📈 ТОП-5 IP с которых были входы:")
        for ip, count in top_login_ips:
            report_lines.append(f"   {ip}: {count} раз")

    # Топ-5 пользователей с входами
    user_login_counter = Counter()
    for login in all_login_attempts:
        user_login_counter[login['username']] += 1

    top_login_users = user_login_counter.most_common(5)
    if top_login_users:
        report_lines.append("\n👤 ТОП-5 пользователей с входами:")
        for user, count in top_login_users:
            report_lines.append(f"   {user}: {count} раз")

    # Подключения к пользователям по IP
    if all_login_attempts:
        report_lines.append(f"\n📋 Подключения к пользователям по IP:")

        # Группируем логины по пользователю
        user_ip_mapping = defaultdict(Counter)
        for login in all_login_attempts:
            user_ip_mapping[login['username']][login['ip']] += 1

        # Выводим для каждого пользователя список IP
        for user, ip_counts in user_ip_mapping.items():
            report_lines.append(f"   Пользователь: {user}")
            for ip, count in ip_counts.most_common():
                report_lines.append(f"      • {ip} ({count} подключений)")
            report_lines.append("")  # Пустая строка для разделения

    # Подозрительные PowerShell команды
    if all_powershell_commands:
        report_lines.append(f"\n⚠️ Подозрительные PowerShell команды:")
        for cmd in all_powershell_commands:
            reasons_str = ", ".join(cmd['reasons']) if cmd['reasons'] else "длинная_команда"
            report_lines.append(
                f"   [⏰{cmd['time']}] {cmd['user']} [LogonID: {cmd['logon_id']}] : {cmd['command'][:100]}... ({reasons_str}) [файл: {cmd['file']}]")

    # Подозрительные процессы
    if all_process_creations:
        suspicious_processes = [p for p in all_process_creations if any(proc in p['process'].lower() for proc in
                                                                        ['powershell', 'cmd', 'net', 'netsh',
                                                                         'certutil', 'bitsadmin', 'psexec', 'wmic'])]
        if suspicious_processes:
            report_lines.append(f"\n🚨 Подозрительные процессы:")
            for proc in suspicious_processes[:10]:
                report_lines.append(
                    f"   [⏰{proc['time']}] {proc['user']} [LogonID: {proc['logon_id']}] запустил {proc['process']} с командой: {proc['command_line']} [файл: {proc['file']}]")

    # Подозрительные сетевые подключения
    if all_network_connections:
        suspicious_connections = [conn for conn in all_network_connections if conn['remote_ip'] in SUSPICIOUS_IPS]
        if suspicious_connections:
            report_lines.append(f"\n📡 Подозрительные сетевые подключения:")
            for conn in suspicious_connections:
                report_lines.append(
                    f"   [⏰{conn['time']}] {conn['process']} подключился к {conn['remote_ip']}:{conn['remote_port']} [файл: {conn['file']}]")

    # Общие подозрительные события
    if all_suspicious_events:
        report_lines.append(f"\n🚨 Обнаруженные подозрительные события:")
        for event in all_suspicious_events:
            report_lines.append(
                f"   [⏰{event['time']}] Event {event['event_id']}: {event['description']} [файл: {event['file']}]")

    # Сохранение в report.txt
    report_file = "evtx_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    print(f"\n✅ Отчёт сохранён в: {report_file}")

    # Подготовка данных для JSON
    json_data = {
        'summary': {
            'total_files_processed': len(evtx_files),
            'total_logins': len(all_login_attempts),
            'failed_logins': len(all_failed_logins),
            'rdp_sessions_found': len(all_rdp_sessions),
            'smb_accesses_found': len(all_smb_accesses),
            'file_actions_found': len(all_file_actions),
            'file_downloads_found': len(all_file_downloads),
            'log_clearing_events_found': len(all_log_clearing_events),
            'unhandled_events_found': len(all_unhandled_events),
            'powershell_commands': len(all_powershell_commands),
            'process_creations': len(all_process_creations),
            'network_connections': len(all_network_connections),
            'winrm_accesses_found': len(all_winrm_accesses),
            'wmi_queries_found': len(all_wmi_queries),
            'suspicious_events': len(all_suspicious_events),
            'processed_files': evtx_files
        },
        'login_attempts': all_login_attempts,
        'failed_logins': all_failed_logins,
        'rdp_sessions': all_rdp_sessions,
        'smb_accesses': all_smb_accesses,
        'file_actions': all_file_actions,
        'file_downloads': all_file_downloads,
        'log_clearing_events': all_log_clearing_events,
        'unhandled_events': all_unhandled_events,
        'powershell_commands': all_powershell_commands,
        'process_creations': all_process_creations,
        'network_connections': all_network_connections,
        'winrm_accesses': all_winrm_accesses,
        'wmi_queries': all_wmi_queries,
        'suspicious_events': all_suspicious_events
    }

    # Добавляем пользовательско-IP сопоставления в JSON
    user_ip_mapping_json = defaultdict(lambda: defaultdict(int))
    for login in all_login_attempts:
        user_ip_mapping_json[login['username']][login['ip']] += 1

    json_data['user_ip_mapping'] = {user: dict(ip_counts) for user, ip_counts in user_ip_mapping_json.items()}

    # Сохранение детальных событий в JSON по указанному пути
    with open(json_output_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print(f"✅ Детальные события сохранены в: {json_output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python general_scan.py <путь_к_.evtx_или_папке> <путь_к_.json>")
        print("Примеры:")
        print("  python general_scan.py Security.evtx output.json")
        print("  python general_scan.py /path/to/evtx/files/ output.json")
        sys.exit(1)

    input_path = sys.argv[1]
    json_output_file = sys.argv[2]
    main(input_path, json_output_file)