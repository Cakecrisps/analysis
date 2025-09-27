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
    powershell_commands = []  # [(command, time, user, reasons)]
    process_creations = []  # [(process, user, time, command_line, logon_id)]
    network_connections = []  # [(process, local_ip, remote_ip, time)]
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

                    # --- Анализ событий входа в систему (4624, 4625, 4648) ---
                    if event_id in ['4624', '4625', '4648']:
                        username = event_data.get('TargetUserName', '')
                        domain = event_data.get('TargetDomainName', '')
                        ip_address = event_data.get('IpAddress', '')
                        port = event_data.get('IpPort', 'N/A')
                        logon_id = event_data.get('TargetLogonId', 'N/A')

                        # Если IP не найден в IpAddress, пробуем WorkstationName
                        if not ip_address or ip_address == '-':
                            ip_address = event_data.get('WorkstationName', 'N/A')

                        if username and ip_address and ip_address != '-':
                            login_info = {
                                'username': username,
                                'domain': domain,
                                'ip': ip_address,
                                'port': port,
                                'logon_id': logon_id,
                                'time': timestamp,
                                'event_id': event_id,
                                'file': os.path.basename(evtx_path)
                            }

                            if event_id == '4624':  # Успешный вход
                                login_attempts.append(login_info)
                            elif event_id == '4625':  # Неудачная попытка
                                failure_reason = event_data.get('Status', 'Unknown')
                                login_info['failure_reason'] = failure_reason
                                failed_logins.append(login_info)
                            elif event_id == '4648':  # Попытка входа с явными учетными данными
                                login_attempts.append(login_info)

                    # --- Анализ событий NetLogon (4776) ---
                    elif event_id == '4776':
                        username = event_data.get('TargetUserName', '')
                        workstation = event_data.get('Workstation', 'N/A')
                        logon_id = event_data.get('TargetLogonId', 'N/A')
                        if username:
                            login_info = {
                                'username': username,
                                'domain': event_data.get('TargetDomainName', 'N/A'),
                                'ip': workstation,
                                'port': 'N/A',
                                'logon_id': logon_id,
                                'time': timestamp,
                                'event_id': event_id,
                                'file': os.path.basename(evtx_path)
                            }
                            login_attempts.append(login_info)

                    # --- Анализ PowerShell событий (4103, 4104) ---
                    elif event_id in ['4103', '4104']:
                        user = event_data.get('SubjectUserName', '')
                        command_line = event_data.get('Payload', '')
                        logon_id = event_data.get('SubjectLogonId', 'N/A')

                        if command_line:
                            reasons = classify_suspicious_powershell_command(command_line)
                            if reasons or len(command_line) > 100:  # Длинные команды тоже подозрительны
                                powershell_info = {
                                    'command': command_line,
                                    'time': timestamp,
                                    'user': user,
                                    'logon_id': logon_id,
                                    'reasons': reasons,
                                    'file': os.path.basename(evtx_path)
                                }
                                powershell_commands.append(powershell_info)
                                suspicious_events.append({
                                    'event_id': event_id,
                                    'time': timestamp,
                                    'description': f"Подозрительная PowerShell команда: {command_line[:100]}...",
                                    'file': os.path.basename(evtx_path)
                                })

                    # --- Анализ создания процессов (4688) ---
                    elif event_id == '4688':
                        process_name = event_data.get('NewProcessName', '')
                        user = event_data.get('SubjectUserName', '')
                        command_line = event_data.get('CommandLine', '')
                        logon_id = event_data.get('SubjectLogonId', 'N/A')

                        if process_name:
                            process_info = {
                                'process': process_name,
                                'user': user,
                                'time': timestamp,
                                'command_line': command_line,
                                'logon_id': logon_id,
                                'file': os.path.basename(evtx_path)
                            }
                            process_creations.append(process_info)

                            # Проверяем подозрительные процессы
                            suspicious_processes = ['powershell', 'cmd', 'net', 'netsh', 'certutil', 'bitsadmin',
                                                    'psexec', 'wmic']
                            if any(proc in process_name.lower() for proc in suspicious_processes):
                                suspicious_events.append({
                                    'event_id': event_id,
                                    'time': timestamp,
                                    'description': f"Подозрительный процесс: {process_name} с командой: {command_line}",
                                    'file': os.path.basename(evtx_path)
                                })

                    # --- Анализ сетевых подключений (если есть) ---
                    elif event_id == '5156':  # Filtered packet event
                        local_ip = event_data.get('LocalAddr', '')
                        remote_ip = event_data.get('RemoteAddr', '')
                        remote_port = event_data.get('RemotePort', 'N/A')
                        process = event_data.get('Application', '')

                        if remote_ip and remote_ip not in ['127.0.0.1', '::1']:
                            network_info = {
                                'process': process,
                                'local_ip': local_ip,
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'time': timestamp,
                                'file': os.path.basename(evtx_path)
                            }
                            network_connections.append(network_info)

                            # Проверяем подозрительные IP
                            if remote_ip in SUSPICIOUS_IPS:
                                suspicious_events.append({
                                    'event_id': event_id,
                                    'time': timestamp,
                                    'description': f"Подключение к подозрительному IP: {remote_ip}",
                                    'file': os.path.basename(evtx_path)
                                })

                except Exception as e:
                    # print(f"[WARNING] Ошибка при обработке записи {i} в файле {evtx_path}: {e}")
                    continue

    except Exception as e:
        print(f"[ERROR] Ошибка при чтении EVTX файла {evtx_path}: {e}")
        return None

    return {
        'login_attempts': login_attempts,
        'failed_logins': failed_logins,
        'powershell_commands': powershell_commands,
        'process_creations': process_creations,
        'network_connections': network_connections,
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
    all_powershell_commands = []
    all_process_creations = []
    all_network_connections = []
    all_suspicious_events = []

    for evtx_file in evtx_files:
        file_data = analyze_single_evtx_file(evtx_file)
        if file_data:
            all_login_attempts.extend(file_data['login_attempts'])
            all_failed_logins.extend(file_data['failed_logins'])
            all_powershell_commands.extend(file_data['powershell_commands'])
            all_process_creations.extend(file_data['process_creations'])
            all_network_connections.extend(file_data['network_connections'])
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
    report_lines.append(f"🔧 Найдено PowerShell команд: {len(all_powershell_commands)}")
    report_lines.append(f"⚙️ Найдено созданий процессов: {len(all_process_creations)}")
    report_lines.append(f"🌐 Найдено сетевых подключений: {len(all_network_connections)}")

    # Все логины построчно
    if all_login_attempts:
        report_lines.append(f"\n📋 Все успешные входы:")
        for login in all_login_attempts:
            report_lines.append(
                f"   [⏰{login['time']}] [IP: {login['ip']}:{login['port']}] [User: {login['username']}@{login['domain']}] "
                f"[LogonID: {login['logon_id']}] [EventID: {login['event_id']}] [File: {login['file']}]")

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
            'powershell_commands': len(all_powershell_commands),
            'process_creations': len(all_process_creations),
            'network_connections': len(all_network_connections),
            'suspicious_events': len(all_suspicious_events),
            'processed_files': evtx_files
        },
        'login_attempts': all_login_attempts,
        'failed_logins': all_failed_logins,
        'powershell_commands': all_powershell_commands,
        'process_creations': all_process_creations,
        'network_connections': all_network_connections,
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
        print("Использование: python analyze_evtx_enhanced.py <путь_к_.evtx_или_папке> <путь_к_.json>")
        print("Примеры:")
        print("  python analyze_evtx_enhanced.py Security.evtx output.json")
        print("  python analyze_evtx_enhanced.py /path/to/evtx/files/ output.json")
        sys.exit(1)

    input_path = sys.argv[1]
    json_output_file = sys.argv[2]
    main(input_path, json_output_file)