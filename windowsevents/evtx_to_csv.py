#!/usr/bin/env python3
# to_csv.py

import sys
import os
import csv
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
import xml.etree.ElementTree as ET

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
        return {}

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


def clean_xml_string(xml_str):
    """Убирает переносы строк, табы, лишние пробелы и делает XML в одну строку"""
    import re
    # Заменяем все переносы строк и табы на пробелы
    xml_str = re.sub(r'\s+', ' ', xml_str)
    # Убираем лишние пробелы вокруг тегов
    xml_str = re.sub(r'>\s+<', '><', xml_str)
    return xml_str.strip()


def main(input_path, csv_output_path):
    evtx_files = get_evtx_files(input_path)

    if not evtx_files:
        print(f"[ERROR] Не найдено EVTX файлов в: {input_path}")
        return

    print(f"[INFO] Найдено {len(evtx_files)} EVTX файлов для обработки")

    # Определяем столбцы
    fieldnames = [
        'RowID',
        'EventID',
        'TimeCreated',
        'Channel',
        'Level',
        'Computer',
        'Provider',
        'EventRecordID',
        'SubjectUserSid',
        'SubjectUserName',
        'SubjectDomainName',
        'TargetUserSid',
        'TargetUserName',
        'TargetDomainName',
        'IpAddress',
        'WorkstationName',
        'ProcessName',
        'CommandLine',
        'ObjectName',
        'AccessMask',
        'Status',
        'Message',
        'LogonID',  # Новый столбец
        'RawXML',
        'File'
    ]

    row_id = 1

    with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for evtx_path in evtx_files:
            print(f"[INFO] Обрабатываем файл: {evtx_path}")
            try:
                with Evtx(evtx_path) as log:
                    for record in log.records():
                        try:
                            raw_xml = record.xml()
                            # Очищаем XML: убираем переносы строк, табы, лишние пробелы
                            cleaned_xml = clean_xml_string(raw_xml)
                            event_data = extract_event_data(raw_xml)

                            # Извлекаем поля из System
                            system_event_id = event_data.get('System_EventID', 'N/A')
                            time_created = str(record.timestamp())
                            channel = event_data.get('System_Channel', 'N/A')
                            level = event_data.get('System_Level', 'N/A')
                            computer = event_data.get('System_Computer', 'N/A')
                            provider = event_data.get('System_Provider', 'N/A')
                            event_record_id = event_data.get('System_EventRecordID', 'N/A')

                            # Извлекаем поля из EventData
                            subject_user_sid = event_data.get('SubjectUserSid', 'N/A')
                            subject_user_name = event_data.get('SubjectUserName', 'N/A')
                            subject_domain_name = event_data.get('SubjectDomainName', 'N/A')
                            target_user_sid = event_data.get('TargetUserSid', 'N/A')
                            target_user_name = event_data.get('TargetUserName', 'N/A')
                            target_domain_name = event_data.get('TargetDomainName', 'N/A')
                            ip_address = event_data.get('IpAddress', 'N/A')
                            workstation_name = event_data.get('WorkstationName', 'N/A')
                            process_name = event_data.get('ProcessName', 'N/A') or event_data.get('NewProcessName', 'N/A')
                            command_line = event_data.get('CommandLine', 'N/A')
                            object_name = event_data.get('ObjectName', 'N/A')
                            access_mask = event_data.get('AccessMask', 'N/A')
                            status = event_data.get('Status', 'N/A')
                            message = event_data.get('Message', 'N/A')

                            # Извлекаем LogonID (TargetLogonId или SubjectLogonId)
                            logon_id = event_data.get('TargetLogonId', 'N/A')
                            if logon_id == 'N/A':
                                logon_id = event_data.get('SubjectLogonId', 'N/A')

                            # Записываем строку в CSV
                            writer.writerow({
                                'RowID': row_id,
                                'EventID': system_event_id,
                                'TimeCreated': time_created,
                                'Channel': channel,
                                'Level': level,
                                'Computer': computer,
                                'Provider': provider,
                                'EventRecordID': event_record_id,
                                'SubjectUserSid': subject_user_sid,
                                'SubjectUserName': subject_user_name,
                                'SubjectDomainName': subject_domain_name,
                                'TargetUserSid': target_user_sid,
                                'TargetUserName': target_user_name,
                                'TargetDomainName': target_domain_name,
                                'IpAddress': ip_address,
                                'WorkstationName': workstation_name,
                                'ProcessName': process_name,
                                'CommandLine': command_line,
                                'ObjectName': object_name,
                                'AccessMask': access_mask,
                                'Status': status,
                                'Message': message,
                                'LogonID': logon_id,
                                'RawXML': cleaned_xml,
                                'File': os.path.basename(evtx_path)
                            })
                            row_id += 1
                        except Exception as e:
                            print(f"[WARNING] Ошибка при обработке записи в файле {evtx_path}: {e}")
                            continue
            except Exception as e:
                print(f"[ERROR] Ошибка при чтении EVTX файла {evtx_path}: {e}")
                continue

    print(f"[INFO] CSV файл сохранён: {csv_output_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python to_csv.py <путь_к_.evtx_или_папке> <путь_к_.csv>")
        print("Примеры:")
        print("  python to_csv.py Security.evtx output.csv")
        print("  python to_csv.py /path/to/evtx/files/ output.csv")
        sys.exit(1)

    input_path = sys.argv[1]
    csv_output_file = sys.argv[2]
    main(input_path, csv_output_file)