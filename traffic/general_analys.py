#!/usr/bin/env python3
# analyze_pcap_enhanced.py

import sys
import os
import pyshark
import re
import json
from collections import Counter, defaultdict
import socket
from datetime import datetime

# --- Конфигурация ---
LOCAL_NETS = [
    ('192.168.0.0', '255.255.0.0'),
    ('10.0.0.0', '255.0.0.0'),
    ('172.16.0.0', '255.240.0.0')
]

# Подозрительные паттерны в DNS
SUSPICIOUS_DOMAIN_PATTERNS = {
    "hex_32": r'^[a-f0-9]{32}\.',  # MD5-like
    "hex_40": r'^[a-f0-9]{40}\.',  # SHA1-like
    "hex_64": r'^[a-f0-9]{64}\.',  # SHA256-like
    "long_random": r'^[a-z0-9]{16,}\.',  # длинные случайные
    "exe_dll": r'\.(exe|dll|js|zip|rar|bat|ps1|vbs)$',
    "base64_like": r'^[A-Za-z0-9+/=]{20,}\.',
    "ip_in_domain": r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.',
    "double_dot": r'\.{2,}',  # .. или ...
    "underscore": r'_',  # подчеркивания — редко в легитимных доменах
}

# Подозрительные IP (можно заменить на API)
SUSPICIOUS_IPS = {
    "185.130.5.12", "45.155.205.233", "104.21.16.198", "209.99.64.10", "198.51.100.1"
}


# --- Вспомогательные функции ---

def get_pcap_files(input_path):
    """Возвращает список PCAP файлов из указанного пути (файл или папка)"""
    if os.path.isfile(input_path) and input_path.lower().endswith(('.pcap', '.pcapng')):
        return [input_path]
    elif os.path.isdir(input_path):
        pcap_files = []
        for root, dirs, files in os.walk(input_path):
            for file in files:
                if file.lower().endswith(('.pcap', '.pcapng')):
                    pcap_files.append(os.path.join(root, file))
        return pcap_files
    else:
        return []


def ip_to_int(ip):
    return int.from_bytes(socket.inet_aton(ip), 'big')


def int_to_ip(n):
    return socket.inet_ntoa(n.to_bytes(4, 'big'))


def is_local_ip(ip_str):
    try:
        ip_int = ip_to_int(ip_str)
        for net, mask in LOCAL_NETS:
            net_int = ip_to_int(net)
            mask_int = ip_to_int(mask)
            if (ip_int & mask_int) == net_int:
                return True
        return False
    except Exception:
        return False


def classify_suspicious_domain(domain):
    """Возвращает список причин, почему домен подозрительный"""
    reasons = []
    domain = domain.lower().strip()
    if len(domain) > 100:
        reasons.append("длинный_домен")
    if domain.startswith('www.') and len(domain) > 50:
        reasons.append("www_длинный")
    for pattern_name, pattern in SUSPICIOUS_DOMAIN_PATTERNS.items():
        if re.search(pattern, domain):
            reasons.append(pattern_name)
    return reasons


def analyze_single_pcap_file(pcap_path, ignore_local_ips):
    """Анализирует один PCAP файл и возвращает собранные данные"""
    print(f"[INFO] Анализируем файл: {pcap_path}")

    # Структуры данных
    src_ips = []
    dst_ips = []
    dns_queries = []
    nbns_queries = []  # NetBIOS Name Service
    unique_ips = set()
    suspicious_domains = []  # [(domain, time, reasons)]
    suspicious_ips = set()
    http_requests = {}  # domain -> list of URLs
    domain_count = Counter()  # domain -> count
    protocol_stats = Counter()  # протокол -> count
    login_attempts = []  # [(src_ip, dst_ip, username, protocol, time)]

    try:
        cap = pyshark.FileCapture(pcap_path, keep_packets=False)
        for pkt in cap:
            # Подсчет протоколов
            if hasattr(pkt, 'transport_layer'):
                protocol_stats[pkt.transport_layer] = protocol_stats.get(pkt.transport_layer, 0) + 1
            else:
                # Если нет транспортного слоя, проверяем другие протоколы
                for layer in pkt.layers:
                    protocol_stats[str(layer.layer_name)] = protocol_stats.get(str(layer.layer_name), 0) + 1

            # Обработка IP-адресов
            if 'IP' in pkt:
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst

                # Проверяем, нужно ли игнорировать локальные IP
                if not ignore_local_ips or not is_local_ip(src_ip):
                    src_ips.append(src_ip)
                    unique_ips.add(src_ip)
                if not ignore_local_ips or not is_local_ip(dst_ip):
                    dst_ips.append(dst_ip)
                    unique_ips.add(dst_ip)

                # Проверка на подозрительные IP
                if src_ip in SUSPICIOUS_IPS:
                    suspicious_ips.add(src_ip)
                if dst_ip in SUSPICIOUS_IPS:
                    suspicious_ips.add(dst_ip)

            # Обработка DNS
            if 'DNS' in pkt and hasattr(pkt.dns, 'qry_name'):
                domain = str(pkt.dns.qry_name)
                dns_queries.append(domain)
                domain_count[domain] += 1

                # Проверка на подозрительность
                reasons = classify_suspicious_domain(domain)
                if reasons:
                    timestamp = str(pkt.sniff_time) if hasattr(pkt, 'sniff_time') else "unknown"
                    suspicious_domains.append({
                        'domain': domain,
                        'time': timestamp,
                        'reasons': reasons,
                        'src_ip': getattr(pkt.ip, 'src', 'unknown') if 'IP' in pkt else 'unknown',
                        'file': os.path.basename(pcap_path)  # Добавляем имя файла
                    })

            # Обработка NetBIOS Name Service (NBNS)
            if 'NBNS' in pkt:
                if hasattr(pkt.nbns, 'name'):
                    nbns_query = str(pkt.nbns.name)
                    nbns_queries.append(nbns_query)

                    # Проверяем на подозрительность
                    reasons = classify_suspicious_domain(nbns_query)
                    if reasons:
                        timestamp = str(pkt.sniff_time) if hasattr(pkt, 'sniff_time') else "unknown"
                        suspicious_domains.append({
                            'domain': nbns_query,
                            'time': timestamp,
                            'reasons': reasons,
                            'src_ip': getattr(pkt.ip, 'src', 'unknown') if 'IP' in pkt else 'unknown',
                            'protocol': 'NBNS',
                            'file': os.path.basename(pcap_path)
                        })

            # Обработка HTTP (если есть)
            if 'HTTP' in pkt and hasattr(pkt.http, 'request_full_uri'):
                uri = str(pkt.http.request_full_uri)
                # Извлечём домен из URI
                match = re.search(r'https?://([^/]+)', uri)
                if match:
                    domain = match.group(1)
                    if domain not in http_requests:
                        http_requests[domain] = []
                    http_requests[domain].append({
                        'uri': uri,
                        'time': str(pkt.sniff_time) if hasattr(pkt, 'sniff_time') else "unknown",
                        'file': os.path.basename(pcap_path)
                    })

            # Обработка SMB/NTLM (возможные попытки аутентификации)
            if 'SMB' in pkt or 'NTLM' in pkt:
                src_ip = getattr(pkt.ip, 'src', 'unknown') if 'IP' in pkt else 'unknown'
                dst_ip = getattr(pkt.ip, 'dst', 'unknown') if 'IP' in pkt else 'unknown'

                # Попытка извлечь имя пользователя из SMB/NTLM
                username = 'unknown'
                if hasattr(pkt, 'smb') and hasattr(pkt.smb, 'ntlmssp_auth_username'):
                    username = str(pkt.smb.ntlmssp_auth_username)
                elif hasattr(pkt, 'ntlm') and hasattr(pkt.ntlm, 'username'):
                    username = str(pkt.ntlm.username)

                if username != 'unknown':
                    timestamp = str(pkt.sniff_time) if hasattr(pkt, 'sniff_time') else "unknown"
                    protocol = 'SMB' if 'SMB' in pkt else 'NTLM'
                    login_attempts.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'username': username,
                        'protocol': protocol,
                        'time': timestamp,
                        'file': os.path.basename(pcap_path)
                    })

    except Exception as e:
        print(f"[ERROR] Ошибка при анализе пакета в файле {pcap_path}: {e}")
        return None

    return {
        'src_ips': src_ips,
        'dst_ips': dst_ips,
        'dns_queries': dns_queries,
        'nbns_queries': nbns_queries,
        'unique_ips': unique_ips,
        'suspicious_domains': suspicious_domains,
        'suspicious_ips': suspicious_ips,
        'http_requests': http_requests,
        'domain_count': domain_count,
        'protocol_stats': protocol_stats,
        'login_attempts': login_attempts,
        'total_packets': len(list(pyshark.FileCapture(pcap_path, keep_packets=False)))
    }


def main(input_path, json_output_path, ignore_local_ips):
    pcap_files = get_pcap_files(input_path)

    if not pcap_files:
        print(f"[ERROR] Не найдено PCAP файлов в: {input_path}")
        return

    print(f"[INFO] Найдено {len(pcap_files)} PCAP файлов для анализа")
    print(f"[INFO] Режим игнорирования локальных IP: {'ВКЛ' if ignore_local_ips else 'ВЫКЛ'}")
    print(f"[INFO] Выходной JSON файл: {json_output_path}")

    # Объединяем данные из всех файлов
    all_src_ips = []
    all_dst_ips = []
    all_dns_queries = []
    all_nbns_queries = []
    all_unique_ips = set()
    all_suspicious_domains = []
    all_suspicious_ips = set()
    all_http_requests = defaultdict(list)
    all_domain_count = Counter()
    all_protocol_stats = Counter()
    all_login_attempts = []
    total_packets = 0

    for pcap_file in pcap_files:
        file_data = analyze_single_pcap_file(pcap_file, ignore_local_ips)
        if file_data:
            all_src_ips.extend(file_data['src_ips'])
            all_dst_ips.extend(file_data['dst_ips'])
            all_dns_queries.extend(file_data['dns_queries'])
            all_nbns_queries.extend(file_data['nbns_queries'])
            all_unique_ips.update(file_data['unique_ips'])
            all_suspicious_domains.extend(file_data['suspicious_domains'])
            all_suspicious_ips.update(file_data['suspicious_ips'])

            # Объединяем HTTP запросы
            for domain, requests in file_data['http_requests'].items():
                all_http_requests[domain].extend(requests)

            # Объединяем счетчики доменов
            all_domain_count.update(file_data['domain_count'])

            # Объединяем статистику протоколов
            all_protocol_stats.update(file_data['protocol_stats'])

            # Объединяем попытки входа
            all_login_attempts.extend(file_data['login_attempts'])

            total_packets += file_data['total_packets']

    # --- Генерация отчёта ---

    report_lines = []

    report_lines.append("=" * 70)
    report_lines.append("📊 РАСШИРЕННЫЙ АНАЛИЗ .PCAP ФАЙЛОВ")
    report_lines.append("=" * 70)
    report_lines.append(f"📁 Всего обработано файлов: {len(pcap_files)}")
    report_lines.append(f"🔒 Режим игнорирования локальных IP: {'ВКЛ' if ignore_local_ips else 'ВЫКЛ'}")
    for file_path in pcap_files:
        report_lines.append(f"📄 {file_path}")
    report_lines.append(f"⏱️ Всего пакетов: {total_packets}")
    report_lines.append(f"🌐 Уникальных внешних IP: {len(all_unique_ips)}")
    report_lines.append(f"📡 Всего DNS-запросов: {len(all_dns_queries)}")
    report_lines.append(f"🏷️ Всего NBNS-запросов: {len(all_nbns_queries)}")
    report_lines.append(f"🔑 Найдено попыток входа: {len(all_login_attempts)}")

    # Топ-5 отправителей и получателей
    src_counter = Counter(all_src_ips)
    dst_counter = Counter(all_dst_ips)

    top_src = src_counter.most_common(5)
    top_dst = dst_counter.most_common(5)

    report_lines.append("\n📈 ТОП-5 IP-отправителей:")
    for ip, count in top_src:
        report_lines.append(f"   {ip}: {count} раз")

    report_lines.append("\n📥 ТОП-5 IP-получателей:")
    for ip, count in top_dst:
        report_lines.append(f"   {ip}: {count} раз")

    # Топ-5 протоколов
    if all_protocol_stats:
        top_protocols = all_protocol_stats.most_common(5)
        report_lines.append("\n🔗 ТОП-5 протоколов:")
        for protocol, count in top_protocols:
            report_lines.append(f"   {protocol}: {count} пакетов")

    # Попытки входа
    if all_login_attempts:
        report_lines.append(f"\n🔑 Обнаруженные попытки входа:")
        for attempt in all_login_attempts:
            report_lines.append(
                f"   [⏰{attempt['time']}] {attempt['username']}@{attempt['src_ip']} → {attempt['dst_ip']} ({attempt['protocol']}) [файл: {attempt['file']}]")

    # Подозрительные домены с временем и причинами
    report_lines.append(f"\n⚠️ Найдено подозрительных доменов: {len(all_suspicious_domains)}")
    if all_suspicious_domains:
        report_lines.append("   Детализация (время, домен, причины):")
        for item in all_suspicious_domains:
            reasons_str = ", ".join(item['reasons'])
            protocol_info = f" ({item.get('protocol', 'DNS')})" if 'protocol' in item else ""
            report_lines.append(
                f"      [⏰{item['time']}] {item['domain']}{protocol_info} → ({reasons_str}) [файл: {item['file']}]")

    # Часто запрашиваемые домены (подозрительно частые)
    frequent_domains = [d for d, cnt in all_domain_count.most_common(10) if cnt > 5]
    if frequent_domains:
        report_lines.append(f"\n🔁 Часто запрашиваемые домены (>5 раз):")
        for d in frequent_domains:
            report_lines.append(f"   {d}: {all_domain_count[d]} раз")

    # Подозрительные IP
    report_lines.append(f"\n🚨 Найдено подозрительных IP: {len(all_suspicious_ips)}")
    if all_suspicious_ips:
        report_lines.append("   IP:")
        for ip in all_suspicious_ips:
            report_lines.append(f"      {ip}")

    # HTTP-запросы к подозрительным доменам
    if all_http_requests:
        report_lines.append(f"\n🌐 HTTP-запросы к доменам:")
        for domain, requests in all_http_requests.items():
            if domain in [d['domain'] for d in all_suspicious_domains]:
                report_lines.append(f"   ⚠️ {domain} ({len(requests)} запросов):")
                for req in requests[:3]:  # первые 3 URL
                    report_lines.append(f"      • {req['uri']} [⏰{req['time']}] [файл: {req['file']}]")
                if len(requests) > 3:
                    report_lines.append(f"      ... и ещё {len(requests) - 3} запросов")

    # Сохранение в report.txt
    report_file = "pcap_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    print(f"\n✅ Отчёт сохранён в: {report_file}")

    # Подготовка данных для JSON
    json_data = {
        'summary': {
            'total_files_processed': len(pcap_files),
            'total_packets': total_packets,
            'unique_external_ips': len(all_unique_ips),
            'total_dns_queries': len(all_dns_queries),
            'total_nbns_queries': len(all_nbns_queries),
            'login_attempts_found': len(all_login_attempts),
            'suspicious_domains_found': len(all_suspicious_domains),
            'suspicious_ips_found': len(all_suspicious_ips),
            'ignore_local_ips': ignore_local_ips,
            'processed_files': pcap_files
        },
        'src_ips': all_src_ips,
        'dst_ips': all_dst_ips,
        'dns_queries': all_dns_queries,
        'nbns_queries': all_nbns_queries,
        'unique_ips': list(all_unique_ips),
        'suspicious_domains': all_suspicious_domains,
        'suspicious_ips': list(all_suspicious_ips),
        'http_requests': {domain: [{'uri': req['uri'], 'time': req['time'], 'file': req['file']} for req in requests]
                          for domain, requests in all_http_requests.items()},
        'domain_count': dict(all_domain_count),
        'protocol_stats': dict(all_protocol_stats),
        'login_attempts': all_login_attempts
    }

    # Сохранение детальных событий в JSON по указанному пути
    with open(json_output_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    print(f"✅ Детальные события сохранены в: {json_output_path}")


def parse_arguments():
    """Парсит аргументы командной строки"""
    args = []
    flags = []

    for arg in sys.argv[1:]:
        if arg.startswith('-'):
            flags.append(arg.lstrip('-'))
        else:
            args.append(arg)

    return args, flags


if __name__ == "__main__":
    args, flags = parse_arguments()

    if len(args) != 2:
        print("Использование: python analyze_pcap_enhanced.py [-l] <путь_к_.pcap_или_папке> <путь_к_.json>")
        print("Флаги:")
        print("  -l : игнорировать локальные IP-адреса")
        print("Примеры:")
        print("  python analyze_pcap_enhanced.py capture.pcap output.json")
        print("  python analyze_pcap_enhanced.py -l capture.pcap output.json")
        print("  python analyze_pcap_enhanced.py /path/to/pcap/files/ output.json")
        sys.exit(1)

    input_path = args[0]
    json_output_file = args[1]
    ignore_local_ips = 'l' in flags

    main(input_path, json_output_file, ignore_local_ips)