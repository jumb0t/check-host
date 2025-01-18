#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
check_hosts.py

Скрипт для проверки доступности хостов с использованием API check-host.net.
Включает прогресс-бар в заголовке окна терминала, расширенное логирование, обработку сигналов и немедленную запись результатов.
Поддерживает SOCKS5-прокси.

Автор: OpenAI ChatGPT
Дата: 2024-11-13
"""

import argparse
import logging
import re
import sys
import time
import json
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict
import ipaddress
import threading
import queue

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from colorama import Fore, Style, init as colorama_init

# Инициализация colorama
colorama_init(autoreset=True)

# Константы
DEFAULT_TIMEOUT = 10  # секунд
DEFAULT_MAX_CONCURRENT_REQUESTS = 2  # Уменьшено для предотвращения превышения лимитов API
DEFAULT_MAX_NODES = 3
LOG_FILE = 'check_hosts.log'
RESULTS_FILE = 'results.txt'
JSON_RESULTS_FILE = 'results.json'
CHECKHOST_RESULTS_FILE = 'checkhost_results.json'
IP_PORT_LINK_FILE = 'ip_port_links.txt'

# Настройка логирования
logger = logging.getLogger('check_hosts')
logger.setLevel(logging.DEBUG)  # Установить уровень логирования на DEBUG

# Форматтер для логов
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(funcName)s() - %(message)s'
)

# Обработчик для файла
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)  # Логировать все уровни в файл
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Обработчик для консоли с цветовой подсветкой и расширенным логированием
class ColorFormatter(logging.Formatter):
    """Класс для добавления цветовой подсветки в консольные логи."""

    LEVEL_COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.MAGENTA,
    }

    STATUS_COLORS = {
        'Успешно': Fore.GREEN,
        'Частично успешно': Fore.YELLOW,
        'Неуспешно': Fore.RED,
        'Ошибка создания задачи': Fore.RED,
        'Нет результатов': Fore.MAGENTA,
        'Исключение': Fore.RED,
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)
        message = super().format(record)
        if hasattr(record, 'status') and record.status in self.STATUS_COLORS:
            status_color = self.STATUS_COLORS.get(record.status, Fore.WHITE)
            message = f"{status_color}{message}{Style.RESET_ALL}"
        else:
            message = f"{color}{message}{Style.RESET_ALL}"
        return message

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # В консоль выводить INFO и выше
console_handler.setFormatter(ColorFormatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(console_handler)

# Настройка логирования запросов
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# Класс для хранения информации о хосте
class HostEntry:
    """Класс для хранения информации о хосте и порте."""

    def __init__(self, original: str, host: str, port: int):
        self.original = original
        self.host = host
        self.port = port

    def __repr__(self):
        return f"{self.host}:{self.port}"

    def __hash__(self):
        return hash((self.host, self.port))

    def __eq__(self, other):
        return (self.host, self.port) == (other.host, other.port)

# Модуль для парсинга входного файла
class HostParser:
    """Модуль для парсинга входного файла и извлечения хостов и портов."""

    DEFAULT_PORTS = {
        'http': 80,
        'https': 443,
    }

    IP_PORT_PATTERN = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$')
    URL_PATTERN = re.compile(
        r'^(?:(http|https)://)?([^/:]+)(?::(\d{1,5}))?(?:/.*)?$'
    )

    @staticmethod
    def is_valid_public_ip(ip: str) -> bool:
        """
        Проверяет, является ли IP-адрес публичным.
        Исключает приватные, локальные и зарезервированные IP.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or
                        ip_obj.is_multicast or ip_obj.is_unspecified)
        except ValueError:
            return False

    @staticmethod
    def parse_line(line: str) -> Optional[HostEntry]:
        """
        Парсит одну строку входного файла и возвращает объект HostEntry.
        """
        line = line.strip()
        if not line or line.startswith('#'):
            logger.debug(f"Пропуск пустой или комментированной строки: {line}")
            return None

        # Проверка на формат ip:port
        ip_port_match = HostParser.IP_PORT_PATTERN.match(line)
        if ip_port_match:
            host = ip_port_match.group(1)
            port = int(ip_port_match.group(2))
            if HostParser.is_valid_public_ip(host) and 1 <= port <= 65535:
                logger.debug(f"Распознан IP:Port - {host}:{port}")
                return HostEntry(original=line, host=host, port=port)
            else:
                logger.warning(f"Некорректный IP или порт в строке: {line}")
                return None

        # Проверка на URL
        url_match = HostParser.URL_PATTERN.match(line)
        if url_match:
            scheme = url_match.group(1) or 'tcp'
            host = url_match.group(2)
            port = url_match.group(3)
            if port:
                port = int(port)
                if not (1 <= port <= 65535):
                    logger.warning(f"Недопустимый порт в строке: {line}")
                    return None
            else:
                port = HostParser.DEFAULT_PORTS.get(scheme, 80)
            # Проверка, является ли хост IP или доменом
            try:
                ipaddress.ip_address(host)
                if not HostParser.is_valid_public_ip(host):
                    logger.warning(f"Пропуск не публичного IP-адреса: {host}")
                    return None
            except ValueError:
                # Хост не является IP-адресом, предполагаем, что это домен
                pass  # Можно добавить дополнительные проверки доменов, если необходимо
            logger.debug(f"Распознан URL - Host: {host}, Port: {port}")
            return HostEntry(original=line, host=host, port=port)

        # Если не удалось распознать формат
        logger.warning(f"Не удалось распознать строку: {line}")
        return None

    @staticmethod
    def parse_file(file_path: str) -> List[HostEntry]:
        """
        Парсит входной файл и возвращает список уникальных HostEntry.
        """
        host_entries = []
        seen = set()
        try:
            with open(file_path, mode='r', encoding='utf-8') as f:
                for line in f:
                    entry = HostParser.parse_line(line)
                    if entry and (entry.host, entry.port) not in seen:
                        host_entries.append(entry)
                        seen.add((entry.host, entry.port))
                    elif entry:
                        logger.debug(f"Пропуск дублирующейся записи: {entry.original}")
        except FileNotFoundError:
            logger.error(f"Файл не найден: {file_path}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Ошибка при чтении файла {file_path}: {e}")
            sys.exit(1)
        logger.info(f"Всего уникальных хостов для проверки: {len(host_entries)}")
        return host_entries

# Модуль для взаимодействия с API check-host.net
class CheckHostClient:
    """Модуль для взаимодействия с API check-host.net."""

    BASE_URL = 'https://check-host.net'

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, proxies: Optional[Dict[str, str]] = None):
        self.session = requests.Session()
        self.timeout = timeout

        # Настройка прокси, если предоставлены
        if proxies:
            self.session.proxies.update(proxies)
            logger.debug(f"Настроены прокси: {proxies}")

        # Настройка повторных попыток при ошибках соединения
        retries = Retry(total=3, backoff_factor=0.3,
                        status_forcelist=[500, 502, 503, 504])
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def fetch_nodes(self, node_type: str = 'hosts') -> Optional[Dict]:
        """
        Получает список доступных узлов.
        """
        url = f"{self.BASE_URL}/nodes/{node_type}"
        headers = {
            'Accept': 'application/json'
        }
        try:
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            logger.debug(f"Запрос на получение узлов: {response.url}")
            logger.debug(f"Ответ на получение узлов: {response.status_code} {response.text}")
            if response.status_code == 200:
                data = response.json()
                nodes = data.get('nodes')
                logger.debug(f"Получен список узлов ({node_type}): {nodes}")
                return nodes
            else:
                logger.error(f"HTTP {response.status_code} при получении списка узлов ({node_type})")
                return None
        except requests.Timeout:
            logger.error(f"Таймаут при получении списка узлов ({node_type})")
            return None
        except Exception as e:
            logger.error(f"Исключение при получении списка узлов ({node_type}) - {e}")
            return None

    def check_tcp(self, host: str, port: int, max_nodes: int = DEFAULT_MAX_NODES, nodes: Optional[List[str]] = None) -> Optional[str]:
        """
        Отправляет запрос на проверку TCP-соединения к указанному хосту и порту.
        """
        url = f"{self.BASE_URL}/check-tcp"
        params = {
            'host': f"{host}:{port}",
            'max_nodes': max_nodes
        }
        if nodes:
            for node in nodes:
                params.setdefault('node', []).append(node)
        headers = {
            'Accept': 'application/json'
        }
        try:
            response = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
            logger.debug(f"Запрос на проверку TCP: {response.url}")
            logger.debug(f"Ответ на проверку TCP: {response.status_code} {response.text}")
            if response.status_code == 200:
                data = response.json()
                if data.get('ok') == 1:
                    task_id = data.get('request_id')
                    logger.debug(f"Создана задача {task_id} для {host}:{port}")
                    return task_id
                else:
                    error_message = data.get('error', 'Unknown error')
                    logger.error(f"Ответ API не ок для {host}:{port}: {data}")
                    if error_message == 'limit_exceeded':
                        logger.warning("Лимит запросов превышен. Пытаемся повторить позже.")
                    return None
            else:
                logger.error(f"HTTP {response.status_code} при создании задачи для {host}:{port}")
                return None
        except requests.Timeout:
            logger.error(f"Таймаут при создании задачи для {host}:{port}")
            return None
        except Exception as e:
            logger.error(f"Исключение при создании задачи для {host}:{port} - {e}")
            return None

    def get_results(self, task_id: str) -> Optional[Dict]:
        """
        Получает результаты проверки по task_id.
        """
        url = f"{self.BASE_URL}/check-result/{task_id}"
        headers = {
            'Accept': 'application/json'
        }
        try:
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            logger.debug(f"Запрос на получение результатов: {response.url}")
            logger.debug(f"Ответ на получение результатов: {response.status_code} {response.text}")
            if response.status_code == 200:
                data = response.json()
                logger.debug(f"Получены результаты для задачи {task_id}: {data}")
                return data
            else:
                logger.error(f"HTTP {response.status_code} при получении результатов задачи {task_id}")
                return None
        except requests.Timeout:
            logger.error(f"Таймаут при получении результатов задачи {task_id}")
            return None
        except Exception as e:
            logger.error(f"Исключение при получении результатов задачи {task_id} - {e}")
            return None

# Функция для отображения списка узлов
def display_nodes(client: CheckHostClient, node_type: str):
    """
    Получает и отображает список доступных узлов.
    """
    nodes = client.fetch_nodes(node_type=node_type)
    if nodes:
        if node_type == 'hosts':
            print(f"{Fore.CYAN}Список доступных узлов ({node_type}):{Style.RESET_ALL}")
            for node, info in nodes.items():
                location = ', '.join(info.get('location', []))
                asn = info.get('asn', 'N/A')
                ip = info.get('ip', 'N/A')
                print(f"{Fore.YELLOW}{node}{Style.RESET_ALL}: ASN={asn}, IP={ip}, Location={location}")
        elif node_type == 'ips':
            print(f"{Fore.CYAN}Список доступных узлов ({node_type}):{Style.RESET_ALL}")
            for ip in nodes:
                print(f"{Fore.YELLOW}{ip}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Не удалось получить список узлов.{Style.RESET_ALL}")

# Функция для проверки доступности хостов
def check_hosts(client: CheckHostClient, host_entries: List[HostEntry], max_concurrent: int, selected_nodes: Optional[List[str]], output_file: Optional[str],
               json_results_file: Optional[str], checkhost_results_file: Optional[str], ip_port_link_file: Optional[str]):
    """
    Проверяет доступность хостов с использованием рабочих потоков и очереди, обеспечивая немедленную запись результатов.
    """
    processed_hosts = 0
    total_hosts = len(host_entries)
    progress_lock = threading.Lock()

    host_queue = queue.Queue()
    for entry in host_entries:
        host_queue.put(entry)

    # Открытие файлов для немедленной записи
    output_fh = None
    json_fh = None
    checkhost_fh = None
    link_fh = None
    try:
        if output_file:
            output_fh = open(output_file, mode='w', encoding='utf-8')
        if json_results_file:
            json_fh = open(json_results_file, mode='w', encoding='utf-8')
            json_fh.write('[\n')
        if checkhost_results_file:
            checkhost_fh = open(checkhost_results_file, mode='w', encoding='utf-8')
            checkhost_fh.write('[\n')
        if ip_port_link_file:
            link_fh = open(ip_port_link_file, mode='w', encoding='utf-8')

        # Обработчик сигнала для корректного завершения
        stop_event = threading.Event()

        def signal_handler(sig, frame):
            logger.error("Получен сигнал завершения. Завершение работы...")
            stop_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        def update_title_bar():
            """
            Обновляет заголовок окна терминала с прогресс-баром.
            """
            # Временно отключено для избежания зависаний
            # Можно добавить обратно после успешной отладки
            pass
            # with progress_lock:
            #     percentage = (processed_hosts / total_hosts) * 100 if total_hosts else 100
            #     bar_length = 30
            #     filled_length = int(bar_length * processed_hosts // total_hosts) if total_hosts else bar_length
            #     bar = '#' * filled_length + '-' * (bar_length - filled_length)
            #     title = f"Проверка хостов: [{bar}] {percentage:.2f}%"
            #     set_title(title)

        def worker():
            nonlocal processed_hosts
            while not host_queue.empty() and not stop_event.is_set():
                try:
                    entry = host_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    logger.debug(f"Начало обработки {entry}")
                    task_id = client.check_tcp(entry.host, entry.port, max_nodes=DEFAULT_MAX_NODES, nodes=selected_nodes)
                    if not task_id:
                        status = 'Ошибка создания задачи'
                        if output_fh:
                            output_fh.write(f"{entry.original}: {status}\n")
                        logger.error(f"{entry.original}: {status}", extra={'status': status})
                        if checkhost_fh:
                            checkhost_fh.write(json.dumps({
                                'host': entry.host,
                                'port': entry.port,
                                'status': status
                            }, ensure_ascii=False) + ",\n")
                        if link_fh:
                            link_fh.write(f"{entry.host}:{entry.port}: N/A\n")
                        with progress_lock:
                            processed_hosts += 1
                            update_title_bar()
                        continue

                    logger.debug(f"Задача создана: {task_id} для {entry}")

                    # Ожидание завершения задачи с экспоненциальным backoff
                    backoff = 1  # Начальная задержка в секундах
                    max_backoff = 60  # Максимальная задержка
                    status = 'Неуспешно'
                    for attempt in range(1, 11):  # Максимум 10 попыток
                        if stop_event.is_set():
                            logger.debug(f"Остановка обработки {entry} по сигналу")
                            break
                        logger.debug(f"Попытка {attempt} для задачи {task_id}")
                        time.sleep(backoff)
                        data = client.get_results(task_id)
                        if data:
                            # Проверяем статус всех проверок
                            all_success = True
                            any_success = False
                            for node, check_info in data.items():
                                if check_info:
                                    for result in check_info:
                                        if isinstance(result, dict):
                                            if 'error' in result:
                                                all_success = False
                                                logger.debug(f"Результат проверки на {node}: {result['error']}")
                                            elif 'address' in result:
                                                any_success = True
                                        elif isinstance(result, list):
                                            # Неожиданный формат
                                            all_success = False
                                            logger.debug(f"Неожиданный формат результата на {node}: {result}")
                                else:
                                    all_success = False
                                    logger.debug(f"Пустой результат проверки на {node}")
                            if all_success:
                                status = 'Успешно'
                            elif any_success:
                                status = 'Частично успешно'
                            else:
                                status = 'Неуспешно'
                            break
                        else:
                            logger.debug(f"Результаты задачи {task_id} для {entry} еще не готовы или произошла ошибка.")
                            # Экспоненциальный backoff
                            backoff = min(backoff * 2, max_backoff)

                    # Запись результатов
                    if status == 'Успешно' or status == 'Частично успешно' or status == 'Неуспешно':
                        if output_fh:
                            output_fh.write(f"{entry.original}: {status}\n")
                        logger.info(f"{entry.original}: {status}", extra={'status': status})
                        if checkhost_fh:
                            checkhost_fh.write(json.dumps({
                                'host': entry.host,
                                'port': entry.port,
                                'status': status,
                                'task_id': task_id,
                                'data': data if data else {}
                            }, ensure_ascii=False) + ",\n")
                        if link_fh:
                            checkhost_link = data.get('permanent_link', 'N/A') if data else 'N/A'
                            link_fh.write(f"{entry.host}:{entry.port}: {checkhost_link}\n")
                    else:
                        # Если статус не был обновлен, считать как 'Нет результатов'
                        status = 'Нет результатов'
                        if output_fh:
                            output_fh.write(f"{entry.original}: {status}\n")
                        logger.warning(f"{entry.original}: {status}", extra={'status': status})
                        if checkhost_fh:
                            checkhost_fh.write(json.dumps({
                                'host': entry.host,
                                'port': entry.port,
                                'status': status
                            }, ensure_ascii=False) + ",\n")
                        if link_fh:
                            link_fh.write(f"{entry.host}:{entry.port}: N/A\n")

                    with progress_lock:
                        processed_hosts += 1
                        update_title_bar()

                except Exception as e:
                    logger.error(f"Исключение при обработке {entry}: {e}", extra={'status': 'Исключение'})
                    if output_fh:
                        output_fh.write(f"{entry.original}: Исключение\n")
                    with progress_lock:
                        processed_hosts += 1
                        update_title_bar()
                finally:
                    host_queue.task_done()

        # Создание и запуск рабочих потоков
        threads = []
        for _ in range(max_concurrent):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # Ожидание завершения очереди
        try:
            while any(t.is_alive() for t in threads):
                time.sleep(1)
                if stop_event.is_set():
                    logger.debug("Стоп событие установлено, прерывание ожидания завершения потоков.")
                    break
        except KeyboardInterrupt:
            logger.error("Получен KeyboardInterrupt. Завершение работы...", extra={'status': 'Исключение'})
            stop_event.set()

    except Exception as e:
        logger.error(f"Неожиданная ошибка: {e}", extra={'status': 'Исключение'})
    finally:
        # Закрытие JSON файлов
        if json_results_file and json_fh:
            try:
                json_fh.write('\n]')
                json_fh.close()
            except Exception as e:
                logger.error(f"Ошибка при закрытии файла {json_results_file}: {e}", extra={'status': 'Исключение'})
        if checkhost_results_file and checkhost_fh:
            try:
                checkhost_fh.write('\n]')
                checkhost_fh.close()
            except Exception as e:
                logger.error(f"Ошибка при закрытии файла {checkhost_results_file}: {e}", extra={'status': 'Исключение'})
        if ip_port_link_file and link_fh:
            try:
                link_fh.close()
            except Exception as e:
                logger.error(f"Ошибка при закрытии файла {ip_port_link_file}: {e}", extra={'status': 'Исключение'})
        if output_file and output_fh:
            try:
                output_fh.close()
            except Exception as e:
                logger.error(f"Ошибка при закрытии файла {output_file}: {e}", extra={'status': 'Исключение'})

        # Сброс заголовка окна
        # set_title("Проверка хостов завершена.")  # Временно отключено

        logger.info("Проверка хостов завершена.")

# Функция для парсинга аргументов командной строки
def parse_arguments() -> argparse.Namespace:
    """
    Парсит аргументы командной строки.
    """
    parser = argparse.ArgumentParser(
        description='Скрипт для проверки доступности хостов с использованием API check-host.net.'
    )
    subparsers = parser.add_subparsers(dest='command', help='Доступные подкоманды')

    # Подкоманда для проверки хостов
    check_parser = subparsers.add_parser('check', help='Проверка доступности хостов')
    check_parser.add_argument(
        '-i', '--input',
        required=True,
        help='Путь к входному текстовому файлу со списком хостов.'
    )
    check_parser.add_argument(
        '-o', '--output',
        help='Путь к выходному файлу для записи результатов.'
    )
    check_parser.add_argument(
        '-c', '--concurrent',
        type=int,
        default=DEFAULT_MAX_CONCURRENT_REQUESTS,
        help=f'Максимальное количество одновременных потоков (по умолчанию: {DEFAULT_MAX_CONCURRENT_REQUESTS}).'
    )
    check_parser.add_argument(
        '-n', '--nodes',
        type=int,
        default=DEFAULT_MAX_NODES,
        help=f'Максимальное количество узлов для проверки каждого хоста (по умолчанию: {DEFAULT_MAX_NODES}).'
    )
    check_parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f'Таймаут для HTTP-запросов в секундах (по умолчанию: {DEFAULT_TIMEOUT}).'
    )
    check_parser.add_argument(
        '-l', '--log-file',
        default=LOG_FILE,
        help=f'Путь к файлу для логирования (по умолчанию: {LOG_FILE}).'
    )
    check_parser.add_argument(
        '--node',
        action='append',
        help='Указывает конкретные узлы для проверки. Можно использовать несколько раз для указания нескольких узлов.'
    )
    check_parser.add_argument(
        '--nodes-file',
        help='Путь к файлу со списком узлов для проверки. Один узел на строку.'
    )
    check_parser.add_argument(
        '--json-results',
        help='Путь к файлу для записи JSON результатов.'
    )
    check_parser.add_argument(
        '--checkhost-results',
        help='Путь к файлу для записи JSON данных от check-host.net.'
    )
    check_parser.add_argument(
        '--ip-port-link',
        help='Путь к файлу для записи IP, порта и ссылки на результат.'
    )
    check_parser.add_argument(
        '--proxy',
        help='URL SOCKS5-прокси (например, socks5://user:password@host:port).'
    )
    check_parser.add_argument(
        '--proxy-type',
        choices=['socks5', 'http'],
        default='socks5',
        help='Тип прокси-сервера (по умолчанию: socks5).'
    )

    # Подкоманда для отображения узлов
    list_parser = subparsers.add_parser('list-nodes', help='Получение и отображение списка доступных узлов')
    list_parser.add_argument(
        '-t', '--node-type',
        choices=['hosts', 'ips'],
        default='hosts',
        help='Тип узлов для получения (по умолчанию: hosts).'
    )
    list_parser.add_argument(
        '-l', '--log-file',
        default=LOG_FILE,
        help=f'Путь к файлу для логирования (по умолчанию: {LOG_FILE}).'
    )

    # Если не указана подкоманда, вывести справку
    if len(sys.argv) <= 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    return args

# Главный блок
def main():
    """
    Главный блок для запуска скрипта.
    """
    args = parse_arguments()

    # Установка настроек логирования, если указан другой файл
    if hasattr(args, 'log_file') and args.log_file != LOG_FILE:
        # Удаление существующего обработчика файла
        logger.handlers = [h for h in logger.handlers if not isinstance(h, logging.FileHandler)]
        # Добавление нового обработчика файла
        new_file_handler = logging.FileHandler(args.log_file, encoding='utf-8')
        new_file_handler.setLevel(logging.DEBUG)
        new_file_handler.setFormatter(formatter)
        logger.addHandler(new_file_handler)

    # Настройка прокси, если указан
    proxies = None
    if args.command == 'check' and args.proxy:
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
        logger.info(f"Используется прокси: {args.proxy}")

    # Создание клиента API с указанным таймаутом и прокси
    client = CheckHostClient(timeout=args.timeout if hasattr(args, 'timeout') else DEFAULT_TIMEOUT, proxies=proxies)

    if args.command == 'list-nodes':
        # Отображение списка узлов
        display_nodes(client, node_type=args.node_type)
    elif args.command == 'check':
        # Парсинг входного файла
        host_entries = HostParser.parse_file(args.input)

        # Чтение списка узлов из файла, если указан
        selected_nodes = args.node
        if args.nodes_file:
            try:
                with open(args.nodes_file, mode='r', encoding='utf-8') as f:
                    nodes_from_file = [line.strip() for line in f if line.strip()]
                selected_nodes = nodes_from_file
                logger.info(f"Узлы загружены из файла {args.nodes_file}: {', '.join(selected_nodes)}")
            except Exception as e:
                logger.error(f"Ошибка при чтении файла узлов {args.nodes_file}: {e}", extra={'status': 'Исключение'})
                sys.exit(1)

        if selected_nodes:
            logger.info(f"Используются указанные узлы для проверок: {', '.join(selected_nodes)}")
        else:
            logger.info(f"Используются автоматически выбранные узлы (максимум {args.nodes})")

        # Проверка хостов
        check_hosts(
            client=client,
            host_entries=host_entries,
            max_concurrent=args.concurrent,
            selected_nodes=selected_nodes,
            output_file=args.output,
            json_results_file=args.json_results,
            checkhost_results_file=args.checkhost_results,
            ip_port_link_file=args.ip_port_link
        )
    else:
        logger.error("Неизвестная команда.")
        sys.exit(1)

if __name__ == '__main__':
    main()
