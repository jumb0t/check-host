# Скрипт для проверки доступности хостов через API check-host.net

## Описание

Этот скрипт позволяет проверять доступность хостов с использованием API [check-host.net](https://check-host.net). Он поддерживает:

- Проверку доступности хостов из списка.
- Получение и отображение списка доступных узлов.
- Настройку через аргументы командной строки.
- Логирование событий.
- Использование прокси (SOCKS5 и HTTP).

## Функции

### Главные функции

### `main()`

Главный блок программы. Выполняет:
1. Парсинг аргументов командной строки с помощью `parse_arguments()`.
2. Настройку логирования.
3. Настройку прокси (если указано).
4. Вызов соответствующих функций в зависимости от подкоманды:
   - `list-nodes`: Отображение списка узлов.
   - `check`: Проверка доступности хостов.

### `parse_arguments() -> argparse.Namespace`

Функция для парсинга аргументов командной строки. Поддерживает две подкоманды:

1. **`check`**
   - `-i`, `--input`: Путь к входному текстовому файлу со списком хостов. (Обязательный параметр)
   - `-o`, `--output`: Путь к выходному файлу для записи результатов.
   - `-c`, `--concurrent`: Максимальное количество одновременных потоков. По умолчанию 10.
   - `-n`, `--nodes`: Максимальное количество узлов для проверки хостов. По умолчанию 5.
   - `-t`, `--timeout`: Таймаут для HTTP-запросов. По умолчанию 30 секунд.
   - `--node`: Указывает конкретные узлы для проверки (можно указать несколько).
   - `--nodes-file`: Путь к файлу со списком узлов для проверки.
   - `--json-results`: Путь к файлу для записи результатов в формате JSON.
   - `--checkhost-results`: Путь к файлу для записи сырых данных от API check-host.net.
   - `--ip-port-link`: Путь к файлу для записи IP, порта и ссылки на результат.
   - `--proxy`: URL SOCKS5-прокси (например, `socks5://user:password@host:port`).
   - `--proxy-type`: Тип прокси-сервера (`socks5` или `http`).

2. **`list-nodes`**
   - `-t`, `--node-type`: Тип узлов (`hosts` или `ips`). По умолчанию `hosts`.
   - `-l`, `--log-file`: Путь к файлу для логирования.

### `check_hosts(client, host_entries, max_concurrent, selected_nodes, output_file, json_results_file, checkhost_results_file, ip_port_link_file)`

Функция для проверки доступности хостов. Выполняет:

1. Обращение к API check-host.net для проверки хостов.
2. Сохранение результатов в указанные файлы.
3. Логирование прогресса и ошибок.

### `display_nodes(client, node_type)`

Отображает список узлов, доступных для проверки через API check-host.net.

### Вспомогательные функции

#### `HostParser.parse_file(input_file)`

Читает файл с хостами и возвращает список записей. Каждая строка файла должна содержать один хост.

#### `CheckHostClient`

Класс для взаимодействия с API check-host.net. Поддерживает таймауты и прокси.

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/your-username/check-host-script.git
   ```

2. Установите зависимости (если используются сторонние библиотеки):
   ```bash
   pip install -r requirements.txt
   ```

## Использование

### Проверка доступности хостов

```bash
python check_host.py check \
  -i hosts.txt \
  -o results.txt \
  --json-results results.json \
  --checkhost-results raw_results.json \
  --proxy socks5://user:password@host:port
```

### Получение списка узлов

```bash
python check_host.py list-nodes -t hosts
```

## Логирование

По умолчанию логирование записывается в файл `check-host.log`. Это можно изменить с помощью аргумента `--log-file`.

## Пример структуры входных и выходных файлов

### Входной файл (hosts.txt)
```
google.com
example.com
127.0.0.1
```

### Выходной файл (results.txt)
```
Host: google.com - Status: Reachable
Host: example.com - Status: Unreachable
Host: 127.0.0.1 - Status: Reachable
```

### JSON результаты (results.json)
```json
[
  {
    "host": "google.com",
    "status": "Reachable",
    "nodes": [
      {"node": "node1", "latency": 20},
      {"node": "node2", "latency": 25}
    ]
  },
  {
    "host": "example.com",
    "status": "Unreachable",
    "nodes": []
  }
]
```

## Лицензия

Этот проект распространяется под лицензией MIT. Подробнее см. в файле LICENSE.
