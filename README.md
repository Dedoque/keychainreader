keychainreader/
├── __init__.py
├── models.py      # Модели данных и константы путей
├── scanner.py     # Кроссплатформенное сканирование Keychain / Secret Service
├── storage.py     # SQLite-индекс метаданных (~/.cache/keycahainreader)
├── security.py    # Редактирование логов и безопасный буфер обмена с TTL
└── server.py      # MCP-сервер и точка входа
