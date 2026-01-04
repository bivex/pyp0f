#!/bin/bash
# Скрипт для запуска PyP0f GUI
# Использование: ./run_gui.sh

echo "🔧 Запуск PyP0f GUI..."
echo "📋 Требуются права root для захвата пакетов"
echo ""

# Получаем путь к директории скрипта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYPOF_ROOT="$(dirname "$SCRIPT_DIR")"

# Активируем виртуальное окружение
source "$PYPOF_ROOT/venv/bin/activate"

# Настраиваем переменные окружения для Qt на macOS
export QT_QPA_PLATFORM_PLUGIN_PATH="$PYPOF_ROOT/venv/lib/python3.14/site-packages/PyQt5/Qt5/plugins"
export QT_DEBUG_PLUGINS=1

echo "🔌 Qt plugin path: $QT_QPA_PLATFORM_PLUGIN_PATH"

# Запускаем GUI с sudo, сохраняя переменные окружения
sudo -E python3 "$SCRIPT_DIR/pyp0f_gui.py"
