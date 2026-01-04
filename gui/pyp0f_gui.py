
# Copyright (c) 2026 Bivex
#
# Author: Bivex
# Available for contact via email: support@b-b.top
# For up-to-date contact information:
# https://github.com/bivex
#
# Created: 2026-01-04T23:15:57
# Last Updated: 2026-01-04T23:22:51
#
# Licensed under the MIT License.
# Commercial licensing available upon request.
"""
PyQt5 GUI для просмотра сетевого трафика в реальном времени с pyp0f
Запуск: sudo python3 pyp0f_gui.py
"""

import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QWidget, QTableWidget, QTableWidgetItem, QPushButton,
                             QLabel, QTextEdit, QSplitter, QGroupBox, QProgressBar,
                             QStatusBar, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QEventLoop
from PyQt5.QtGui import QColor, QClipboard
import signal
import sys

from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_tcp, fingerprint_mtu
from pyp0f.net.layers.tcp import TCPFlag
from scapy.all import sniff
from scapy.layers.inet import IP, TCP


class PacketCaptureThread(QThread):
    """Поток для захвата и анализа пакетов"""

    packet_captured = pyqtSignal(dict)  # Сигнал с данными пакета
    capture_started = pyqtSignal()
    capture_stopped = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, interface='en0'):
        super().__init__()
        self.interface = interface
        self.running = False
        self.packets_analyzed = 0

    def run(self):
        """Основной цикл захвата пакетов"""
        try:
            self.running = True
            self.capture_started.emit()

            def packet_handler(packet):
                if not self.running:
                    return

                if IP in packet and TCP in packet:
                    analysis_result = self.analyze_packet(packet)
                    if analysis_result:
                        self.packet_captured.emit(analysis_result)

            # Захватываем только TCP SYN пакеты
            sniff(iface=self.interface,
                  filter="tcp and (tcp[tcpflags] & tcp-syn != 0)",
                  prn=packet_handler,
                  store=0,
                  stop_filter=lambda x: not self.running)

        except Exception as e:
            self.error_occurred.emit(f"Ошибка захвата: {str(e)}")
        finally:
            self.capture_stopped.emit()

    def analyze_packet(self, packet):
        """Анализирует пакет с помощью pyp0f"""
        try:
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            # Определяем тип пакета
            flags = TCPFlag(int(tcp_layer.flags))
            packet_type = "SYN"
            if flags & TCPFlag.ACK:
                packet_type = "SYN+ACK"

            # Базовая информация
            packet_info = {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'type': packet_type,
                'src_ip': ip_layer.src,
                'src_port': tcp_layer.sport,
                'dst_ip': ip_layer.dst,
                'dst_port': tcp_layer.dport,
                'os': 'Не определено',
                'os_flavor': '',
                'distance': 'N/A',
                'mtu': 'Не определено',
                'raw_packet': f"{ip_layer.src}:{tcp_layer.sport} → {ip_layer.dst}:{tcp_layer.dport}"
            }

            # TCP fingerprinting
            tcp_result = fingerprint_tcp(packet)
            if tcp_result.match:
                packet_info['os'] = tcp_result.match.record.label.name
                packet_info['os_flavor'] = tcp_result.match.record.label.flavor
                packet_info['distance'] = str(tcp_result.distance) if tcp_result.distance != -1 else 'N/A'

            # MTU fingerprinting (только для SYN пакетов)
            if flags == TCPFlag.SYN:
                mtu_result = fingerprint_mtu(packet)
                if mtu_result.match:
                    packet_info['mtu'] = mtu_result.match.label.name

            self.packets_analyzed += 1
            return packet_info

        except Exception as e:
            return {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'type': 'ERROR',
                'src_ip': 'ERROR',
                'src_port': 0,
                'dst_ip': 'ERROR',
                'dst_port': 0,
                'os': f'Ошибка: {str(e)}',
                'os_flavor': '',
                'distance': 'N/A',
                'mtu': 'N/A',
                'raw_packet': f"Ошибка анализа: {str(e)}"
            }

    def stop(self):
        """Останавливает захват"""
        self.running = False


class Pyp0fGUI(QMainWindow):
    """Главное окно приложения"""

    def __init__(self):
        super().__init__()
        self.capture_thread = None
        self.packets_data = []
        self.stats = defaultdict(int)
        self.is_shutting_down = False

        # Загружаем базу данных
        self.load_database()

        # Настраиваем интерфейс
        self.init_ui()
        self.setup_timers()

        # Настраиваем обработку сигналов
        self.setup_signal_handlers()

    def load_database(self):
        """Загружает базу данных pyp0f"""
        try:
            DATABASE.load()
            self.statusBar().showMessage("База данных pyp0f загружена успешно")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить базу данных: {str(e)}")
            sys.exit(1)

    def init_ui(self):
        """Инициализирует пользовательский интерфейс"""
        self.setWindowTitle("PyP0f - Анализ сетевого трафика в реальном времени")
        self.setGeometry(100, 100, 1200, 800)

        # Создаем центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Основной layout
        main_layout = QVBoxLayout(central_widget)

        # Панель управления
        control_layout = QHBoxLayout()

        self.start_btn = QPushButton("▶️ Начать захват")
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 10px; font-size: 14px; }")

        self.stop_btn = QPushButton("⏹️ Остановить")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; padding: 10px; font-size: 14px; }")

        self.clear_btn = QPushButton("🗑️ Очистить")
        self.clear_btn.clicked.connect(self.clear_data)
        self.clear_btn.setStyleSheet("QPushButton { background-color: #FF9800; color: white; padding: 10px; font-size: 14px; }")

        self.copy_btn = QPushButton("📋 Копировать в Markdown")
        self.copy_btn.clicked.connect(self.copy_to_markdown)
        self.copy_btn.setStyleSheet("QPushButton { background-color: #2196F3; color: white; padding: 10px; font-size: 14px; }")

        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addWidget(self.copy_btn)
        control_layout.addStretch()

        # Статус
        self.status_label = QLabel("Готов к работе")
        self.status_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        control_layout.addWidget(self.status_label)

        main_layout.addLayout(control_layout)

        # Разделитель для основной области
        splitter = QSplitter(Qt.Vertical)

        # Таблица пакетов
        table_group = QGroupBox("Захваченные пакеты")
        table_layout = QVBoxLayout()

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Время", "Тип", "Источник", "Назначение", "ОС", "Дистанция", "MTU", "Подробности"
        ])

        # Настраиваем ширину колонок
        self.table.setColumnWidth(0, 80)   # Время
        self.table.setColumnWidth(1, 80)   # Тип
        self.table.setColumnWidth(2, 140)  # Источник
        self.table.setColumnWidth(3, 140)  # Назначение
        self.table.setColumnWidth(4, 120)  # ОС
        self.table.setColumnWidth(5, 80)   # Дистанция
        self.table.setColumnWidth(6, 100)  # MTU
        # Последняя колонка растягивается

        table_layout.addWidget(self.table)
        table_group.setLayout(table_layout)
        splitter.addWidget(table_group)

        # Нижняя панель со статистикой и логом
        bottom_splitter = QSplitter(Qt.Horizontal)

        # Статистика
        stats_group = QGroupBox("Статистика")
        stats_layout = QVBoxLayout()

        self.stats_text = QTextEdit()
        self.stats_text.setMaximumHeight(200)
        self.stats_text.setReadOnly(True)
        stats_layout.addWidget(self.stats_text)

        stats_group.setLayout(stats_layout)
        bottom_splitter.addWidget(stats_group)

        # Лог
        log_group = QGroupBox("Лог событий")
        log_layout = QVBoxLayout()

        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(200)
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)

        log_group.setLayout(log_layout)
        bottom_splitter.addWidget(log_group)

        splitter.addWidget(bottom_splitter)
        splitter.setSizes([500, 300])

        main_layout.addWidget(splitter)

        # Прогресс-бар для показа активности
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Неопределенный прогресс
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # Настраиваем статус-бар
        self.statusBar().showMessage("Готов к работе")

        # Применяем стиль
        self.apply_style()

    def apply_style(self):
        """Применяет светлую тему к интерфейсу"""
        self.setStyleSheet("""
            /* Основная светлая тема */
            QWidget {
                background-color: #f8f9fa;
                color: #212529;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                font-size: 13px;
            }

            /* Главное окно */
            QMainWindow {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
            }

            /* Групповые контейнеры */
            QGroupBox {
                font-weight: bold;
                border: 2px solid #dee2e6;
                border-radius: 8px;
                margin-top: 1ex;
                background-color: #ffffff;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #495057;
                font-weight: 600;
                font-size: 14px;
            }

            /* Кнопки */
            QPushButton {
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 500;
                color: #495057;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #f8f9fa;
                border-color: #adb5bd;
            }
            QPushButton:pressed {
                background-color: #e9ecef;
            }
            QPushButton:disabled {
                background-color: #f8f9fa;
                color: #adb5bd;
                border-color: #dee2e6;
            }

            /* Специальные стили для кнопок управления */
            QPushButton#start_btn {
                background-color: #28a745;
                color: white;
                border-color: #28a745;
            }
            QPushButton#start_btn:hover {
                background-color: #218838;
                border-color: #1e7e34;
            }
            QPushButton#stop_btn {
                background-color: #dc3545;
                color: white;
                border-color: #dc3545;
            }
            QPushButton#stop_btn:hover {
                background-color: #c82333;
                border-color: #bd2130;
            }
            QPushButton#clear_btn {
                background-color: #ffc107;
                color: #212529;
                border-color: #ffc107;
            }
            QPushButton#clear_btn:hover {
                background-color: #e0a800;
                border-color: #d39e00;
            }

            /* Таблица */
            QTableWidget {
                gridline-color: #dee2e6;
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                selection-background-color: #e3f2fd;
                selection-color: #212529;
                alternate-background-color: #f8f9fa;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #f1f3f4;
            }
            QTableWidget::item:selected {
                background-color: #e3f2fd;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                color: #495057;
                padding: 10px 8px;
                border: 1px solid #dee2e6;
                border-left: none;
                font-weight: 600;
                font-size: 12px;
            }

            /* Текстовые области */
            QTextEdit {
                background-color: #ffffff;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 8px;
                font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
                font-size: 11px;
                line-height: 1.4;
                color: #212529;
            }
            QTextEdit:focus {
                border-color: #007bff;
            }

            /* Метки */
            QLabel {
                color: #495057;
                font-size: 13px;
            }

            /* Статус бар */
            QStatusBar {
                background-color: #f8f9fa;
                border-top: 1px solid #dee2e6;
                color: #6c757d;
            }

            /* Прогресс бар */
            QProgressBar {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                text-align: center;
                background-color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #007bff;
                border-radius: 2px;
            }

            /* Разделители */
            QSplitter::handle {
                background-color: #dee2e6;
            }
            QSplitter::handle:hover {
                background-color: #adb5bd;
            }

            /* Скроллбары */
            QScrollBar:vertical {
                background-color: #f8f9fa;
                width: 14px;
                border-radius: 7px;
            }
            QScrollBar::handle:vertical {
                background-color: #dee2e6;
                border-radius: 7px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #adb5bd;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }

            /* Таблица пакетов */
            QTableWidget#packet_table {
                background-color: #ffffff;
                alternate-background-color: #f8f9fa;
            }
        """)

        # Устанавливаем идентификаторы для специальных кнопок
        self.start_btn.setObjectName("start_btn")
        self.stop_btn.setObjectName("stop_btn")
        self.clear_btn.setObjectName("clear_btn")
        self.table.setObjectName("packet_table")

    def setup_timers(self):
        """Настраивает таймеры для обновления интерфейса"""
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000)  # Обновление каждую секунду

    def setup_signal_handlers(self):
        """Настраивает обработку системных сигналов"""
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)

    def handle_signal(self, signum, frame):
        """Обработчик системных сигналов"""
        self.log_message(f"Получен сигнал {signum}, завершение работы...")
        self.graceful_shutdown()

    def graceful_shutdown(self):
        """Корректное завершение работы приложения"""
        if self.is_shutting_down:
            return
        self.is_shutting_down = True

        self.log_message("Начинаем корректное завершение работы...")

        try:
            # Останавливаем таймеры
            if hasattr(self, 'stats_timer') and self.stats_timer.isActive():
                self.stats_timer.stop()
                self.log_message("Таймеры остановлены")

            # Останавливаем захват пакетов
            if self.capture_thread and self.capture_thread.isRunning():
                self.log_message("Останавливаем захват пакетов...")
                self.capture_thread.stop()

                # Ждем завершения потока с таймаутом
                if self.capture_thread.wait(3000):  # 3 секунды таймаут
                    self.log_message("Поток захвата успешно остановлен")
                else:
                    self.log_message("⚠️ Поток захвата не ответил вовремя")

            # Сохраняем финальную статистику в лог
            if self.packets_data:
                self.log_message(f"Финальная статистика: {len(self.packets_data)} пакетов, "
                               f"{len(self.stats)} типов ОС")

            self.log_message("Корректное завершение работы завершено")

        except Exception as e:
            self.log_message(f"Ошибка при завершении работы: {e}")

        finally:
            # Принудительно завершаем приложение
            QApplication.quit()

    def start_capture(self):
        """Запускает захват пакетов"""
        if self.is_shutting_down:
            return

        if self.capture_thread and self.capture_thread.isRunning():
            return

        self.capture_thread = PacketCaptureThread()
        self.capture_thread.packet_captured.connect(self.on_packet_captured)
        self.capture_thread.capture_started.connect(self.on_capture_started)
        self.capture_thread.capture_stopped.connect(self.on_capture_stopped)
        self.capture_thread.error_occurred.connect(self.on_error)

        self.capture_thread.start()

    def stop_capture(self):
        """Останавливает захват пакетов"""
        if self.is_shutting_down:
            return

        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()

    def clear_data(self):
        """Очищает все данные"""
        if self.is_shutting_down:
            return

        self.packets_data.clear()
        self.stats.clear()
        self.table.setRowCount(0)
        self.stats_text.clear()
        self.log_text.clear()
        self.log_message("Все данные очищены")

    def copy_to_markdown(self):
        """Копирует все данные в формате Markdown в буфер обмена"""
        markdown_content = self.generate_markdown_report()

        # Копируем в буфер обмена
        clipboard = QApplication.clipboard()
        clipboard.setText(markdown_content)

        # Показываем уведомление
        self.statusBar().showMessage("✅ Отчет скопирован в буфер обмена (Markdown)", 3000)
        self.log_message("Отчет в формате Markdown скопирован в буфер обмена")

    def generate_markdown_report(self):
        """Генерирует отчет в формате Markdown"""
        report = []

        # Заголовок
        report.append("# Отчет анализа сетевого трафика - PyP0f")
        report.append("")
        report.append(f"**Дата и время:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Всего пакетов:** {len(self.packets_data)}")
        report.append("")

        # Статистика ОС
        if self.stats:
            report.append("## Статистика операционных систем")
            report.append("")
            report.append("| ОС | Количество пакетов |")
            report.append("|----|-------------------|")

            for os_name, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
                if os_name and os_name != 'Не определено':
                    report.append(f"| {os_name} | {count} |")

            report.append("")

        # Таблица пакетов
        if self.packets_data:
            report.append("## Захваченные пакеты")
            report.append("")
            report.append("| Время | Тип | Источник | Назначение | ОС | Дистанция | MTU |")
            report.append("|-------|-----|----------|------------|----|-----------|-----|")

            for packet in self.packets_data[-50:]:  # Последние 50 пакетов
                src = f"{packet['src_ip']}:{packet['src_port']}"
                dst = f"{packet['dst_ip']}:{packet['dst_port']}"
                os_info = f"{packet['os']} {packet['os_flavor']}".strip()

                report.append(f"| {packet['timestamp']} | {packet['type']} | {src} | {dst} | {os_info} | {packet['distance']} | {packet['mtu']} |")

            if len(self.packets_data) > 50:
                report.append("")
                report.append(f"*Показаны последние 50 пакетов из {len(self.packets_data)}*")

            report.append("")

        # Детальная статистика
        report.append("## Детальная статистика")
        report.append("")

        # Типы пакетов
        syn_count = sum(1 for p in self.packets_data if p['type'] == 'SYN')
        synack_count = sum(1 for p in self.packets_data if p['type'] == 'SYN+ACK')
        error_count = sum(1 for p in self.packets_data if p['type'] == 'ERROR')

        report.append("### Типы пакетов")
        report.append(f"- **SYN пакеты:** {syn_count}")
        report.append(f"- **SYN+ACK пакеты:** {synack_count}")
        report.append(f"- **Пакеты с ошибками:** {error_count}")
        report.append("")

        # Уникальные IP
        src_ips = set(p['src_ip'] for p in self.packets_data if p['src_ip'] != 'ERROR')
        dst_ips = set(p['dst_ip'] for p in self.packets_data if p['dst_ip'] != 'ERROR')

        report.append("### Сетевые адреса")
        report.append(f"- **Уникальных источников:** {len(src_ips)}")
        report.append(f"- **Уникальных получателей:** {len(dst_ips)}")
        report.append("")

        # Лог событий (если есть)
        log_content = self.log_text.toPlainText()
        if log_content.strip():
            report.append("## Лог событий")
            report.append("")
            report.append("```")
            report.append(log_content)
            report.append("```")
            report.append("")

        # Подвал
        report.append("---")
        report.append("*Создано с помощью PyP0f GUI*")

        return "\n".join(report)

    def on_packet_captured(self, packet_info):
        """Обработчик захваченного пакета"""
        # Добавляем в таблицу
        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row, 0, QTableWidgetItem(packet_info['timestamp']))
        self.table.setItem(row, 1, QTableWidgetItem(packet_info['type']))
        self.table.setItem(row, 2, QTableWidgetItem(f"{packet_info['src_ip']}:{packet_info['src_port']}"))
        self.table.setItem(row, 3, QTableWidgetItem(f"{packet_info['dst_ip']}:{packet_info['dst_port']}"))
        self.table.setItem(row, 4, QTableWidgetItem(f"{packet_info['os']} {packet_info['os_flavor']}"))
        self.table.setItem(row, 5, QTableWidgetItem(packet_info['distance']))
        self.table.setItem(row, 6, QTableWidgetItem(packet_info['mtu']))
        self.table.setItem(row, 7, QTableWidgetItem(packet_info['raw_packet']))

        # Раскрашиваем строку в зависимости от типа пакета
        if packet_info['type'] == 'SYN':
            # Зеленый для SYN пакетов (исходящие)
            background_color = QColor('#d4edda')
            text_color = QColor('#155724')
        elif packet_info['type'] == 'SYN+ACK':
            # Желтый для SYN+ACK пакетов (входящие)
            background_color = QColor('#fff3cd')
            text_color = QColor('#856404')
        else:
            # Красный для ошибок
            background_color = QColor('#f8d7da')
            text_color = QColor('#721c24')

        # Применяем цвета ко всем ячейкам строки
        for col in range(8):
            if self.table.item(row, col):
                self.table.item(row, col).setBackground(background_color)
                self.table.item(row, col).setForeground(text_color)

        # Автопрокрутка к последней строке
        self.table.scrollToBottom()

        # Добавляем в статистику
        self.packets_data.append(packet_info)
        self.stats[packet_info['os']] += 1

    def on_capture_started(self):
        """Обработчик начала захвата"""
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.status_label.setText("🔴 Захват активен")
        self.statusBar().showMessage("Захват пакетов запущен")
        self.log_message("Захват пакетов начат")

    def on_capture_stopped(self):
        """Обработчик остановки захвата"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText("🟢 Готов")
        self.statusBar().showMessage("Захват пакетов остановлен")
        self.log_message("Захват пакетов остановлен")

    def on_error(self, error_msg):
        """Обработчик ошибок"""
        QMessageBox.warning(self, "Ошибка", error_msg)
        self.log_message(f"Ошибка: {error_msg}")

    def update_stats(self):
        """Обновляет статистику"""
        if not self.packets_data:
            self.stats_text.setPlainText("Нет данных для статистики")
            return

        stats_text = f"📊 ОБЩАЯ СТАТИСТИКА\n"
        stats_text += f"Всего пакетов: {len(self.packets_data)}\n\n"

        stats_text += f"🔍 ОПЕРАЦИОННЫЕ СИСТЕМЫ:\n"
        for os_name, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            if os_name != 'Не определено':
                stats_text += f"  {os_name}: {count} пакетов\n"

        stats_text += f"\n📈 ТИПЫ ПАКЕТОВ:\n"
        syn_count = sum(1 for p in self.packets_data if p['type'] == 'SYN')
        synack_count = sum(1 for p in self.packets_data if p['type'] == 'SYN+ACK')
        stats_text += f"  SYN: {syn_count}\n"
        stats_text += f"  SYN+ACK: {synack_count}\n"

        # Последние 5 пакетов
        stats_text += f"\n🕒 ПОСЛЕДНИЕ ПАКЕТЫ:\n"
        for packet in self.packets_data[-5:]:
            stats_text += f"  {packet['timestamp']} {packet['type']} {packet['os']}\n"

        self.stats_text.setPlainText(stats_text)

    def log_message(self, message):
        """Добавляет сообщение в лог"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.append(f"[{timestamp}] {message}")
        # Автопрокрутка
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def closeEvent(self, event):
        """Обработчик закрытия окна с корректным завершением"""
        # Если захват активен, показываем диалог подтверждения
        if self.capture_thread and self.capture_thread.isRunning():
            reply = QMessageBox.question(
                self,
                'Подтверждение выхода',
                'Захват пакетов активен. Вы действительно хотите выйти?\n'
                'Все несохраненные данные будут потеряны.',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.No:
                event.ignore()
                return

        # Показываем статус завершения
        self.statusBar().showMessage("Завершение работы...")
        self.log_message("Пользователь инициировал закрытие окна")

        # Запускаем корректное завершение
        self.graceful_shutdown()

        # Даем время на завершение операций
        QTimer.singleShot(100, lambda: event.accept())


def main():
    """Главная функция"""
    app = QApplication(sys.argv)
    app.setApplicationName("PyP0f GUI")
    app.setApplicationVersion("1.0")

    # Проверяем, запущены ли мы с sudo
    import os
    if os.geteuid() != 0:
        QMessageBox.critical(None, "Ошибка прав доступа",
                           "Для захвата сетевых пакетов требуются права root.\n"
                           "Запустите приложение с sudo:\n\n"
                           "sudo python3 pyp0f_gui.py")
        sys.exit(1)

    window = Pyp0fGUI()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
