from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QPixmap, QImage, QColor
from PySide6.QtWidgets import QComboBox, QTextEdit, QPushButton, QLabel, QTableWidget, QTableWidgetItem, QApplication, QWidget
import time
import threading
from services.connection_service import ConnectionService
from services.arduino_io_service import ArduinoIOService
from ui.histogram import HistogramUI


class MonitoringUI:
    def __init__(self, window: QWidget, generalUI):
        self.window = window
        self.generalUI = generalUI
        self.connection_service = ConnectionService()
        self.arduino_io_service = ArduinoIOService(self.connection_service)

        self.state_connected = None
        self.pv_prev = None  # For trend calculation

        # Available ports/baudrates
        self.ports = self.arduino_io_service.list_ports()
        self.baudrates = [9600, 19200, 38400, 57600, 115200]
        self._bind_widgets()
        # populate UI widgets
        self.update_com_ports()
        self.update_baudrates()
        # initialize connect button state
        if self.connect_button:
            self.connect_button.setText("Connect")
            # ensure comboboxes enabled when starting
            if hasattr(self, 'com') and self.com:
                self.com.setEnabled(True)
            if hasattr(self, 'baudrate') and self.baudrate:
                self.baudrate.setEnabled(True)
        
        # Setup histogram
        self.histogram = HistogramUI(parent_widget=self.histogram_1, max_samples=500)
        
        # Setup telemetry callback
        self.arduino_io_service.on_telemetry = self.on_telemetry_received

    def __del__(self):
        """Cleanup khi UI bị xóa"""
        try:
            if self.state_connected:
                self.arduino_io_service.disconnect()
            self.arduino_io_service.on_telemetry = None  # Xóa callback
        except Exception:
            pass

    def _bind_widgets(self):
        self.pv = self.window.findChild(QLabel, "pv_label")
        self.sp = self.window.findChild(QLabel, "sp_label")
        self.mode = self.window.findChild(QLabel, "mode_label")
        self.error = self.window.findChild(QLabel, "error_label")
        self.trend = self.window.findChild(QLabel, "trend_label")
        self.fan = self.window.findChild(QLabel, "fan_label")
        self.heater = self.window.findChild(QLabel, "heater_label")
        self.state_label = self.window.findChild(QLabel, "state_label")
        self.job = self.window.findChild(QComboBox, "job_box")
        self.com = self.window.findChild(QComboBox, "com_box")
        self.baudrate = self.window.findChild(QComboBox, "baudrate_box")
        self.start_button = self.window.findChild(QPushButton, "startButton")
        self.stop_button = self.window.findChild(QPushButton, "stopButton")
        self.connect_button = self.window.findChild(QPushButton, "connectBtn")
        self.refresh_button = self.window.findChild(QPushButton, "refreshBtn")
        self.histogram_1 = self.window.findChild(QWidget, "histogram_1")
        self.info = self.window.findChild(QTextEdit, "info_edit")

        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        if self.refresh_button:
            self.refresh_button.clicked.connect(self.refresh)
        if self.connect_button:
            self.connect_button.clicked.connect(self.handle_connect)
    
    def start(self):
        self.arduino_io_service.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
    
    def stop(self):
        self.arduino_io_service.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def refresh(self):
        self.ports = self.arduino_io_service.list_ports()
        self.update_com_ports()
        self.update_baudrates()
        self.info.append("[Refresh] Đã làm mới danh sách cổng COM.")

    def on_telemetry_received(self, telemetry):
        """Callback từ arduino_io_service khi nhận data từ Arduino"""
        try:
            # Update labels với giá trị mới
            if self.pv and telemetry.pv is not None:
                self.pv.setText(f"{telemetry.pv:.2f}°C")
            
            if self.sp and telemetry.sp is not None:
                self.sp.setText(f"{telemetry.sp:.2f}°C")
            
            if self.mode and telemetry.mode is not None:
                self.mode.setText(str(telemetry.mode))
            
            if self.error and telemetry.err is not None:
                self.error.setText(f"{telemetry.err:.2f}")
            
            if self.fan and telemetry.fan is not None:
                self.fan.setText(f"{telemetry.fan}%")
            
            if self.heater and telemetry.heater is not None:
                self.heater.setText(f"{telemetry.heater}%")
            
            # Cập nhật histogram
            if telemetry.pv is not None:
                self.histogram.add_pv_sample(telemetry.pv)
            if telemetry.sp is not None:
                self.histogram.set_setpoint(telemetry.sp)
            
            # Cập nhật vẽ histogram mỗi 50 samples
            if len(self.histogram.pv_samples) % 50 == 0:
                self.histogram.update_histogram()
            
            # Tính trend: so sánh pv hiện tại với pv trước đó
            if self.trend and telemetry.pv is not None:
                if self.pv_prev is None:
                    trend_str = "→"
                elif telemetry.pv > self.pv_prev:
                    trend_str = "↑"
                elif telemetry.pv < self.pv_prev:
                    trend_str = "↓"
                else:
                    trend_str = "→"
                self.trend.setText(trend_str)
                self.pv_prev = telemetry.pv
        except Exception as e:
            # UI widget đã bị xóa hoặc lỗi khác
            pass

    def update_com_ports(self):
        if self.com is None:
            return
        self.com.clear()
        for p in self.ports:
            try:
                self.com.addItem(p)
            except Exception:
                # ensure we don't crash if item type is unexpected
                self.com.addItem(str(p))

    def update_baudrates(self):
        if self.baudrate is None:
            return
        self.baudrate.clear()
        for b in self.baudrates:
            self.baudrate.addItem(str(b))
        # set default to 9600 if available
        idx = self.baudrate.findText("9600")
        if idx >= 0:
            self.baudrate.setCurrentIndex(idx)

    def handle_connect(self):
        # Toggle connect/disconnect depending on current state
        if self.connection_service and self.state_connected:
            # currently connected -> disconnect
            try:
                self.arduino_io_service.disconnect()
                self.state_connected = False
            except Exception:
                pass
            self._set_connected_state(False)
            self.info.append("[Connect] Đã ngắt kết nối.")
            return

        # Not connected -> attempt connect
        port = self.com.currentText() if self.com else None
        baud_text = self.baudrate.currentText() if self.baudrate else ""
        try:
            baud = int(baud_text) if baud_text else 9600
        except Exception:
            baud = 9600

        if not port:
            self.info.append("[Connect] Vui lòng chọn cổng COM.")
            return

        # Run on background thread
        self.connect_button.setEnabled(False)
        self.info.append(f"[Connect] Đang kết nối {port} @ {baud}...")
        thread = threading.Thread(target=self._connect_async, args=(port, baud), daemon=True)
        thread.start()
    
    def _connect_async(self, port, baud):
        """Kết nối trên background thread"""
        try:
            success = self.arduino_io_service.connect(port, baudrate=baud)
        except Exception as e:
            print(f"[Connect] Error: {e}")
            success = False
        
        # Update UI trên main thread
        self.connect_button.setEnabled(True)
        self.state_connected = success
        if success:
            self._set_connected_state(True)
            self.info.append(f"[Connect] ✓ Đã kết nối {port} @ {baud}.")
        else:
            self.info.append(f"[Connect] ✗ Kết nối thất bại - kiểm tra port hoặc Arduino.")

    def _set_connected_state(self, connected: bool):
        # Update button text and enable/disable comboboxes
        self.connect_button.setText("Disconnect" if connected else "Connect")
        self.com.setEnabled(not connected)
        self.baudrate.setEnabled(not connected)
        
        # Update state label color: green if connected, yellow if disconnected
        if connected:
            self.state_label.setStyleSheet("QLabel { background-color: #00CC00; color: white; padding: 5px; border-radius: 3px; }")
        else:
            self.state_label.setStyleSheet("QLabel { background-color: #FFCC00; color: black; padding: 5px; border-radius: 3px; }")
