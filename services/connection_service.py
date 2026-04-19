# services/connection_service.py

import serial
import serial.tools.list_ports
import threading
import time
from services.Logging_service import LoggingService


class ConnectionService:
    """
    Service chịu trách nhiệm kết nối & giao tiếp với Arduino qua Serial
    """

    def __init__(self):
        self.ser = None
        self.port = None
        self.baudrate = 115200
        self.is_connected = False
        self.logger = LoggingService("log/logs.csv")

        self._read_thread = None
        self._stop_event = threading.Event()

        # callback để bắn data lên UI / service khác
        self.on_data_received = None  # function(str)

    # -----------------------------
    # PORT UTILS
    # -----------------------------
    @staticmethod
    def list_ports():
        """
        Trả về danh sách COM ports
        """
        ports = serial.tools.list_ports.comports()
        return [p.device for p in ports]

    # -----------------------------
    # CONNECTION
    # -----------------------------
    def connect(self, port: str, baudrate: int = 115200, timeout: int = 2):
        if self.is_connected:
            return True

        # Kiểm tra port có tồn tại không
        available_ports = self.list_ports()
        if port not in available_ports:
            self.logger.warning(
                "ConnectionService",
                f"Port {port} not found. Connection failed.",
                f"Available: {available_ports}",
            )
            return False

        try:
            # Giảm timeout khi mở serial port
            self.ser = serial.Serial(
                port=port,
                baudrate=baudrate,
                timeout=0.5,
                write_timeout=1
            )
            self.port = port
            self.baudrate = baudrate
            
            # Chờ Arduino reset (khi mở COM, Arduino UNO sẽ reset)
            time.sleep(2)
            
            # Xóa buffer cũ
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            
            # Gửi lệnh REQ để kiểm tra
            self.ser.write(b"REQ\n")
            
            # Chờ response với timeout
            start_time = time.time()
            response_received = False
            
            while time.time() - start_time < timeout:
                if self.ser.in_waiting > 0:
                    line = self.ser.readline().decode(errors="ignore").strip()
                    # Kiểm tra xem có phải telemetry response không (chứa "PV=" và "SP=")
                    if "PV=" in line and "SP=" in line:
                        response_received = True
                        self.logger.info(
                            "ConnectionService",
                            "Handshake OK",
                            line,
                        )
                        break
                time.sleep(0.05)
            
            if not response_received:
                self.ser.close()
                self.is_connected = False
                self.logger.warning(
                    "ConnectionService",
                    f"No response from Arduino on {port}",
                )
                return False
            
            self.is_connected = True
            self._start_reading()
            self.logger.info(
                "ConnectionService",
                f"Connected to {port}",
            )
            return True

        except Exception as e:
            self.logger.error(
                "ConnectionService",
                "Connect failed",
                str(e),
            )
            self.is_connected = False
            return False

    def disconnect(self):
        if not self.is_connected:
            return

        self._stop_event.set()

        if self._read_thread:
            self._read_thread.join(timeout=1)

        if self.ser and self.ser.is_open:
            self.ser.close()

        self.is_connected = False
        self.ser = None
        self.logger.info("ConnectionService", "Disconnected")

    # -----------------------------
    # SEND / RECEIVE
    # -----------------------------
    def send(self, message: str):
        """
        Gửi lệnh xuống Arduino
        """
        if not self.is_connected or not self.ser:
            return

        if not message.endswith("\n"):
            message += "\n"

        try:
            self.ser.write(message.encode())
        except Exception as e:
            self.logger.error("ConnectionService", "Send error", str(e))

    def _start_reading(self):
        self._stop_event.clear()
        self._read_thread = threading.Thread(
            target=self._read_loop,
            daemon=True
        )
        self._read_thread.start()

    def _read_loop(self):
        """
        Thread đọc dữ liệu từ Arduino
        """
        while not self._stop_event.is_set():
            try:
                if self.ser and self.ser.in_waiting:
                    line = self.ser.readline().decode(errors="ignore").strip()
                    if line:
                        # callback ra ngoài
                        if self.on_data_received:
                            self.on_data_received(line)
                        else:
                            self.logger.info("Arduino", line)
            except Exception as e:
                self.logger.error("ConnectionService", "Read error", str(e))
                break

            time.sleep(0.01)
