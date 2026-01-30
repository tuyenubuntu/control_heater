# services/connection_service.py

import serial
import serial.tools.list_ports
import threading
import time


class ConnectionService:
    """
    Service chịu trách nhiệm kết nối & giao tiếp với Arduino qua Serial
    """

    def __init__(self):
        self.ser = None
        self.port = None
        self.baudrate = 115200
        self.is_connected = False

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
    def connect(self, port: str, baudrate: int = 115200):
        if self.is_connected:
            return True

        try:
            self.ser = serial.Serial(
                port=port,
                baudrate=baudrate,
                timeout=1
            )
            self.port = port
            self.baudrate = baudrate
            self.is_connected = True

            self._start_reading()
            print(f"[ConnectionService] Connected to {port}")

            return True

        except Exception as e:
            print(f"[ConnectionService] Connect failed: {e}")
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
        print("[ConnectionService] Disconnected")

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
            print(f"[ConnectionService] Send error: {e}")

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
                            print(f"[Arduino] {line}")
            except Exception as e:
                print(f"[ConnectionService] Read error: {e}")
                break

            time.sleep(0.01)
