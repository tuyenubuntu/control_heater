# services/arduino_io_service.py
from __future__ import annotations

from typing import Optional, Callable

from services.connection_service import ConnectionService
from services.arduino_protocol import ArduinoProtocol, Telemetry


class ArduinoIOService:
    """
    API cấp cao cho đồ án:
    - connect/disconnect
    - set/get setpoint, pid
    - start/stop
    - nhận telemetry và lưu latest
    """

    def __init__(self, conn: ConnectionService):
        self.conn = conn
        self.proto = ArduinoProtocol()
        self.latest: Telemetry = Telemetry()

        # optional callback để UI nhận telemetry đã parse
        self.on_telemetry: Optional[Callable[[Telemetry], None]] = None

        # gắn callback raw từ connection_service
        self.conn.on_data_received = self._handle_line

    # ---------- Connection ----------
    def list_ports(self):
        return self.conn.list_ports()

    def connect(self, port: str, baudrate: int = 9600) -> bool:
        return self.conn.connect(port, baudrate)

    def disconnect(self):
        self.conn.disconnect()

    # ---------- High-level Commands ----------
    def start(self):
        self.conn.send(self.proto.cmd_start())

    def stop(self):
        self.conn.send(self.proto.cmd_stop())

    def set_mode(self, mode: str):
        self.conn.send(self.proto.cmd_mode(mode))

    def set_setpoint(self, sp: float):
        self.conn.send(self.proto.cmd_set_sp(sp))

    def set_pid(self, kp: float, ki: float, kd: float):
        self.conn.send(self.proto.cmd_set_pid(kp, ki, kd))

    def set_manual_outputs(self, heater_pct: int, fan_pct: int):
        self.conn.send(self.proto.cmd_manual_outputs(heater_pct, fan_pct))

    # ---------- Receive handler ----------
    def _handle_line(self, line: str):
        # Parse telemetry
        t = self.proto.parse_telemetry(line)
        if t is None:
            return

        # Update latest values (chỉ update cái nào có)
        if t.pv is not None: self.latest.pv = t.pv
        if t.sp is not None: self.latest.sp = t.sp
        if t.err is not None: self.latest.err = t.err
        if t.heater is not None: self.latest.heater = t.heater
        if t.fan is not None: self.latest.fan = t.fan
        if t.mode is not None: self.latest.mode = t.mode
        if t.alarm is not None: self.latest.alarm = t.alarm

        if self.on_telemetry:
            self.on_telemetry(self.latest)
