# services/arduino_protocol.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict


@dataclass
class Telemetry:
    pv: Optional[float] = None      # Process Value (nhiet do do)
    sp: Optional[float] = None      # Setpoint
    err: Optional[float] = None     # Error = SP - PV
    heater: Optional[int] = None    # 0..100 (%)
    fan: Optional[int] = None       # 0..100 (%)
    mode: Optional[str] = None      # AUTO/MANUAL
    alarm: Optional[str] = None     # NONE/OVERTEMP/SENSOR...


class ArduinoProtocol:
    """
    Protocol đơn giản dạng key=value, phân tách bởi dấu phẩy.
    """

    # ---------- Encode commands (PC -> Arduino) ----------
    @staticmethod
    def cmd_set_sp(sp: float) -> str:
        return f"SP={sp:.2f}"

    @staticmethod
    def cmd_set_pid(kp: float, ki: float, kd: float) -> str:
        return f"PID,KP={kp:.3f},KI={ki:.3f},KD={kd:.3f}"

    @staticmethod
    def cmd_start() -> str:
        return "START"

    @staticmethod
    def cmd_stop() -> str:
        return "STOP"

    @staticmethod
    def cmd_mode(mode: str) -> str:
        mode = mode.upper().strip()
        if mode not in ("AUTO", "MANUAL"):
            raise ValueError("mode must be AUTO or MANUAL")
        return f"MODE={mode}"

    @staticmethod
    def cmd_manual_outputs(heater_pct: int, fan_pct: int) -> str:
        heater_pct = max(0, min(100, int(heater_pct)))
        fan_pct = max(0, min(100, int(fan_pct)))
        return f"MAN,H={heater_pct},F={fan_pct}"

    # ---------- Decode telemetry (Arduino -> PC) ----------
    @staticmethod
    def parse_telemetry(line: str) -> Telemetry | None:
        """
        line ví dụ:
          PV=72.5,SP=80.0,ERR=-7.5,H=35,F=0,MODE=AUTO,ALARM=NONE
        """
        line = line.strip()
        if not line:
            return None

        # Nếu bạn muốn phân biệt telemetry bằng prefix, có thể dùng:
        # if not line.startswith("T,"): return None
        # line = line[2:]

        parts = [p.strip() for p in line.split(",") if p.strip()]
        kv: Dict[str, str] = {}
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                kv[k.strip().upper()] = v.strip()
            else:
                # token không có '=' (ví dụ: "AUTO") -> bỏ qua
                pass

        t = Telemetry()

        def to_float(key: str) -> Optional[float]:
            if key not in kv:
                return None
            try:
                return float(kv[key])
            except:
                return None

        def to_int(key: str) -> Optional[int]:
            if key not in kv:
                return None
            try:
                return int(float(kv[key]))
            except:
                return None

        t.pv = to_float("PV")
        t.sp = to_float("SP")
        t.err = to_float("ERR")
        t.heater = to_int("H")
        t.fan = to_int("F")
        t.mode = kv.get("MODE")
        t.alarm = kv.get("ALARM")

        return t
