import time
from services.connection_service import ConnectionService
from services.arduino_io_service import ArduinoIOService

def f2(x):
    return "--" if x is None else f"{x:.2f}"

def on_telemetry(data):
    print(
        f"PV={f2(data.pv)} | "
        f"SP={f2(data.sp)} | "
        f"ERR={f2(data.err)} | "
        f"Heater={data.heater} | "
        f"Fan={data.fan} | "
        f"Mode={data.mode} | "
        f"Alarm={data.alarm}"
    )


def main():
    conn = ConnectionService()
    arduino = ArduinoIOService(conn)

    # 1. List COM ports
    ports = arduino.list_ports()
    print("Available ports:", ports)
    if not ports:
        print("❌ Không tìm thấy Arduino")
        return

    # 2. Gán callback nhận dữ liệu
    arduino.on_telemetry = on_telemetry

    # 3. Kết nối (đổi index nếu cần)
    ok = arduino.connect(ports[1], baudrate=9600)
    print("Connected:", ok)
    if not ok:
        return

    # 4. Arduino UNO reset khi mở COM
    time.sleep(2.5)

    print("▶️ Bắt đầu đọc dữ liệu từ Arduino...\n")

    try:
        while True:
            # chỉ cần giữ chương trình sống
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n⏹ Stop by user")

    finally:
        arduino.disconnect()


if __name__ == "__main__":
    main()
