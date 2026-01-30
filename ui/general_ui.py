# ui/general_ui.py
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile


def run():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    ui_path = Path(__file__).parent / "general_ui.ui"

    loader = QUiLoader()
    file = QFile(str(ui_path))
    file.open(QFile.ReadOnly)

    window = loader.load(file)
    file.close()

    if window is None:
        raise RuntimeError("Load UI failed")

    window.show()
    app.exec()


# cho phép chạy trực tiếp file này
if __name__ == "__main__":
    run()
