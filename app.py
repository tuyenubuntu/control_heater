# app.py
import sys
import traceback

def handle_exception(exc_type, exc_value, exc_traceback):
    """Global exception handler"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    print("=" * 80)
    print("UNCAUGHT EXCEPTION:")
    print("=" * 80)
    print(''.join(traceback.format_exception(exc_type, exc_value, exc_traceback)))
    print("=" * 80)

sys.excepthook = handle_exception

from ui.general_ui import GeneralUI
gui = GeneralUI()
if __name__ == "__main__":
    gui.run()
