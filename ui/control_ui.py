import warnings
from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtWidgets import QComboBox, QTextEdit, QPushButton, QLabel, QTableWidget, QTableWidgetItem, QApplication, QWidget
from entities.log_ui_entity import LogUIEntity
from infrastructure.log_ui_type import LogUIType

class ControlUI:
    def __init__(self, window: QWidget, generalUI):
        self.window = window
        self.generalUI = generalUI
        self.mode_boxs = ["Auto", "Manual", "Standard", "Dual"]
        self.buzzer_state = False  # Track buzzer state
        self.fan_state = False  # Track fan force state
        self.heater_state = False  # Track heater force state
        self._widgets_bound = False  # Guard flag to prevent multiple bindings
        self._bind_widgets()

    
    def _bind_widgets(self):
        # Prevent multiple bindings
        if self._widgets_bound:
            return
        self._widgets_bound = True
        
        # First try to find buttons in the control tab directly
        # Get the control_tab first
        control_tab = self.window.findChild(QWidget, "control_tab")
        
        if control_tab:
            self.mode_box = control_tab.findChild(QComboBox, "mode_box")
            self.force_fan_Btn = control_tab.findChild(QPushButton, "force_fan_Btn")
            self.force_heater_Btn = control_tab.findChild(QPushButton, "force_heater_Btn")
            self.force_alarm_Btn = control_tab.findChild(QPushButton, "force_alarm_Btn")
        else:
            # Fallback to searching in the whole window
            self.mode_box = self.window.findChild(QComboBox, "mode_box")
            self.force_fan_Btn = self.window.findChild(QPushButton, "force_fan_Btn")
            self.force_heater_Btn = self.window.findChild(QPushButton, "force_heater_Btn")
            self.force_alarm_Btn = self.window.findChild(QPushButton, "force_alarm_Btn")
        
        if self.mode_box:
            # Suppress the warning about disconnecting (None) - no connection may exist
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=".*Failed to disconnect.*")
                try:
                    self.mode_box.currentTextChanged.disconnect()
                except (RuntimeError, TypeError):
                    pass
            
            # Block signals during initialization
            self.mode_box.blockSignals(True)
            # Clear existing items and load items from self.mode_boxs
            self.mode_box.clear()
            self.mode_box.addItems(self.mode_boxs)
            # Unblock signals
            self.mode_box.blockSignals(False)
            self.mode_box.currentTextChanged.connect(self._on_mode_changed)
            # Initialize to Manual mode to enable buttons by default
            self.mode_box.setCurrentText("Manual")
            self._on_mode_changed("Manual")
        
        # Connect button clicks
        if self.force_fan_Btn:
            self.force_fan_Btn.clicked.connect(self._on_fan_button_clicked)
            self.force_fan_Btn.setText("Set")
        if self.force_heater_Btn:
            self.force_heater_Btn.clicked.connect(self._on_heater_button_clicked)
            self.force_heater_Btn.setText("Set")
        if self.force_alarm_Btn:
            self.force_alarm_Btn.clicked.connect(self._on_alarm_button_clicked)
            self.force_alarm_Btn.setText("Set")
    
    def _on_mode_changed(self, mode: str):
        """Enable/disable buttons based on selected mode"""
        is_manual = mode == "Manual"
        self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO,f"[Mode Change] Chế độ đã thay đổi thành {self.mode_box.currentText()}.",""))

        # Send mode command to Arduino
        arduino_mode = "MANUAL" if is_manual else "AUTO"
        self.generalUI.arduino_io_service.set_mode(arduino_mode)

        # List of all buttons to control
        buttons = [
            self.force_fan_Btn,
            self.force_heater_Btn,
            self.force_alarm_Btn
        ]
        
        # Enable buttons if Manual mode, disable otherwise
        for button in buttons:
            if button:
                button.setEnabled(is_manual)
            else:
                self.generalUI.gui_log_update(
                    LogUIEntity(LogUIType.WARNING, "[ControlUI] WARNING: Button not found", str(button))
                )
        
        
    
    def _on_alarm_button_clicked(self):
        """Handle alarm button click - toggle buzzer on/off"""
        self.buzzer_state = not self.buzzer_state
        
        self.generalUI.arduino_io_service.set_buzzer(self.buzzer_state)
        
        # Update button text to show current state
        if self.force_alarm_Btn:
            self.force_alarm_Btn.setText("Reset" if self.buzzer_state else "Set")
            self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, f"[Buzzer Control] {'On' if self.buzzer_state else 'Off'} buzzer/alarm", ""))
    
    def _on_fan_button_clicked(self):
        """Handle fan button click - toggle Set/Reset"""
        self.fan_state = not self.fan_state
        
        # Send fan control command (100% when Set, 0% when Reset)
        if self.fan_state:
            self.generalUI.arduino_io_service.set_manual_outputs(0, 100)  # heater=0, fan=100
        else:
            self.generalUI.arduino_io_service.set_manual_outputs(0, 0)    # heater=0, fan=0
        
        # Update button text
        if self.force_fan_Btn:
            self.force_fan_Btn.setText("Reset" if self.fan_state else "Set")
            self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, f"[Fan Control] {'Bật' if self.fan_state else 'Tắt'} quạt", ""))
    
    def _on_heater_button_clicked(self):
        """Handle heater button click - toggle Set/Reset"""
        self.heater_state = not self.heater_state
        
        # Send heater control command (100% when Set, 0% when Reset)
        if self.heater_state:
            self.generalUI.arduino_io_service.set_manual_outputs(100, 0)  # heater=100, fan=0
        else:
            self.generalUI.arduino_io_service.set_manual_outputs(0, 0)    # heater=0, fan=0
        
        # Update button text
        if self.force_heater_Btn:
            self.force_heater_Btn.setText("Reset" if self.heater_state else "Set")
            self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, f"[Heater Control] {'Bật' if self.heater_state else 'Tắt'} sưởi", ""))