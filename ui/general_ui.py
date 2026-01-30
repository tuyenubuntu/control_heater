# ui/general_ui.py
import sys
from typing import Optional, Set
import platform
from pathlib import Path
from PySide6.QtWidgets import QApplication, QPushButton, QTabWidget, QWidget, QTableWidget, QTableWidgetItem, QLabel, QMessageBox ,  QDialog, QVBoxLayout
from PySide6.QtGui import QIcon
from PySide6.QtUiTools import QUiLoader
from PySide6.QtCore import QFile, Qt, QFileSystemWatcher, QObject, Signal,QTimer
from services.security_service import SecurityService
from ui.monitoring_ui import MonitoringUI
from ui.control_ui import ControlUI
from ui.setting_ui import SettingUI
from ui.accountmanager_ui import AccountManagerUI

class GuiUpdater(QObject):
    # update_gui_log_signal        = Signal(object)  # window, broadcast
    # # Main service
    # update_gui_inspection_signal = Signal(object)  # window, broadcast
    # start_button_enable          = Signal(bool)
    # start_job_changed            = Signal(bool)
    # job_name_changed             = Signal(str)
    # mix_name_changed             = Signal(str)
    # # Manual service
    # update_frame_signal   = Signal(object)  # window, broadcast
    # update_histogram_data = Signal(object, float, float, float)  # (counts[256], ema, target, tol)
    # update_profile_data   = Signal(object) 
    # manual_changed        = Signal(bool)
    # # Error
    # plc_error_signal = Signal(bool, str)
    pass

class GeneralUI:
    def __init__(self, ui_path= "ui/general.ui", icon_path="ui/images/logo.jpg", window_title="Heater Panel"):
        self.app = QApplication([])
        self.loader = QUiLoader()
        self.window = self._load_ui(ui_path)
        # self.window.setWindowFlags(Qt.FramelessWindowHint)
        self.version = "1.0.0"   # Update this value when releasing a new version
        # self.gui_updater = GuiUpdater()
        # self.gui_updater.update_gui_log_signal.connect(self.gui_log_update)
        if icon_path:
            self.set_app_icon(icon_path)
        # Set window title if provided
        if window_title:
            self.set_window_title(window_title)

        # self.user_watcher.fileChanged.connect(self.setting_service.from_json_file)
        # --- Init Security service (users.json auto-reload) ---
        self.security = SecurityService("configs/security/users.json")
        self.user_watcher = QFileSystemWatcher([str(self.security.users_json_path)])
        self.user_watcher.fileChanged.connect(self.security.load)

        self.enable_role = False
        
        # --- Account manager backend (used by UI buttons) ---
        self.account_manager = AccountManagerUI(parent_window=self.window, loader=self.loader, security_service=self.security, generalUI=self)

        # Child UIs (inspection is initialized at start; others are lazy)
        self._monitor_ui = MonitoringUI(self.window)
        self._control_ui: Optional[ControlUI] = None
        self._setting_ui: Optional[SettingUI] = None
        self._inited: Set[int] = set()
        self.bind_widget()

    def bind_widget(self):

        self.changeuser_btn     = self.window.findChild(QPushButton, "changeUserBtn")
        self.accountmanager_btn = self.window.findChild(QPushButton, "accountManagementBtn")
        self.info_btn           = self.window.findChild(QPushButton, "infoBtn")
        self.end_button         = self.window.findChild(QPushButton, "endBtn")
        self.tab                = self.window.findChild(QTabWidget, "tabWidget")
        self.tab_monitor        = self.window.findChild(QWidget, "monitoring_tab")
        self.tab_setting        = self.window.findChild(QWidget, "setting_tab")
        self.tab_control        = self.window.findChild(QWidget, "control_tab")
        self.save_config        = self.window.findChild(QPushButton, "saveBtn")
        self.apply_btn          = self.window.findChild(QPushButton, "applyBtn")


        self.end_button.clicked.connect(QApplication.instance().quit)

        self.idx_monitor = self.tab.indexOf(self.tab_monitor) if self.tab and self.tab_monitor else -1
        self.idx_control = self.tab.indexOf(self.tab_control) if self.tab and self.tab_control else -1
        self.idx_setting = self.tab.indexOf(self.tab_setting) if self.tab and self.tab_setting else -1

        if self.changeuser_btn:
            self.changeuser_btn.clicked.connect(self.account_manager.open_general_login)
        if self.accountmanager_btn:
            self.accountmanager_btn.clicked.connect(self.account_manager.open_login_then_admin)

        if self.idx_control >= 0 and self.idx_setting >=0:
            self.tab.setTabEnabled(self.idx_control, False)
            self.tab.setTabEnabled(self.idx_setting, False)

        # Tab events (lazy init + optional pre-init on click)
        if self.tab:
            self._prev_tab_idx = self.tab.currentIndex() 
            self.tab.currentChanged.connect(self._on_tab_changed)
            self.tab.tabBar().tabBarClicked.connect(self._maybe_preinit_on_click)

        if self.info_btn:
            self.info_btn.clicked.connect(self.show_info_dialog)

    # ------------- HELPER -------------
    # ---------- tabs changed ----------
    def _on_tab_changed(self, idx: int):
        """Lazy init + monitorTab lifecycle management (polling/reset)."""

        if idx == self.idx_control and self._control_ui is None:
            self._control_ui = ControlUI(self.window)
            self._setting_ui = SettingUI(self.window)
        self._prev_tab_idx = idx
    
    def _maybe_preinit_on_click(self, idx: int):
        """Optional: pre-init when clicking a tab before currentChanged is emitted."""
        if idx == self.idx_control and self._control_ui is None:
            self._manual_ui = ControlUI(self.window)
            self._inited.add(idx)
        if idx == self.idx_setting and self._setting_ui is None:
            self._setting_ui = SettingUI(self.window)
            self._inited.add(idx)

    # --- role-based permission for any tab ---
    def _apply_tab_permission(self, role: str, user: str):
        if self.idx_control < 0 or not self.tab:
            return
        self.enable_role = (role != "administrator")
        # If the role is restricted and the user is on the cam/monitor tab -> switch to inspection
        if not self.enable_role and self.tab.currentIndex() in (self.idx_control, self.idx_setting):
            if self.idx_monitor >= 0:
                self.tab.setCurrentIndex(self.idx_monitor)
        # Update enable/disable for tab
        if self.window and not self.window.isHidden():
            self.tab.setTabEnabled(self.idx_control, self.enable_role)
            self.tab.setTabEnabled(self.idx_setting, self.enable_role)
            # self.tab.setTabEnabled(self.idx_setting, self.enable_role)
        if role == "administrator" and user == "administrator":
            self.tab.setTabEnabled(self.idx_control, True)
            self.tab.setTabEnabled(self.idx_setting, True)
            self.save_config.setEnabled(True)
        else:
            self.tab.setTabEnabled(self.idx_setting, False)
            self.tab.setTabEnabled(self.idx_control, False)
            if self.idx_monitor >= 0:
                self.tab.setCurrentIndex(self.idx_monitor)
                self.save_config.setEnabled(False)
    
    def _enabled_tab(self, enabled):
        for idx in (self.idx_control, self.idx_setting):
            self.tab.setTabEnabled(idx, enabled and self.enable_role)
    

    def show_info_dialog(self):
        app_name = "Heater Panel"
        os_version = platform.platform()
        copyright_text = "© Truong Thanh Tuyen"

        info_text = (
            f"<b>Application:</b> {app_name}<br>"
            f"<b>Version:</b> {self.version}<br>"
            f"<b>OS Version:</b> {os_version}<br>"
            f"<b>Copyright:</b> {copyright_text}")

        msg_box = QMessageBox(self.window)
        msg_box.setWindowTitle("Application Information")
        msg_box.setText(info_text)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec()

    def _load_ui(self, path):
        file = QFile(path)
        file.open(QFile.ReadOnly)
        ui = self.loader.load(file)
        file.close()
        return ui
    
    def set_app_icon(self, icon_path):
        """Set the application icon."""
        try:
            icon = QIcon(icon_path)
            self.app.setWindowIcon(icon)
            self.window.setWindowIcon(icon)
        except Exception as e:
            print(f"Failed to set application icon: {e}")
    
    def set_window_title(self, title):
        """Set the window title."""
        try:
            self.window.setWindowTitle(title)
        except Exception as e:
            print(f"Failed to set window title: {e}")

    def run(self):
        self.window.show()
        self.app.exec()
