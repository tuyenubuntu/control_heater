# ui/accountmanager_ui.py
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Type, TypeVar, Callable
from shiboken6 import isValid  
from PySide6.QtCore import QFile, Qt
from PySide6.QtWidgets import QWidget, QDialog, QPushButton, QLineEdit, QTextEdit, QComboBox,QMessageBox, QTabWidget, QCheckBox, QButtonGroup
from PySide6.QtUiTools import QUiLoader
# from infrastructure.log_ui_type import LogUIType
# from entities.log_ui_entity import LogUIEntity

T = TypeVar("T", bound=QWidget)

@dataclass
class AccountManagerConfig:
    users_json_path: Path = Path("configs/security/users.json")
    login_ui_path: str = "ui/login.ui"
    admin_ui_path: str = "ui/admin.ui"
    # Ask before creating a user with empty password
    confirm_empty_password: bool = True
class AccountManagerUI:
    """
    PUBLIC (called from GeneralUI):
      - open_general_login()      # normal login, can be called anywhere
      - open_login_then_admin()   # force admin login, then open admin.ui
      - bind_widget()             # open admin.ui and wire Create/Permission/Manager tabs

    Notes:
      - Dialogs use WA_DeleteOnClose for safe destruction.
      - Permission/Manager tab signals are wired safely and rebind applyBtn per tab.
    """
    # ---------- init ----------
    def __init__(self, parent_window, loader: QUiLoader, security_service, generalUI, cfg: Optional[AccountManagerConfig] = None):
        self.parent_window = parent_window
        self.loader = loader
        self.security = security_service
        self.generalUI =  generalUI
        # self.gui_updater = gui_updaters
        self.cfg = cfg or AccountManagerConfig()

        # dialog + tab state
        self._admin_dlg: Optional[QDialog] = None
        self._perm_inited: bool = False  # signals on permission tab wired?

        # Create tab widgets
        self._create_user_edit: Optional[QLineEdit] = None
        self._create_pass_edit: Optional[QLineEdit] = None
        self._desc_edit: Optional[QTextEdit] = None
        self._create_btn: Optional[QPushButton] = None

        # Permission tab widgets
        self._perm_user_box: Optional[QComboBox] = None
        self._admin_box: Optional[QCheckBox] = None
        self._op_box: Optional[QCheckBox] = None
        self._apply_btn: Optional[QPushButton] = None  # shared button

        # Manager tab widgets
        self._mgr_user_box: Optional[QComboBox] = None          # userBox_1
        self._mgr_pass_edit: Optional[QLineEdit] = None          # passEdit (current password)
        self._mgr_new_pass_edit: Optional[QLineEdit] = None      # new_passEdit (new password)
        self._mgr_delete_box: Optional[QCheckBox] = None         # deleteBox
        self._mgr_change_box: Optional[QCheckBox] = None         # change_passBox
        self._mgr_group: Optional[QButtonGroup] = None

    # ===================== PUBLIC =====================

    def open_general_login(self):
        """Normal login. Applies role to GeneralUI on success."""
        dlg = self._load_dialog(self.cfg.login_ui_path)
        if not dlg:
            # self.generalUI.gui_log_update(LogUIEntity(LogUIType.ERROR, "Open account management window", "Failed."))
            QMessageBox.critical(self.parent_window, "Login", "Cannot load login UI.")
            return

        user_box, pass_edit, login_btn, cancel_btn, status_lbl = self._login_widgets(dlg)
        logout_btn = self._find(dlg, "logoutBtn", QPushButton, silent=True)
        if logout_btn:
            logout_btn.clicked.connect(lambda: self._handle_logout(dlg))

        # clear any old status
        if hasattr(status_lbl, "setText"):
            try: status_lbl.setText("")
            except Exception: pass

        # Fill user list
        names = self.security.list_usernames() or ["system"]
        user_box.clear(); user_box.addItems(names)
        if "system" in names:
            user_box.setCurrentText("system")

        def do_login():
            user = user_box.currentText().strip()
            password = pass_edit.text()
            if self.security.verify(user, password):
                # self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, f"Login in to user: {user}", "Sucessfully."))
                role = (self.security.get_role(user) or "operator").lower()
                if hasattr(self.generalUI, "_apply_tab_permission"):
                    self.generalUI._apply_tab_permission(role, user)
                dlg.accept()
                # If admin dialog is open, refresh its permission tab safely
                if self._admin_dlg and self._admin_dlg.isVisible():
                    self._init_permission_tab(refresh=True)
            else:
                # self.generalUI.gui_log_update(LogUIEntity(LogUIType.WARNING, f"Login in to user: {user}", "Failed, wrong account or password!"))
                QMessageBox.critical(dlg, "Login failed", "Wrong account or password!")
                if hasattr(status_lbl, "setText"):
                    try: status_lbl.setText("Wrong account or password!")
                    except Exception: pass
                pass_edit.setFocus(); pass_edit.selectAll()

        self._wire_login_controls(dlg, pass_edit, login_btn, cancel_btn, do_login)
        dlg.exec()

    def open_login_then_admin(self):
        """Force 'administrator' login then open admin dialog."""
        dlg = self._load_dialog(self.cfg.login_ui_path)
        if not dlg:
            # self.generalUI.gui_log_update(LogUIEntity(LogUIType.ERROR, "Open login window", "Failed."))
            QMessageBox.critical(self.parent_window, "Login", "Cannot load login UI.")
            return

        user_box, pass_edit, login_btn, cancel_btn, _ = self._login_widgets(dlg)
        user_box.clear(); user_box.addItem("administrator"); user_box.setEditable(False)

        def do_login_admin():
            if self.security.verify("administrator", pass_edit.text()):
                # self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, "Login in to user: administrator", "Sucessfully."))
                # self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, "Open Account Management", "Sucessfully."))
                dlg.accept()
            else:
                # self.generalUI.gui_log_update(LogUIEntity(LogUIType.WARNING, "Login in to user: administrator", "Failed, wrong password for 'administrator'."))
                QMessageBox.critical(dlg, "Login failed", "Wrong password for 'administrator'.")
                pass_edit.setFocus(); pass_edit.selectAll()

        self._wire_login_controls(dlg, pass_edit, login_btn, cancel_btn, do_login_admin)
        if dlg.exec() == QDialog.Accepted:
            self.bind_widget()
    
    def create_user(self):
        u = (self._create_user_edit.text().strip() if self._create_user_edit else "")
        p = (self._create_pass_edit.text() if self._create_pass_edit else "")
        d = (self._desc_edit.toPlainText().strip() if self._desc_edit else "")

        if not u:
            QMessageBox.warning(self._admin_dlg, "Validation", "Username is required.")
            return
        if " " in u:
            QMessageBox.warning(self._admin_dlg, "Validation", "Username must not contain spaces.")
            return
        if self.cfg.confirm_empty_password and not p:
            res = QMessageBox.question(
                self._admin_dlg, "Empty password",
                "Password is empty. Create user with empty password?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if res != QMessageBox.Yes:
                return

        ok, msg = self.security.create_user(u, p, role="operator", description=d)
        if not ok:
            # self.generalUI.gui_log_update(LogUIEntity(LogUIType.WARNING, f"Create user: {u}", "Failed."))
            QMessageBox.critical(self._admin_dlg, "Error", msg or "Create user failed.")
            return
        # self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, f"Create user: {u}", "Sucessfully, role : operator."))
        QMessageBox.information(self._admin_dlg, "Success", msg or f"User '{u}' created.")
        for w in (self._create_user_edit, self._create_pass_edit, self._desc_edit):
            if w:
                w.clear()

        # Refresh list in Permission and Manager tabs
        self._init_permission_tab(refresh=True)
        self._init_manager_tab(refresh=True)
        if self._perm_user_box and isValid(self._perm_user_box):
            self._perm_user_box.setCurrentText(u)
        self._apply_role_to_checkboxes()
    
    def apply_role(self):
        """Write selected role to users.json via security service."""
        if not self._perm_user_box or not isValid(self._perm_user_box):
            return
        username = (self._perm_user_box.currentText() or "").strip()
        if not username:
            QMessageBox.warning(self._admin_dlg, "Validation", "Please select a user.")
            return

        if not (self._admin_box.isChecked() or self._op_box.isChecked()):
            self._op_box.setChecked(True)

        role = "administrator" if self._admin_box.isChecked() else "operator"
        ok, msg = self.security.update_role(username, role)
        if not ok:
            # self.generalUI.gui_log_update(LogUIEntity(LogUIType.WARNING, f"Change role user: {username}", f"Failed."))
            QMessageBox.critical(self._admin_dlg, "Update role failed", msg or "Could not update user role.")
            return
        # self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, f"Change role user: {username}", f"Sucessfully, updated '{username}' to role '{role}'."))
        QMessageBox.information(self._admin_dlg, "Success", msg or f"Updated '{username}' to role '{role}'.")
    
    def manager_user(self):
        """Apply action for managerTab: delete user OR change password."""
        if not all([self._mgr_user_box, self._mgr_pass_edit, self._mgr_new_pass_edit,
                    self._mgr_delete_box, self._mgr_change_box]):
            return

        username = (self._mgr_user_box.currentText() or "").strip()
        if not username:
            QMessageBox.warning(self._admin_dlg, "Validation", "Please select a user.")
            return

        cur_pass = self._mgr_pass_edit.text()
        if not cur_pass:
            QMessageBox.warning(self._admin_dlg, "Validation", "Please enter current password.")
            return

        # Verify current password first
        if not self.security.verify(username, cur_pass):
            QMessageBox.critical(self._admin_dlg, "Authentication failed", "Wrong current password.")
            self._mgr_pass_edit.setFocus(); self._mgr_pass_edit.selectAll()
            return

        if not (self._mgr_delete_box.isChecked() or self._mgr_change_box.isChecked()):
            QMessageBox.information(self._admin_dlg, "No action", "Please select Delete or Change password.")
            return

        # Protect administrator from deletion
        if username.lower() == "administrator" and self._mgr_delete_box.isChecked():
            QMessageBox.warning(self._admin_dlg, "Not allowed", "Cannot delete 'administrator' account.")
            return

        # Delete user
        if self._mgr_delete_box.isChecked():
            res = QMessageBox.question(self._admin_dlg, "Confirm delete", f"Delete user '{username}'?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if res != QMessageBox.Yes:
                return

            ok, msg = (self.security.delete_user(username)
                       if hasattr(self.security, "delete_user")
                       else (False, "delete_user() not implemented"))
            if not ok:
                # self.generalUI.gui_log_update(LogUIEntity(LogUIType.WARNING, f"Delete user: {username}", f"Failed."))
                QMessageBox.critical(self._admin_dlg, "Delete failed", msg or "Could not delete user.")
                return
            # self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, f"Delete user: {username}", f"Sucessfully."))
            QMessageBox.information(self._admin_dlg, "Success", msg or f"User '{username}' deleted.")
            self._mgr_pass_edit.clear(); self._mgr_new_pass_edit.clear()
            # Refresh lists
            self._init_permission_tab(refresh=True)
            self._init_manager_tab(refresh=True)
            return

        # Change password
        if self._mgr_change_box.isChecked():
            new_pass = self._mgr_new_pass_edit.text()
            if not new_pass:
                QMessageBox.warning(self._admin_dlg, "Validation", "Please enter a new password.")
                self._mgr_new_pass_edit.setFocus()
                return

            ok, msg = (self.security.update_password(username, new_pass)
                       if hasattr(self.security, "update_password")
                       else (False, "update_password() not implemented"))
            if not ok:
                # self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, f"Change passwords: {username}", f"Failed."))
                QMessageBox.critical(self._admin_dlg, "Change password failed", msg or "Could not change password.")
                return
            # self.generalUI.gui_log_update(LogUIEntity(LogUIType.INFO, f"Change passwords: {username}", f"Sucessfully."))
            QMessageBox.information(self._admin_dlg, "Success", msg or "Password changed successfully.")
            self._mgr_pass_edit.clear(); self._mgr_new_pass_edit.clear()
            return

        # Neither checkbox selected
        QMessageBox.information(self._admin_dlg, "No action", "Please select an action (Delete or Change password).")

    def bind_widget(self):
        """Open admin.ui and wire Create/Permission/Manager tabs."""
        dlg = self._load_dialog(self.cfg.admin_ui_path)
        if not dlg:
            QMessageBox.critical(self.parent_window, "Error", "Cannot load admin UI.")
            return
        self._admin_dlg = dlg
        dlg.finished.connect(self._on_admin_dialog_finished)  # clear refs on close

        tabw = self._find(dlg, "tabWidget", QTabWidget)
        create_tab = self._find(dlg, "createTab", QWidget, silent=True)
        permission_tab = self._find(dlg, "permissionTab", QWidget, silent=True)
        manager_tab = self._find(dlg, "managerTab", QWidget, silent=True)

        # Show Create tab first
        if tabw and create_tab:
            idx = tabw.indexOf(create_tab)
            if idx >= 0:
                tabw.setCurrentIndex(idx)

        # Wire tabs
        self._setup_create_tab(dlg)
        have_perm = self._setup_permission_tab(dlg)
        have_mgr  = self._setup_manager_tab(dlg)

        # Bind applyBtn per current tab
        if tabw:
            curw = tabw.currentWidget()
            if have_perm and curw is permission_tab:
                self._rebind_apply_btn(self.apply_role)
            elif have_mgr and curw is manager_tab:
                self._rebind_apply_btn(self.manager_user)
            self._sync_buttons_for_tab(curw)

            # Rebind on tab change
            tabw.currentChanged.connect(self._on_tab_changed_admin)
        dlg.show()

    # ===================== LIFECYCLE + HELPER =====================

    def _on_admin_dialog_finished(self, _code: int):
        """Dialog closed: drop all references and reset flags."""
        self._perm_inited = False
        # create tab
        self._create_user_edit = None
        self._create_pass_edit = None
        self._desc_edit = None
        # permission tab
        self._perm_user_box = None
        self._admin_box = None
        self._op_box = None
        # manager tab
        self._mgr_user_box = None
        self._mgr_pass_edit = None
        self._mgr_new_pass_edit = None
        self._mgr_delete_box = None
        self._mgr_change_box = None

        self._apply_btn = None
        self._admin_dlg = None
    
    def _handle_logout(self, dlg: QDialog):
        """Force logout to operator and close login window."""
        user = "operator"
        role = "operator"
        try:
            # Đặt lại user về operator
            if hasattr(self.generalUI, "_apply_tab_permission"):
                self.generalUI._apply_tab_permission(role, user)

            # Ghi log logout
            # self.generalUI.gui_log_update(
            #     LogUIEntity(LogUIType.INFO, "Logout", "Switched to user: operator.")
            # )

            # Đóng cửa sổ login
            dlg.accept()
        except Exception as e:
            QMessageBox.critical(self.parent_window, "Logout Error", str(e))

    def _on_tab_changed_admin(self, idx: int):
        """Called when admin tabWidget index changes -> reinit/rebind applyBtn."""
        if not self._admin_dlg:
            return
        tabw = self._admin_dlg.findChild(QTabWidget, "tabWidget")
        if not tabw:
            return

        permission_tab = self._admin_dlg.findChild(QWidget, "permissionTab")
        manager_tab    = self._admin_dlg.findChild(QWidget, "managerTab")

        w = tabw.widget(idx)
        if w is permission_tab:
            self._init_permission_tab(refresh=True)
            self._rebind_apply_btn(self.apply_role)
        elif w is manager_tab:
            self._init_manager_tab(refresh=True)
            self._rebind_apply_btn(self.manager_user)
        self._sync_buttons_for_tab(w)

    # ===================== TAB: CREATE =====================

    def _setup_create_tab(self, dlg: QDialog):
        # Support both "uerEdit" (old typo) and "userEdit" (correct)
        self._create_user_edit = (self._find(dlg, "uerEdit", QLineEdit, silent=True) or self._find(dlg, "userEdit", QLineEdit, silent=True))
        self._create_pass_edit = self._find(dlg, "create_passEdit", QLineEdit, silent=True)
        self._desc_edit = self._find(dlg, "descriptionEdit", QTextEdit, silent=True)
        self._create_btn = self._find(dlg, "createBtn", QPushButton, silent=True) 
        cancel_btn = self._find(dlg, "cancelBtn", QPushButton, silent=True)

        if self._create_pass_edit:
            self._create_pass_edit.setEchoMode(QLineEdit.Password)
        if self._create_btn:
            self._create_btn.clicked.connect(self.create_user)
        if cancel_btn:
            cancel_btn.clicked.connect(lambda: dlg.reject())

    # ===================== TAB: PERMISSION =====================

    def _setup_permission_tab(self, dlg: QDialog) -> bool:
        self._perm_user_box = self._find(dlg, "userBox_2", QComboBox, silent=True)
        self._admin_box = self._find(dlg, "adminBox", QCheckBox, silent=True)
        self._op_box = self._find(dlg, "opBox", QCheckBox, silent=True)
        # shared apply button
        self._apply_btn = self._find(dlg, "applyBtn", QPushButton, silent=True)

        if not all([self._perm_user_box, self._admin_box, self._op_box, self._apply_btn]):
            QMessageBox.critical(dlg, "Admin UI mismatch",
                                 "Missing widgets in admin.ui (userBox_2, adminBox, opBox, applyBtn).")
            return False

        self._init_permission_tab(refresh=True)
        return True

    def _init_permission_tab(self, refresh: bool = False):
        """(Re)initialize user list and wire signals for permission tab."""
        if not self._admin_dlg:
            return
        if not all([self._perm_user_box, self._admin_box, self._op_box, self._apply_btn]):
            return
        if not (isValid(self._perm_user_box) and isValid(self._admin_box)
                and isValid(self._op_box) and isValid(self._apply_btn)):
            return

        if refresh:
            names = self.security.list_usernames() or []
            self._perm_user_box.blockSignals(True)
            self._perm_user_box.clear()
            self._perm_user_box.addItems(names)
            self._perm_user_box.blockSignals(False)

        if not self._perm_inited:
            self._perm_user_box.currentIndexChanged.connect(lambda _: self._apply_role_to_checkboxes())
            self._admin_box.toggled.connect(lambda c: self._on_role_toggled("administrator", c))
            self._op_box.toggled.connect(lambda c: self._on_role_toggled("operator", c))
            # NOTE: applyBtn is rebound per tab by _rebind_apply_btn; keep a default here
            self._apply_btn.clicked.connect(self.apply_role)
            self._perm_inited = True

        self._apply_role_to_checkboxes()

    def _on_role_toggled(self, which: str, checked: bool):
        """Mutually exclusive role toggles and prevent 'no role selected'."""
        if not all([self._admin_box, self._op_box]) or not (isValid(self._admin_box) and isValid(self._op_box)):
            return
        primary = self._admin_box if which == "administrator" else self._op_box
        other   = self._op_box if which == "administrator" else self._admin_box

        if checked:
            other.blockSignals(True); other.setChecked(False); other.blockSignals(False)
        else:
            if not other.isChecked():
                primary.blockSignals(True); primary.setChecked(True); primary.blockSignals(False)

    def _apply_role_to_checkboxes(self):
        """Sync checkboxes from selected user's role."""
        if not self._perm_user_box or not isValid(self._perm_user_box):
            return
        role = (self.security.get_role(self._perm_user_box.currentText()) or "operator").lower()
        mapping = [
            (self._admin_box, role == "administrator"),
            (self._op_box, role == "operator"),
        ]
        for box, checked in mapping:
            if box and isValid(box):
                box.blockSignals(True)
                box.setChecked(checked)
                box.blockSignals(False)

    # ===================== TAB: MANAGER =====================

    def _setup_manager_tab(self, dlg: QDialog) -> bool:
        """Lookup widgets on managerTab and wire basic toggles."""
        self._mgr_user_box      = self._find(dlg, "userBox_1", QComboBox, silent=True)
        self._mgr_pass_edit     = self._find(dlg, "passEdit", QLineEdit, silent=True)
        self._mgr_delete_box    = self._find(dlg, "deleteBox", QCheckBox, silent=True)
        self._mgr_new_pass_edit = self._find(dlg, "new_passEdit", QLineEdit, silent=True)
        self._mgr_change_box    = self._find(dlg, "change_passBox", QCheckBox, silent=True)

        # Group 2 checkboxes to only tick 1 of the 2
        self._mgr_group = QButtonGroup(self._admin_dlg)
        self._mgr_group.setExclusive(True)
        self._mgr_group.addButton(self._mgr_delete_box)
        self._mgr_group.addButton(self._mgr_change_box)

        # When the state changes, update enable/disable of new_passEdit
        self._mgr_group.buttonToggled.connect(lambda _b, _c: self._on_manager_mode_changed())


        # Ensure shared apply button exists (from permission tab section)
        if not self._apply_btn:
            self._apply_btn = self._find(dlg, "applyBtn", QPushButton, silent=True)

        widgets_ok = all([
            self._mgr_user_box, self._mgr_pass_edit, self._mgr_new_pass_edit,
            self._mgr_delete_box, self._mgr_change_box, self._apply_btn
        ])
        if not widgets_ok:
            return False

        # Password echo modes
        self._mgr_pass_edit.setEchoMode(QLineEdit.Password)
        self._mgr_new_pass_edit.setEchoMode(QLineEdit.Password)

        # Toggle rules
        self._mgr_delete_box.toggled.connect(self._on_manager_mode_changed)
        self._mgr_change_box.toggled.connect(self._on_manager_mode_changed)

        self._init_manager_tab(refresh=True)
        return True

    def _init_manager_tab(self, refresh: bool = False):
        if not all([self._mgr_user_box, self._mgr_pass_edit, self._mgr_new_pass_edit,
                    self._mgr_delete_box, self._mgr_change_box]):
            return
        if not (isValid(self._mgr_user_box) and isValid(self._mgr_pass_edit)
                and isValid(self._mgr_new_pass_edit) and isValid(self._mgr_delete_box)
                and isValid(self._mgr_change_box)):
            return

        if refresh:
            names = self.security.list_usernames() or []
            self._mgr_user_box.blockSignals(True)
            self._mgr_user_box.clear()
            self._mgr_user_box.addItems(names)
            self._mgr_user_box.blockSignals(False)

        # Default: both off, new_pass disabled
        self._mgr_delete_box.blockSignals(True); self._mgr_delete_box.setChecked(False); self._mgr_delete_box.blockSignals(False)
        self._mgr_change_box.blockSignals(True); self._mgr_change_box.setChecked(False); self._mgr_change_box.blockSignals(False)
        self._on_manager_mode_changed()

    def _on_manager_mode_changed(self):
        if not all([self._mgr_delete_box, self._mgr_change_box, self._mgr_new_pass_edit]):
            return
        chg_on = self._mgr_change_box.isChecked()
        # chỉ bật new_passEdit khi change_passBox được tick
        self._mgr_new_pass_edit.setEnabled(chg_on)
        if not chg_on:
            self._mgr_new_pass_edit.clear()

    # ===================== GENERIC HELPERS =====================

    def _sync_buttons_for_tab(self, current_widget: QWidget):
        """Enable/disable applyBtn & createBtn theo tab hiện tại."""
        if not self._admin_dlg:
            return
        create_tab = self._admin_dlg.findChild(QWidget, "createTab")
        # applyBtn lấy ở permission tab setup; createBtn lấy ở create tab setup
        apply_btn_ok = self._apply_btn and isValid(self._apply_btn)
        create_btn_ok = self._create_btn and isValid(self._create_btn)

        if current_widget is create_tab:
            if apply_btn_ok:  self._apply_btn.setEnabled(False)
            if create_btn_ok: self._create_btn.setEnabled(True)
        else:
            if apply_btn_ok:  self._apply_btn.setEnabled(True)
            if create_btn_ok: self._create_btn.setEnabled(False)


    def _rebind_apply_btn(self, slot: Callable[[], None]):
        """Detach old clicked handlers and bind to a new slot."""
        if not self._apply_btn or not isValid(self._apply_btn):
            return
        try:
            self._apply_btn.clicked.disconnect()
        except Exception:
            pass
        self._apply_btn.clicked.connect(slot)

    def _find(self, parent: QWidget, name: str, cls: Type[T], silent: bool = False) -> Optional[T]:
        """Find a widget by objectName and type (optional error popup)."""
        w = parent.findChild(cls, name)
        if w is None and not silent:
            QMessageBox.critical(self.parent_window or parent, "UI mismatch",
                                 f"Widget '{name}' ({cls.__name__}) not found in UI.")
        return w

    def _load_dialog(self, ui_path: str) -> Optional[QDialog]:
        """Load a .ui file as QDialog, set WA_DeleteOnClose for safe destruction."""
        f = QFile(ui_path)
        if not f.open(QFile.ReadOnly):
            return None
        try:
            dlg = self.loader.load(f, self.parent_window)
        finally:
            f.close()
        if isinstance(dlg, QDialog):
            dlg.setAttribute(Qt.WA_DeleteOnClose, True)
            return dlg
        return None

    def _login_widgets(self, dlg: QDialog) -> Tuple[QComboBox, QLineEdit, QPushButton, QPushButton, QWidget]:
        """Lookup login controls (status label optional)."""
        user_box = self._find(dlg, "userBox", QComboBox)
        pass_edit = self._find(dlg, "pass_loginEdit", QLineEdit)
        if pass_edit:
            pass_edit.setEchoMode(QLineEdit.Password)
        login_btn = self._find(dlg, "loginBtn", QPushButton)
        cancel_btn = self._find(dlg, "cancelBtn", QPushButton)
        status_lbl = self._find(dlg, "statusLabel", QWidget, silent=True) or QWidget(dlg)
        return user_box, pass_edit, login_btn, cancel_btn, status_lbl

    def _wire_login_controls(self, dlg: QDialog, pass_edit: QLineEdit,
                             login_btn: QPushButton, cancel_btn: QPushButton, slot: Callable[[], None]):
        """Wire login buttons/returnPressed to a given slot."""
        if pass_edit:
            pass_edit.returnPressed.connect(slot)
        if login_btn:
            login_btn.setDefault(True)
            login_btn.clicked.connect(slot)
        if cancel_btn:
            cancel_btn.clicked.connect(dlg.reject)
