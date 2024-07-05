from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
from api_requests import change_password
import requests

class ChangePasswordView(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("Change Master Password")
        title.setFont(QFont("Arial", 24))  # Now QFont is defined
        title.setAlignment(Qt.AlignCenter)

        form_layout = QVBoxLayout()

        self.current_password_label = QLabel("Current Password:")
        self.current_password_input = QLineEdit()
        self.current_password_input.setEchoMode(QLineEdit.Password)
        self.current_password_input.setFixedHeight(40)

        self.new_password_label = QLabel("New Password:")
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)
        self.new_password_input.setFixedHeight(40)

        form_layout.addWidget(self.current_password_label)
        form_layout.addWidget(self.current_password_input)
        form_layout.addWidget(self.new_password_label)
        form_layout.addWidget(self.new_password_input)

        change_password_button = QPushButton("Change Password")
        change_password_button.setFixedHeight(40)
        change_password_button.clicked.connect(self.change_password)

        back_button = QPushButton("Back")
        back_button.setFixedHeight(40)
        back_button.clicked.connect(self.main_window.show_main_view)

        layout.addWidget(title)
        layout.addLayout(form_layout)
        layout.addWidget(change_password_button)
        layout.addWidget(back_button)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(50, 50, 50, 50)

        self.setLayout(layout)

    def change_password(self):
        current_password = self.current_password_input.text()
        new_password = self.new_password_input.text()

        if not current_password or not new_password:
            QMessageBox.warning(self, "Validation Error", "Both current and new password fields are required.")
            return

        try:
            response = change_password(current_password, new_password)
            status = response.get("status")

            if status == 200:
                QMessageBox.information(self, "Success", "Master password changed successfully.")
                self.main_window.list_view.sync_credentials()
                self.main_window.show_main_view()
            elif status == 401:
                QMessageBox.warning(self, "Error", "Unauthorized. Current password is incorrect.")
            elif status == 404:
                QMessageBox.warning(self, "Error", "User not found.")
            else:
                QMessageBox.warning(self, "Error", response.get("message", "Unknown error"))
        except requests.HTTPError as e:
            QMessageBox.warning(self, "Error", f"HTTP error occurred: {e}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"An error occurred: {e}")

    def prefill_form(self, item={'currentPassword': '', 'newPassword': ''}):
        self.current_password_input.setText(item.get('currentPassword'))
        self.new_password_input.setText(item.get('newPassword'))
