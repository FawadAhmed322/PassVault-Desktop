from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
from api_requests import register
import requests

class SignUpView(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("Sign Up")
        title.setFont(QFont("Arial", 24))
        title.setAlignment(Qt.AlignCenter)

        form_layout = QVBoxLayout()

        self.email_label = QLabel("Email:")
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter your email")
        self.email_input.setFixedHeight(40)

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setFixedHeight(40)

        self.confirm_password_label = QLabel("Confirm Password:")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Confirm your password")
        self.confirm_password_input.setFixedHeight(40)

        form_layout.addWidget(self.email_label)
        form_layout.addWidget(self.email_input)
        form_layout.addWidget(self.password_label)
        form_layout.addWidget(self.password_input)
        form_layout.addWidget(self.confirm_password_label)
        form_layout.addWidget(self.confirm_password_input)

        sign_up_button = QPushButton("Sign Up")
        sign_up_button.setFixedHeight(40)
        sign_up_button.clicked.connect(self.sign_up)

        switch_to_sign_in_button = QPushButton("Already have an account? Sign In")
        switch_to_sign_in_button.setFixedHeight(40)
        switch_to_sign_in_button.clicked.connect(self.main_window.show_sign_in_view)

        layout.addWidget(title)
        layout.addLayout(form_layout)
        layout.addWidget(sign_up_button)
        layout.addWidget(switch_to_sign_in_button)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(50, 50, 50, 50)

        self.setLayout(layout)

    def sign_up(self):
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()
        confirm_password = self.confirm_password_input.text().strip()

        if not email or not password or not confirm_password:
            QMessageBox.warning(self, "Validation Error", "All fields must be filled out.")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Validation Error", "Passwords do not match.")
            return

        try:
            response = register(email, password)
            if response.get("success"):
                QMessageBox.information(self, "Success", "Account created successfully! Please sign in.")
                self.main_window.show_sign_in_view()
            else:
                QMessageBox.warning(self, "Error", response.get("message", "Unknown error occurred during sign up."))
        except requests.HTTPError as e:
            QMessageBox.warning(self, "Error", f"HTTP error occurred: {e.response.status_code}")
        except requests.RequestException as e:
            QMessageBox.warning(self, "Error", f"Network error occurred: {e}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"An unexpected error occurred: {e}")
