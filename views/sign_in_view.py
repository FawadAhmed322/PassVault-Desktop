from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
from api_requests import login
import requests

class SignInView(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Title label
        title = QLabel("Sign In")
        title.setFont(QFont("Arial", 24))
        title.setAlignment(Qt.AlignCenter)

        # Form layout for email and password fields
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

        form_layout.addWidget(self.email_label)
        form_layout.addWidget(self.email_input)
        form_layout.addWidget(self.password_label)
        form_layout.addWidget(self.password_input)

        # Sign In button
        sign_in_button = QPushButton("Sign In")
        sign_in_button.setFixedHeight(40)
        sign_in_button.clicked.connect(self.sign_in)

        # Switch to Sign Up button
        switch_to_sign_up_button = QPushButton("Don't have an account? Sign Up")
        switch_to_sign_up_button.setFixedHeight(40)
        switch_to_sign_up_button.clicked.connect(self.main_window.show_sign_up_view)

        # Add widgets and layouts to the main layout
        layout.addWidget(title)
        layout.addLayout(form_layout)
        layout.addWidget(sign_in_button)
        layout.addWidget(switch_to_sign_up_button)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(50, 50, 50, 50)

        self.setLayout(layout)

    def sign_in(self):
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()

        if not email or not password:
            QMessageBox.warning(self, "Validation Error", "Email and password fields cannot be empty.")
            return

        try:
            response = login(email, password)
            if response.get("success"):
                self.main_window.show_main_view()
            else:
                QMessageBox.warning(self, "Error", response.get("message", "Unknown error occurred during login."))
        except requests.HTTPError as e:
            QMessageBox.warning(self, "Error", f"HTTP error occurred: {e.response.status_code}")
        except requests.RequestException as e:
            QMessageBox.warning(self, "Error", f"Network error occurred: {e}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"An unexpected error occurred: {e}")
