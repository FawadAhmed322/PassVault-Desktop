from PySide6.QtWidgets import QMainWindow, QStackedWidget, QMessageBox
from views.sign_in_view import SignInView
from views.sign_up_view import SignUpView
from views.list_view import ListView
from views.add_view import AddView
from views.detail_view import DetailView
from views.change_password_view import ChangePasswordView
from api_requests import load_session, save_session, get_credentials, session, add_credentials, update_credentials, delete_credentials
import requests
from dotenv import load_dotenv
import os

load_dotenv()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PassVault")
        self.setGeometry(100, 100, 800, 600)

        self.session = session
        load_session(self.session)

        self.array_items = []  # Initialize the array_items list
        self.stack = QStackedWidget()
        self.sign_in_view = SignInView(self)
        self.sign_up_view = SignUpView(self)
        self.list_view = ListView(self)
        self.add_view = AddView(self)
        self.detail_view = DetailView(self)
        self.change_password_view = ChangePasswordView(self)

        self.stack.addWidget(self.sign_in_view)
        self.stack.addWidget(self.sign_up_view)
        self.stack.addWidget(self.list_view)
        self.stack.addWidget(self.add_view)
        self.stack.addWidget(self.detail_view)
        self.stack.addWidget(self.change_password_view)

        self.setCentralWidget(self.stack)

        self.check_session()

    def check_session(self):
        try:
            response = get_credentials(self.session)
            if response.get("success"):
                self.array_items.extend(response.get("credentials", []))
                self.show_main_view()
            else:
                self.show_sign_in_view()
        except requests.HTTPError as e:
            QMessageBox.warning(self, "Error", f"HTTP error occurred: {e}")
            self.show_sign_in_view()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"An error occurred: {e}")
            self.show_sign_in_view()

    def show_sign_in_view(self):
        self.stack.setCurrentWidget(self.sign_in_view)

    def show_sign_up_view(self):
        self.stack.setCurrentWidget(self.sign_up_view)

    def show_main_view(self):
        self.stack.setCurrentWidget(self.list_view)

    def show_add_view(self):
        self.stack.setCurrentWidget(self.add_view)

    def show_detail_view(self):
        self.stack.setCurrentWidget(self.detail_view)

    def show_change_password_view(self):
        self.stack.setCurrentWidget(self.change_password_view)
