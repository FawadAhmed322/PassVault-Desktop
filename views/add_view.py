from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QGridLayout, QMessageBox
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
from api_requests import add_credentials

class AddView(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()

    def init_ui(self):
        font = QFont("Arial", 16)

        labels = [
            self.create_label("Name:", font),
            self.create_label("URL:", font),
            self.create_label("Username:", font),
            self.create_label("Password:", font)
        ]

        self.line_edits = [
            self.create_line_edit(font),
            self.create_line_edit(font),
            self.create_line_edit(font),
            self.create_line_edit(font, echo_mode=QLineEdit.Password)
        ]

        add_button = self.create_button("Add", self.save_new_entry)
        cancel_button = self.create_button("Cancel", self.main_window.show_main_view)

        add_form_layout = QGridLayout()
        for i, (label, line_edit) in enumerate(zip(labels, self.line_edits)):
            add_form_layout.addWidget(label, i, 0)
            add_form_layout.addWidget(line_edit, i, 1)

        button_layout = QVBoxLayout()
        button_layout.addWidget(add_button)
        button_layout.addWidget(cancel_button)

        layout = QVBoxLayout()
        layout.addLayout(add_form_layout)
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def create_label(self, text, font):
        label = QLabel(text)
        label.setFont(font)
        return label

    def create_line_edit(self, font, echo_mode=None):
        line_edit = QLineEdit()
        line_edit.setFont(font)
        if echo_mode:
            line_edit.setEchoMode(echo_mode)
        return line_edit

    def create_button(self, text, callback):
        button = QPushButton(text)
        button.clicked.connect(callback)
        return button

    def save_new_entry(self):
        new_item = {
            "name": self.line_edits[0].text(),
            "url": self.line_edits[1].text(),
            "username": self.line_edits[2].text(),
            "password": self.line_edits[3].text()
        }

        if not new_item["name"] or not new_item["username"] or not new_item["password"]:
            QMessageBox.warning(self, "Incomplete Data", "Please fill in all fields.")
            return

        # Call main_window.add_credentials and handle the response
        response = add_credentials([new_item])
        
        if response["success"]:
            self.main_window.list_view.sync_credentials()
            # QMessageBox.information(self, "Entry Added", "New entry has been added successfully.")
            self.main_window.show_main_view()
            # self.main_window.show_status_message("Entry added")
        else:
            if "errors" in response and response["errors"]:
                error_message = "\n".join([f"{error['credential']['name']} - {error['error']}" for error in response["errors"]])
                QMessageBox.warning(self, "Partial Success", f"Some entries were not added:\n{error_message}")
            else:
                QMessageBox.warning(self, "Error", "Failed to add the entry.")

    def prefill_form(self, item={'name': '', 'url': '', 'username': '', 'password': ''}):
        """
        Prefill the form with the provided item's details.
        """
        self.line_edits[0].setText(item["name"])
        self.line_edits[1].setText(item.get("url", ""))  # URL might be optional
        self.line_edits[2].setText(item["username"])
        self.line_edits[3].setText(item["password"])