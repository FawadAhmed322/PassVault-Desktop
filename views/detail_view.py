from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QGridLayout, QFrame, QSpacerItem, QSizePolicy, QHBoxLayout, QMessageBox
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
from utils.utils import create_button
from api_requests import update_credentials

class DetailView(QWidget):
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

        for line_edit in self.line_edits:
            line_edit.setReadOnly(True)

        copy_buttons = [
            self.create_button("Copy", lambda e=line_edit: self.copy_to_clipboard(e), fixed_height=30, width_policy=QSizePolicy.Fixed) 
            for line_edit in self.line_edits
        ]

        self.toggle_password_button = self.create_button("Show Password", self.toggle_password)
        self.toggle_edit_button = self.create_button("Edit Item", self.toggle_edit_mode)
        self.update_button = self.create_button("Save Changes", self.save_changes)
        self.delete_button = self.create_button("Delete Item", self.delete_current_item)
        self.back_button = self.create_button("Back", self.main_window.show_main_view)

        form_layout = self.create_form_layout(labels, self.line_edits, copy_buttons)

        form_frame = QFrame()
        form_frame.setLayout(form_layout)
        form_frame.setStyleSheet("background-color: white;")
        form_frame.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Expanding)
        form_frame.setFixedWidth(500)

        centered_layout = QVBoxLayout()
        centered_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        centered_layout.addWidget(form_frame)
        centered_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        button_layout = QVBoxLayout()
        button_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        for button in [
            self.toggle_password_button, self.toggle_edit_button, 
            self.update_button, self.delete_button, self.back_button
        ]:
            button_layout.addWidget(button)
        button_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        button_frame = QFrame()
        button_frame.setLayout(button_layout)
        button_frame.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        main_layout = QHBoxLayout()
        main_layout.addLayout(centered_layout)
        main_layout.addWidget(button_frame)

        self.setLayout(main_layout)

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

    def create_button(self, text, callback, fixed_height=40, width_policy=QSizePolicy.Expanding):
        button = QPushButton(text)
        button.setFixedHeight(fixed_height)
        button.setSizePolicy(width_policy, QSizePolicy.Fixed)
        button.setStyleSheet("margin: 5px;")
        button.clicked.connect(callback)
        return button

    def create_form_layout(self, labels, line_edits, copy_buttons):
        layout = QGridLayout()
        for i, (label, line_edit, copy_button) in enumerate(zip(labels, line_edits, copy_buttons)):
            layout.addWidget(label, i, 0)
            layout.addWidget(line_edit, i, 1)
            layout.addWidget(copy_button, i, 2)
        return layout

    def toggle_password(self):
        if self.line_edits[3].echoMode() == QLineEdit.Password:
            self.line_edits[3].setEchoMode(QLineEdit.Normal)
            self.toggle_password_button.setText("Hide Password")
        else:
            self.line_edits[3].setEchoMode(QLineEdit.Password)
            self.toggle_password_button.setText("Show Password")

    def toggle_edit_mode(self):
        if self.line_edits[0].isReadOnly():
            self.set_fields_readonly(False)
            self.toggle_edit_button.setText("Cancel Edit")
        else:
            self.set_fields_readonly(True)
            self.update_detail_view()
            self.toggle_edit_button.setText("Edit Item")

    def set_fields_readonly(self, readonly):
        for line_edit in self.line_edits:
            line_edit.setReadOnly(readonly)

    def save_changes(self):
        new_item = {
            "name": self.line_edits[0].text(),
            "url": self.line_edits[1].text(),
            "username": self.line_edits[2].text(),
            "password": self.line_edits[3].text()
        }

        # Validate mandatory fields
        if not new_item["name"] or not new_item["username"] or not new_item["password"]:
            QMessageBox.warning(self, "Missing Information", "Name, username, and password are mandatory fields.")
            return

        # Check for duplicate name if the name has changed
        if new_item["name"] != self.main_window.original_item["name"]:
            for entry in self.main_window.array_items:
                if entry["name"] == new_item["name"]:
                    QMessageBox.warning(self, "Duplicate Name", "An entry with this name already exists. Please choose a different name.")
                    return

        # Check if any changes were made
        if new_item == self.main_window.original_item:
            QMessageBox.information(self, "No Changes", "No changes were made to the data.")
        else:
            # Construct the update payload
            updated_items = [{
                "oldName": self.main_window.original_item["name"],
                "oldUsername": self.main_window.original_item["username"],
                "newName": new_item["name"],
                "newUrl": new_item["url"],
                "newUsername": new_item["username"],
                "newPassword": new_item["password"]
            }]

            # Call update_credentials
            result = update_credentials(updated_items)

            if result.get("status") == 200:
                self.main_window.list_view.sync_credentials()
                QMessageBox.information(self, "Changes Saved", "Changes have been saved successfully.")
            else:
                QMessageBox.warning(self, "Update Failed", "Failed to save changes. Please try again.")

        self.set_fields_readonly(True)
        self.toggle_edit_button.setText("Edit Item")
        self.main_window.show_status_message("Changes saved")


    def delete_current_item(self):
        reply = QMessageBox.question(self, "Delete Item", "Are you sure you want to delete this item?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.main_window.array_items.remove(self.main_window.current_item)
            self.main_window.list_view.populate_list()
            self.main_window.show_main_view()
            self.main_window.show_status_message("Item deleted")

    def copy_to_clipboard(self, line_edit):
        self.main_window.clipboard.setText(line_edit.text())

    def update_detail_view(self):
        self.line_edits[0].setText(self.main_window.current_item["name"])
        self.line_edits[1].setText(self.main_window.current_item["url"])
        self.line_edits[2].setText(self.main_window.current_item["username"])
        self.line_edits[3].setText(self.main_window.current_item["password"])
        self.line_edits[3].setEchoMode(QLineEdit.Password)
        self.toggle_password_button.setText("Show Password")
        self.set_fields_readonly(True)