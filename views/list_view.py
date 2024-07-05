from PySide6.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QPushButton, QListWidget, QListWidgetItem, QMessageBox, QSizePolicy, QHBoxLayout, QFrame, QSpacerItem, QLabel, QFileDialog
from PySide6.QtGui import QFont
from utils.utils import create_button
from views.item_widget import ItemWidget
from api_requests import import_passwords, export_passwords, get_credentials, delete_credentials, logout
import logging
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ListView(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_ui()
        self.sync_credentials(show_success=False)  # Sync credentials when ListView is initialized without showing success message

    def init_ui(self):
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search...")
        self.search_bar.textChanged.connect(self.filter_items)

        self.sort_button = QPushButton("Sort by Name")
        self.sort_button.clicked.connect(self.sort_items)

        self.sync_button = create_button("Sync", self.sync_credentials_button)
        self.sync_button.setFixedHeight(40)

        self.logout_button = create_button("Logout", self.logout)
        self.logout_button.setFixedHeight(40)

        self.change_password_button = create_button("Change Master Password", self.show_change_password_view)
        self.change_password_button.setFixedHeight(40)

        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.ExtendedSelection)
        self.list_widget.setStyleSheet("""
            QListWidget::item {
                margin-top: 5px;  /* Add top margin to each item */
            }
            QListWidget::item:selected {
                background-color: transparent;  /* Avoid default highlighting */
            }
        """)
        self.list_widget.itemSelectionChanged.connect(self.on_item_selection_changed)
        self.list_widget.itemDoubleClicked.connect(self.on_item_double_click)

        font = QFont("Arial", 12)
        self.list_widget.setFont(font)
        self.list_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        add_button = create_button("Add Entry", self.add_entry)
        add_button.setFixedHeight(40)
        duplicate_button = create_button("Duplicate Selected", self.duplicate_selected_entry)
        duplicate_button.setFixedHeight(40)
        edit_button = create_button("Edit Selected", self.edit_selected_entry)
        edit_button.setFixedHeight(40)
        delete_button = create_button("Delete Selected", self.delete_selected_items)
        delete_button.setFixedHeight(40)
        import_button = create_button("Import", self.import_passwords)
        import_button.setFixedHeight(40)
        export_button = create_button("Export", self.export_passwords)
        export_button.setFixedHeight(40)

        button_layout = QVBoxLayout()
        button_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        button_layout.addWidget(self.sync_button)
        button_layout.addWidget(add_button)
        button_layout.addWidget(duplicate_button)
        button_layout.addWidget(edit_button)
        button_layout.addWidget(delete_button)
        button_layout.addWidget(import_button)
        button_layout.addWidget(export_button)
        button_layout.addWidget(self.change_password_button)  # Add change password button to the layout
        button_layout.addWidget(self.logout_button)  # Add logout button to the layout
        button_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        button_frame = QFrame()
        button_frame.setLayout(button_layout)
        button_frame.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        main_layout = QHBoxLayout()
        list_layout = QVBoxLayout()
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(10)
        list_layout.addWidget(self.search_bar)
        list_layout.addWidget(self.sort_button)
        list_layout.addWidget(self.list_widget)
        list_frame = QFrame()
        list_frame.setLayout(list_layout)
        list_frame.setMaximumWidth(400)  # Set maximum width for the list view section
        main_layout.addWidget(list_frame)
        main_layout.addWidget(button_frame)

        self.setLayout(main_layout)

    def sync_credentials_button(self):
        self.sync_credentials(show_success=True)

    def populate_list(self):
        self.list_widget.clear()
        for item in self.main_window.array_items:
            list_widget_item = QListWidgetItem(self.list_widget)
            item_widget = ItemWidget(item["name"], item["username"], item["url"], item["password"])
            list_widget_item.setSizeHint(item_widget.sizeHint())
            self.list_widget.setItemWidget(list_widget_item, item_widget)

    def on_item_selection_changed(self):
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            widget = self.list_widget.itemWidget(item)
            if widget:
                widget.set_selected(item.isSelected())

    def on_item_double_click(self, item):
        selected_items = self.list_widget.selectedItems()
        self.main_window.selected_items = []
        for entry in self.main_window.array_items:
            if entry["name"] == self.list_widget.itemWidget(item).findChild(QLabel).text():
                self.main_window.selected_items.append(entry)
                self.main_window.current_item = entry
                self.main_window.original_item = entry.copy()
                self.main_window.password_visible = False
                self.main_window.detail_view.update_detail_view()
                self.main_window.show_detail_view()
                break

    def add_entry(self):
        self.main_window.add_view.prefill_form()
        self.main_window.show_add_view()

    def duplicate_selected_entry(self):
        selected_items = self.list_widget.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "No item selected to duplicate.")
            return

        self.main_window.current_item = None
        for entry in self.main_window.array_items:
            if entry["name"] == self.list_widget.itemWidget(selected_items[0]).findChild(QLabel).text():
                self.main_window.current_item = entry
                break

        if self.main_window.current_item:
            self.main_window.add_view.prefill_form(self.main_window.current_item)
            self.main_window.show_add_view()

    def edit_selected_entry(self):
        selected_items = self.list_widget.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "No item selected to edit.")
            return

        self.on_item_double_click(selected_items[0])
        self.main_window.detail_view.toggle_edit_mode()

    def delete_selected_items(self):
        """
        Handle the selection and confirmation process for deleting items.
        """
        selected_items = self.list_widget.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "No Selection", "No item selected to delete.")
            return
        print(selected_items)

        credentials_to_delete = []
        for item in selected_items:
            widget = self.list_widget.itemWidget(item)
            if not widget:
                continue

            # Find the labels containing the credential information
            name_label = widget.findChild(QLabel, "nameLabel")
            url_label = widget.findChild(QLabel, "urlLabel")
            username_label = widget.findChild(QLabel, "usernameLabel")
            password_label = widget.findChild(QLabel, "passwordLabel")

            # Ensure the mandatory labels are found and have text
            if not (name_label and username_label and password_label):
                continue

            # Extract the text from the labels
            name = name_label.text()
            url = url_label.text()
            username = username_label.text()
            password = password_label.text()

            # Ensure none of the fields are empty
            if not (name and username and password):
                continue

            # Create a dictionary for the credential
            credential = {
                "name": name,
                "url": url,
                "username": username,
                "password": password
            }

            # Add the credential to the list if it's not already included
            if credential not in credentials_to_delete:
                credentials_to_delete.append(credential)

        if not credentials_to_delete:
            return

        # Confirm the deletion with the user
        reply = QMessageBox.question(
            self,
            "Delete Items",
            f"Are you sure you want to delete {len(credentials_to_delete)} items?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            # Call the function to delete the credentials
            self.delete_credentials_batch(credentials_to_delete)

    def filter_items(self, text):
        filtered_items = [item for item in self.main_window.array_items if text.lower() in item["name"].lower()]
        self.list_widget.clear()
        for item in filtered_items:
            list_widget_item = QListWidgetItem(self.list_widget)
            item_widget = ItemWidget(item["name"], item["username"])
            list_widget_item.setSizeHint(item_widget.sizeHint())
            self.list_widget.setItemWidget(list_widget_item, item_widget)

    def sort_items(self):
        self.main_window.array_items.sort(key=lambda x: x["name"].lower())
        self.populate_list()

    def import_passwords(self):
        file_dialog = QFileDialog(self)
        file_path, _ = file_dialog.getOpenFileName(self, "Import Passwords", "", "CSV Files (*.csv)")
        if file_path:
            result = import_passwords(file_path)
            if result:
                if isinstance(result, dict) and result.get("status") == 207:
                    self.sync_credentials(show_success=False)
                    QMessageBox.warning(self, "Partial Import", "Some passwords were imported successfully. Check logs for details on failures.")
                else:
                    self.sync_credentials(show_success=False)
                    QMessageBox.information(self, "Import Successful", "Passwords imported successfully.")
            else:
                QMessageBox.warning(self, "Import Failed", "Failed to import passwords. Check logs for details.")

    def export_passwords(self):
        file_dialog = QFileDialog(self)
        file_path, _ = file_dialog.getSaveFileName(self, "Export Passwords", "passwords.csv", "CSV Files (*.csv)")
        if file_path:
            export_passwords(file_path)
            QMessageBox.information(self, "Export Successful", f"Passwords exported to {file_path}")

    def sync_credentials(self, show_success=False):
        try:
            response = get_credentials()
            if response.get("success"):
                self.main_window.array_items = response.get("credentials", [])
                self.populate_list()
                if show_success:
                    QMessageBox.information(self, "Sync Successful", "Credentials synchronized successfully.")
            else:
                QMessageBox.warning(self, "Sync Failed", "Failed to synchronize credentials.")
        except requests.HTTPError as e:
            QMessageBox.warning(self, "Error", f"HTTP error occurred: {e}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"An error occurred: {e}")

    def delete_credentials_batch(self, credentials_to_delete):
        """
        Delete selected credentials and update the UI.

        Args:
            credentials_to_delete (list of dict): List of credentials to be deleted, where each credential is a dictionary with keys 'name', 'url', 'username', and 'password'.
        """
        try:
            # Call the delete_credentials function from api_requests
            response = delete_credentials(credentials_to_delete)
            
            if response.get("success"):
                # Call the sync_credentials method to update the UI
                self.sync_credentials()
                QMessageBox.information(self, "Delete Successful", "Selected items deleted successfully.")
            else:
                logger.warning(f"Delete failed with response: {response}")
                QMessageBox.warning(self, "Delete Failed", "Failed to delete some items. Check logs for details.")
        
        except requests.HTTPError as e:
            logger.error(f"HTTP error occurred: {e}")
            QMessageBox.warning(self, "Error", f"HTTP error occurred: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            QMessageBox.warning(self, "Error", f"An unexpected error occurred: {e}")


    def logout(self):
        try:
            response = logout(self.main_window.session)
            if response.get("success"):
                self.main_window.show_sign_in_view()
                # QMessageBox.information(self, "Logout Successful", "You have been logged out.")
            else:
                QMessageBox.warning(self, "Logout Failed", "Failed to log out.")
        except requests.HTTPError as e:
            QMessageBox.warning(self, "Error", f"HTTP error occurred: {e}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"An error occurred: {e}")

    def show_change_password_view(self):
        self.main_window.change_password_view.prefill_form()
        self.main_window.show_change_password_view()
