from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QFrame, QSizePolicy
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

class ItemWidget(QWidget):
    def __init__(self, name, username, url, password):
        super().__init__()
        self.init_ui(name, username, url, password)

    def init_ui(self, name, username, url, password):
        self.frame = QFrame()
        self.frame.setObjectName("itemFrame")
        
        name_label = QLabel(name)
        name_label.setObjectName("nameLabel")
        
        url_label = QLabel(url)
        url_label.setObjectName("urlLabel")
        
        username_label = QLabel(username)
        username_label.setObjectName("usernameLabel")
        
        password_label = QLabel(password)
        password_label.setObjectName("passwordLabel")

        name_label.setFont(QFont("Arial", 12, QFont.Bold))
        url_label.setFont(QFont("Arial", 10))
        username_label.setFont(QFont("Arial", 10))
        password_label.setFont(QFont("Arial", 10))

        name_label.setAlignment(Qt.AlignCenter)
        url_label.setAlignment(Qt.AlignCenter)
        username_label.setAlignment(Qt.AlignCenter)
        password_label.setAlignment(Qt.AlignCenter)

        name_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        url_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        username_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        password_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QVBoxLayout()
        layout.addWidget(name_label)
        layout.addWidget(url_label)
        layout.addWidget(username_label)
        layout.addWidget(password_label)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.frame.setLayout(layout)
        self.frame.setFrameShape(QFrame.StyledPanel)
        self.frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.frame.setStyleSheet("""
            QFrame#itemFrame {
                background-color: #f0f0f0;
                padding: 2px;
                border: none;
            }
            QLabel {
                color: #333;
                background-color: #fff;
                padding: 2px;
                margin: 0px;
                border: none;
            }
        """)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.frame)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setLayout(main_layout)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

    def set_selected(self, selected):
        if selected:
            self.frame.setStyleSheet("""
                QFrame#itemFrame {
                    background-color: #a0c4ff;
                    padding: 2px;
                    border: none;
                }
                QLabel {
                    color: #333;
                    background-color: #a0c4ff;
                    padding: 2px;
                    margin: 0px;
                    border: none;
                }
            """)
        else:
            self.frame.setStyleSheet("""
                QFrame#itemFrame {
                    background-color: #f0f0f0;
                    padding: 2px;
                    border: none;
                }
                QLabel {
                    color: #333;
                    background-color: #fff;
                    padding: 2px;
                    margin: 0px;
                    border: none;
                }
            """)
