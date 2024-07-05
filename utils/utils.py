from PySide6.QtWidgets import QLabel, QLineEdit, QPushButton, QGridLayout, QSizePolicy
from PySide6.QtGui import QFont

def create_label(text, font):
    label = QLabel(text)
    label.setFont(font)
    return label

def create_line_edit(font, echo_mode=None):
    line_edit = QLineEdit()
    line_edit.setFont(font)
    if echo_mode:
        line_edit.setEchoMode(echo_mode)
    return line_edit

def create_button(text, callback, fixed_height=40, width_policy=QSizePolicy.Expanding):
    button = QPushButton(text)
    button.setFixedHeight(fixed_height)
    button.setSizePolicy(width_policy, QSizePolicy.Fixed)
    button.setStyleSheet("margin: 5px;")
    button.clicked.connect(callback)
    return button

def create_form_layout(labels, line_edits, copy_buttons):
    layout = QGridLayout()
    for i, (label, line_edit, copy_button) in enumerate(zip(labels, line_edits, copy_buttons)):
        layout.addWidget(label, i, 0)
        layout.addWidget(line_edit, i, 1)
        layout.addWidget(copy_button, i, 2)
    return layout
