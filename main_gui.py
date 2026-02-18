import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QFileDialog, QTableWidget, QTableWidgetItem, QHBoxLayout, QCheckBox
)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt
from scanner_engine import scan_project

class SecureCodeInspector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ SecureCode Inspector")
        self.setGeometry(300, 150, 900, 600)

        # Dark mode flag
        self.dark_mode = False

        # Layouts
        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()

        # Label
        self.label = QLabel("Select a folder to scan for vulnerabilities 💖")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        main_layout.addWidget(self.label)

        # Scan button
        self.scan_button = QPushButton("📂 Select Folder & Scan")
        self.scan_button.clicked.connect(self.select_folder)
        self.scan_button.setFont(QFont("Arial", 12))
        top_layout.addWidget(self.scan_button)

        # Dark mode toggle
        self.dark_toggle = QCheckBox("🌙 Dark Mode")
        self.dark_toggle.stateChanged.connect(self.toggle_dark_mode)
        top_layout.addWidget(self.dark_toggle)

        main_layout.addLayout(top_layout)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["File", "Line", "Issue", "Risk"])
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #fff;
                border-radius: 10px;
            }
        """)
        main_layout.addWidget(self.table)

        self.setLayout(main_layout)
        self.apply_light_theme()

    # Folder selection
    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            results = scan_project(folder)
            self.display_results(results)

    # Display results
    def display_results(self, results):
        self.table.setRowCount(len(results))

        if not results:
            self.label.setText("✅ No vulnerabilities detected! 💖")
            return
        else:
            self.label.setText(f"⚠️ {len(results)} vulnerabilities detected!")

        for row, result in enumerate(results):
            self.table.setItem(row, 0, QTableWidgetItem(result["file"]))
            self.table.setItem(row, 1, QTableWidgetItem(str(result["line"])))
            self.table.setItem(row, 2, QTableWidgetItem(result["issue"]))

            risk_item = QTableWidgetItem(result["risk"])
            if result["risk"] == "HIGH":
                risk_item.setBackground(QColor("#FF6961"))  # red
            elif result["risk"] == "MEDIUM":
                risk_item.setBackground(QColor("#FFD966"))  # yellow
            else:
                risk_item.setBackground(QColor("#77DD77"))  # green
            self.table.setItem(row, 3, risk_item)

    # Dark mode toggle
    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

    def apply_light_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #FDEFF4;
                color: #333;
            }
            QPushButton {
                background-color: #FFB6C1;
                border-radius: 12px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #FF69B4;
                color: white;
            }
            QTableWidget {
                background-color: white;
            }
        """)

    def apply_dark_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #2C2C2C;
                color: #EEE;
            }
            QPushButton {
                background-color: #FF69B4;
                border-radius: 12px;
                padding: 8px;
                font-weight: bold;
                color: white;
            }
            QPushButton:hover {
                background-color: #FF1493;
            }
            QTableWidget {
                background-color: #3C3C3C;
                color: #EEE;
            }
        """)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureCodeInspector()
    window.show()
    sys.exit(app.exec())