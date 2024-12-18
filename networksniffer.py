import sys
import threading
from scapy.all import sniff, IP, TCP, UDP, Raw
from PyQt5.QtWidgets import QApplication, QTableWidget, QTableWidgetItem, QVBoxLayout, QPushButton, QWidget, QFileDialog
import pandas as pd

# Initialize data storage
packets_data = []

class PacketSnifferGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.sniffing = False
        self.sniffer_thread = None

    def initUI(self):
        self.setWindowTitle('Network Sniffer')
        self.setGeometry(100, 100, 800, 400)
        
        # Layout
        layout = QVBoxLayout()
        
        # Table to display packets
        self.tableWidget = QTableWidget()
        self.tableWidget.setColumnCount(6)
        self.tableWidget.setHorizontalHeaderLabels(['No.', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Info'])
        layout.addWidget(self.tableWidget)
        
        # Buttons
        self.startButton = QPushButton('Start Sniffing')
        self.stopButton = QPushButton('Stop Sniffing')
        self.exportButton = QPushButton('Export to CSV')
        
        self.startButton.clicked.connect(self.start_sniffing)
        self.stopButton.clicked.connect(self.stop_sniffing)
        self.exportButton.clicked.connect(self.export_csv)
        
        layout.addWidget(self.startButton)
        layout.addWidget(self.stopButton)
        layout.addWidget(self.exportButton)
        
        self.setLayout(layout)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.sniffer_thread = threading.Thread(target=self.sniff_packets)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()

    def sniff_packets(self):
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing, store=False)

    def stop_sniffing(self):
        self.sniffing = False
        if self.sniffer_thread:
            self.sniffer_thread.join()

    def process_packet(self, packet):
        global packets_data
        packet_info = {
            'Source IP': packet[IP].src if IP in packet else '',
            'Destination IP': packet[IP].dst if IP in packet else '',
            'Protocol': packet[IP].proto if IP in packet else '',
            'Length': len(packet),
            'Info': str(packet.summary())
        }
        packets_data.append(packet_info)
        self.update_table(packet_info)

    def update_table(self, packet_info):
        rowPosition = self.tableWidget.rowCount()
        self.tableWidget.insertRow(rowPosition)
        self.tableWidget.setItem(rowPosition, 0, QTableWidgetItem(str(rowPosition + 1)))
        self.tableWidget.setItem(rowPosition, 1, QTableWidgetItem(packet_info['Source IP']))
        self.tableWidget.setItem(rowPosition, 2, QTableWidgetItem(packet_info['Destination IP']))
        self.tableWidget.setItem(rowPosition, 3, QTableWidgetItem(packet_info['Protocol']))
        self.tableWidget.setItem(rowPosition, 4, QTableWidgetItem(str(packet_info['Length'])))
        self.tableWidget.setItem(rowPosition, 5, QTableWidgetItem(packet_info['Info']))

    def export_csv(self):
        if packets_data:
            options = QFileDialog.Options()
            filePath, _ = QFileDialog.getSaveFileName(self, "Save File", "", "CSV Files (*.csv);;All Files (*)", options=options)
            if filePath:
                df = pd.DataFrame(packets_data)
                df.to_csv(filePath, index=False)
                print(f"Data exported to {filePath}")
        else:
            print("No packets to export!")

# Run application
if __name__ == '__main__':
    app = QApplication(sys.argv)
    snifferGUI = PacketSnifferGUI()
    snifferGUI.show()
    sys.exit(app.exec_())
