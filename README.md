Network Sniffer with PyQt5 and Scapy
This project implements a network packet sniffer using Python, PyQt5 for the graphical user interface (GUI), and Scapy for packet capturing. The tool captures network packets, displays key information about them, and allows users to export the captured data to a CSV file.

Features :- 
- Packet Sniffing: Captures network packets in real-time using Scapy.
- GUI for Interaction: Built with PyQt5, the application offers a user-friendly interface for viewing packet details.
- Packet Details: Displays information such as source and destination IP, protocol, packet length, and a summary of the packet.
- CSV Export: Allows users to export captured packet data to a CSV file for analysis or storage.

Usage :-
Start Sniffing: Press the "Start Sniffing" button to begin capturing packets from the network.

Stop Sniffing: Press the "Stop Sniffing" button to halt the packet capture process.

Export to CSV: Press the "Export to CSV" button to save the captured packet data to a CSV file.

How It Works :-
Scapy: This library is used to capture network packets. It processes the packets as they are sniffed, extracting key details like source IP, destination IP, protocol, and packet length.

PyQt5: The GUI is built using PyQt5, providing an interface to control the sniffing process and view packet data in a table format.

CSV Export: Captured packet details are stored in a list, which can be exported to a CSV file for analysis using pandas.
Files and Structure

main.py: Contains the main script for the sniffer GUI, including packet sniffing logic and PyQt5 setup.

requirements.txt: A text file listing the required Python libraries to run the project.

Example Output
Captured packets will be displayed in a table with columns for:

No.: Packet number.

Source IP: The IP address of the sender.

Destination IP: The IP address of the recipient.

Protocol: The protocol used (TCP, UDP, etc.).

Length: The length of the packet.

Info: A summary of the packet.


