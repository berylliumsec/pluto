import argparse
import asyncio
import base64
import logging
import os
import ssl
import sys
from typing import List

import numpy as np
import websockets
from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import (QApplication, QDialog,
                             QFileDialog, QLabel, QLineEdit,
                             QMainWindow, QPushButton, QRadioButton,
                             QTextEdit, QVBoxLayout, QWidget)

# Configure logging
logging.basicConfig(level=logging.DEBUG)


class FileTypeDialog(QDialog):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setWindowTitle("Select File Type")

        layout = QVBoxLayout(self)

        # Add a label for clarity
        layout.addWidget(QLabel("Select File Type:"))

        # Radio buttons for selection
        self.regularRadioButton = QRadioButton("Regular File")
        self.decoyRegularRadioButton = QRadioButton("Decoy")
        self.payloadRadioButton = QRadioButton(
            "Payload"
        )  # New radio button for payload
        self.regularRadioButton.setChecked(True)  # Default selection

        layout.addWidget(self.regularRadioButton)
        layout.addWidget(self.decoyRegularRadioButton)
        layout.addWidget(self.payloadRadioButton)  # Add payload radio button to layout

        # Confirm button
        self.confirmButton = QPushButton("Confirm")
        self.confirmButton.clicked.connect(self.accept)
        layout.addWidget(self.confirmButton)

    def file_type(self):
        # Return the type of file selected
        if self.regularRadioButton.isChecked():
            return "Regular File"
        elif self.decoyRegularRadioButton.isChecked():
            return "Decoy"
        elif self.payloadRadioButton.isChecked():
            return "Payload"
        else:
            return "Unknown"


class Server(QObject):
    received_signal = pyqtSignal(str)
    send_message_signal = pyqtSignal(str)

    def __init__(
        self,
        ip="0.0.0.0",
        port=8765,
        certificate="certificate.pem",
        keyfile="private.key",
    ):
        super().__init__()
        self.ip = ip
        self.port = port
        self.certificate = certificate
        self.keyfile = keyfile
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.client_websocket = None
        self.loop = None  # Add a reference to the asyncio event loop
        self.send_message_signal.connect(self.schedule_send_message)
        self.key = 100
        self.transform_matrix = np.array([[1, 1], [0, 1]])
        self.inverse_matrix = np.linalg.inv(self.transform_matrix)
        try:
            self.ssl_context.load_cert_chain(
                certfile=self.certificate, keyfile=self.keyfile
            )
        except FileNotFoundError:
            logging.error("SSL certificate or key file not found.")
            sys.exit(1)
        except ssl.SSLError as e:
            logging.error(f"SSL error: {e}")
            sys.exit(1)

    async def echo(self, websocket, path):
        self.client_websocket = websocket
        try:
            async for message in websocket:
                logging.info(f"Received: {message}")
                self.received_signal.emit(message)
        except websockets.ConnectionClosed as e:
            logging.info(f"Closed: {e}")
            self.client_websocket = None
        except Exception as e:
            logging.error(f"Error: {e}")
            self.client_websocket = None

    async def send_message_to_client(self, message):
        if self.client_websocket:
            try:
                logging.debug(f"Sending message: {message}")
                await self.client_websocket.send(message)
                logging.debug(f"Message sent: {message}")
            except Exception as e:
                logging.error(f"Failed to send message: {e}")
        else:
            logging.warning("No client to send to.")

    def transform_last_element(self, value: int) -> int:
        return value ^ self.key

    def reverse_transform_decimal(self, values: np.ndarray) -> np.ndarray:
        reversed_values = np.dot(self.inverse_matrix, values)
        # Here too, ensure values conform to expectations without modulo
        return reversed_values.astype(int)

    def transform_hex_values(self, hex_values: List[int]) -> bytes:
        transformed_results = []
        is_odd = len(hex_values) % 2 != 0

        for i in range(0, len(hex_values) - is_odd, 2):
            pair = np.array(hex_values[i : i + 2])
            transformed_pair = self.transform_decimal(pair)
            # No modulo applied here; ensure transformation is reversible
            transformed_results.extend(transformed_pair)

        if is_odd:
            last_element = hex_values[-1]
            transformed_last_element = self.transform_last_element(last_element)
            transformed_results.append(transformed_last_element)

        # Convert to bytes, ensuring all are in the 0-255 range
        return bytes([val % 256 for val in transformed_results])

    def parse_hex_values(self, hex_string: str) -> List[int]:
        hex_values = hex_string.replace("\\x", "0x").split(",")
        return [int(val, 16) for val in hex_values if val]

    def transform_decimal(self, values: np.ndarray) -> np.ndarray:
        transformed = np.dot(self.transform_matrix, values)
        # Instead of applying modulo here, ensure values are initially within range
        return transformed.astype(int)

    def read_hex_from_file(self, file_path: str) -> List[str]:
        """Read lines from a file, each potentially containing hex values in various formats."""
        try:
            with open(file_path, "r") as file:
                return [line.strip() for line in file.readlines()]
        except FileNotFoundError as e:
            logging.error("File not found.")
            raise e

    def reverse_transform_last_element(self, value: int) -> int:
        return value ^ self.key

    def reverse_transform_hex_values(self, transformed_values: List[int]) -> List[str]:
        reversed_results = []
        is_odd = len(transformed_values) % 2 != 0

        for i in range(0, len(transformed_values) - is_odd, 2):
            pair = np.array(transformed_values[i : i + 2])
            reversed_pair = self.reverse_transform_decimal(pair)
            reversed_results.extend([hex(val) for val in reversed_pair])

        if is_odd:
            last_element = transformed_values[-1]
            reversed_last_element = self.reverse_transform_last_element(last_element)
            reversed_results.append(hex(reversed_last_element))

        return reversed_results

    async def send_file_to_client(self, filepath, file_type):
        if self.client_websocket:
            try:
                filename = os.path.basename(filepath)
                if file_type == "Regular File":
                    # Handling for regular files
                    filesize = os.path.getsize(filepath)
                    await self.client_websocket.send(f"FILE:{filename}:{filesize}")
                    with open(filepath, "rb") as file:
                        chunk = file.read(4096)
                        while chunk:
                            await self.client_websocket.send(chunk)
                            chunk = file.read(4096)
                elif file_type == "Payload":
                    # For non-regular files, read, transform, and compile the content into a single bytes object
                    transformed_bytes = bytes()  # Initialize an empty bytes object
                    lines = self.read_hex_from_file(filepath)

                    for line in lines:
                        try:
                            decimal_values = self.parse_hex_values(line)
                            transformed_values_bytes = self.transform_hex_values(
                                decimal_values
                            )  # Now returns a bytes object
                            try:
                                transformed_bytes += transformed_values_bytes  # Concatenate bytes objects
                            except Exception as e:
                                logging.error(
                                    f"An error occurred during processing of line while adding to transformed_values_bytes: {line}, error {e}"
                                )
                        except ValueError as e:
                            logging.error(
                                f"An error occurred during processing of line: {line}, error {e}"
                            )

                    # Now, we have all our transformed values in transformed_bytes
                    filesize = len(transformed_bytes)  # Size in bytes
                    await self.client_websocket.send(f"PAYLOAD:{filename}:{filesize}")
                    # Send transformed content as one message
                    await self.client_websocket.send(
                        transformed_bytes
                    )  # Send the bytes object directly
                    logging.debug("File or payload sent successfully.")

                elif file_type == "Decoy":
                    filename = os.path.basename(filepath)
                    filesize = os.path.getsize(filepath)
                    await self.client_websocket.send(f"DECOY:{filename}:{filesize}")

                    with open(filepath, "r") as file:
                        file_data = file.read()  # Read the entire file at once
                        encoded_data = base64.b64encode(
                            file_data.encode()
                        ).decode()  # Encode the file data
                        await self.client_websocket.send(
                            encoded_data
                        )  # Send the encoded data
            except Exception as e:
                logging.error(f"Failed to send Decoy: {e}")

    def schedule_send_message(self, message):
        if self.client_websocket:
            logging.debug(f"Scheduling message: {message}")
            if self.loop is not None:
                asyncio.run_coroutine_threadsafe(
                    self.send_message_to_client(message), self.loop
                )
            else:
                logging.error("Event loop is not running.")
        else:
            logging.warning("Attempting to send a message, but no client is connected.")

    def start_server(self):
        self.loop = (
            asyncio.new_event_loop()
        )  # Initialize the event loop for this thread
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.main())
        self.loop.close()

    async def main(self):
        async with websockets.serve(
            self.echo, self.ip, self.port, ssl=self.ssl_context
        ):
            logging.info(f"Server started on {self.ip}:{self.port}.")
            await asyncio.Future()  # Keeps server running

    def schedule_send_file(self, filepath, file_type):
        if self.client_websocket:
            logging.debug(f"Scheduling file transfer for: {filepath}")
            if self.loop is not None:
                asyncio.run_coroutine_threadsafe(
                    self.send_file_to_client(filepath, file_type), self.loop
                )
            else:
                logging.error("Event loop is not running.")
        else:
            logging.warning("Attempting to send a file, but no client is connected.")


class MainWindow(QMainWindow):
    def __init__(
        self,
        ip="0.0.0.0",
        port=8765,
        certificate="certificate.pem",
        keyfile="private.key",
    ):
        super().__init__()
        self.ip = ip
        self.port = port
        self.certificate = certificate
        self.keyfile = keyfile
        self.setWindowTitle("Pluto")
        self.resize(400, 600)

        # Create layout and widgets
        layout = QVBoxLayout()
        self.textEdit = QTextEdit()
        self.textEdit.setReadOnly(True)  # Make the QTextEdit non-editable
        self.lineEdit = QLineEdit()

        # Set dark theme colors
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #1E1E1E;
            }
            QTextEdit, QLineEdit, QPushButton {
                background-color: #252526;
                color: #CCCCCC;
                border: 1px solid #3C3C3C;
                margin-bottom: 5px;
            }
            """
        )

        # Add widgets to layout
        layout.addWidget(self.textEdit)
        layout.addWidget(self.lineEdit)

        # Add the upload button
        self.uploadButton = QPushButton("Upload File")
        self.uploadButton.clicked.connect(self.uploadFile)
        layout.addWidget(self.uploadButton)

        # Add the clear button
        self.clearButton = QPushButton("Clear")
        self.clearButton.clicked.connect(self.clearChat)
        layout.addWidget(self.clearButton)

        # Set the central widget
        centralWidget = QWidget()
        centralWidget.setLayout(layout)
        self.setCentralWidget(centralWidget)

        # Connect the Enter key press in QLineEdit to send message
        self.lineEdit.returnPressed.connect(self.sendMessage)

        # Setup server thread
        self.server = Server(
            ip=self.ip,
            port=self.port,
            certificate=self.certificate,
            keyfile=self.keyfile,
        )
        self.thread = QThread()
        self.server.moveToThread(self.thread)
        self.thread.started.connect(self.server.start_server)
        self.server.received_signal.connect(self.displayMessage)
        self.thread.start()

    def uploadFile(self):
        # First, let the user select the file
        dialog = QFileDialog()
        dialog.setFileMode(QFileDialog.FileMode.AnyFile)
        dialog.setNameFilter("All files (*.*)")
        if dialog.exec():
            selected_file = dialog.selectedFiles()[0]

            # Now ask for the file type using the custom dialog
            fileTypeDialog = FileTypeDialog()
            if fileTypeDialog.exec():
                file_type = fileTypeDialog.file_type()
                print(f"file type is {file_type}")
                # Proceed with sending the file and its type
                self.server.schedule_send_file(selected_file, file_type)

    def sendMessage(self):
        message = self.lineEdit.text()
        self.lineEdit.clear()
        if message:
            self.server.send_message_signal.emit(message)
            logging.debug(f"sending message: {message}")

    def displayMessage(self, message):
        self.textEdit.append(message)

    def clearChat(self):
        self.textEdit.clear()  # Clear the QTextEdit


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(description="WebSocket Chat Server")
    parser.add_argument(
        "--ip",
        type=str,
        default="0.0.0.0",
        help="IP address to host the WebSocket server on (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port number for the WebSocket server (default: 8765)",
    )
    parser.add_argument(
        "--keyfile", default="private.key", type=str, help="The Private Key"
    )
    parser.add_argument(
        "--certificate", default="certificate.pem", type=str, help="The SSL Cert"
    )

    args = parser.parse_args()

    app = QApplication(sys.argv)
    window = MainWindow(
        ip=args.ip, port=args.port, certificate=args.certificate, keyfile=args.keyfile
    )
    window.show()
    sys.exit(app.exec())
