import argparse
import sys

from PyQt6.QtWidgets import QApplication

from pluto.terminal_client import \
    TerminalEmulator  # Adjusted import based on your snippet


class MainApplication(QApplication):
    def __init__(self, argv, server_address):
        super().__init__(argv)
        self.terminal_emulator = TerminalEmulator(server_address=server_address)

    def start(self):
        # Perform additional setup if needed
        self.terminal_emulator.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PyQt application with TerminalEmulator."
    )
    parser.add_argument(
        "--server_address",
        default="wss://192.168.1.154:8765",
        help="WebSocket server address (default: wss://192.168.1.154:8765)",
    )
    args = parser.parse_args()

    app = MainApplication(sys.argv, args.server_address)
    app.start()
    sys.exit(app.exec())
