import asyncio
import logging
import os
import ssl  # Import the SSL module
import sys

import backoff
import websockets
from PyQt6.QtCore import QThread, pyqtSignal
from websockets.exceptions import ConnectionClosed

logging.basicConfig(level=logging.DEBUG)


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    if getattr(sys, "frozen", False):
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def is_run_as_package():
    return "site-packages" in os.path.abspath(__file__)


def return_path(path):
    if is_run_as_package():
        return path
    else:
        return resource_path(path)


class WebSocketClient(QThread):
    messageReceived = pyqtSignal(str)
    messageReceivedBytes = pyqtSignal(bytes)

    def __init__(
        self, uri="wss://192.168.1.155:8765", cert_path=return_path("certificate.pem")
    ):
        super().__init__()
        self.uri = uri
        self.cert_path = (
            cert_path  # Path to the server's certificate or CA's certificate
        )
        self.websocket = None
        self.running = True
        self.loop = asyncio.new_event_loop()
        logging.debug("WebSocketClient initialized")

    def create_ssl_context(self):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations(self.cert_path)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        logging.debug("SSL context created")
        return ssl_context

    def run(self):
        logging.debug("WebSocketClient thread starting")
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.main())
        logging.debug("WebSocketClient thread finished")

    async def connect_and_listen(self):
        @backoff.on_exception(
            backoff.expo, websockets.exceptions.WebSocketException, max_time=60
        )
        async def connect():
            ssl_context = self.create_ssl_context()
            logging.debug(f"Attempting to connect to {self.uri}")
            async with websockets.connect(self.uri, ssl=ssl_context) as websocket:
                self.websocket = websocket
                logging.debug("Connected to the server")
                await websocket.send("Hello, server!")
                logging.debug("Message sent to the server: Hello, server!")
                while self.running:
                    response = await websocket.recv()
                    logging.debug(f"Message received from the server: {response}")
                    if isinstance(response, bytes):
                        self.messageReceivedBytes.emit(response)
                    else:
                        self.messageReceived.emit(response)

        await connect()

    async def main(self):
        while self.running:
            try:
                logging.debug("Main loop running")
                await self.connect_and_listen()
            except ConnectionClosed as e:
                logging.error(f"Connection closed: {e}, attempting to reconnect...")
            except Exception as e:
                logging.error(f"An error occurred: {e}")

    def stop(self):
        logging.debug("Stopping WebSocketClient")
        self.running = False
        if self.websocket:
            asyncio.run_coroutine_threadsafe(self.websocket.close(), self.loop)
            logging.debug("WebSocket closed")
        self.loop.call_soon_threadsafe(self.loop.stop)
        logging.debug("Event loop stopped")

    async def send_message(self, message):
        if self.websocket:
            logging.debug(f"Sending message to the server: {message}")
            await self.websocket.send(message)
