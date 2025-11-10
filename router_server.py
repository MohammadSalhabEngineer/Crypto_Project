"""
Central Router Server for the Cryptography Project.

The router handles:
- Client connections (3 pods)
- RSA public key exchange between clients
- Message routing by source/destination IDs
- Displaying Caesar cipher decoys (without being able to decrypt real AES content)
- Multi-threaded handling of multiple clients
"""

import socket
import threading
import json
import time
from datetime import datetime
from crypto_utils import CryptoUtils


class RouterServer:
    """Central router server for handling encrypted communication between pods."""

    def __init__(self, host='0.0.0.0', port=5555):
        """
        Initialize the router server.

        Args:
            host (str): Host address to bind to
            port (int): Port number to listen on
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # {client_id: {'socket': socket, 'address': address, 'public_key': key}}
        self.clients_lock = threading.Lock()
        self.running = False

    def start(self):
        """Start the router server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            print("=" * 60)
            print("CRYPTOGRAPHY ROUTER SERVER")
            print("=" * 60)
            print(f"Server started on {self.host}:{self.port}")
            print(f"Waiting for pod connections...")
            print("=" * 60 + "\n")

            # Accept connections in a loop
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"[{self._timestamp()}] New connection from {address}")

                    # Start a new thread to handle this client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()

                except Exception as e:
                    if self.running:
                        print(f"[ERROR] Error accepting connection: {e}")

        except Exception as e:
            print(f"[ERROR] Failed to start server: {e}")
        finally:
            self.stop()

    def handle_client(self, client_socket, address):
        """
        Handle communication with a connected client.

        Args:
            client_socket: Socket object for the client
            address: Client address tuple
        """
        client_id = None

        try:
            # Receive initial registration message
            data = self._receive_message(client_socket)

            if data and data.get('type') == 'register':
                client_id = data.get('client_id')
                public_key_pem = data.get('public_key')

                if client_id and public_key_pem:
                    # Store client information
                    with self.clients_lock:
                        self.clients[client_id] = {
                            'socket': client_socket,
                            'address': address,
                            'public_key': public_key_pem
                        }

                    print(f"[{self._timestamp()}] Pod '{client_id}' registered from {address}")
                    print(f"                      Total connected pods: {len(self.clients)}")

                    # Send acknowledgment
                    self._send_message(client_socket, {
                        'type': 'register_ack',
                        'status': 'success',
                        'message': f'Welcome {client_id}! You are now connected to the router.'
                    })

                    # Broadcast updated client list to all clients
                    self._broadcast_client_list()

                    # Handle subsequent messages from this client
                    while self.running:
                        msg_data = self._receive_message(client_socket)

                        if msg_data is None:
                            break  # Connection closed

                        self.process_message(client_id, msg_data)

        except Exception as e:
            print(f"[{self._timestamp()}] Error handling client {client_id or address}: {e}")

        finally:
            # Clean up client connection
            if client_id:
                with self.clients_lock:
                    if client_id in self.clients:
                        del self.clients[client_id]
                        print(f"[{self._timestamp()}] Pod '{client_id}' disconnected")
                        print(f"                      Remaining pods: {len(self.clients)}")

                # Notify other clients about disconnection
                self._broadcast_client_list()

            try:
                client_socket.close()
            except:
                pass

    def process_message(self, source_id, message_data):
        """
        Process a message from a client and route it appropriately.

        Args:
            source_id (str): ID of the sender
            message_data (dict): Message data
        """
        msg_type = message_data.get('type')

        if msg_type == 'request_public_key':
            # Client requesting another client's public key
            target_id = message_data.get('target_id')
            self.send_public_key(source_id, target_id)

        elif msg_type == 'encrypted_message':
            # Route encrypted message to destination
            self.route_message(source_id, message_data)

        elif msg_type == 'broadcast':
            # Broadcast message to all clients
            self.broadcast_message(source_id, message_data)

        else:
            print(f"[{self._timestamp()}] Unknown message type from {source_id}: {msg_type}")

    def send_public_key(self, requester_id, target_id):
        """
        Send a client's public key to another client.

        Args:
            requester_id (str): ID of the client requesting the key
            target_id (str): ID of the target client
        """
        with self.clients_lock:
            if target_id in self.clients:
                public_key = self.clients[target_id]['public_key']
                requester_socket = self.clients[requester_id]['socket']

                response = {
                    'type': 'public_key_response',
                    'target_id': target_id,
                    'public_key': public_key
                }

                self._send_message(requester_socket, response)
                print(f"[{self._timestamp()}] Sent {target_id}'s public key to {requester_id}")
            else:
                print(f"[{self._timestamp()}] Public key request failed: {target_id} not connected")

    def route_message(self, source_id, message_data):
        """
        Route an encrypted message to the destination client.
        The router can see the Caesar cipher decoy but cannot decrypt the real message.

        Args:
            source_id (str): ID of the sender
            message_data (dict): Message containing encrypted content
        """
        dest_id = message_data.get('dest_id')
        caesar_decoy = message_data.get('caesar_decoy', 'N/A')

        print("\n" + "=" * 60)
        print(f"[{self._timestamp()}] MESSAGE ROUTING")
        print("-" * 60)
        print(f"From:           {source_id}")
        print(f"To:             {dest_id}")
        print(f"Caesar Decoy:   {caesar_decoy}")

        # Try to decrypt Caesar cipher to show router's perspective
        try:
            decrypted_decoy = CryptoUtils.caesar_cipher_decrypt(caesar_decoy)
            print(f"Decoy Decrypted: {decrypted_decoy}")
        except:
            print(f"Decoy Decrypted: (failed to decrypt)")

        print(f"Real Message:   [ENCRYPTED - Router cannot decrypt AES]")
        print("=" * 60 + "\n")

        # Route the message to destination
        with self.clients_lock:
            if dest_id in self.clients:
                dest_socket = self.clients[dest_id]['socket']

                # Forward the message
                forwarded_message = {
                    'type': 'incoming_message',
                    'source_id': source_id,
                    'message_data': message_data
                }

                self._send_message(dest_socket, forwarded_message)
                print(f"[{self._timestamp()}] Message forwarded to {dest_id}")

            else:
                # Destination not connected, send error back to sender
                print(f"[{self._timestamp()}] Routing failed: {dest_id} not connected")

                if source_id in self.clients:
                    error_msg = {
                        'type': 'routing_error',
                        'message': f'Destination {dest_id} is not connected'
                    }
                    self._send_message(self.clients[source_id]['socket'], error_msg)

    def broadcast_message(self, source_id, message_data):
        """
        Broadcast a message to all connected clients except the sender.

        Args:
            source_id (str): ID of the sender
            message_data (dict): Message data
        """
        print(f"[{self._timestamp()}] Broadcasting message from {source_id}")

        with self.clients_lock:
            for client_id, client_info in self.clients.items():
                if client_id != source_id:
                    broadcast_msg = {
                        'type': 'broadcast_message',
                        'source_id': source_id,
                        'message': message_data.get('message', '')
                    }
                    self._send_message(client_info['socket'], broadcast_msg)

    def _broadcast_client_list(self):
        """Broadcast the list of connected clients to all clients."""
        with self.clients_lock:
            client_list = list(self.clients.keys())

            message = {
                'type': 'client_list_update',
                'clients': client_list
            }

            for client_id, client_info in self.clients.items():
                self._send_message(client_info['socket'], message)

    def _send_message(self, client_socket, message_dict):
        """
        Send a JSON message to a client.

        Args:
            client_socket: Socket to send to
            message_dict (dict): Message to send
        """
        try:
            message_json = json.dumps(message_dict)
            message_bytes = message_json.encode('utf-8')
            length_prefix = len(message_bytes).to_bytes(4, byteorder='big')

            client_socket.sendall(length_prefix + message_bytes)
        except Exception as e:
            print(f"[ERROR] Failed to send message: {e}")

    def _receive_message(self, client_socket):
        """
        Receive a JSON message from a client.

        Args:
            client_socket: Socket to receive from

        Returns:
            dict or None: Received message or None if connection closed
        """
        try:
            # Read length prefix (4 bytes)
            length_bytes = self._recv_exactly(client_socket, 4)
            if not length_bytes:
                return None

            message_length = int.from_bytes(length_bytes, byteorder='big')

            # Read the message
            message_bytes = self._recv_exactly(client_socket, message_length)
            if not message_bytes:
                return None

            message_json = message_bytes.decode('utf-8')
            return json.loads(message_json)

        except Exception as e:
            print(f"[ERROR] Failed to receive message: {e}")
            return None

    def _recv_exactly(self, client_socket, num_bytes):
        """
        Receive exactly num_bytes from socket.

        Args:
            client_socket: Socket to receive from
            num_bytes (int): Number of bytes to receive

        Returns:
            bytes or None: Received bytes or None if connection closed
        """
        data = b''
        while len(data) < num_bytes:
            chunk = client_socket.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _timestamp(self):
        """Get current timestamp string."""
        return datetime.now().strftime("%H:%M:%S")

    def stop(self):
        """Stop the router server."""
        self.running = False

        print(f"\n[{self._timestamp()}] Shutting down router server...")

        # Close all client connections
        with self.clients_lock:
            for client_id, client_info in self.clients.items():
                try:
                    client_info['socket'].close()
                except:
                    pass
            self.clients.clear()

        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        print("Router server stopped.")


def main():
    """Main function to run the router server."""
    router = RouterServer(host='0.0.0.0', port=5555)

    try:
        router.start()
    except KeyboardInterrupt:
        print("\n\nReceived interrupt signal...")
        router.stop()


if __name__ == "__main__":
    main()
