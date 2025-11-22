"""
Pod Client for the Cryptography Project.

This client:
- Connects to the router server
- Uses Diffie-Hellman for key exchange
- Sends encrypted messages with AES-GCM
- Displays Caesar cipher decoys
"""

import socket
import threading
import json
import time
from crypto_utils import CryptoUtils


class PodClient:
    """Pod client for encrypted communication through router."""

    def __init__(self, pod_id, router_host, router_port=5555):
        """
        Initialize the pod client.

        Args:
            pod_id (str): Unique pod identifier (e.g., "POD_1")
            router_host (str): Router IP address
            router_port (int): Router port number
        """
        self.pod_id = pod_id
        self.router_host = router_host
        self.router_port = router_port
        self.socket = None
        self.running = False

        # Diffie-Hellman keys
        self.dh_private_key = None
        self.dh_public_key = None

        # Shared secrets with other pods
        self.shared_secrets = {}  # {pod_id: shared_aes_key}

        # Connected pods
        self.connected_pods = []

    def connect(self):
        """Connect to the router server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.router_host, self.router_port))

            # Generate DH keypair
            self.dh_private_key, self.dh_public_key = CryptoUtils.generate_dh_keypair()

            # Register with router
            register_msg = {
                'type': 'register',
                'client_id': self.pod_id,
                'dh_public_key': str(self.dh_public_key)
            }

            self._send_message(register_msg)

            # Wait for acknowledgment
            ack = self._receive_message()
            if ack and ack.get('type') == 'register_ack':
                print(f"[SUCCESS] {ack.get('message')}")
                self.running = True

                # Start listening thread
                listen_thread = threading.Thread(target=self._listen_for_messages, daemon=True)
                listen_thread.start()

                return True
            else:
                print("[ERROR] Failed to register with router")
                return False

        except Exception as e:
            print(f"[ERROR] Connection failed: {e}")
            return False

    def _listen_for_messages(self):
        """Listen for incoming messages from router."""
        while self.running:
            try:
                msg = self._receive_message()
                if msg is None:
                    break

                msg_type = msg.get('type')

                if msg_type == 'client_list_update':
                    self.connected_pods = msg.get('clients', [])
                    print(f"\n[INFO] Connected pods: {', '.join(self.connected_pods)}")

                elif msg_type == 'dh_public_key_response':
                    self._handle_dh_key_response(msg)

                elif msg_type == 'incoming_message':
                    self._handle_incoming_message(msg)

                elif msg_type == 'routing_error':
                    print(f"\n[ERROR] {msg.get('message')}")

            except Exception as e:
                if self.running:
                    print(f"[ERROR] Listening error: {e}")
                break

    def _handle_dh_key_response(self, msg):
        """Handle received DH public key from another pod."""
        target_id = msg.get('target_id')
        dh_public_key_str = msg.get('dh_public_key')

        if target_id and dh_public_key_str:
            other_public_key = int(dh_public_key_str)

            # Compute shared secret
            shared_secret = CryptoUtils.compute_dh_shared_secret(
                self.dh_private_key,
                other_public_key
            )

            self.shared_secrets[target_id] = shared_secret
            print(f"[INFO] Established shared secret with {target_id}")

    def _handle_incoming_message(self, msg):
        """Handle incoming encrypted message."""
        source_id = msg.get('source_id')
        message_data = msg.get('message_data', {})

        caesar_decoy = message_data.get('caesar_decoy', 'N/A')
        encrypted_message = message_data.get('encrypted_message')

        print(f"\n{'=' * 60}")
        print(f"MESSAGE RECEIVED FROM {source_id}")
        print(f"{'-' * 60}")
        print(f"Caesar Decoy: {caesar_decoy}")

        # Decrypt Caesar decoy
        try:
            decrypted_decoy = CryptoUtils.caesar_cipher_decrypt(caesar_decoy)
            print(f"Decoy Decrypted: {decrypted_decoy}")
        except:
            print(f"Decoy Decrypted: (failed)")

        # Decrypt real message
        if source_id in self.shared_secrets and encrypted_message:
            try:
                shared_key = self.shared_secrets[source_id]
                plaintext = CryptoUtils.aes_gcm_decrypt(shared_key, encrypted_message)
                print(f"Real Message: {plaintext.decode('utf-8')}")
            except Exception as e:
                print(f"Real Message: [DECRYPTION FAILED - {e}]")
        else:
            print(f"Real Message: [NO SHARED SECRET WITH {source_id}]")

        print(f"{'=' * 60}\n")

    def request_shared_secret(self, target_id):
        """Request DH public key from another pod to establish shared secret."""
        if target_id not in self.shared_secrets:
            request_msg = {
                'type': 'request_dh_public_key',
                'target_id': target_id
            }
            self._send_message(request_msg)
            print(f"[INFO] Requesting shared secret with {target_id}...")

            # Wait a moment for response
            time.sleep(0.5)

    def send_message(self, dest_id, real_message, decoy_message):
        """
        Send encrypted message to another pod.

        Args:
            dest_id (str): Destination pod ID
            real_message (str): Real secret message
            decoy_message (str): Decoy message (Caesar cipher)
        """
        # Ensure we have shared secret
        if dest_id not in self.shared_secrets:
            self.request_shared_secret(dest_id)

            if dest_id not in self.shared_secrets:
                print(f"[ERROR] No shared secret with {dest_id}")
                return False

        try:
            # Encrypt real message with AES
            shared_key = self.shared_secrets[dest_id]
            encrypted_message = CryptoUtils.aes_gcm_encrypt(shared_key, real_message)

            # Encrypt decoy with Caesar cipher
            caesar_decoy = CryptoUtils.caesar_cipher_encrypt(decoy_message)

            # Send message
            msg = {
                'type': 'encrypted_message',
                'dest_id': dest_id,
                'caesar_decoy': caesar_decoy,
                'encrypted_message': encrypted_message
            }

            self._send_message(msg)
            print(f"\n[SUCCESS] Message sent to {dest_id}")
            print(f"Decoy sent: {caesar_decoy}")
            print(f"Real message encrypted with AES-GCM\n")

            return True

        except Exception as e:
            print(f"[ERROR] Failed to send message: {e}")
            return False

    def _send_message(self, message_dict):
        """Send JSON message to router."""
        try:
            message_json = json.dumps(message_dict)
            message_bytes = message_json.encode('utf-8')
            length_prefix = len(message_bytes).to_bytes(4, byteorder='big')

            self.socket.sendall(length_prefix + message_bytes)
        except Exception as e:
            print(f"[ERROR] Send failed: {e}")

    def _receive_message(self):
        """Receive JSON message from router."""
        try:
            length_bytes = self._recv_exactly(4)
            if not length_bytes:
                return None

            message_length = int.from_bytes(length_bytes, byteorder='big')

            message_bytes = self._recv_exactly(message_length)
            if not message_bytes:
                return None

            message_json = message_bytes.decode('utf-8')
            return json.loads(message_json)

        except:
            return None

    def _recv_exactly(self, num_bytes):
        """Receive exactly num_bytes from socket."""
        data = b''
        while len(data) < num_bytes:
            chunk = self.socket.recv(num_bytes - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def disconnect(self):
        """Disconnect from router."""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print("\n[INFO] Disconnected from router")


def main():
    """Main function to run the pod client."""
    print("=" * 60)
    print("POD CLIENT - Cryptography Project")
    print("=" * 60)

    # Get configuration
    pod_id = input("Enter your Pod ID (e.g., POD_1, POD_2, POD_3): ").strip()
    router_input = input("Enter router IP:PORT (default: localhost:5555): ").strip() or "localhost:5555"

    # Parse IP and port
    if ':' in router_input:
        try:
            router_host, port_str = router_input.rsplit(':', 1)
            router_port = int(port_str)
        except (ValueError, AttributeError):
            print("[ERROR] Invalid IP:PORT format. Using localhost:5555")
            router_host = "localhost"
            router_port = 5555
    else:
        router_host = router_input
        router_port = 5555

    print(f"[INFO] Connecting to {router_host}:{router_port}...")

    # Create and connect client
    client = PodClient(pod_id, router_host, router_port)

    if not client.connect():
        print("[ERROR] Failed to connect to router")
        return

    print(f"\n{'=' * 60}")
    print("COMMANDS:")
    print("  list    - Show connected pods")
    print("  send    - Send encrypted message")
    print("  exit    - Disconnect and exit")
    print("=" * 60)

    # Interactive loop
    try:
        while client.running:
            cmd = input("\nCommand: ").strip().lower()

            if cmd == 'list':
                print(f"\nConnected pods: {', '.join(client.connected_pods)}")

            elif cmd == 'send':
                dest = input("Destination Pod ID: ").strip()
                if dest not in client.connected_pods:
                    print(f"[ERROR] {dest} is not connected")
                    continue

                real_msg = input("Real secret message: ").strip()
                decoy_msg = input("Decoy message (for router to see): ").strip()

                client.send_message(dest, real_msg, decoy_msg)

            elif cmd == 'exit':
                break

            else:
                print("[ERROR] Unknown command. Use: list, send, exit")

    except KeyboardInterrupt:
        print("\n\n[INFO] Interrupted...")

    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
