import socket
import threading
import datetime
import os
import json # For sending structured data like user lists

# Server configuration
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 12345      # Port to listen on

# List to keep track of connected clients (sockets)
clients = []
# Dictionary to map client sockets to their usernames
client_usernames = {}
# Dictionary to map usernames to their client sockets for direct messaging
username_to_socket = {}
# Dictionary to manage active groups: {group_name: {members: {username: socket}, creator: username}}
groups = {"General": {"members": {}, "creator": "Server"}} # Default public group

log_file_name = "chat_log.txt"

# --- Helper Function for Sending Structured Data ---
def send_json_to_client(client_socket, data):
    """Sends JSON encoded data to a specific client."""
    try:
        json_message = json.dumps(data).encode('utf-8')
        # Prepend a fixed-size header indicating message length
        # This helps the client know how much data to expect for the JSON object
        length_header = f"{len(json_message):<10}".encode('utf-8') # 10-byte length header
        client_socket.sendall(length_header + json_message)
    except Exception as e:
        print(f"Error sending JSON to client: {e}")
        # If sending fails, assume client is disconnected and remove
        remove_client(client_socket)

# --- Logging Function ---
def log_message(message):
    """Appends a timestamped message to the chat log file."""
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    log_entry = f"{timestamp} {message}\n"
    with open(log_file_name, "a") as f:
        f.write(log_entry)
    print(message) # Also print to server console

# --- Broadcast Public Message ---
def broadcast_public_message(sender_username, message):
    """Sends a public message to all connected clients."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    message_data = {
        "type": "public_message",
        "sender": sender_username,
        "message": message,
        "timestamp": timestamp
    }
    log_message(f"[PUBLIC] [{timestamp}] {sender_username}: {message.strip()}")
    for client_socket in clients:
        # Send to all, including sender for consistent display
        send_json_to_client(client_socket, message_data)

# --- Send Server Message to All ---
def send_server_message_to_all(message):
    """Sends a server-generated message to all clients."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    message_data = {
        "type": "server_message",
        "message": message,
        "timestamp": timestamp
    }
    log_message(f"[SERVER BROADCAST] [{timestamp}] {message.strip()}")
    for client_socket in clients:
        send_json_to_client(client_socket, message_data)

# --- Send Online User List Update ---
def send_user_list_update():
    """Sends the current list of online usernames to all clients."""
    online_users = list(username_to_socket.keys())
    user_list_data = {
        "type": "user_list_update",
        "users": online_users
    }
    log_message(f"[SERVER] Sending user list update: {online_users}")
    for client_socket in clients:
        send_json_to_client(client_socket, user_list_data)

# --- Send Group List Update ---
def send_group_list_update():
    """Sends the current list of active groups to all clients."""
    active_groups = list(groups.keys())
    group_list_data = {
        "type": "group_list_update",
        "groups": active_groups
    }
    log_message(f"[SERVER] Sending group list update: {active_groups}")
    for client_socket in clients:
        send_json_to_client(client_socket, group_list_data)

# --- Send Private Message ---
def send_private_message(sender_username, target_username, message):
    """Sends a private message from sender to target."""
    target_socket = username_to_socket.get(target_username)
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if target_socket:
        private_message_data = {
            "type": "private_message",
            "sender": sender_username,
            "message": message,
            "timestamp": timestamp
        }
        log_message(f"[PRIVATE] [{timestamp}] From {sender_username} to {target_username}: {message.strip()}")
        try:
            send_json_to_client(target_socket, private_message_data)
            # Send confirmation to sender
            sender_socket = username_to_socket.get(sender_username)
            if sender_socket:
                send_json_to_client(sender_socket, {
                    "type": "private_sent_confirmation",
                    "recipient": target_username,
                    "message": message,
                    "timestamp": timestamp
                })
        except Exception as e:
            print(f"Error sending private message to {target_username}: {e}")
            log_message(f"[SERVER ERROR] Failed to send private message to {target_username}: {e}")
            # Notify sender if target is unreachable
            sender_socket = username_to_socket.get(sender_username)
            if sender_socket:
                send_json_to_client(sender_socket, {
                    "type": "error",
                    "message": f"Could not send private message to {target_username}. User might be offline or disconnected."
                })
    else:
        log_message(f"[SERVER] Private message failed: {target_username} not found.")
        # Notify sender that target user is not online
        sender_socket = username_to_socket.get(sender_username)
        if sender_socket:
            send_json_to_client(sender_socket, {
                "type": "error",
                "message": f"User '{target_username}' is not online."
            })

# --- Send Group Message ---
def send_group_message(sender_username, group_name, message):
    """Sends a message to all members of a specific group."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    if group_name not in groups:
        sender_socket = username_to_socket.get(sender_username)
        if sender_socket:
            send_json_to_client(sender_socket, {
                "type": "error",
                "message": f"Group '{group_name}' does not exist."
            })
        log_message(f"[SERVER ERROR] Group message failed: Group '{group_name}' not found.")
        return

    group_info = groups[group_name]
    group_members_sockets = group_info["members"].values()

    message_data = {
        "type": "group_message",
        "group": group_name,
        "sender": sender_username,
        "message": message,
        "timestamp": timestamp
    }
    log_message(f"[GROUP] [{timestamp}] {group_name} From {sender_username}: {message.strip()}")

    for member_socket in group_members_sockets:
        try:
            send_json_to_client(member_socket, message_data)
        except Exception as e:
            print(f"Error sending group message to a member in {group_name}: {e}")
            remove_client(member_socket) # Remove if sending fails

# --- Handle Typing Indicator ---
def handle_typing_indicator(sender_username, context, target=None, is_typing=True):
    """Broadcasts typing status to relevant recipients."""
    typing_data = {
        "type": "typing_indicator",
        "username": sender_username,
        "is_typing": is_typing,
        "context": context
    }
    
    if context == "public":
        for client_socket in clients:
            if client_socket != username_to_socket.get(sender_username): # Don't send to self
                send_json_to_client(client_socket, typing_data)
    elif context == "private" and target:
        target_socket = username_to_socket.get(target)
        if target_socket:
            send_json_to_client(target_socket, typing_data)
    elif context == "group" and target: # target here is group_name
        if target in groups:
            group_members_sockets = groups[target]["members"].values()
            for member_socket in group_members_sockets:
                if member_socket != username_to_socket.get(sender_username): # Don't send to self
                    send_json_to_client(member_socket, typing_data)

# --- Client Handling Function ---
def handle_client(client_socket, addr):
    """Handles communication with a single client."""
    print(f"[NEW CONNECTION] {addr} connected.")
    log_message(f"[SERVER] Client {addr} connected.")

    username = None
    try:
        # First message from client should be their username
        username = client_socket.recv(1024).decode('utf-8')
        if not username:
            raise ValueError("No username received.")
        
        # Check for duplicate username
        if username in username_to_socket:
            send_json_to_client(client_socket, {
                "type": "error",
                "message": f"Username '{username}' is already taken. Please choose another."
            })
            log_message(f"[SERVER] Connection from {addr} rejected: Username '{username}' already taken.")
            client_socket.close()
            return

        clients.append(client_socket)
        client_usernames[client_socket] = username
        username_to_socket[username] = client_socket

        send_server_message_to_all(f"{username} has joined the chat!")
        log_message(f"[SERVER] {username} ({addr}) joined.")
        
        # Add new user to the default "General" group
        groups["General"]["members"][username] = client_socket
        send_json_to_client(client_socket, {
            "type": "group_action_confirmation",
            "action": "joined",
            "group_name": "General",
            "status": "success",
            "message": f"You have joined the 'General' group."
        })

        send_user_list_update() # Send updated user list to all clients
        send_group_list_update() # Send updated group list to all clients

        # Buffer for incoming data to handle fragmented JSON messages
        data_buffer = b""
        message_length = 0

        while True:
            data = client_socket.recv(4096) # Receive more data at once
            if not data:
                break # Client disconnected

            data_buffer += data

            while True:
                if message_length == 0 and len(data_buffer) >= 10:
                    # Try to read the 10-byte length header
                    try:
                        length_str = data_buffer[:10].decode('utf-8').strip()
                        message_length = int(length_str)
                        data_buffer = data_buffer[10:]
                    except ValueError:
                        # If header is not a valid integer, it's likely corrupted data or old protocol.
                        # For robustness, we will discard this malformed header and try to process
                        # the remaining buffer as if it were the start of a new message,
                        # or clear it if it's too short.
                        log_message(f"[SERVER WARNING] Malformed length header from {username}: '{data_buffer[:10].decode('utf-8', errors='ignore')}'")
                        data_buffer = b"" # Clear buffer to prevent further parsing issues
                        message_length = 0
                        break
                
                if message_length > 0 and len(data_buffer) >= message_length:
                    # We have enough data for the full JSON message
                    json_data = data_buffer[:message_length]
                    data_buffer = data_buffer[message_length:]
                    message_length = 0 # Reset for next message

                    try:
                        parsed_data = json.loads(json_data.decode('utf-8'))
                        msg_type = parsed_data.get("type")

                        if msg_type == "public_message":
                            text_message = parsed_data.get("message")
                            broadcast_public_message(username, text_message)
                        elif msg_type == "private_message":
                            text_message = parsed_data.get("message")
                            recipient = parsed_data.get("recipient")
                            send_private_message(username, recipient, text_message)
                        elif msg_type == "group_message":
                            text_message = parsed_data.get("message")
                            group_name = parsed_data.get("group")
                            send_group_message(username, group_name, text_message)
                        elif msg_type == "typing_status":
                            context = parsed_data.get("context")
                            target = parsed_data.get("target") # For private/group
                            is_typing = parsed_data.get("is_typing", True)
                            handle_typing_indicator(username, context, target, is_typing)
                        elif msg_type == "create_group":
                            group_name = parsed_data.get("group_name")
                            if group_name in groups:
                                send_json_to_client(client_socket, {
                                    "type": "error",
                                    "message": f"Group '{group_name}' already exists."
                                })
                            else:
                                groups[group_name] = {"members": {username: client_socket}, "creator": username}
                                send_json_to_client(client_socket, {
                                    "type": "group_action_confirmation",
                                    "action": "created",
                                    "group_name": group_name,
                                    "status": "success",
                                    "message": f"Group '{group_name}' created and you have joined it."
                                })
                                log_message(f"[SERVER] {username} created group '{group_name}'.")
                                send_group_list_update() # Notify all clients of new group
                        elif msg_type == "join_group":
                            group_name = parsed_data.get("group_name")
                            if group_name not in groups:
                                send_json_to_client(client_socket, {
                                    "type": "error",
                                    "message": f"Group '{group_name}' does not exist."
                                })
                            elif username in groups[group_name]["members"]:
                                send_json_to_client(client_socket, {
                                    "type": "error",
                                    "message": f"You are already a member of '{group_name}'."
                                })
                            else:
                                groups[group_name]["members"][username] = client_socket
                                send_json_to_client(client_socket, {
                                    "type": "group_action_confirmation",
                                    "action": "joined",
                                    "group_name": group_name,
                                    "status": "success",
                                    "message": f"You have joined group '{group_name}'."
                                })
                                send_group_message("Server", group_name, f"{username} has joined the group.")
                                log_message(f"[SERVER] {username} joined group '{group_name}'.")
                        elif msg_type == "leave_group":
                            group_name = parsed_data.get("group_name")
                            if group_name not in groups:
                                send_json_to_client(client_socket, {
                                    "type": "error",
                                    "message": f"Group '{group_name}' does not exist."
                                })
                            elif username not in groups[group_name]["members"]:
                                send_json_to_client(client_socket, {
                                    "type": "error",
                                    "message": f"You are not a member of '{group_name}'."
                                })
                            elif group_name == "General":
                                send_json_to_client(client_socket, {
                                    "type": "error",
                                    "message": "You cannot leave the 'General' group."
                                })
                            else:
                                del groups[group_name]["members"][username]
                                send_json_to_client(client_socket, {
                                    "type": "group_action_confirmation",
                                    "action": "left",
                                    "group_name": group_name,
                                    "status": "success",
                                    "message": f"You have left group '{group_name}'."
                                })
                                send_group_message("Server", group_name, f"{username} has left the group.")
                                log_message(f"[SERVER] {username} left group '{group_name}'.")
                                # If group becomes empty and is not "General", delete it
                                if not groups[group_name]["members"] and group_name != "General":
                                    del groups[group_name]
                                    send_group_list_update() # Notify all clients of group deletion
                                    log_message(f"[SERVER] Group '{group_name}' is empty and has been deleted.")
                        else:
                            log_message(f"[SERVER] Received unknown message type from {username}: {msg_type}")
                            send_json_to_client(client_socket, {
                                "type": "error",
                                "message": f"Unknown message type: {msg_type}"
                            })

                    except json.JSONDecodeError:
                        log_message(f"[SERVER WARNING] Malformed JSON from {username}: {json_data.decode('utf-8', errors='ignore')}")
                        send_json_to_client(client_socket, {
                            "type": "error",
                            "message": "Malformed message received by server."
                        })
                    except Exception as e:
                        print(f"Error processing client message from {username}: {e}")
                        log_message(f"[SERVER ERROR] Processing message from {username}: {e}")
                else:
                    break # Not enough data for a full message, wait for more

    except ConnectionResetError:
        print(f"[DISCONNECTION] {addr} forcefully disconnected.")
        log_message(f"[SERVER] {username if username else addr} forcefully disconnected.")
    except Exception as e:
        print(f"[ERROR] Handling client {addr}: {e}")
        log_message(f"[SERVER] Error with {username if username else addr}: {e}")
    finally:
        if username:
            send_server_message_to_all(f"{username} has left the chat.")
            log_message(f"[SERVER] {username} ({addr}) left.")
            # Remove user from all groups they were a member of
            groups_to_update = set()
            for group_name, group_info in list(groups.items()): # Use list() to allow modification during iteration
                if username in group_info["members"]:
                    del group_info["members"][username]
                    groups_to_update.add(group_name)
                    # If group becomes empty and is not "General", delete it
                    if not group_info["members"] and group_name != "General":
                        del groups[group_name]
                        send_group_list_update() # Notify all clients of group deletion
                        log_message(f"[SERVER] Group '{group_name}' is empty and has been deleted due to {username}'s departure.")
                    else:
                        send_group_message("Server", group_name, f"{username} has left the group.")
            
            # Update user lists and group lists for all clients
            remove_client(client_socket)
            send_user_list_update()
            send_group_list_update() # In case groups were deleted

        client_socket.close()

# --- Remove Client Function ---
def remove_client(client_socket):
    """Removes a client from the active clients list and updates mappings."""
    if client_socket in clients:
        clients.remove(client_socket)
        username = client_usernames.pop(client_socket, None)
        if username and username in username_to_socket:
            del username_to_socket[username]
        print(f"[CLIENTS] Current active clients: {len(clients)}")

# --- Main Server Start Function ---
def start_server():
    """Initializes and starts the chat server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reusing the address
    
    try:
        server.bind((HOST, PORT))
        server.listen(5) # Listen for up to 5 pending connections
        print(f"[STARTING] Server is listening on {HOST}:{PORT}")
        log_message(f"[SERVER START] Listening on {HOST}:{PORT}")

        while True:
            client_socket, addr = server.accept()
            # Start a new thread for each connected client
            thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}") # Subtract server thread

    except OSError as e:
        if e.errno == 98: # Address already in use
            print(f"[ERROR] Port {PORT} is already in use. Please close other applications or choose a different port.")
        else:
            print(f"[ERROR] Server binding error: {e}")
        log_message(f"[SERVER ERROR] Binding failed: {e}")
    except KeyboardInterrupt:
        print("\n[SHUTTING DOWN] Server is shutting down...")
        log_message("[SERVER SHUTDOWN] Server stopped by user.")
    finally:
        for client_socket in clients:
            client_socket.close()
        server.close()
        print("[SHUTDOWN COMPLETE] Server closed.")

if __name__ == "__main__":
    # Clear log file on server start for fresh session, or comment out to append
    # if os.path.exists(log_file_name):
    #     os.remove(log_file_name)
    print(f"Chat logs will be saved to: {os.path.abspath(log_file_name)}")
    start_server()
