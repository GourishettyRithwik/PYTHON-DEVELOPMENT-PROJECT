import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk # ttk for Combobox
import sys
import json
import time # For typing indicator timeout

# Client configuration
HOST = '127.0.0.1'  # Server IP address (use your server's LAN IP if not on same machine)
PORT = 12345      # Server port

class ChatClient:
    def __init__(self, master):
        self.master = master
        master.title("LAN Chat Client")
        master.geometry("850x600") # Set initial window size, wider for user/group lists
        master.resizable(True, True) # Allow resizing

        self.client_socket = None
        self.username = ""
        self.is_muted = False
        self.online_users = [] # To store the list of online users
        self.active_groups = [] # To store the list of active groups
        self.current_chat_target = "All" # Can be "All", a username, or a group name

        self.typing_status_active = False
        self.last_typing_sent_time = 0
        self.TYPING_INDICATOR_INTERVAL = 1.5 # seconds

        self.setup_ui()

        # Handle window close event
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_ui(self):
        # Main frame to hold chat, user list, and group list side-by-side
        main_frame = tk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Chat Area Frame (Left) ---
        chat_area_frame = tk.Frame(main_frame)
        chat_area_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        # --- Chat Display Area ---
        self.chat_display = scrolledtext.ScrolledText(chat_area_frame, wrap=tk.WORD, state='disabled', font=("Inter", 10), bg="#f0f0f0", fg="#333", relief=tk.FLAT, padx=10, pady=10)
        self.chat_display.pack(padx=0, pady=0, fill=tk.BOTH, expand=True)

        # Configure tags for different message types
        self.chat_display.tag_config('system', foreground='blue', font=("Inter", 10, "bold"))
        self.chat_display.tag_config('server', foreground='blue', font=("Inter", 10, "bold")) # Alias for system
        self.chat_display.tag_config('public_self', foreground='green', font=("Inter", 10, "bold")) # Own public messages
        self.chat_display.tag_config('public_other', foreground='black', font=("Inter", 10)) # Other public messages
        self.chat_display.tag_config('private_sent', foreground='purple', font=("Inter", 10, "italic")) # For sent private messages
        self.chat_display.tag_config('private_received', foreground='#8B008B', font=("Inter", 10, "bold italic")) # For received private messages
        self.chat_display.tag_config('group_message', foreground='#006400', font=("Inter", 10)) # Group messages
        self.chat_display.tag_config('group_self', foreground='#008000', font=("Inter", 10, "bold")) # Own group messages
        self.chat_display.tag_config('error', foreground='red', font=("Inter", 10, "bold"))
        self.chat_display.tag_config('timestamp', foreground='gray', font=("Inter", 8))
        
        # Typing indicator label
        self.typing_indicator_label = tk.Label(chat_area_frame, text="", anchor='w', font=("Inter", 9, "italic"), fg="gray", bg="#f0f0f0")
        self.typing_indicator_label.pack(fill=tk.X, padx=10, pady=(0,5))


        # --- Input Frame ---
        input_frame = tk.Frame(chat_area_frame, bg="#e0e0e0", padx=5, pady=5)
        input_frame.pack(padx=0, pady=5, fill=tk.X)

        # Recipient selection for private/group messages
        recipient_frame = tk.Frame(input_frame, bg="#e0e0e0")
        recipient_frame.pack(fill=tk.X, pady=(0, 5))
        tk.Label(recipient_frame, text="To:", font=("Inter", 9), bg="#e0e0e0", fg="#333").pack(side=tk.LEFT, padx=(0, 5))
        
        self.recipient_combobox = ttk.Combobox(recipient_frame, font=("Inter", 9), state='readonly', width=20)
        self.recipient_combobox['values'] = ["All"] # Default to public chat
        self.recipient_combobox.set("All")
        self.recipient_combobox.pack(side=tk.LEFT, padx=(0, 10))
        self.recipient_combobox.bind("<<ComboboxSelected>>", self.on_recipient_selected)

        self.message_input = tk.Entry(input_frame, font=("Inter", 10), relief=tk.FLAT, bd=2, bg="white", fg="#333")
        self.message_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_input.bind("<Return>", self.send_message_event) # Bind Enter key
        self.message_input.bind("<KeyRelease>", self.on_key_release) # For typing indicator

        self.send_button = tk.Button(input_frame, text="Send", command=self.send_message, font=("Inter", 10, "bold"), bg="#4CAF50", fg="white", activebackground="#45a049", activeforeground="white", relief=tk.RAISED, bd=0, padx=10, pady=5, borderwidth=0, highlightthickness=0)
        self.send_button.pack(side=tk.RIGHT)
        self.send_button.config(cursor="hand2") # Change cursor on hover

        # --- Right Side Frame for Users and Groups ---
        right_panel_frame = tk.Frame(main_frame, width=200, bg="#e0e0e0")
        right_panel_frame.pack(side=tk.RIGHT, fill=tk.Y)
        right_panel_frame.pack_propagate(False) # Prevent frame from shrinking to fit content

        # --- Online Users List Frame ---
        users_frame = tk.Frame(right_panel_frame, bg="#e0e0e0")
        users_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        tk.Label(users_frame, text="Online Users", font=("Inter", 10, "bold"), bg="#e0e0e0", fg="#333", pady=5).pack(fill=tk.X)
        self.user_list_display = tk.Listbox(users_frame, font=("Inter", 10), bg="#ffffff", fg="#333", selectbackground="#cceeff", selectforeground="#333", relief=tk.FLAT, exportselection=False)
        self.user_list_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.user_list_display.bind('<<ListboxSelect>>', self.on_user_list_select)

        # --- Groups List Frame ---
        groups_frame = tk.Frame(right_panel_frame, bg="#e0e0e0")
        groups_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))

        tk.Label(groups_frame, text="Groups", font=("Inter", 10, "bold"), bg="#e0e0e0", fg="#333", pady=5).pack(fill=tk.X)
        self.group_list_display = tk.Listbox(groups_frame, font=("Inter", 10), bg="#ffffff", fg="#333", selectbackground="#cceeff", selectforeground="#333", relief=tk.FLAT, exportselection=False)
        self.group_list_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.group_list_display.bind('<<ListboxSelect>>', self.on_group_list_select)

        # Group management buttons
        group_buttons_frame = tk.Frame(groups_frame, bg="#e0e0e0", pady=5)
        group_buttons_frame.pack(fill=tk.X)
        tk.Button(group_buttons_frame, text="Create Group", command=self.create_group_dialog, font=("Inter", 9), bg="#5cb85c", fg="white", relief=tk.RAISED, bd=0, padx=5, pady=2).pack(side=tk.LEFT, expand=True, padx=2)
        tk.Button(group_buttons_frame, text="Join Group", command=self.join_group_dialog, font=("Inter", 9), bg="#f0ad4e", fg="white", relief=tk.RAISED, bd=0, padx=5, pady=2).pack(side=tk.LEFT, expand=True, padx=2)
        tk.Button(group_buttons_frame, text="Leave Group", command=self.leave_group_dialog, font=("Inter", 9), bg="#d9534f", fg="white", relief=tk.RAISED, bd=0, padx=5, pady=2).pack(side=tk.LEFT, expand=True, padx=2)


        # --- Connection/Username Input (at the bottom) ---
        self.connect_frame = tk.Frame(self.master, bg="#e0e0e0", padx=5, pady=5)
        self.connect_frame.pack(padx=10, pady=5, fill=tk.X, side=tk.BOTTOM) # Place at bottom

        tk.Label(self.connect_frame, text="Username:", font=("Inter", 10), bg="#e0e0e0", fg="#333").pack(side=tk.LEFT, padx=(0, 5))
        self.username_entry = tk.Entry(self.connect_frame, font=("Inter", 10), relief=tk.FLAT, bd=2, bg="white", fg="#333")
        self.username_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.username_entry.focus_set() # Focus on username entry initially

        self.connect_button = tk.Button(self.connect_frame, text="Connect", command=self.connect_to_server, font=("Inter", 10, "bold"), bg="#008CBA", fg="white", activebackground="#007ba7", activeforeground="white", relief=tk.RAISED, bd=0, padx=10, pady=5, borderwidth=0, highlightthickness=0)
        self.connect_button.pack(side=tk.RIGHT)
        self.connect_button.config(cursor="hand2")

        # Initially disable chat input and send button
        self.message_input.config(state='disabled')
        self.send_button.config(state='disabled')
        self.recipient_combobox.config(state='disabled')
        self.typing_indicator_label.config(text="") # Clear typing indicator

    def display_message(self, message, tag='message', timestamp=None):
        """Inserts a message into the chat display with optional timestamp."""
        self.chat_display.config(state='normal')
        if timestamp:
            self.chat_display.insert(tk.END, f"[{timestamp}] ", 'timestamp')
        self.chat_display.insert(tk.END, message + "\n", tag)
        self.chat_display.yview(tk.END) # Auto-scroll to the bottom
        self.chat_display.config(state='disabled')

    def update_user_list(self, users):
        """Updates the Listbox with online users."""
        self.online_users = sorted(users) # Keep sorted
        self.user_list_display.delete(0, tk.END) # Clear current list

        for user in self.online_users:
            if user != self.username: # Don't list self in the main user list
                self.user_list_display.insert(tk.END, user)
        
        self.update_recipient_combobox()

    def update_group_list(self, groups):
        """Updates the Listbox with active groups."""
        self.active_groups = sorted(groups)
        self.group_list_display.delete(0, tk.END)
        for group in self.active_groups:
            self.group_list_display.insert(tk.END, group)
        
        self.update_recipient_combobox()

    def update_recipient_combobox(self):
        """Updates the recipient combobox values based on online users and groups."""
        combobox_values = ["All"] + [u for u in self.online_users if u != self.username] + self.active_groups
        self.recipient_combobox['values'] = combobox_values
        # If current recipient is no longer available, reset to "All"
        if self.current_chat_target not in combobox_values:
            self.current_chat_target = "All"
            self.recipient_combobox.set("All")
            self.display_message(f"--- Chat target reset to: All ---", 'system')

    def on_user_list_select(self, event):
        """Sets the recipient combobox when a user is selected in the listbox."""
        selected_indices = self.user_list_display.curselection()
        if selected_indices:
            index = selected_indices[0]
            selected_user = self.user_list_display.get(index)
            self.current_chat_target = selected_user
            self.recipient_combobox.set(selected_user)
            self.display_message(f"--- Chatting with: {selected_user} (Private) ---", 'system')
            self.typing_indicator_label.config(text="") # Clear typing indicator when switching chat

    def on_group_list_select(self, event):
        """Sets the recipient combobox when a group is selected in the listbox."""
        selected_indices = self.group_list_display.curselection()
        if selected_indices:
            index = selected_indices[0]
            selected_group = self.group_list_display.get(index)
            self.current_chat_target = selected_group
            self.recipient_combobox.set(selected_group)
            self.display_message(f"--- Chatting in group: {selected_group} ---", 'system')
            self.typing_indicator_label.config(text="") # Clear typing indicator when switching chat

    def on_recipient_selected(self, event):
        """Updates current_chat_target when recipient combobox selection changes."""
        self.current_chat_target = self.recipient_combobox.get()
        if self.current_chat_target == "All":
            self.display_message(f"--- Chatting in: Public Chat ---", 'system')
        elif self.current_chat_target in self.online_users:
            self.display_message(f"--- Chatting with: {self.current_chat_target} (Private) ---", 'system')
        elif self.current_chat_target in self.active_groups:
            self.display_message(f"--- Chatting in group: {self.current_chat_target} ---", 'system')
        self.typing_indicator_label.config(text="") # Clear typing indicator when switching chat


    def connect_to_server(self):
        """Attempts to connect to the chat server."""
        self.username = self.username_entry.get().strip()
        if not self.username:
            messagebox.showwarning("Warning", "Please enter a username to connect.")
            return

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            self.client_socket.send(self.username.encode('utf-8'))
            
            # Start a thread to receive messages immediately after sending username
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True # Allow main program to exit even if this thread is running
            receive_thread.start()

            # UI updates will happen after server confirms connection/sends initial data
            self.display_message(f"--- Attempting to connect as {self.username} ---", 'system')
            self.username_entry.config(state='disabled')
            self.connect_button.config(state='disabled')
            self.message_input.config(state='normal')
            self.send_button.config(state='normal')
            self.recipient_combobox.config(state='readonly')
            self.message_input.focus_set() # Focus on message input after connecting

        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", f"Could not connect to server at {HOST}:{PORT}. Make sure the server is running.")
            self.display_message(f"--- Connection failed: Server not found at {HOST}:{PORT} ---", 'error')
            self.reset_ui_for_disconnect()
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            self.display_message(f"--- An error occurred: {e} ---", 'error')
            self.reset_ui_for_disconnect()

    def receive_messages(self):
        """Continuously receives messages from the server, handling JSON."""
        data_buffer = b""
        message_length = 0

        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    self.display_message("--- Server disconnected or connection lost ---", 'system')
                    break

                data_buffer += data

                while True:
                    if message_length == 0 and len(data_buffer) >= 10:
                        # Try to read the 10-byte length header for JSON messages
                        try:
                            length_str = data_buffer[:10].decode('utf-8').strip()
                            message_length = int(length_str)
                            data_buffer = data_buffer[10:]
                        except ValueError:
                            # This should ideally not happen with the server's current protocol.
                            # If it does, it means corrupted data or an unexpected plain text message.
                            # We'll log it and clear the buffer to prevent a loop.
                            self.display_message(f"--- Received malformed length header: {data_buffer[:10].decode('utf-8', errors='ignore')} ---", 'error')
                            data_buffer = b"" # Clear buffer
                            message_length = 0
                            break # Go back to outer loop to wait for new data
                    
                    if message_length > 0 and len(data_buffer) >= message_length:
                        # We have enough data for the full JSON message
                        json_data = data_buffer[:message_length]
                        data_buffer = data_buffer[message_length:]
                        message_length = 0 # Reset for next message

                        try:
                            parsed_data = json.loads(json_data.decode('utf-8'))
                            self.process_structured_message(parsed_data)
                        except json.JSONDecodeError:
                            self.display_message(f"--- Received malformed JSON: {json_data.decode('utf-8', errors='ignore')} ---", 'error')
                        except Exception as e:
                            self.display_message(f"--- Error processing structured message: {e} ---", 'error')
                    else:
                        break # Not enough data for a full message, wait for more

            except OSError as e:
                if "Bad file descriptor" in str(e) or "Socket is closed" in str(e):
                    break # Socket was closed intentionally
                else:
                    self.display_message(f"--- Error receiving message: {e} ---", 'error')
                    break
            except Exception as e:
                self.display_message(f"--- An unexpected error occurred while receiving: {e} ---", 'error')
                break
        
        self.reset_ui_for_disconnect()


    def process_structured_message(self, data):
        """Processes structured (JSON) messages received from the server."""
        msg_type = data.get("type")
        timestamp = data.get("timestamp") # All messages now have timestamps

        if msg_type == "user_list_update":
            users = data.get("users", [])
            self.update_user_list(users)
            self.display_message(f"--- Online users updated: {', '.join(users)} ---", 'system')
        elif msg_type == "group_list_update":
            groups = data.get("groups", [])
            self.update_group_list(groups)
            self.display_message(f"--- Active groups updated: {', '.join(groups)} ---", 'system')
        elif msg_type == "public_message":
            sender = data.get("sender")
            message = data.get("message")
            if sender == self.username:
                self.display_message(f"[{sender}] {message}", 'public_self', timestamp)
            else:
                self.display_message(f"[{sender}] {message}", 'public_other', timestamp)
            # Clear typing indicator if this message is from the current typing user
            if self.typing_indicator_label.cget("text").startswith(f"{sender} is typing"):
                self.typing_indicator_label.config(text="")
        elif msg_type == "private_message":
            sender = data.get("sender")
            message = data.get("message")
            self.display_message(f"[Private from {sender}]: {message}", 'private_received', timestamp)
            # Clear typing indicator if this message is from the current typing user
            if self.typing_indicator_label.cget("text").startswith(f"{sender} is typing") and self.current_chat_target == sender:
                self.typing_indicator_label.config(text="")
        elif msg_type == "private_sent_confirmation":
            recipient = data.get("recipient")
            message = data.get("message")
            self.display_message(f"[Private to {recipient}]: {message}", 'private_sent', timestamp)
        elif msg_type == "group_message":
            group_name = data.get("group")
            sender = data.get("sender")
            message = data.get("message")
            if sender == self.username:
                self.display_message(f"[{group_name}] [{sender}] {message}", 'group_self', timestamp)
            else:
                self.display_message(f"[{group_name}] [{sender}] {message}", 'group_message', timestamp)
            # Clear typing indicator if this message is from the current typing user
            if self.typing_indicator_label.cget("text").startswith(f"{sender} is typing") and self.current_chat_target == group_name:
                self.typing_indicator_label.config(text="")
        elif msg_type == "server_message":
            message = data.get("message")
            self.display_message(f"[SERVER] {message}", 'server', timestamp)
        elif msg_type == "typing_indicator":
            typing_username = data.get("username")
            is_typing = data.get("is_typing")
            context = data.get("context")
            target = data.get("target") # Recipient for private, group name for group

            # Only show typing indicator if it's for the currently selected chat
            if is_typing and typing_username != self.username:
                if (context == "public" and self.current_chat_target == "All") or \
                   (context == "private" and self.current_chat_target == typing_username) or \
                   (context == "group" and self.current_chat_target == target):
                    self.typing_indicator_label.config(text=f"{typing_username} is typing...")
            else:
                # Clear indicator if the user stopped typing or it's not relevant to current chat
                current_text = self.typing_indicator_label.cget("text")
                if current_text.startswith(f"{typing_username} is typing"):
                    self.typing_indicator_label.config(text="")
        elif msg_type == "group_action_confirmation":
            action = data.get("action")
            group_name = data.get("group_name")
            status = data.get("status")
            message = data.get("message")
            if status == "success":
                self.display_message(f"--- Group '{group_name}': {message} ---", 'system')
            else:
                self.display_message(f"--- Group '{group_name}' {action} failed: {message} ---", 'error')
        elif msg_type == "error":
            error_message = data.get("message", "An unknown error occurred.")
            self.display_message(f"--- Server Error: {error_message} ---", 'error')
        else:
            self.display_message(f"--- Received unknown structured message type: {msg_type} ---", 'error')

    def on_key_release(self, event):
        """Sends typing indicator when user types."""
        if not self.client_socket or self.is_muted:
            return

        current_time = time.time()
        if not self.typing_status_active and self.message_input.get():
            self.typing_status_active = True
            self.send_typing_indicator(True)
            self.last_typing_sent_time = current_time
        elif self.typing_status_active and not self.message_input.get():
            # User deleted all text, send stop typing
            self.typing_status_active = False
            self.send_typing_indicator(False)
        elif self.typing_status_active and (current_time - self.last_typing_sent_time > self.TYPING_INDICATOR_INTERVAL):
            # Send typing indicator periodically if still typing
            self.send_typing_indicator(True)
            self.last_typing_sent_time = current_time

    def send_typing_indicator(self, is_typing):
        """Sends a typing status message to the server."""
        context = "public"
        target = None
        if self.current_chat_target != "All":
            if self.current_chat_target in self.online_users:
                context = "private"
                target = self.current_chat_target
            elif self.current_chat_target in self.active_groups:
                context = "group"
                target = self.current_chat_target
        
        typing_data = {
            "type": "typing_status",
            "context": context,
            "target": target,
            "is_typing": is_typing
        }
        self._send_json_to_server(typing_data)

    def send_message_event(self, event=None):
        """Event handler for sending message (e.g., Enter key press)."""
        self.send_message()

    def send_message(self):
        """Sends a message from the input field to the server."""
        if not self.client_socket:
            messagebox.showwarning("Not Connected", "Please connect to the server first.")
            return

        message = self.message_input.get().strip()
        if not message:
            return # Don't send empty messages

        # Send stop typing indicator if there was text
        if self.typing_status_active:
            self.typing_status_active = False
            self.send_typing_indicator(False)

        if message.startswith('/'):
            self.handle_command(message)
        else:
            if not self.is_muted:
                try:
                    chat_data = {
                        "message": message,
                    }
                    
                    if self.current_chat_target == "All":
                        chat_data["type"] = "public_message"
                    elif self.current_chat_target in self.online_users:
                        chat_data["type"] = "private_message"
                        chat_data["recipient"] = self.current_chat_target
                    elif self.current_chat_target in self.active_groups:
                        chat_data["type"] = "group_message"
                        chat_data["group"] = self.current_chat_target
                    else:
                        self.display_message(f"--- Invalid chat target: {self.current_chat_target} ---", 'error')
                        return

                    self._send_json_to_server(chat_data)
                    self.message_input.delete(0, tk.END) # Clear input field
                except Exception as e:
                    self.display_message(f"--- Error sending message: {e} ---", 'error')
                    self.reset_ui_for_disconnect()
            else:
                self.display_message("You are muted. Type /mute again to unmute.", 'system')
                self.message_input.delete(0, tk.END) # Clear input field

    def _send_json_to_server(self, data):
        """Helper to send JSON data to the server with length header."""
        try:
            json_message = json.dumps(data).encode('utf-8')
            length_header = f"{len(json_message):<10}".encode('utf-8')
            self.client_socket.sendall(length_header + json_message)
        except Exception as e:
            self.display_message(f"--- Error sending data to server: {e} ---", 'error')
            self.reset_ui_for_disconnect()


    def handle_command(self, command):
        """Handles client-side commands."""
        parts = command.split(' ', 1)
        cmd = parts[0]

        if cmd == '/exit':
            self.on_closing()
        elif cmd == '/mute':
            self.is_muted = not self.is_muted
            status = "muted" if self.is_muted else "unmuted"
            self.display_message(f"You are now {status}.", 'system')
            self.message_input.delete(0, tk.END)
        elif cmd == '/create_group':
            if len(parts) > 1:
                group_name = parts[1].strip()
                self.create_group(group_name)
            else:
                messagebox.showwarning("Command Error", "Usage: /create_group <group_name>")
        elif cmd == '/join_group':
            if len(parts) > 1:
                group_name = parts[1].strip()
                self.join_group(group_name)
            else:
                messagebox.showwarning("Command Error", "Usage: /join_group <group_name>")
        elif cmd == '/leave_group':
            if len(parts) > 1:
                group_name = parts[1].strip()
                self.leave_group(group_name)
            else:
                messagebox.showwarning("Command Error", "Usage: /leave_group <group_name>")
        else:
            self.display_message(f"Unknown command: {command}", 'error')
        self.message_input.delete(0, tk.END)

    def create_group_dialog(self):
        """Opens a dialog to create a new group."""
        dialog = tk.Toplevel(self.master)
        dialog.title("Create Group")
        dialog.transient(self.master)
        dialog.grab_set()

        tk.Label(dialog, text="Group Name:").pack(padx=10, pady=5)
        group_name_entry = tk.Entry(dialog)
        group_name_entry.pack(padx=10, pady=5)
        group_name_entry.focus_set()

        def submit():
            group_name = group_name_entry.get().strip()
            if group_name:
                self.create_group(group_name)
                dialog.destroy()
            else:
                messagebox.showwarning("Input Error", "Group name cannot be empty.", parent=dialog)

        tk.Button(dialog, text="Create", command=submit).pack(pady=10)
        self.master.wait_window(dialog)

    def create_group(self, group_name):
        """Sends request to server to create a group."""
        self._send_json_to_server({
            "type": "create_group",
            "group_name": group_name
        })

    def join_group_dialog(self):
        """Opens a dialog to join an existing group."""
        dialog = tk.Toplevel(self.master)
        dialog.title("Join Group")
        dialog.transient(self.master)
        dialog.grab_set()

        tk.Label(dialog, text="Group Name:").pack(padx=10, pady=5)
        group_name_entry = tk.Entry(dialog)
        group_name_entry.pack(padx=10, pady=5)
        group_name_entry.focus_set()

        def submit():
            group_name = group_name_entry.get().strip()
            if group_name:
                self.join_group(group_name)
                dialog.destroy()
            else:
                messagebox.showwarning("Input Error", "Group name cannot be empty.", parent=dialog)

        tk.Button(dialog, text="Join", command=submit).pack(pady=10)
        self.master.wait_window(dialog)

    def join_group(self, group_name):
        """Sends request to server to join a group."""
        self._send_json_to_server({
            "type": "join_group",
            "group_name": group_name
        })

    def leave_group_dialog(self):
        """Opens a dialog to leave a group."""
        dialog = tk.Toplevel(self.master)
        dialog.title("Leave Group")
        dialog.transient(self.master)
        dialog.grab_set()

        tk.Label(dialog, text="Group Name:").pack(padx=10, pady=5)
        group_name_entry = tk.Entry(dialog)
        group_name_entry.pack(padx=10, pady=5)
        group_name_entry.focus_set()

        def submit():
            group_name = group_name_entry.get().strip()
            if group_name:
                self.leave_group(group_name)
                dialog.destroy()
            else:
                messagebox.showwarning("Input Error", "Group name cannot be empty.", parent=dialog)

        tk.Button(dialog, text="Leave", command=submit).pack(pady=10)
        self.master.wait_window(dialog)

    def leave_group(self, group_name):
        """Sends request to server to leave a group."""
        self._send_json_to_server({
            "type": "leave_group",
            "group_name": group_name
        })


    def reset_ui_for_disconnect(self):
        """Resets the UI state after disconnection."""
        self.username_entry.config(state='normal')
        self.connect_button.config(state='normal')
        self.message_input.config(state='disabled')
        self.send_button.config(state='disabled')
        self.recipient_combobox.config(state='disabled')
        self.user_list_display.delete(0, tk.END) # Clear user list
        self.group_list_display.delete(0, tk.END) # Clear group list
        self.typing_indicator_label.config(text="") # Clear typing indicator
        self.username_entry.focus_set()
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR) # Attempt graceful shutdown
                self.client_socket.close()
            except OSError:
                pass # Socket already closed or not connected
            self.client_socket = None

    def on_closing(self):
        """Handles the window closing event."""
        if self.client_socket:
            try:
                # Send one last typing off indicator
                if self.typing_status_active:
                    self.send_typing_indicator(False)
                self.client_socket.shutdown(socket.SHUT_RDWR) # Attempt graceful shutdown
                self.client_socket.close()
            except OSError:
                pass # Socket already closed or not connected
        self.master.destroy()
        sys.exit(0) # Ensure all threads are terminated

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
