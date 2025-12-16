import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import re
from datetime import datetime

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("TCP Channel Chat System v1.0")
        self.root.geometry("700x600")
        self.root.minsize(600, 500)
        
        # Connection state
        self.socket = None
        self.connected = False
        self.username = ""
        self.current_channel = -1
        self.connected_users = 0
        self.receive_thread = None
        self.running = False
        
        # Color scheme
        self.bg_color = "#2b2b2b"
        self.fg_color = "#ffffff"
        self.entry_bg = "#3c3c3c"
        self.button_color = "#4a90e2"
        self.accent_color = "#5cb85c"
        
        self.setup_ui()
        
    def setup_ui(self):
        # Configure root styling
        self.root.configure(bg=self.bg_color)
        
        # Create main container
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connection Frame (top)
        self.setup_connection_frame(main_frame)
        
        # Status Frame
        self.setup_status_frame(main_frame)
        
        # Chat Frame (middle)
        self.setup_chat_frame(main_frame)
        
        # Input Frame (bottom)
        self.setup_input_frame(main_frame)
        
    def setup_connection_frame(self, parent):
        conn_frame = tk.LabelFrame(parent, text="Server Connection", 
                                   bg=self.bg_color, fg=self.fg_color,
                                   font=("Arial", 10, "bold"))
        conn_frame.pack(fill=tk.X, pady=(0, 10))
        
        # IP Address
        tk.Label(conn_frame, text="Server IP:", bg=self.bg_color, 
                fg=self.fg_color).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.ip_entry = tk.Entry(conn_frame, width=20, bg=self.entry_bg, 
                                fg=self.fg_color, insertbackground=self.fg_color)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Port
        tk.Label(conn_frame, text="Port:", bg=self.bg_color, 
                fg=self.fg_color).grid(row=0, column=2, padx=5, pady=5)
        
        self.port_entry = tk.Entry(conn_frame, width=8, bg=self.entry_bg, 
                                   fg=self.fg_color, insertbackground=self.fg_color)
        self.port_entry.insert(0, "8888")
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)
        
        # Connect Button
        self.connect_btn = tk.Button(conn_frame, text="Connect", 
                                     command=self.toggle_connection,
                                     bg=self.button_color, fg=self.fg_color,
                                     width=12, cursor="hand2")
        self.connect_btn.grid(row=0, column=4, padx=10, pady=5)
        
        # Username
        tk.Label(conn_frame, text="Username:", bg=self.bg_color, 
                fg=self.fg_color).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.username_entry = tk.Entry(conn_frame, width=20, bg=self.entry_bg, 
                                       fg=self.fg_color, insertbackground=self.fg_color)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Channel
        tk.Label(conn_frame, text="Channel:", bg=self.bg_color, 
                fg=self.fg_color).grid(row=1, column=2, padx=5, pady=5)
        
        self.channel_entry = tk.Entry(conn_frame, width=8, bg=self.entry_bg, 
                                      fg=self.fg_color, insertbackground=self.fg_color)
        self.channel_entry.insert(0, "0000")
        self.channel_entry.grid(row=1, column=3, padx=5, pady=5)
        
        # Join Button
        self.join_btn = tk.Button(conn_frame, text="Join Channel", 
                                  command=self.join_channel,
                                  bg=self.accent_color, fg=self.fg_color,
                                  width=12, state=tk.DISABLED, cursor="hand2")
        self.join_btn.grid(row=1, column=4, padx=10, pady=5)
        
    def setup_status_frame(self, parent):
        status_frame = tk.Frame(parent, bg=self.bg_color)
        status_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Status label
        self.status_label = tk.Label(status_frame, text="Status: Disconnected", 
                                     bg=self.bg_color, fg="#ff6b6b",
                                     font=("Arial", 9, "bold"))
        self.status_label.pack(side=tk.LEFT)
        
        # Channel info
        self.channel_label = tk.Label(status_frame, text="Channel: ----", 
                                      bg=self.bg_color, fg=self.fg_color,
                                      font=("Arial", 9))
        self.channel_label.pack(side=tk.LEFT, padx=20)
        
        # User count
        self.users_label = tk.Label(status_frame, text="Users: 0", 
                                    bg=self.bg_color, fg=self.fg_color,
                                    font=("Arial", 9))
        self.users_label.pack(side=tk.LEFT)
        
    def setup_chat_frame(self, parent):
        chat_frame = tk.LabelFrame(parent, text="Chat Room", 
                                  bg=self.bg_color, fg=self.fg_color,
                                  font=("Arial", 10, "bold"))
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Chat display with scrollbar
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, wrap=tk.WORD, 
            bg="#1e1e1e", fg=self.fg_color,
            font=("Consolas", 10),
            state=tk.DISABLED,
            cursor="arrow"
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags for colored text
        self.chat_display.tag_config("username", foreground="#5cb85c", font=("Consolas", 10, "bold"))
        self.chat_display.tag_config("system", foreground="#f0ad4e", font=("Consolas", 10, "italic"))
        self.chat_display.tag_config("error", foreground="#ff6b6b", font=("Consolas", 10, "bold"))
        self.chat_display.tag_config("info", foreground="#4a90e2", font=("Consolas", 10))
        self.chat_display.tag_config("timestamp", foreground="#888888", font=("Consolas", 8))
        
    def setup_input_frame(self, parent):
        input_frame = tk.Frame(parent, bg=self.bg_color)
        input_frame.pack(fill=tk.X)
        
        # Message entry
        self.message_entry = tk.Entry(input_frame, bg=self.entry_bg, 
                                      fg=self.fg_color, 
                                      insertbackground=self.fg_color,
                                      font=("Arial", 10))
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        self.message_entry.bind("<KeyPress>", self.on_key_press)
        
        # Send button
        self.send_btn = tk.Button(input_frame, text="Send", 
                                  command=self.send_message,
                                  bg=self.button_color, fg=self.fg_color,
                                  width=10, state=tk.DISABLED, cursor="hand2")
        self.send_btn.pack(side=tk.LEFT)
        
        # Command hint
        hint_frame = tk.Frame(parent, bg=self.bg_color)
        hint_frame.pack(fill=tk.X, pady=(5, 0))
        
        tk.Label(hint_frame, 
                text="Commands: /list (list users) | /quit (leave channel)",
                bg=self.bg_color, fg="#888888", font=("Arial", 8)).pack(side=tk.LEFT)
        
    def on_key_press(self, event):
        # Show command suggestions
        text = self.message_entry.get()
        if text.startswith('/'):
            # Could add autocomplete here
            pass
    
    def validate_ip(self, ip):
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    def toggle_connection(self):
        if not self.connected:
            self.connect_to_server()
        else:
            self.disconnect_from_server()
    
    def connect_to_server(self):
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()
        
        # Validate inputs
        if not ip or not port:
            messagebox.showerror("Error", "Please enter IP address and port")
            return
        
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Port must be between 1 and 65535")
            return
        
        # Attempt connection
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            
            self.append_chat("Connecting to server...", "info")
            self.socket.connect((ip, port))
            self.socket.settimeout(None)
            
            self.connected = True
            self.running = True
            
            # Start receive thread
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
            
            # Update UI
            self.connect_btn.config(text="Disconnect", bg="#d9534f")
            self.join_btn.config(state=tk.NORMAL)
            self.status_label.config(text=f"Status: Connected to {ip}:{port}", fg=self.accent_color)
            
            # Disable connection fields
            self.ip_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            
            self.append_chat(f"Connected to {ip}:{port}", "system")
            
        except socket.timeout:
            messagebox.showerror("Connection Error", "Connection timed out")
            if self.socket:
                self.socket.close()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
            if self.socket:
                self.socket.close()
    
    def disconnect_from_server(self):
        if self.current_channel != -1:
            self.leave_channel()
        
        self.running = False
        self.connected = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        # Update UI
        self.connect_btn.config(text="Connect", bg=self.button_color)
        self.join_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Disconnected", fg="#ff6b6b")
        
        # Enable connection fields
        self.ip_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        
        self.append_chat("Disconnected from server", "system")
        
        self.current_channel = -1
        self.update_channel_info()
    
    def join_channel(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return
        
        username = self.username_entry.get().strip()
        channel = self.channel_entry.get().strip()
        
        if not username:
            messagebox.showerror("Error", "Please enter a username")
            return
        
        if len(username) > 31:
            messagebox.showerror("Error", "Username must be 31 characters or less")
            return
        
        try:
            channel_id = int(channel)
            if channel_id < 0 or channel_id > 9999:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Channel must be between 0000 and 9999")
            return
        
        # Send join command
        self.username = username
        msg = f"JOIN:{channel_id:04d}:{username}"
        self.send_to_server(msg)
        
        # Update UI
        self.username_entry.config(state=tk.DISABLED)
        self.channel_entry.config(state=tk.DISABLED)
        self.join_btn.config(text="Leave Channel", command=self.leave_channel)
        self.send_btn.config(state=tk.NORMAL)
        self.message_entry.focus()
    
    def leave_channel(self):
        if self.current_channel != -1:
            self.send_to_server("LEAVE")
            self.current_channel = -1
            self.update_channel_info()
        
        # Update UI
        self.username_entry.config(state=tk.NORMAL)
        self.channel_entry.config(state=tk.NORMAL)
        self.join_btn.config(text="Join Channel", command=self.join_channel)
        self.send_btn.config(state=tk.DISABLED)
    
    def send_message(self):
        message = self.message_entry.get().strip()
        
        if not message:
            return
        
        if not self.connected or self.current_channel == -1:
            self.append_chat("Not in a channel. Join a channel first.", "error")
            return
        
        # Handle commands
        if message.startswith('/'):
            self.handle_command(message)
        else:
            # Send regular message
            msg = f"MSG:{message}"
            self.send_to_server(msg)
        
        self.message_entry.delete(0, tk.END)
    
    def handle_command(self, command):
        cmd = command.lower().strip()
        
        if cmd == "/list":
            self.send_to_server("LIST")
        elif cmd == "/quit":
            self.leave_channel()
        elif cmd == "/help":
            self.append_chat("Available commands:", "info")
            self.append_chat("  /list - List users in channel", "info")
            self.append_chat("  /quit - Leave current channel", "info")
            self.append_chat("  /help - Show this help", "info")
        else:
            self.append_chat(f"Unknown command: {command}", "error")
    
    def send_to_server(self, message):
        if not self.connected or not self.socket:
            return
        
        try:
            self.socket.send(message.encode('utf-8'))
        except Exception as e:
            self.append_chat(f"Failed to send message: {str(e)}", "error")
            self.disconnect_from_server()
    
    def receive_messages(self):
        buffer = ""
        while self.running and self.connected:
            try:
                data = self.socket.recv(2048).decode('utf-8')
                if not data:
                    self.append_chat("Server closed connection", "error")
                    self.root.after(0, self.disconnect_from_server)
                    break
                
                buffer += data
                messages = buffer.split('\n')
                buffer = messages[-1]
                
                for msg in messages[:-1]:
                    if msg:
                        self.process_message(msg)
                
                # Process buffer if it contains complete message
                if buffer and not buffer.endswith('\n'):
                    self.process_message(buffer)
                    buffer = ""
                    
            except Exception as e:
                if self.running:
                    self.append_chat(f"Connection error: {str(e)}", "error")
                    self.root.after(0, self.disconnect_from_server)
                break
    
    def process_message(self, message):
        if message.startswith("USERCOUNT:"):
            count = message.split(':')[1]
            self.connected_users = int(count)
            self.root.after(0, self.update_channel_info)
            
        elif message.startswith("JOINED:"):
            channel = message.split(':')[1]
            self.current_channel = int(channel)
            self.root.after(0, self.update_channel_info)
            self.append_chat(f"Joined channel {channel}", "system")
            
        elif message.startswith("ERROR:"):
            error_msg = message.split(':', 1)[1]
            self.append_chat(f"Server Error: {error_msg}", "error")
            
        elif message.startswith("USERLIST:"):
            users = message.split(':', 1)[1]
            self.append_chat(f"Users in channel: {users}", "info")
            
        else:
            # Regular message - parse username and text
            if ':' in message:
                username, text = message.split(':', 1)
                self.append_chat_message(username, text)
            else:
                self.append_chat(message, "info")
    
    def append_chat_message(self, username, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        def update():
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"<{username}>", "username")
            self.chat_display.insert(tk.END, f" {message}\n")
            self.chat_display.see(tk.END)
            self.chat_display.config(state=tk.DISABLED)
        
        self.root.after(0, update)
    
    def append_chat(self, message, tag="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        def update():
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"{message}\n", tag)
            self.chat_display.see(tk.END)
            self.chat_display.config(state=tk.DISABLED)
        
        self.root.after(0, update)
    
    def update_channel_info(self):
        if self.current_channel == -1:
            self.channel_label.config(text="Channel: ----")
            self.users_label.config(text="Users: 0")
        else:
            self.channel_label.config(text=f"Channel: {self.current_channel:04d}")
            self.users_label.config(text=f"Users: {self.connected_users}")

def main():
    root = tk.Tk()
    app = ChatClient(root)
    
    # Handle window close
    def on_closing():
        if app.connected:
            app.disconnect_from_server()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
