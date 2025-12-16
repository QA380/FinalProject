#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <conio.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 2048
#define MAX_USERNAME 32
#define MAX_MSG 512
#define MAX_IP 16

typedef struct {
    SOCKET sock;
    char username[MAX_USERNAME];
    int current_channel;
    int connected_users;
    int running;
} ClientState;

void set_color(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void clear_screen() {
    system("cls");
}

void print_header() {
    set_color(11); // Cyan
    printf("=================================================\n");
    printf("|         TCP CHANNEL CHAT SYSTEM v1.0          |\n");
    printf("=================================================\n");
    set_color(7);
}

exit(0)
int validate_ip(const char *ip) {
    int a, b, c, d;
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        return 0;
    }
    if (a < 0 || a > 255 || b < 0 || b > 255 || 
        c < 0 || c > 255 || d < 0 || d > 255) {
        return 0;
    }
    return 1;
}

void print_main_screen(ClientState *state, const char *server_ip, int server_port) {
    clear_screen();
    print_header();
    set_color(14); // Yellow
    printf("\nUsername: ");
    set_color(10); // Green
    printf("%s\n", state->username[0] ? state->username : "[Not Set]");
    
    set_color(14);
    printf("Channel ID: ");
    set_color(10);
    printf("%04d\n", state->current_channel);
    
    set_color(14);
    printf("Connected to: ");
    set_color(10);
    printf("%s:%d\n\n", server_ip, server_port);
    
    set_color(7);
    printf("Commands:\n");
    printf("  /join [0000-9999] - Join a channel\n");
    printf("  /name [username]  - Set username\n");
    printf("  /reconnect        - Change server connection\n");
    printf("  /quit             - Exit program\n");
    printf("\n> ");
}

void print_chat_header(ClientState *state) {
    set_color(11);
    printf("Channel: [%04d]", state->current_channel);
    set_color(14);
    printf(" | Connected: %d user%s\n", 
           state->connected_users, 
           state->connected_users != 1 ? "s" : "");
    set_color(11);
    printf("═══════════════════════════════════════════════════\n");
    set_color(7);
}

int send_message(SOCKET sock, const char *msg) {
    int len = strlen(msg);
    int sent = send(sock, msg, len, 0);
    
    if (sent == SOCKET_ERROR) {
        set_color(12);
        printf("\n[ERROR] Failed to send message: %d\n", WSAGetLastError());
        set_color(7);
        return 0;
    }
    return 1;
}

DWORD WINAPI receive_thread(LPVOID param) {
    ClientState *state = (ClientState*)param;
    char buffer[BUFFER_SIZE];
    int bytes;
    
    while (state->running) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes = recv(state->sock, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes <= 0) {
            if (state->running) {
                set_color(12);
                printf("\n[ERROR] Connection lost to server\n");
                set_color(7);
                state->running = 0;
            }
            break;
        }
        
        buffer[bytes] = '\0';
        
        // Parse server messages
        if (strncmp(buffer, "USERCOUNT:", 10) == 0) {
            state->connected_users = atoi(buffer + 10);
            continue;
        }
        else if (strncmp(buffer, "JOINED:", 7) == 0) {
            state->current_channel = atoi(buffer + 7);
            clear_screen();
            print_chat_header(state);
            continue;
        }
        else if (strncmp(buffer, "ERROR:", 6) == 0) {
            set_color(12);
            printf("\n[SERVER ERROR] %s\n", buffer + 6);
            set_color(7);
            continue;
        }
        else if (strncmp(buffer, "USERLIST:", 9) == 0) {
            set_color(13);
            printf("\n[Users in channel]: %s\n", buffer + 9);
            set_color(7);
            continue;
        }
        
        // Regular message - parse username and message
        char *delim = strchr(buffer, ':');
        if (delim) {
            *delim = '\0';
            set_color(10);
            printf("<%s>", buffer);
            set_color(7);
            printf(" %s\n", delim + 1);
        } else {
            printf("%s\n", buffer);
        }
    }
    
    return 0;
}

int connect_to_server(ClientState *state, const char *host, int port) {
    WSADATA wsa;
    struct sockaddr_in server;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        set_color(12);
        printf("[ERROR] WSAStartup failed: %d\n", WSAGetLastError());
        set_color(7);
        return 0;
    }
    
    state->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (state->sock == INVALID_SOCKET) {
        set_color(12);
        printf("[ERROR] Socket creation failed: %d\n", WSAGetLastError());
        set_color(7);
        WSACleanup();
        return 0;
    }
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(host);
    server.sin_port = htons(port);
    
    set_color(14);
    printf("\nConnecting to %s:%d", host, port);
    set_color(7);
    
    // Set socket timeout for connection
    int timeout = 5000; // 5 seconds
    setsockopt(state->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    if (connect(state->sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        set_color(12);
        printf("\n[ERROR] Connection failed: %d\n", WSAGetLastError());
        printf("Make sure:\n");
        printf("  - Server is running at %s:%d\n", host, port);
        printf("  - IP address is correct\n");
        printf("  - Firewall allows connection\n");
        printf("  - You're on the same Hamachi network\n");
        set_color(7);
        closesocket(state->sock);
        WSACleanup();
        return 0;
    }
    
    // Reset timeout to blocking mode
    timeout = 0;
    setsockopt(state->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    set_color(10);
    printf("\n[SUCCESS] Connected to server %s:%d\n", host, port);
    set_color(7);
    return 1;
}

// Handle user commands
void handle_command(ClientState *state, const char *input, int *reconnect_flag) {
    char cmd[MAX_MSG];
    strncpy(cmd, input, MAX_MSG - 1);
    cmd[MAX_MSG - 1] = '\0';
    
    if (strncmp(cmd, "/join ", 6) == 0) {
        int channel = atoi(cmd + 6);
        if (channel < 0 || channel > 9999) {
            set_color(12);
            printf("[ERROR] Channel ID must be between 0000-9999\n");
            set_color(7);
            return;
        }
        
        if (strlen(state->username) == 0) {
            set_color(12);
            printf("[ERROR] Please set username first with /name\n");
            set_color(7);
            return;
        }
        
        char msg[BUFFER_SIZE];
        snprintf(msg, BUFFER_SIZE, "JOIN:%04d:%s", channel, state->username);
        send_message(state->sock, msg);
    }
    else if (strncmp(cmd, "/name ", 6) == 0) {
        const char *name = cmd + 6;
        if (strlen(name) == 0 || strlen(name) >= MAX_USERNAME) {
            set_color(12);
            printf("[ERROR] Username must be 1-%d characters\n", MAX_USERNAME - 1);
            set_color(7);
            return;
        }
        
        strncpy(state->username, name, MAX_USERNAME - 1);
        state->username[MAX_USERNAME - 1] = '\0';
        
        set_color(10);
        printf("[SUCCESS] Username set to: %s\n", state->username);
        set_color(7);
    }
    else if (strcmp(cmd, "/list") == 0) {
        if (state->current_channel == -1) {
            set_color(12);
            printf("[ERROR] You must join a channel first\n");
            set_color(7);
            return;
        }
        send_message(state->sock, "LIST");
    }
    else if (strcmp(cmd, "/rc") == 0) {
        set_color(14);
        printf("\n[INFO] Disconnecting from current server...\n");
        set_color(7);
        *reconnect_flag = 1;
        state->running = 0;
    }
    else if (strcmp(cmd, "/quit") == 0) {
        if (state->current_channel != -1) {
            send_message(state->sock, "LEAVE");
            state->current_channel = -1;
            print_main_screen(state, "", 0);
        } else {
            state->running = 0;
        }
    }
    else if (strcmp(cmd, "/help") == 0) {
        set_color(14);
        printf("\nAvailable commands:\n");
        printf("  /join [0000-9999] - Join a channel\n");
        printf("  /name [username]  - Set your username\n");
        printf("  /list             - List users in current channel\n");
        printf("  /rc        - Change server connection\n");
        printf("  /quit             - Leave channel or exit\n");
        printf("  /help             - Show this help\n\n");
        set_color(7);
    }
    else {
        set_color(12);
        printf("[ERROR] Unknown command. Type /help for commands\n");
        set_color(7);
    }
}

void chat_loop(ClientState *state, const char *server_ip, int server_port, int *reconnect_flag) {
    char input[MAX_MSG];
    HANDLE recv_handle;
    DWORD thread_id;
    
    state->running = 1;
    recv_handle = CreateThread(NULL, 0, receive_thread, state, 0, &thread_id);
    
    if (recv_handle == NULL) {
        set_color(12);
        printf("[ERROR] Failed to create receive thread\n");
        set_color(7);
        return;
    }
    
    print_main_screen(state, server_ip, server_port);
    
    while (state->running) {
        if (fgets(input, MAX_MSG, stdin) == NULL) {
            continue;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) == 0) {
            continue;
        }
        
        if (input[0] == '/') {
            handle_command(state, input, reconnect_flag);
        } else {
            if (state->current_channel == -1) {
                set_color(12);
                printf("[ERROR] Join a channel first with /join [id]\n");
                set_color(7);
            } else {
                char msg[BUFFER_SIZE];
                snprintf(msg, BUFFER_SIZE, "MSG:%s", input);
                send_message(state->sock, msg);
            }
        }
    }
    
    WaitForSingleObject(recv_handle, 3000);
    CloseHandle(recv_handle);
}

int get_server_info(char *host, int *port) {
    set_color(14);
    printf("\n=================================================\n");
    printf(  "|            SERVER CONNECTION SETUP            |\n");
    printf(  "=================================================\n");
    set_color(7);
    
    printf("Enter server IPv4 address\n");
    set_color(10);
    printf("Examples:\n");
    printf("  Localhost:      127.0.0.1\n");
    printf("  Local network:  192.168.1.100\n");
    set_color(7);
    
    while (1) {
        set_color(14);
        printf("Server IP: ");
        set_color(7);
        
        if (fgets(host, MAX_IP, stdin) == NULL) {
            set_color(12);
            printf("[ERROR] Failed to read input\n");
            set_color(7);
            continue;
        }
        
        // Remove newline
        host[strcspn(host, "\n")] = 0;
        
        // Validate IP
        if (strlen(host) == 0) {
            set_color(12);
            printf("[ERROR] IP address cannot be empty\n");
            set_color(7);
            continue;
        }
        
        if (!validate_ip(host)) {
            set_color(12);
            printf("[ERROR] Invalid IP format. Use: xxx.xxx.xxx.xxx\n");
            set_color(7);
            continue;
        }
        
        break;
    }
    
    // Optional: Get port
    set_color(14);
    printf("\nServer Port [default: 8888]: ");
    set_color(7);
    
    char port_input[10];
    *port = 8888; // Default
    
    if (fgets(port_input, 10, stdin) != NULL) {
        port_input[strcspn(port_input, "\n")] = 0;
        if (strlen(port_input) > 0) {
            int user_port = atoi(port_input);
            if (user_port > 0 && user_port <= 65535) {
                *port = user_port;
            } else {
                set_color(14);
                printf("[WARNING] Invalid port, using default: 8888\n");
                set_color(7);
            }
        }
    }
    
    printf("\n");
    return 1;
}

int main(int argc, char *argv[]) {
    ClientState state = {0};
    state.current_channel = -1;
    state.connected_users = 0;
    
    char host[MAX_IP];
    int port = 8888;
    int reconnect_flag = 0;
    int exit_program = 0;
    
    while (!exit_program) {
        clear_screen();
        print_header();
        
        // Get server connection info
        get_server_info(host, &port);
        
        // Connect to server
        if (!connect_to_server(&state, host, port)) {
            set_color(14);
            printf("\nPress 'r' to retry or any other key to exit...");
            set_color(7);
            
            char choice = _getch();
            if (choice == 'r' || choice == 'R') {
                continue;
            } else {
                exit_program = 1;
                break;
            }
        }
        
        Sleep(1000);
        
        // Reset reconnect flag
        reconnect_flag = 0;
        
        // Start chat loop
        chat_loop(&state, host, port, &reconnect_flag);
        
        // Clean up connection
        if (state.current_channel != -1) {
            send_message(state.sock, "LEAVE");
        }
        closesocket(state.sock);
        
        // Check if user wants to reconnect
        if (!reconnect_flag) {
            exit_program = 1;
        } else {
            set_color(10);
            printf("\n[INFO] Preparing to reconnect...\n");
            set_color(7);
            Sleep(1000);
            
            // Reset state for new connection
            state.current_channel = -1;
            state.connected_users = 0;
            // Keep username
        }
    }
    
    WSACleanup();
    
    set_color(14);
    printf("\nGoodbye!\n");
    set_color(7);
    
    return 0;
}
