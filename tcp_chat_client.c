#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <conio.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 4096
#define MAX_USERNAME 32
#define MAX_MSG 512
#define MAX_IP 16
#define MAX_PASSWORD 64

typedef struct {
    SOCKET sock;
    char username[MAX_USERNAME];
    int current_channel;
    int connected_users;
    int running;
    int echo_local_messages;
    int client_id;
    int loading_animation;
    int authenticated;          // New: server authentication status
    int server_requires_auth;   // New: does server require auth?
} ClientState;

typedef struct {
    HANDLE hConsole;
    int width;
    int height;
    int message_area_start;
    int message_area_end;
    int input_row;
    int current_message_row;
} ConsoleLayout;

ConsoleLayout console_layout;
CRITICAL_SECTION console_lock;

void set_color(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void clear_screen() {
    system("cls");
}

void set_cursor_position(int x, int y) {
    COORD coord;
    coord.X = x;
    coord.Y = y;
    SetConsoleCursorPosition(console_layout.hConsole, coord);
}

COORD get_cursor_position() {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(console_layout.hConsole, &csbi);
    return csbi.dwCursorPosition;
}

void show_loading_animation(const char *message) {
    const char *spinner[] = {"|", "/", "-", "\\"};
    int i = 0;
    
    set_color(14);
    printf("\n%s ", message);
    
    for (int j = 0; j < 20; j++) {
        printf("\b%s", spinner[i]);
        fflush(stdout);
        Sleep(100);
        i = (i + 1) % 4;
    }
    
    printf("\b \b");
    set_color(7);
}

void init_console_layout() {
    console_layout.hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(console_layout.hConsole, &csbi);
    
    console_layout.width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    console_layout.height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    
    console_layout.message_area_start = 3;
    console_layout.message_area_end = console_layout.height - 3;
    console_layout.input_row = console_layout.height - 2;
    console_layout.current_message_row = console_layout.message_area_start;
    
    InitializeCriticalSection(&console_lock);
    
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(console_layout.hConsole, &cursorInfo);
    cursorInfo.bVisible = TRUE;
    SetConsoleCursorInfo(console_layout.hConsole, &cursorInfo);
}

void draw_header(ClientState *state) {
    EnterCriticalSection(&console_lock);
    
    COORD saved_pos = get_cursor_position();
    
    set_cursor_position(0, 0);
    set_color(11);
    for (int i = 0; i < console_layout.width; i++) printf("=");
    
    set_cursor_position(0, 1);
    set_color(14);
    printf("Channel: ");
    set_color(10);
    if (state->current_channel == -1) {
        printf("[----]");
    } else {
        printf("[%04d]", state->current_channel);
    }
    set_color(14);
    printf(" | Users: ");
    set_color(10);
    printf("%d", state->connected_users);

    set_color(14);
    printf(" | User: ");
    set_color(10);
    if (strlen(state->username) == 0) {
        printf("[not set]");
    } else {
        printf("%s", state->username);
    }
    
    // Show authentication status
    set_color(14);
    printf(" | Auth: ");
    if (state->authenticated) {
        set_color(10);
        printf("OK");
    } else if (state->server_requires_auth) {
        set_color(12);
        printf("REQ");
    } else {
        set_color(8);
        printf("N/A");
    }
    
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(console_layout.hConsole, &csbi);
    int remaining = console_layout.width - csbi.dwCursorPosition.X;
    for (int i = 0; i < remaining; i++) printf(" ");
    
    set_cursor_position(0, 2);
    set_color(11);
    for (int i = 0; i < console_layout.width; i++) printf("=");
    
    set_color(7);
    set_cursor_position(saved_pos.X, saved_pos.Y);
    
    LeaveCriticalSection(&console_lock);
}

void update_user_count(int count) {
    EnterCriticalSection(&console_lock);
    
    COORD saved_pos = get_cursor_position();
    
    set_cursor_position(29, 1);
    
    set_color(10);
    printf("%d   ", count);
    set_color(7);
    
    set_cursor_position(saved_pos.X, saved_pos.Y);
    
    LeaveCriticalSection(&console_lock);
}

void draw_input_area() {
    EnterCriticalSection(&console_lock);
    
    set_cursor_position(0, console_layout.input_row - 1);
    set_color(11);
    for (int i = 0; i < console_layout.width; i++) printf("=");
    
    set_cursor_position(0, console_layout.input_row);
    set_color(14);
    printf("> ");
    set_color(7);
    
    set_cursor_position(0, console_layout.input_row + 1);
    set_color(8);
    printf("Commands: /id /list /quit /help /rc /clear /auth");
    
    int cmd_len = 55;
    for (int i = cmd_len; i < console_layout.width; i++) printf(" ");
    set_color(7);
    
    LeaveCriticalSection(&console_lock);
}

void print_message_to_area(const char *message, int color) {
    EnterCriticalSection(&console_lock);
    
    COORD input_pos;
    input_pos.X = 2;
    input_pos.Y = console_layout.input_row;
    
    if (console_layout.current_message_row >= console_layout.message_area_end) {
        SMALL_RECT scrollRect;
        scrollRect.Left = 0;
        scrollRect.Top = console_layout.message_area_start + 1;
        scrollRect.Right = console_layout.width - 1;
        scrollRect.Bottom = console_layout.message_area_end - 1;
        
        COORD dest;
        dest.X = 0;
        dest.Y = console_layout.message_area_start;
        
        CHAR_INFO fill;
        fill.Char.AsciiChar = ' ';
        fill.Attributes = 7;
        
        ScrollConsoleScreenBuffer(console_layout.hConsole, &scrollRect, NULL, dest, &fill);
        
        console_layout.current_message_row = console_layout.message_area_end - 1;
    }
    
    set_cursor_position(0, console_layout.current_message_row);
    set_color(color);
    
    int chars_printed = 0;
    int len = strlen(message);
    
    for (int i = 0; i < len; i++) {
        if (chars_printed >= console_layout.width) {
            console_layout.current_message_row++;
            if (console_layout.current_message_row >= console_layout.message_area_end) {
                break;
            }
            set_cursor_position(0, console_layout.current_message_row);
            chars_printed = 0;
        }
        printf("%c", message[i]);
        chars_printed++;
    }
    
    while (chars_printed < console_layout.width) {
        printf(" ");
        chars_printed++;
    }
    
    console_layout.current_message_row++;
    
    set_cursor_position(input_pos.X, input_pos.Y);
    set_color(7);
    
    LeaveCriticalSection(&console_lock);
}

void print_header() {
    set_color(11);
    printf("===================================================\n");
    printf("          TCP CHANNEL CHAT SYSTEM v1.3.21          \n");
    printf("===================================================\n");
    set_color(7);
}

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

int send_message(SOCKET sock, const char *msg) {
    int len = strlen(msg);
    int sent = send(sock, msg, len, 0);
    
    if (sent == SOCKET_ERROR) {
        char error_msg[256];
        snprintf(error_msg, 256, "[ERROR] Failed to send message: %d", WSAGetLastError());
        print_message_to_area(error_msg, 12);
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
                print_message_to_area("[ERROR] Connection lost to server", 12);
                state->running = 0;
            }
            break;
        }
        
        buffer[bytes] = '\0';
        
        // Handle server messages
        if (strncmp(buffer, "USERCOUNT:", 10) == 0) {
            state->connected_users = atoi(buffer + 10);
            update_user_count(state->connected_users);
            continue;
        }
        else if (strncmp(buffer, "JOINED:", 7) == 0) {
            state->current_channel = atoi(buffer + 7);
            state->loading_animation = 0;
            clear_screen();
            init_console_layout();
            draw_header(state);
            draw_input_area();
            set_cursor_position(2, console_layout.input_row);
            
            char msg[BUFFER_SIZE];
            snprintf(msg, BUFFER_SIZE, "*** Joined channel %04d ***", state->current_channel);
            print_message_to_area(msg, 14);
            continue;
        }
        else if (strncmp(buffer, "CLIENTID:", 9) == 0) {
            state->client_id = atoi(buffer + 9);
            continue;
        }
        // New: Authentication responses
        else if (strncmp(buffer, "AUTH:OK", 7) == 0) {
            state->authenticated = 1;
            state->server_requires_auth = 1;
            print_message_to_area("[AUTH] Successfully authenticated with server", 10);
            draw_header(state);
            continue;
        }
        else if (strncmp(buffer, "AUTH:FAILED", 11) == 0) {
            state->authenticated = 0;
            print_message_to_area("[AUTH] Authentication failed - incorrect password", 12);
            draw_header(state);
            continue;
        }
        else if (strncmp(buffer, "AUTH:REQUIRED", 13) == 0) {
            state->server_requires_auth = 1;
            state->authenticated = 0;
            print_message_to_area("[AUTH] Server requires authentication. Use /auth <password>", 14);
            draw_header(state);
            continue;
        }
        else if (strncmp(buffer, "AUTH:BANNED", 11) == 0) {
            print_message_to_area("[BANNED] You have been banned due to too many failed attempts", 12);
            state->running = 0;
            continue;
        }
        // New: Channel password required
        else if (strncmp(buffer, "CHANNEL:PASSWORD_REQUIRED", 25) == 0) {
            state->loading_animation = 0;
            print_message_to_area("[CHANNEL] This channel is password protected", 14);
            print_message_to_area("[CHANNEL] Use: /join <channel> <password>", 14);
            continue;
        }
        else if (strncmp(buffer, "CHANNEL:PASSWORD_INVALID", 24) == 0) {
            state->loading_animation = 0;
            print_message_to_area("[CHANNEL] Invalid channel password", 12);
            continue;
        }
        // New: Rate limiting
        else if (strncmp(buffer, "RATELIMIT:", 10) == 0) {
            char msg[BUFFER_SIZE];
            snprintf(msg, BUFFER_SIZE, "[RATE LIMIT] %s", buffer + 10);
            print_message_to_area(msg, 14);
            continue;
        }
        else if (strncmp(buffer, "KICKED:", 7) == 0) {
            char msg[BUFFER_SIZE];
            snprintf(msg, BUFFER_SIZE, "[KICKED] %s", buffer + 7);
            print_message_to_area(msg, 12);
            Sleep(3000);
            state->running = 0;
            continue;
        }
        else if (strncmp(buffer, "ERROR:", 6) == 0) {
            state->loading_animation = 0;
            char msg[BUFFER_SIZE];
            snprintf(msg, BUFFER_SIZE, "[SERVER ERROR] %s", buffer + 6);
            print_message_to_area(msg, 12);
            
            // Check for ban message
            if (strstr(buffer, "banned") != NULL) {
                Sleep(2000);
                state->running = 0;
            }
            continue;
        }
        else if (strncmp(buffer, "USERLIST:", 9) == 0) {
            char msg[BUFFER_SIZE];
            snprintf(msg, BUFFER_SIZE, "[Users in channel]: %s", buffer + 9);
            print_message_to_area(msg, 13);
            continue;
        }
        // New: Server info message
        else if (strncmp(buffer, "INFO:", 5) == 0) {
            char msg[BUFFER_SIZE];
            snprintf(msg, BUFFER_SIZE, "[SERVER] %s", buffer + 5);
            print_message_to_area(msg, 11);
            continue;
        }
        // New: Warning message
        else if (strncmp(buffer, "WARNING:", 8) == 0) {
            char msg[BUFFER_SIZE];
            snprintf(msg, BUFFER_SIZE, "[WARNING] %s", buffer + 8);
            print_message_to_area(msg, 14);
            continue;
        }
        else {
            // Regular chat message
            char *delim = strchr(buffer, ':');
            if (delim) {
                *delim = '\0';
                char *username = buffer;
                char *text = delim + 1;
                
                if (state->echo_local_messages && strcmp(username, state->username) == 0) {
                    continue;
                }
                
                char msg[BUFFER_SIZE];
                snprintf(msg, BUFFER_SIZE, "<%s> %s", username, text);
                print_message_to_area(msg, 7);
            } else {
                print_message_to_area(buffer, 7);
            }
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
    printf("\nConnecting to %s:%d...\n", host, port);
    set_color(7);
    
    show_loading_animation("Establishing connection");
    
    int timeout = 5000;
    setsockopt(state->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    if (connect(state->sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        set_color(12);
        printf("\n[ERROR] Connection failed: %d\n", WSAGetLastError());
        printf("Make sure:\n");
        printf("  - Server is running at %s:%d\n", host, port);
        printf("  - IP address is correct\n");
        printf("  - Firewall allows connection\n");
        printf("  - You are not IP banned\n");
        set_color(7);
        closesocket(state->sock);
        WSACleanup();
        return 0;
    }
    
    timeout = 0;
    setsockopt(state->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Reset authentication state
    state->authenticated = 0;
    state->server_requires_auth = 0;
    
    set_color(10);
    printf("\n[SUCCESS] Connected to server %s:%d\n", host, port);
    set_color(7);
    return 1;
}

// Handle command input
void handle_command(ClientState *state, const char *input, int *reconnect_flag) {
    char cmd[MAX_MSG];
    strncpy(cmd, input, MAX_MSG - 1);
    cmd[MAX_MSG - 1] = '\0';
    
    // New: /auth command for server authentication
    if (strncmp(cmd, "/auth ", 6) == 0) {
        const char *password = cmd + 6;
        if (strlen(password) == 0) {
            print_message_to_area("[ERROR] Usage: /auth <password>", 12);
            return;
        }
        
        char msg[BUFFER_SIZE];
        snprintf(msg, BUFFER_SIZE, "AUTH:%s", password);
        send_message(state->sock, msg);
        print_message_to_area("[AUTH] Sending authentication...", 14);
    }
    // Modified: /join now supports optional channel password
    else if (strncmp(cmd, "/join ", 6) == 0) {
        char *args = cmd + 6;
        int channel = -1;
        char channel_password[MAX_PASSWORD] = "";
        
        // Parse channel and optional password
        char *space = strchr(args, ' ');
        if (space) {
            *space = '\0';
            channel = atoi(args);
            strncpy(channel_password, space + 1, MAX_PASSWORD - 1);
            channel_password[MAX_PASSWORD - 1] = '\0';
        } else {
            channel = atoi(args);
        }
        
        if (channel < 0 || channel > 9999) {
            print_message_to_area("[ERROR] Channel ID must be between 0000-9999", 12);
            return;
        }
        
        if (strlen(state->username) == 0) {
            print_message_to_area("[ERROR] Please set username first with /name", 12);
            return;
        }
        
        // Check if server requires auth
        if (state->server_requires_auth && !state->authenticated) {
            print_message_to_area("[ERROR] You must authenticate first. Use /auth <password>", 12);
            return;
        }
        
        state->loading_animation = 1;
        print_message_to_area("Joining channel...", 14);
        
        char msg[BUFFER_SIZE];
        if (strlen(channel_password) > 0) {
            snprintf(msg, BUFFER_SIZE, "JOIN:%04d:%s:%s", channel, state->username, channel_password);
        } else {
            snprintf(msg, BUFFER_SIZE, "JOIN:%04d:%s", channel, state->username);
        }
        send_message(state->sock, msg);
    }
    // Name command
    else if (strncmp(cmd, "/name ", 6) == 0) {
        const char *name = cmd + 6;
        if (strlen(name) == 0 || strlen(name) >= MAX_USERNAME) {
            print_message_to_area("[ERROR] Username must be 1-31 characters", 12);
            return;
        }
        
        strncpy(state->username, name, MAX_USERNAME - 1);
        state->username[MAX_USERNAME - 1] = '\0';
        
        char msg[BUFFER_SIZE];
        snprintf(msg, BUFFER_SIZE, "[SUCCESS] Username set to: %s", state->username);
        print_message_to_area(msg, 10);
        
        draw_header(state);
    }
    // Check id command
    else if (strcmp(cmd, "/id") == 0) {
        if (state->client_id > 0) {
            char msg[BUFFER_SIZE];
            snprintf(msg, BUFFER_SIZE, "[INFO] Your Client ID: %d", state->client_id);
            print_message_to_area(msg, 14);
        } else {
            print_message_to_area("[INFO] Client ID not assigned yet. Join a channel first.", 14);
        }
    }
    // Check list command
    else if (strcmp(cmd, "/list") == 0) {
        if (state->current_channel == -1) {
            print_message_to_area("[ERROR] You must join a channel first", 12);
            return;
        }
        send_message(state->sock, "LIST");
    }
    // Reconnect command
    else if (strcmp(cmd, "/rc") == 0) {
        print_message_to_area("[INFO] Disconnecting from current server...", 14);
        *reconnect_flag = 1;
        state->running = 0;
    }
    // Clear screen command
    else if (strcmp(cmd, "/clear") == 0) {
        clear_screen();
        init_console_layout();
        draw_header(state);
        draw_input_area();
        set_cursor_position(2, console_layout.input_row);
    }
    // Status command
    else if (strcmp(cmd, "/status") == 0) {
        char msg[BUFFER_SIZE];
        print_message_to_area("--- Connection Status ---", 14);
        
        snprintf(msg, BUFFER_SIZE, "  Username: %s", 
                 strlen(state->username) > 0 ? state->username : "[not set]");
        print_message_to_area(msg, 7);
        
        snprintf(msg, BUFFER_SIZE, "  Channel: %s", 
                 state->current_channel != -1 ? "connected" : "not joined");
        print_message_to_area(msg, 7);
        
        snprintf(msg, BUFFER_SIZE, "  Server Auth: %s", 
                 state->server_requires_auth ? 
                     (state->authenticated ? "authenticated" : "required") : "not required");
        print_message_to_area(msg, 7);
        
        snprintf(msg, BUFFER_SIZE, "  Client ID: %d", state->client_id);
        print_message_to_area(msg, 7);
    }

    // Refresh screen command
    else if (strcmp(cmd, "/refresh") == 0) {
        clear_screen();
        init_console_layout();
        draw_header(state);
        draw_input_area();
        set_cursor_position(2, console_layout.input_row);
        print_message_to_area("[INFO] Screen refreshed", 14);
    }

    // Leave channel command
    else if (strcmp(cmd, "/quit") == 0) {
        if (state->current_channel != -1) {
            print_message_to_area("Leaving channel...", 14);
            send_message(state->sock, "LEAVE");
            state->current_channel = -1;
            Sleep(500);
            clear_screen();
            init_console_layout();
            draw_header(state);
            draw_input_area();
            set_cursor_position(2, console_layout.input_row);
            print_message_to_area("*** Left channel ***", 14);
        } else {
            state->running = 0;
        }
    }
    else if (strcmp(cmd, "/help") == 0) {
        print_message_to_area("=== Available Commands ===", 14);
        print_message_to_area("  /join [0000-9999] [password] (optional)", 7);
        print_message_to_area("  /name [username]  - Set username", 7);
        print_message_to_area("  /auth [password]  - Authenticate with server", 7);
        print_message_to_area("  /id               - Show client ID", 7);
        print_message_to_area("  /list             - List users in current channel", 7);
        print_message_to_area("  /status           - Show connection status", 7);
        print_message_to_area("  /rc               - Change server connection", 7);
        print_message_to_area("  /clear            - Clear chat area", 7);
        print_message_to_area("  /refresh          - Refresh screen, fix display error while maintaining values", 7);
        print_message_to_area("  /quit             - Leave channel or exit", 7);
        print_message_to_area("  /help             - Show this help", 7);
    }
    else {
        char msg[BUFFER_SIZE];
        snprintf(msg, BUFFER_SIZE, "[ERROR] Unknown command: %s (type /help for commands)", cmd);
        print_message_to_area(msg, 12);
    }
}

void chat_loop(ClientState *state, const char *server_ip, int server_port, int *reconnect_flag) {
    char input[MAX_MSG];
    HANDLE recv_handle;
    DWORD thread_id;
    
    state->running = 1;
    state->echo_local_messages = 1;
    state->client_id = 0;
    
    init_console_layout();
    clear_screen();
    draw_header(state);
    draw_input_area();
    
    set_cursor_position(2, console_layout.input_row);
    
    recv_handle = CreateThread(NULL, 0, receive_thread, state, 0, &thread_id);
    
    if (recv_handle == NULL) {
        print_message_to_area("[ERROR] Failed to create receive thread", 12);
        return;
    }
    
    char msg[BUFFER_SIZE];
    snprintf(msg, BUFFER_SIZE, "Connected to %s:%d", server_ip, server_port);
    print_message_to_area(msg, 14);
    print_message_to_area("Set username with /name, then join with /join", 7);
    print_message_to_area("If server requires auth, use /auth <password> first", 8);
    
    while (state->running) {
        int pos = 0;
        char ch;
        
        EnterCriticalSection(&console_lock);
        
        set_cursor_position(2, console_layout.input_row);
        for (int i = 0; i < console_layout.width - 2; i++) printf(" ");
        set_cursor_position(2, console_layout.input_row);
        
        LeaveCriticalSection(&console_lock);
        
        while (1) {
            if (!state->running) break;
            
            if (_kbhit()) {
                ch = _getch();
                
                if (ch == '\r' || ch == '\n') {
                    input[pos] = '\0';
                    break;
                }
                else if (ch == '\b') {
                    if (pos > 0) {
                        pos--;
                        EnterCriticalSection(&console_lock);
                        printf("\b \b");
                        LeaveCriticalSection(&console_lock);
                    }
                }
                else if (ch == 27) {
                    pos = 0;
                    EnterCriticalSection(&console_lock);
                    set_cursor_position(2, console_layout.input_row);
                    for (int i = 0; i < console_layout.width - 2; i++) printf(" ");
                    set_cursor_position(2, console_layout.input_row);
                    LeaveCriticalSection(&console_lock);
                }
                else if (pos < MAX_MSG - 1 && ch >= 32 && ch <= 126) {
                    input[pos++] = ch;
                    EnterCriticalSection(&console_lock);
                    printf("%c", ch);
                    LeaveCriticalSection(&console_lock);
                }
            } else {
                Sleep(10);
            }
        }
        
        if (!state->running) break;
        if (strlen(input) == 0) continue;
        
        EnterCriticalSection(&console_lock);
        
        if (input[0] == '/') {
            LeaveCriticalSection(&console_lock);
            handle_command(state, input, reconnect_flag);
            EnterCriticalSection(&console_lock);
        } else {
            if (state->current_channel == -1) {
                LeaveCriticalSection(&console_lock);
                print_message_to_area("[ERROR] Join a channel first with /join [id]", 12);
                EnterCriticalSection(&console_lock);
            } else {
                char display_msg[BUFFER_SIZE];
                snprintf(display_msg, BUFFER_SIZE, "<%s> %s", state->username, input);
                
                LeaveCriticalSection(&console_lock);
                print_message_to_area(display_msg, 10);
                
                char server_msg[BUFFER_SIZE];
                snprintf(server_msg, BUFFER_SIZE, "MSG:%s", input);
                send_message(state->sock, server_msg);
                
                EnterCriticalSection(&console_lock);
            }
        }
        
        set_cursor_position(2, console_layout.input_row);
        for (int i = 0; i < console_layout.width - 2; i++) printf(" ");
        set_cursor_position(2, console_layout.input_row);
        
        LeaveCriticalSection(&console_lock);
    }
    
    WaitForSingleObject(recv_handle, 3000);
    CloseHandle(recv_handle);
    DeleteCriticalSection(&console_lock);
}

int get_server_info(char *host, int *port) {
    set_color(14);
    printf("\n===================================================\n");
    printf(  "          SERVER CONNECTION SETUP                  \n");
    printf(  "===================================================\n\n");
    set_color(7);
    
    printf("Enter server IPv4 address\n");
    set_color(10);
    printf("Examples:\n");
    printf("  - Localhost:      127.0.0.1\n");
    printf("  - Local network:  192.168.1.100\n");
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
        
        host[strcspn(host, "\n")] = 0;
        
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
    
    set_color(14);
    printf("\nServer Port [default: 8888]: ");
    set_color(7);
    
    char port_input[10];
    *port = 8888;
    
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
    (void)argc;
    (void)argv;
    
    ClientState state = {0};
    state.current_channel = -1;
    state.connected_users = 0;
    state.authenticated = 0;
    state.server_requires_auth = 0;
    
    char host[MAX_IP];
    int port = 8888;
    int reconnect_flag = 0;
    int exit_program = 0;
    
    while (!exit_program) {
        clear_screen();
        print_header();
        
        get_server_info(host, &port);
        
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
        
        Sleep(500);
        
        reconnect_flag = 0;
        
        chat_loop(&state, host, port, &reconnect_flag);
        
        if (state.current_channel != -1) {
            send_message(state.sock, "LEAVE");
        }
        closesocket(state.sock);
        
        if (!reconnect_flag) {
            exit_program = 1;
        } else {
            set_color(10);
            printf("\n[INFO] Preparing to reconnect...\n");
            set_color(7);
            Sleep(1000);
            
            state.current_channel = -1;
            state.connected_users = 0;
            state.authenticated = 0;
            state.server_requires_auth = 0;
        }
    }
    WSACleanup();
    set_color(14);
    printf("\nGoodbye!\n");
    set_color(7);
    return 0;
}
