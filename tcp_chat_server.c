#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>
#include <conio.h>
#include <iphlpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_CLIENTS 1000
#define BUFFER_SIZE 2048
#define MAX_USERNAME 32
#define MAX_CHANNELS 10000
#define LOG_BUFFER_SIZE 10000

typedef struct {
    SOCKET socket;
    char username[MAX_USERNAME];
    char ip_address[16];
    int port;
    int channel_id;
    int active;
    int client_id;
    HANDLE thread;
} Client;

typedef struct {
    char message[512];
    time_t timestamp;
} LogEntry;

typedef struct {
    Client clients[MAX_CLIENTS];
    CRITICAL_SECTION lock;
    int running;
    int server_active;
    int next_client_id;
    time_t start_time;
    char server_ip[16];
    int server_port;
    
    LogEntry logs[LOG_BUFFER_SIZE];
    int log_count;
    CRITICAL_SECTION log_lock;
    
    char log_filename[256];
    FILE *log_file;
    
    SOCKET listen_socket;
    HANDLE server_thread;
} Server;

Server server = {0};

void set_color(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void clear_screen() {
    system("cls");
}

void get_local_ipv4(char *ip_buffer) {
    strcpy(ip_buffer, "127.0.0.1");
    
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        return;
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            return;
        }
    }
    
    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (pAdapter->Type == IF_TYPE_IEEE80211 || pAdapter->Type == IF_TYPE_IEEE80211) {
                char *ip = pAdapter->IpAddressList.IpAddress.String;
                if (strcmp(ip, "0.0.0.0") != 0 && strcmp(ip, "127.0.0.1") != 0) {
                    strncpy(ip_buffer, ip, 15);
                    ip_buffer[15] = '\0';
                    break;
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    
    if (pAdapterInfo) {
        free(pAdapterInfo);
    }
}

void add_log(const char *message) {
    EnterCriticalSection(&server.log_lock);
    
    if (server.log_count < LOG_BUFFER_SIZE) {
        strncpy(server.logs[server.log_count].message, message, 511);
        server.logs[server.log_count].message[511] = '\0';
        server.logs[server.log_count].timestamp = time(NULL);
        server.log_count++;
    } else {
        for (int i = 0; i < LOG_BUFFER_SIZE - 1; i++) {
            server.logs[i] = server.logs[i + 1];
        }
        strncpy(server.logs[LOG_BUFFER_SIZE - 1].message, message, 511);
        server.logs[LOG_BUFFER_SIZE - 1].message[511] = '\0';
        server.logs[LOG_BUFFER_SIZE - 1].timestamp = time(NULL);
    }
    
    if (server.log_file) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(server.log_file, "[%02d:%02d:%02d] %s\n", 
                t->tm_hour, t->tm_min, t->tm_sec, message);
        fflush(server.log_file);
    }
    
    LeaveCriticalSection(&server.log_lock);
}

int get_active_clients() {
    int count = 0;
    EnterCriticalSection(&server.lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server.clients[i].active) count++;
    }
    LeaveCriticalSection(&server.lock);
    return count;
}

int get_active_channels() {
    int channels[MAX_CHANNELS] = {0};
    int count = 0;
    
    EnterCriticalSection(&server.lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server.clients[i].active && server.clients[i].channel_id != -1) {
            if (!channels[server.clients[i].channel_id]) {
                channels[server.clients[i].channel_id] = 1;
                count++;
            }
        }
    }
    LeaveCriticalSection(&server.lock);
    return count;
}

void get_uptime(char *buffer) {
    time_t now = time(NULL);
    time_t diff = now - server.start_time;
    
    int days = diff / 86400;
    int hours = (diff % 86400) / 3600;
    int minutes = (diff % 3600) / 60;
    int seconds = diff % 60;
    
    if (days > 0) {
        sprintf(buffer, "%dd %02dh %02dm %02ds", days, hours, minutes, seconds);
    } else if (hours > 0) {
        sprintf(buffer, "%02dh %02dm %02ds", hours, minutes, seconds);
    } else if (minutes > 0) {
        sprintf(buffer, "%02dm %02ds", minutes, seconds);
    } else {
        sprintf(buffer, "%02ds", seconds);
    }
}

void draw_main_menu() {
    clear_screen();
    
    set_color(15);
    printf("================================================================================\n");
    printf("2.3.12                                TERMINAL                                  \n");
    printf("================================================================================\n");
    set_color(7);
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    char uptime[64];
    get_uptime(uptime);
    
    printf("\n");
    set_color(14);
    printf("  SERVER STATUS\n");
    set_color(7);
    printf("  +---------------------------------------------------------------------------+\n");
    printf("  | Status:           ");
    if (server.server_active) {
        set_color(10);
        printf("%-55s", "[ONLINE]");
    } else {
        set_color(12);
        printf("%-55s", "[OFFLINE]");
    }
    set_color(7);
    printf(" |\n");
    
    printf("  | Server IP:        %-55s |\n", server.server_ip);
    printf("  | Server Port:      %-55d |\n", server.server_port);
    printf("  | Uptime:           %-55s |\n", uptime);
    printf("  | Date/Time:        %02d/%02d/%04d %02d:%02d:%02d UTC+8%30s |\n",
           t->tm_mday, t->tm_mon + 1, t->tm_year + 1900,
           t->tm_hour, t->tm_min, t->tm_sec, "");
    printf("  +---------------------------------------------------------------------------+\n");
    
    printf("\n");
    set_color(14);
    printf("  STATISTICS\n");
    set_color(7);
    printf("  +---------------------------------------------------------------------------+\n");
    printf("  | Connected Users:  %-21d  Capacity: %d/1000%16s |\n", 
           get_active_clients(), get_active_clients(), "");
    printf("  | Active Channels:  %-55d |\n", get_active_channels());
    printf("  | Total Logs:       %-55d |\n", server.log_count);
    printf("  | Log File:         %-55s |\n", 
           server.log_filename[0] ? server.log_filename : "[Not Set]");
    printf("  +---------------------------------------------------------------------------+\n");
    
    printf("\n");
    set_color(14);
    printf("  MENU\n");
    set_color(7);
    printf("  +---------------------------------------------------------------------------+\n");
    printf("  |  [1] View Activity Logs              [4] Log File Management              |\n");
    printf("  |  [2] View Connected Users            [5] %s Server                     |\n",server.server_active ? "Stop " : "Start");
    printf("  |  [3] View Channel List               [Q] Quit Application                 |\n");
    printf("  +---------------------------------------------------------------------------+\n");
    
    printf("\n");
    set_color(8);
    printf("  Press a key to select menu...\n");
    set_color(7);
}

void draw_logs_menu() {
    clear_screen();
    
    set_color(15);
    printf("================================================================================\n");
    printf("                            ACTIVITY LOGS VIEWER                               \n");
    printf("================================================================================\n");
    set_color(7);
    
    printf("\n");
    
    EnterCriticalSection(&server.log_lock);
    
    if (server.log_count == 0) {
        set_color(8);
        printf("  No logs available.\n");
        set_color(7);
    } else {
        int start = server.log_count > 20 ? server.log_count - 20 : 0;
        
        for (int i = start; i < server.log_count; i++) {
            struct tm *t = localtime(&server.logs[i].timestamp);
            set_color(8);
            printf("  [%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
            set_color(7);
            printf("%s\n", server.logs[i].message);
        }
    }
    
    LeaveCriticalSection(&server.log_lock);
    
    printf("\n");
    set_color(8);
    printf("  Showing last %d entries. Total: %d\n", 
           server.log_count > 20 ? 20 : server.log_count, server.log_count);
    set_color(7);
    printf("\n");
    printf("  Press [B] to return to main menu...\n");
}

void draw_users_menu() {
    clear_screen();
    
    set_color(15);
    printf("================================================================================\n");
    printf("                           CONNECTED USERS LIST                                \n");
    printf("================================================================================\n");
    set_color(7);
    
    printf("\n");
    printf("  ID    USERNAME          CHANNEL    IP ADDRESS        PORT      \n");
    printf("  --------------------------------------------------------------------\n");
    
    EnterCriticalSection(&server.lock);
    
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server.clients[i].active) {
            printf("  %-5d %-17s ", 
                   server.clients[i].client_id,
                   server.clients[i].username[0] ? server.clients[i].username : "[no name]");
            
            if (server.clients[i].channel_id == -1) {
                set_color(8);
                printf("----       ");
                set_color(7);
            } else {
                set_color(10);
                printf("%04d       ", server.clients[i].channel_id);
                set_color(7);
            }
            
            printf("%-17s %-10d\n",
                   server.clients[i].ip_address,
                   server.clients[i].port);
            
            count++;
        }
    }
    
    LeaveCriticalSection(&server.lock);
    
    if (count == 0) {
        set_color(8);
        printf("  No users connected.\n");
        set_color(7);
    }
    
    printf("\n");
    printf("  Total Users: %d / 1000\n", count);
    printf("\n");
    printf("  Press [B] to return to main menu...\n");
}

void draw_channels_menu() {
    clear_screen();
    
    set_color(15);
    printf("================================================================================\n");
    printf("                           ACTIVE CHANNELS LIST                                \n");
    printf("================================================================================\n");
    set_color(7);
    
    printf("\n");
    printf("  CHANNEL ID    USER COUNT    USERS\n");
    printf("  --------------------------------------------------------------------\n");
    
    EnterCriticalSection(&server.lock);
    
    int channels[MAX_CHANNELS] = {0};
    int channel_count = 0;
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server.clients[i].active && server.clients[i].channel_id != -1) {
            channels[server.clients[i].channel_id]++;
        }
    }
    
    for (int ch = 0; ch < MAX_CHANNELS; ch++) {
        if (channels[ch] > 0) {
            set_color(10);
            printf("  %04d          %-13d ", ch, channels[ch]);
            set_color(7);
            
            int printed = 0;
            for (int i = 0; i < MAX_CLIENTS && printed < 5; i++) {
                if (server.clients[i].active && server.clients[i].channel_id == ch) {
                    if (printed > 0) printf(", ");
                    printf("%s", server.clients[i].username[0] ? 
                           server.clients[i].username : "[no name]");
                    printed++;
                }
            }
            if (channels[ch] > 5) {
                printf(" ... and %d more", channels[ch] - 5);
            }
            printf("\n");
            channel_count++;
        }
    }
    
    LeaveCriticalSection(&server.lock);
    
    if (channel_count == 0) {
        set_color(8);
        printf("  No active channels.\n");
        set_color(7);
    }
    
    printf("\n");
    printf("  Total Active Channels: %d\n", channel_count);
    printf("\n");
    printf("  Press [B] to return to main menu...\n");
}

void draw_logfile_menu() {
    clear_screen();
    
    set_color(15);
    printf("================================================================================\n");
    printf("                           LOG FILE MANAGEMENT                                 \n");
    printf("================================================================================\n");
    set_color(7);
    
    printf("\n");
    printf("  Current log file: %s\n", 
           server.log_filename[0] ? server.log_filename : "[Not Set]");
    printf("  Total logs in memory: %d\n", server.log_count);
    printf("\n");
    printf("  +---------------------------------------------------------------------------+\n");
    printf("  |  [1] Save current logs to file                                           |\n");
    printf("  |  [2] Create new log file (with timestamp)                                |\n");
    printf("  |  [3] Change log filename                                                  |\n");
    printf("  |  [4] View current log file path                                           |\n");
    printf("  |  [B] Return to main menu                                                  |\n");
    printf("  +---------------------------------------------------------------------------+\n");
    printf("\n");
    printf("  Select option: ");
}

void save_logs_to_file() {
    if (!server.log_filename[0]) {
        printf("\n  No log file set. Creating default file...\n");
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        sprintf(server.log_filename, "server_log_%04d%02d%02d_%02d%02d%02d.txt",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec);
    }
    
    FILE *f = fopen(server.log_filename, "w");
    if (!f) {
        set_color(12);
        printf("\n  ERROR: Cannot open file for writing!\n");
        set_color(7);
        return;
    }
    
    EnterCriticalSection(&server.log_lock);
    
    fprintf(f, "TCP Chat Server Activity Log\n");
    fprintf(f, "Generated: %s", ctime(&(time_t){time(NULL)}));
    fprintf(f, "========================================\n\n");
    
    for (int i = 0; i < server.log_count; i++) {
        struct tm *t = localtime(&server.logs[i].timestamp);
        fprintf(f, "[%02d:%02d:%02d] %s\n",
                t->tm_hour, t->tm_min, t->tm_sec,
                server.logs[i].message);
    }
    
    LeaveCriticalSection(&server.log_lock);
    
    fclose(f);
    
    set_color(10);
    printf("\n  SUCCESS: Saved %d log entries to %s\n", server.log_count, server.log_filename);
    set_color(7);
    printf("\n  Press any key to continue...");
    _getch();
}

void create_new_logfile() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    sprintf(server.log_filename, "server_log_%04d%02d%02d_%02d%02d%02d.txt",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
    
    if (server.log_file) {
        fclose(server.log_file);
    }
    
    server.log_file = fopen(server.log_filename, "a");
    
    if (server.log_file) {
        set_color(10);
        printf("\n  SUCCESS: Created new log file: %s\n", server.log_filename);
        set_color(7);
        
        char log_msg[256];
        sprintf(log_msg, "New log file created: %s", server.log_filename);
        add_log(log_msg);
    } else {
        set_color(12);
        printf("\n  ERROR: Cannot create log file!\n");
        set_color(7);
    }
    
    printf("\n  Press any key to continue...");
    _getch();
}

void change_logfile_name() {
    printf("\n  Enter new filename (without .txt): ");
    
    char new_name[256];
    if (fgets(new_name, 256, stdin)) {
        new_name[strcspn(new_name, "\n")] = 0;
        
        if (strlen(new_name) > 0) {
            sprintf(server.log_filename, "%s.txt", new_name);
            
            if (server.log_file) {
                fclose(server.log_file);
            }
            
            server.log_file = fopen(server.log_filename, "a");
            
            if (server.log_file) {
                set_color(10);
                printf("\n  SUCCESS: Log file changed to: %s\n", server.log_filename);
                set_color(7);
                
                char log_msg[256];
                sprintf(log_msg, "Log filename changed to: %s", server.log_filename);
                add_log(log_msg);
            } else {
                set_color(12);
                printf("\n  ERROR: Cannot open new log file!\n");
                set_color(7);
            }
        }
    }
    
    printf("\n  Press any key to continue...");
    _getch();
}

void handle_logfile_menu() {
    while (1) {
        draw_logfile_menu();
        
        char ch = _getch();
        
        if (ch == 'b' || ch == 'B') {
            break;
        } else if (ch == '1') {
            save_logs_to_file();
        } else if (ch == '2') {
            create_new_logfile();
        } else if (ch == '3') {
            change_logfile_name();
        } else if (ch == '4') {
            printf("\n\n  Full path: %s\n", server.log_filename);
            printf("\n  Press any key to continue...");
            _getch();
        }
    }
}

int send_to_client(Client *client, const char *msg) {
    if (!client->active) return 0;
    
    int len = strlen(msg);
    int sent = send(client->socket, msg, len, 0);
    
    if (sent == SOCKET_ERROR) {
        return 0;
    }
    return 1;
}

void broadcast_to_channel(int channel_id, const char *msg, Client *exclude) {
    EnterCriticalSection(&server.lock);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server.clients[i].active && 
            server.clients[i].channel_id == channel_id &&
            &server.clients[i] != exclude) {
            send_to_client(&server.clients[i], msg);
        }
    }
    
    LeaveCriticalSection(&server.lock);
}

int count_users_in_channel(int channel_id) {
    int count = 0;
    EnterCriticalSection(&server.lock);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server.clients[i].active && 
            server.clients[i].channel_id == channel_id) {
            count++;
        }
    }
    
    LeaveCriticalSection(&server.lock);
    return count;
}

void send_user_count(int channel_id) {
    int count = count_users_in_channel(channel_id);
    char msg[BUFFER_SIZE];
    snprintf(msg, BUFFER_SIZE, "USERCOUNT:%d", count);

    EnterCriticalSection(&server.lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server.clients[i].active && 
            server.clients[i].channel_id == channel_id) {
            send_to_client(&server.clients[i], msg);
        }
    }
    LeaveCriticalSection(&server.lock);
}

void handle_join(Client *client, const char *data) {
    int new_channel;
    char username[MAX_USERNAME];
    
    if (sscanf(data, "%d:%31s", &new_channel, username) != 2) {
        send_to_client(client, "ERROR:Invalid join format");
        return;
    }
    
    if (new_channel < 0 || new_channel >= MAX_CHANNELS) {
        send_to_client(client, "ERROR:Invalid channel ID");
        return;
    }
    
    int old_channel = client->channel_id;
    
    EnterCriticalSection(&server.lock);
    strncpy(client->username, username, MAX_USERNAME - 1);
    client->username[MAX_USERNAME - 1] = '\0';
    client->channel_id = new_channel;
    LeaveCriticalSection(&server.lock);
    
    char msg[BUFFER_SIZE];
    snprintf(msg, BUFFER_SIZE, "JOINED:%04d", new_channel);
    send_to_client(client, msg);
    
    snprintf(msg, BUFFER_SIZE, "CLIENTID:%d", client->client_id);
    send_to_client(client, msg);
    
    if (old_channel != -1 && old_channel != new_channel) {
        send_user_count(old_channel);
    }
    
    send_user_count(new_channel);
    
    snprintf(msg, BUFFER_SIZE, "Server:*** %s joined the channel ***", username);
    broadcast_to_channel(new_channel, msg, client);
    
    char log_msg[256];
    snprintf(log_msg, 256, "User '%s' (ID:%d) joined channel %04d", 
             username, client->client_id, new_channel);
    add_log(log_msg);
}

void handle_leave(Client *client) {
    if (client->channel_id == -1) return;
    
    int old_channel = client->channel_id;
    char old_username[MAX_USERNAME];
    strncpy(old_username, client->username, MAX_USERNAME);
    
    EnterCriticalSection(&server.lock);
    client->channel_id = -1;
    LeaveCriticalSection(&server.lock);
    
    char msg[BUFFER_SIZE];
    snprintf(msg, BUFFER_SIZE, "Server:*** %s left the channel ***", old_username);
    broadcast_to_channel(old_channel, msg, NULL);
    
    send_user_count(old_channel);
    
    char log_msg[256];
    snprintf(log_msg, 256, "User '%s' (ID:%d) left channel %04d", 
             old_username, client->client_id, old_channel);
    add_log(log_msg);
}

void handle_list(Client *client) {
    if (client->channel_id == -1) {
        send_to_client(client, "ERROR:Not in a channel");
        return;
    }
    
    char userlist[BUFFER_SIZE] = "";
    int first = 1;
    
    EnterCriticalSection(&server.lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server.clients[i].active && 
            server.clients[i].channel_id == client->channel_id) {
            if (!first) strcat(userlist, ", ");
            strcat(userlist, server.clients[i].username);
            first = 0;
        }
    }
    LeaveCriticalSection(&server.lock);
    
    char msg[BUFFER_SIZE];
    snprintf(msg, BUFFER_SIZE, "USERLIST:%s", userlist);
    send_to_client(client, msg);
}

void handle_message(Client *client, const char *data) {
    if (client->channel_id == -1) {
        send_to_client(client, "ERROR:Not in a channel");
        return;
    }
    
    char msg[BUFFER_SIZE];
    snprintf(msg, BUFFER_SIZE, "%s:%s", client->username, data);
    broadcast_to_channel(client->channel_id, msg, NULL);
}

DWORD WINAPI client_handler(LPVOID param) {
    Client *client = (Client*)param;
    char buffer[BUFFER_SIZE];
    int bytes;
    
    char log_msg[256];
    snprintf(log_msg, 256, "New connection from %s:%d (ID:%d)", 
             client->ip_address, client->port, client->client_id);
    add_log(log_msg);
    
    while (server.running && server.server_active && client->active) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes = recv(client->socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes <= 0) {
            break;
        }
        
        buffer[bytes] = '\0';
        
        if (strncmp(buffer, "JOIN:", 5) == 0) {
            handle_join(client, buffer + 5);
        }
        else if (strcmp(buffer, "LEAVE") == 0) {
            handle_leave(client);
        }
        else if (strcmp(buffer, "LIST") == 0) {
            handle_list(client);
        }
        else if (strncmp(buffer, "MSG:", 4) == 0) {
            handle_message(client, buffer + 4);
        }
        else {
            send_to_client(client, "ERROR:Unknown command");
        }
    }
    
    handle_leave(client);
    
    EnterCriticalSection(&server.lock);
    client->active = 0;
    closesocket(client->socket);
    client->socket = INVALID_SOCKET;
    LeaveCriticalSection(&server.lock);
    
    snprintf(log_msg, 256, "Client disconnected: %s (ID:%d)", 
             client->username[0] ? client->username : "unknown", client->client_id);
    add_log(log_msg);
    
    return 0;
}

DWORD WINAPI server_thread(LPVOID param) {
    WSADATA wsa;
    struct sockaddr_in server_addr;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        add_log("ERROR: WSAStartup failed");
        server.server_active = 0;
        return 1;
    }
    
    server.listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server.listen_socket == INVALID_SOCKET) {
        add_log("ERROR: Socket creation failed");
        WSACleanup();
        server.server_active = 0;
        return 1;
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server.server_port);
    
    if (bind(server.listen_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        add_log("ERROR: Bind failed - Port may be in use");
        closesocket(server.listen_socket);
        WSACleanup();
        server.server_active = 0;
        return 1;
    }
    
    if (listen(server.listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        add_log("ERROR: Listen failed");
        closesocket(server.listen_socket);
        WSACleanup();
        server.server_active = 0;
        return 1;
    }
    
    add_log("Server started successfully");
    
    while (server.running && server.server_active) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        
        SOCKET client_sock = accept(server.listen_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_sock == INVALID_SOCKET) {
            if (server.server_active) {
                add_log("ERROR: Accept failed");
            }
            continue;
        }
        
        int slot = -1;
        EnterCriticalSection(&server.lock);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!server.clients[i].active) {
                slot = i;
                break;
            }
        }
        
        if (slot == -1) {
            LeaveCriticalSection(&server.lock);
            send(client_sock, "ERROR:Server full", 17, 0);
            closesocket(client_sock);
            add_log("Connection rejected: Server full");
            continue;
        }
        
        server.clients[slot].socket = client_sock;
        server.clients[slot].active = 1;
        server.clients[slot].channel_id = -1;
        server.clients[slot].client_id = ++server.next_client_id;
        strcpy(server.clients[slot].ip_address, inet_ntoa(client_addr.sin_addr));
        server.clients[slot].port = ntohs(client_addr.sin_port);
        server.clients[slot].username[0] = '\0';
        
        server.clients[slot].thread = CreateThread(NULL, 0, client_handler, 
                                                     &server.clients[slot], 0, NULL);
        
        LeaveCriticalSection(&server.lock);
    }
    
    closesocket(server.listen_socket);
    WSACleanup();
    
    return 0;
}

void start_server() {
    if (server.server_active) {
        set_color(12);
        printf("\n  ERROR: Server is already running!\n");
        set_color(7);
        printf("\n  Press any key to continue...");
        _getch();
        return;
    }
    
    server.server_active = 1;
    server.running = 1;
    
    server.server_thread = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
    
    if (server.server_thread == NULL) {
        set_color(12);
        printf("\n  ERROR: Failed to create server thread!\n");
        set_color(7);
        server.server_active = 0;
        server.running = 0;
        printf("\n  Press any key to continue...");
        _getch();
        return;
    }
    
    Sleep(500);
    
    if (server.server_active) {
        set_color(10);
        printf("\n  SUCCESS: Server started on %s:%d\n", server.server_ip, server.server_port);
        set_color(7);
        add_log("Server started by administrator");
    } else {
        set_color(12);
        printf("\n  ERROR: Server failed to start. Check logs for details.\n");
        set_color(7);
    }
    
    printf("\n  Press any key to continue...");
    _getch();
}

void stop_server() {
    if (!server.server_active) {
        set_color(12);
        printf("\n  ERROR: Server is not running!\n");
        set_color(7);
        printf("\n  Press any key to continue...");
        _getch();
        return;
    }
    
    set_color(14);
    printf("\n  Stopping server...\n");
    set_color(7);
    
    server.server_active = 0;
    
    EnterCriticalSection(&server.lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server.clients[i].active) {
            send_to_client(&server.clients[i], "ERROR:Server shutting down");
            shutdown(server.clients[i].socket, SD_BOTH);
            closesocket(server.clients[i].socket);
            server.clients[i].active = 0;
        }
    }
    LeaveCriticalSection(&server.lock);
    
    if (server.listen_socket != INVALID_SOCKET) {
        closesocket(server.listen_socket);
        server.listen_socket = INVALID_SOCKET;
    }
    
    if (server.server_thread) {
        WaitForSingleObject(server.server_thread, 3000);
        CloseHandle(server.server_thread);
        server.server_thread = NULL;
    }
    
    set_color(10);
    printf("  SUCCESS: Server stopped\n");
    set_color(7);
    add_log("Server stopped by administrator");
    
    printf("\n  Press any key to continue...");
    _getch();
}

void initialize_server() {
    memset(&server, 0, sizeof(Server));
    
    InitializeCriticalSection(&server.lock);
    InitializeCriticalSection(&server.log_lock);
    
    server.running = 1;
    server.server_active = 0;
    server.next_client_id = 0;
    server.start_time = time(NULL);
    server.server_port = 8888;
    server.listen_socket = INVALID_SOCKET;
    
    get_local_ipv4(server.server_ip);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        server.clients[i].active = 0;
        server.clients[i].socket = INVALID_SOCKET;
        server.clients[i].channel_id = -1;
    }
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    sprintf(server.log_filename, "server_log_%04d%02d%02d_%02d%02d%02d.txt",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
    
    server.log_file = fopen(server.log_filename, "a");
    
    if (server.log_file) {
        fprintf(server.log_file, "==========================================\n");
        fprintf(server.log_file, "TCP Chat Server v4.0 - Log Started\n");
        fprintf(server.log_file, "Timestamp: %s", ctime(&now));
        fprintf(server.log_file, "==========================================\n\n");
        fflush(server.log_file);
    }
    
    add_log("Server initialized");
}

void cleanup_server() {
    if (server.server_active) {
        stop_server();
    }
    
    server.running = 0;
    
    if (server.log_file) {
        time_t now = time(NULL);
        fprintf(server.log_file, "\n==========================================\n");
        fprintf(server.log_file, "Server shutdown at: %s", ctime(&now));
        fprintf(server.log_file, "==========================================\n");
        fclose(server.log_file);
        server.log_file = NULL;
    }
    
    DeleteCriticalSection(&server.lock);
    DeleteCriticalSection(&server.log_lock);
}

int main() {
    initialize_server();
    
    while (server.running) {
        draw_main_menu();
        
        char choice = _getch();
        
        if (choice == '1') {
            while (1) {
                draw_logs_menu();
                char ch = _getch();
                if (ch == 'b' || ch == 'B') break;
            }
        }
        else if (choice == '2') {
            while (1) {
                draw_users_menu();
                char ch = _getch();
                if (ch == 'b' || ch == 'B') break;
            }
        }
        else if (choice == '3') {
            while (1) {
                draw_channels_menu();
                char ch = _getch();
                if (ch == 'b' || ch == 'B') break;
            }
        }
        else if (choice == '4') {
            handle_logfile_menu();
        }
        else if (choice == '5') {
            if (server.server_active) {
                stop_server();
            } else {
                start_server();
            }
        }
        else if (choice == 'q' || choice == 'Q') {
            if (server.server_active) {
                clear_screen();
                set_color(14);
                printf("\n  Server is still running. Stop it before quitting? (Y/N): ");
                set_color(7);
                
                char confirm = _getch();
                if (confirm == 'y' || confirm == 'Y') {
                    stop_server();
                    server.running = 0;
                }
            } else {
                server.running = 0;
            }
        }
    }
    
    cleanup_server();
    
    clear_screen();
    set_color(14);
    printf("\n ========================================\n");
    printf("    TCP Chat Server v4.0 - Shutdown\n");
    printf("  ========================================\n\n");
    sleep(5);
    set_color(7);
    printf("  Server has been shut down gracefully.\n");
    printf("  Logs saved to: %s\n\n", server.log_filename);
    printf("  Thank you for using TCP Chat Server!\n\n");
    
    return 0;
}
