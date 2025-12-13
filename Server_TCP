#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_CLIENTS 100
#define BUFFER_SIZE 2048
#define MAX_USERNAME 32
#define MAX_CHANNELS 10000

typedef struct {
    SOCKET socket;
    char username[MAX_USERNAME];
    int channel_id;
    int active;
    HANDLE thread;
} Client;

typedef struct {
    Client clients[MAX_CLIENTS];
    CRITICAL_SECTION lock;
    int running;
} Server;

Server server = {0};

void set_color(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
// Log messages with timestamp and type
void log_msg(const char *type, const char *msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    if (strcmp(type, "INFO") == 0) set_color(10);
    else if (strcmp(type, "WARN") == 0) set_color(14);
    else if (strcmp(type, "ERROR") == 0) set_color(12);
    else set_color(7);
    
    printf("[%02d:%02d:%02d] [%s] %s\n", st.wHour, st.wMinute, st.wSecond, type, msg);
    set_color(7);
}

int send_to_client(Client *client, const char *msg) {
    if (!client->active) return 0;
    
    int len = strlen(msg);
    int sent = send(client->socket, msg, len, 0);
    
    if (sent == SOCKET_ERROR) {
        char err[256];
        snprintf(err, 256, "Failed to send to %s: %d", 
                 client->username, WSAGetLastError());
        log_msg("ERROR", err);
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
    
    if (old_channel != -1 && old_channel != new_channel) {
        send_user_count(old_channel);
    }
    
    send_user_count(new_channel);
    
    snprintf(msg, BUFFER_SIZE, "Server:*** %s joined the channel ***", username);
    broadcast_to_channel(new_channel, msg, client);
    
    char log[256];
    snprintf(log, 256, "%s joined channel %04d", username, new_channel);
    log_msg("INFO", log);
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
    
    char log[256];
    snprintf(log, 256, "%s left channel %04d", old_username, old_channel);
    log_msg("INFO", log);
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
    
    char log[256];
    snprintf(log, 256, "New client connected from socket %d", (int)client->socket);
    log_msg("INFO", log);
    
    while (server.running && client->active) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes = recv(client->socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes <= 0) {
            if (bytes == 0) {
                log_msg("INFO", "Client disconnected gracefully");
            } else {
                snprintf(log, 256, "Client recv error: %d", WSAGetLastError());
                log_msg("ERROR", log);
            }
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
    
    snprintf(log, 256, "Client %s disconnected", 
             client->username[0] ? client->username : "unknown");
    log_msg("INFO", log);
    
    return 0;
}

int start_server(int port) {
    WSADATA wsa;
    SOCKET listen_sock;
    struct sockaddr_in server_addr;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log_msg("ERROR", "WSAStartup failed");
        return 0;
    }
    
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        log_msg("ERROR", "Socket creation failed");
        WSACleanup();
        return 0;
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        log_msg("ERROR", "Bind failed");
        closesocket(listen_sock);
        WSACleanup();
        return 0;
    }
    
    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        log_msg("ERROR", "Listen failed");
        closesocket(listen_sock);
        WSACleanup();
        return 0;
    }
    
    char msg[256];
    snprintf(msg, 256, "Server listening on port %d", port);
    log_msg("INFO", msg);
    
    server.running = 1;
    InitializeCriticalSection(&server.lock);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        server.clients[i].active = 0;
        server.clients[i].channel_id = -1;
        server.clients[i].socket = INVALID_SOCKET;
    }
    
    while (server.running) {
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        
        SOCKET client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &addr_len);
        
        if (client_sock == INVALID_SOCKET) {
            if (server.running) {
                log_msg("ERROR", "Accept failed");
            }
            continue;
        }
        
        int slot = -1;
        EnterCriticalSection(&server.lock);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!server.clients[i].active) {
                slot = i;
                server.clients[i].socket = client_sock;
                server.clients[i].active = 1;
                server.clients[i].channel_id = -1;
                server.clients[i].username[0] = '\0';
                break;
            }
        }
        LeaveCriticalSection(&server.lock);
        
        if (slot == -1) {
            log_msg("WARN", "Max clients reached, rejecting connection");
            closesocket(client_sock);
            continue;
        }
        
        DWORD thread_id;
        server.clients[slot].thread = CreateThread(NULL, 0, client_handler, 
                                                    &server.clients[slot], 0, &thread_id);
        
        if (server.clients[slot].thread == NULL) {
            log_msg("ERROR", "Failed to create client thread");
            server.clients[slot].active = 0;
            closesocket(client_sock);
        }
    }
    
    closesocket(listen_sock);
    DeleteCriticalSection(&server.lock);
    WSACleanup();
    return 1;
}

int main(int argc, char *argv[]) {
    int port = 8888;
    
    if (argc >= 2) {
        port = atoi(argv[1]);
    }
    
    set_color(11);
    printf("      TCP CHANNEL CHAT SERVER v1.0\n");
    set_color(7);
    
    if (!start_server(port)) {
        log_msg("ERROR", "Failed to start server");
        return 1;
    }
    
    return 0;
}
