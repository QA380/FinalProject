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
#define BUFFER_SIZE 4096
#define MAX_USERNAME 32
#define MAX_CHANNELS 10000
#define LOG_BUFFER_SIZE 10000
#define MAX_PASSWORD 64
#define MAX_BANNED_IPS 1000
#define MAX_MESSAGES_PER_MINUTE 30
#define RATE_LIMIT_WINDOW 60
#define XOR_KEY "SecretKey123"

// Forward declarations for Client struct (needed for function prototypes)
typedef struct Client Client;

// Banned IP structure
typedef struct {
    char ip[16];
    time_t ban_time;
    int permanent;
    char reason[128];
} BannedIP;

// Channel password structure
typedef struct {
    int channel_id;
    char password[MAX_PASSWORD];
    int password_protected;
} ChannelInfo;

// Client structure
struct Client {
    SOCKET socket;
    char username[MAX_USERNAME];
    char ip_address[16];
    int port;
    int channel_id;
    int active;
    int client_id;
    HANDLE thread;
    
    // Security fields
    int authenticated;
    int message_count;
    time_t rate_limit_start;
    int failed_auth_attempts;
};

typedef struct {
    char message[256];
    time_t timestamp;
} LogEntry;

typedef struct {
    Client clients[MAX_CLIENTS];
    SOCKET listen_socket;
    HANDLE server_thread;
    CRITICAL_SECTION lock;
    CRITICAL_SECTION log_lock;
    CRITICAL_SECTION ban_lock;
    CRITICAL_SECTION channel_lock;
    
    int running;
    int server_active;
    int next_client_id;
    time_t start_time;
    
    char server_ip[16];
    int server_port;
    
    LogEntry logs[LOG_BUFFER_SIZE];
    int log_count;
    int log_start;
    
    FILE *log_file;
    char log_filename[256];
    
    // Security
    int require_auth;
    char server_password[MAX_PASSWORD];
    BannedIP banned_ips[MAX_BANNED_IPS];
    int banned_ip_count;
    ChannelInfo channel_passwords[MAX_CHANNELS];
} Server;

Server server = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

void add_log(const char *message);
int send_to_client(Client *client, const char *message);
void set_color(int color);
void clear_screen(void);
void get_local_ipv4(char *buffer);
int get_active_clients(void);
int get_active_channels(void);
void get_uptime(char *buffer);
void broadcast_to_channel(int channel_id, const char *message, Client *exclude);
int count_users_in_channel(int channel_id);
void send_user_count(int channel_id);

// Security functions
void xor_encrypt_decrypt(char *data, int len);
int is_ip_banned(const char *ip);
void ban_ip(const char *ip, const char *reason, int permanent);
void unban_ip(const char *ip);
int check_rate_limit(Client *client);
void set_channel_password(int channel_id, const char *password);
int verify_channel_password(int channel_id, const char *password);
int is_channel_protected(int channel_id);
int handle_auth(Client *client, const char *password);

// Menu functions
void draw_main_menu(void);
void draw_security_menu(void);
void handle_security_menu(void);
void draw_ban_menu(void);
void handle_ban_menu(void);
void draw_logs_menu(void);
void draw_users_menu(void);
void draw_channels_menu(void);
void draw_logfile_menu(void);
void save_logs_to_file(void);
void create_new_logfile(void);
void change_logfile_name(void);
void handle_logfile_menu(void);

// Client/Server functions
void handle_join(Client *client, const char *data);
void handle_leave(Client *client);
void handle_list(Client *client);
void handle_message(Client *client, const char *data);
DWORD WINAPI client_handler(LPVOID param);
DWORD WINAPI server_thread(LPVOID param);
void start_server(void);
void stop_server(void);
void initialize_server(void);
void cleanup_server(void);

// ============================================================================
// ENCRYPTION FUNCTIONS
// ============================================================================

void xor_encrypt_decrypt(char *data, int len) {
    const char *key = XOR_KEY;
    int keylen = (int)strlen(key);
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}

// ============================================================================
// ENCRYPTION FUNCTIONS (Simple XOR - for demonstration)
// ============================================================================

// void xor_encrypt_decrypt(char *data, int len) {
//     const char *key = XOR_KEY;
//     int keylen = (int)strlen(key);
//     for (int i = 0; i < len; i++) {
//         data[i] ^= key[i % keylen];
//     }
// }

// ============================================================================
// IP BANNING FUNCTIONS
// ============================================================================

int is_ip_banned(const char *ip) {
    EnterCriticalSection(&server.ban_lock);
    
    for (int i = 0; i < server.banned_ip_count; i++) {
        if (strcmp(server.banned_ips[i].ip, ip) == 0) {
            // Check if temporary ban expired (1 hour)
            if (!server.banned_ips[i].permanent) {
                time_t now = time(NULL);
                if (now - server.banned_ips[i].ban_time > 3600) {
                    // Remove expired ban
                    for (int j = i; j < server.banned_ip_count - 1; j++) {
                        server.banned_ips[j] = server.banned_ips[j + 1];
                    }
                    server.banned_ip_count--;
                    LeaveCriticalSection(&server.ban_lock);
                    return 0;
                }
            }
            LeaveCriticalSection(&server.ban_lock);
            return 1; // Banned
        }
    }
    
    LeaveCriticalSection(&server.ban_lock);
    return 0; // Not banned
}

void ban_ip(const char *ip, const char *reason, int permanent) {
    EnterCriticalSection(&server.ban_lock);
    
    // Check if already banned
    for (int i = 0; i < server.banned_ip_count; i++) {
        if (strcmp(server.banned_ips[i].ip, ip) == 0) {
            LeaveCriticalSection(&server.ban_lock);
            return;
        }
    }
    
    if (server.banned_ip_count < MAX_BANNED_IPS) {
        strncpy(server.banned_ips[server.banned_ip_count].ip, ip, 15);
        server.banned_ips[server.banned_ip_count].ip[15] = '\0';
        strncpy(server.banned_ips[server.banned_ip_count].reason, reason, 127);
        server.banned_ips[server.banned_ip_count].reason[127] = '\0';
        server.banned_ips[server.banned_ip_count].ban_time = time(NULL);
        server.banned_ips[server.banned_ip_count].permanent = permanent;
        server.banned_ip_count++;
        
        char log_msg[256];
        snprintf(log_msg, 256, "SECURITY: IP %s banned - %s (%s)", 
                 ip, reason, permanent ? "permanent" : "1 hour");
        add_log(log_msg);
    }
    
    LeaveCriticalSection(&server.ban_lock);
}

void unban_ip(const char *ip) {
    EnterCriticalSection(&server.ban_lock);
    
    for (int i = 0; i < server.banned_ip_count; i++) {
        if (strcmp(server.banned_ips[i].ip, ip) == 0) {
            for (int j = i; j < server.banned_ip_count - 1; j++) {
                server.banned_ips[j] = server.banned_ips[j + 1];
            }
            server.banned_ip_count--;
            
            char log_msg[256];
            snprintf(log_msg, 256, "SECURITY: IP %s unbanned", ip);
            add_log(log_msg);
            break;
        }
    }
    
    LeaveCriticalSection(&server.ban_lock);
}

// ============================================================================
// RATE LIMITING FUNCTIONS
// ============================================================================

int check_rate_limit(Client *client) {
    time_t now = time(NULL);
    
    // Reset counter if window expired
    if (now - client->rate_limit_start > RATE_LIMIT_WINDOW) {
        client->message_count = 0;
        client->rate_limit_start = now;
    }
    
    client->message_count++;
    
    if (client->message_count > MAX_MESSAGES_PER_MINUTE) {
        send_to_client(client, "ERROR:Rate limit exceeded. Please wait.");
        
        char log_msg[256];
        snprintf(log_msg, 256, "SECURITY: Rate limit exceeded by %s (ID:%d) from %s", 
                 client->username, client->client_id, client->ip_address);
        add_log(log_msg);
        
        // Auto-ban if severely abusing (5x the limit)
        if (client->message_count > MAX_MESSAGES_PER_MINUTE * 5) {
            ban_ip(client->ip_address, "Rate limit abuse", 0);
            return -1; // Disconnect
        }
        
        return 0; // Blocked but not disconnected
    }
    
    return 1; // Allowed
}

// ============================================================================
// CHANNEL PASSWORD FUNCTIONS
// ============================================================================

void set_channel_password(int channel_id, const char *password) {
    if (channel_id < 0 || channel_id >= MAX_CHANNELS) return;
    
    EnterCriticalSection(&server.channel_lock);
    
    server.channel_passwords[channel_id].channel_id = channel_id;
    if (password && strlen(password) > 0) {
        strncpy(server.channel_passwords[channel_id].password, password, MAX_PASSWORD - 1);
        server.channel_passwords[channel_id].password[MAX_PASSWORD - 1] = '\0';
        server.channel_passwords[channel_id].password_protected = 1;
    } else {
        server.channel_passwords[channel_id].password[0] = '\0';
        server.channel_passwords[channel_id].password_protected = 0;
    }
    
    LeaveCriticalSection(&server.channel_lock);
    
    char log_msg[256];
    snprintf(log_msg, 256, "Channel %04d password %s", channel_id, 
             password ? "set" : "removed");
    add_log(log_msg);
}

int verify_channel_password(int channel_id, const char *password) {
    if (channel_id < 0 || channel_id >= MAX_CHANNELS) return 0;
    
    EnterCriticalSection(&server.channel_lock);
    
    if (!server.channel_passwords[channel_id].password_protected) {
        LeaveCriticalSection(&server.channel_lock);
        return 1; // No password required
    }
    
    int result = (strcmp(server.channel_passwords[channel_id].password, password) == 0);
    
    LeaveCriticalSection(&server.channel_lock);
    return result;
}

int is_channel_protected(int channel_id) {
    if (channel_id < 0 || channel_id >= MAX_CHANNELS) return 0;
    
    EnterCriticalSection(&server.channel_lock);
    int result = server.channel_passwords[channel_id].password_protected;
    LeaveCriticalSection(&server.channel_lock);
    
    return result;
}

// ============================================================================
// AUTHENTICATION FUNCTIONS
// ============================================================================

int handle_auth(Client *client, const char *password) {
    if (!server.require_auth) {
        client->authenticated = 1;
        return 1;
    }
    
    if (strcmp(password, server.server_password) == 0) {
        client->authenticated = 1;
        client->failed_auth_attempts = 0;
        send_to_client(client, "AUTH:OK");
        
        char log_msg[256];
        snprintf(log_msg, 256, "SECURITY: Client %s:%d authenticated successfully", 
                 client->ip_address, client->port);
        add_log(log_msg);
        return 1;
    } else {
        client->failed_auth_attempts++;
        
        char log_msg[256];
        snprintf(log_msg, 256, "SECURITY: Failed auth attempt %d from %s:%d", 
                 client->failed_auth_attempts, client->ip_address, client->port);
        add_log(log_msg);
        
        if (client->failed_auth_attempts >= 3) {
            ban_ip(client->ip_address, "Too many failed auth attempts", 0);
            send_to_client(client, "AUTH:BANNED");
            return -1; // Disconnect
        }
        send_to_client(client, "AUTH:FAILED");
        return 0;
    }
}
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
            if (pAdapter->Type == MIB_IF_TYPE_ETHERNET || pAdapter->Type == IF_TYPE_IEEE80211) {
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
        strncpy(server.logs[server.log_count].message, message, 255);
        server.logs[server.log_count].message[255] = '\0';
        server.logs[server.log_count].timestamp = time(NULL);
        server.log_count++;
    } else {
        for (int i = 0; i < LOG_BUFFER_SIZE - 1; i++) {
            server.logs[i] = server.logs[i + 1];
        }
        strncpy(server.logs[LOG_BUFFER_SIZE - 1].message, message, 255);
        server.logs[LOG_BUFFER_SIZE - 1].message[255] = '\0';
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
    printf("  | Banned IPs:       %-55d |\n", server.banned_ip_count);
    printf("  | Auth Required:    %-55s |\n", server.require_auth ? "Yes" : "No");
    printf("  +---------------------------------------------------------------------------+\n");
    
    printf("\n");
    set_color(14);
    printf("  MENU\n");
    set_color(7);
    printf("  +---------------------------------------------------------------------------+\n");
    printf("  |  [1] View Activity Logs              [5] %s Server                     |\n", server.server_active ? "Stop " : "Start");
    printf("  |  [2] View Connected Users            [6] Security Settings                |\n");
    printf("  |  [3] View Channel List               [7] Ban Management                   |\n");
    printf("  |  [4] Log File Management             [Q] Quit Application                 |\n");
    printf("  +---------------------------------------------------------------------------+\n");
    
    printf("\n");
    set_color(8);
    printf("  Press a key to select menu...\n");
    set_color(7);
}

// ============================================================================
// SECURITY MENU
// ============================================================================

void draw_security_menu() {
    clear_screen();
    
    set_color(15);
    printf("================================================================================\n");
    printf("                            SECURITY SETTINGS                                  \n");
    printf("================================================================================\n");
    set_color(7);
    
    printf("\n");
    printf("  Current Settings:\n");
    printf("  +---------------------------------------------------------------------------+\n");
    printf("  | Server Authentication:  %-49s |\n", server.require_auth ? "ENABLED" : "DISABLED");
    printf("  | Server Password:        %-49s |\n", server.require_auth ? "********" : "[Not Set]");
    printf("  | Rate Limit:             %d messages per %d seconds%23s |\n", 
           MAX_MESSAGES_PER_MINUTE, RATE_LIMIT_WINDOW, "");
    printf("  | Banned IPs:             %-49d |\n", server.banned_ip_count);
    printf("  +---------------------------------------------------------------------------+\n");
    
    printf("\n");
    printf("  +---------------------------------------------------------------------------+\n");
    printf("  |  [1] Toggle Server Authentication                                         |\n");
    printf("  |  [2] Set Server Password                                                  |\n");
    printf("  |  [3] Set Channel Password                                                 |\n");
    printf("  |  [4] Remove Channel Password                                              |\n");
    printf("  |  [B] Return to main menu                                                  |\n");
    printf("  +---------------------------------------------------------------------------+\n");
    printf("\n");
    printf("  Select option: ");
}

void handle_security_menu() {
    while (1) {
        draw_security_menu();
        
        char ch = _getch();
        
        if (ch == 'b' || ch == 'B') {
            break;
        } else if (ch == '1') {
            server.require_auth = !server.require_auth;
            set_color(10);
            printf("\n\n  Authentication %s\n", server.require_auth ? "ENABLED" : "DISABLED");
            set_color(7);
            
            char log_msg[256];
            snprintf(log_msg, 256, "SECURITY: Server authentication %s", 
                     server.require_auth ? "enabled" : "disabled");
            add_log(log_msg);
            
            printf("\n  Press any key to continue...");
            _getch();
        } else if (ch == '2') {
            printf("\n\n  Enter new server password: ");
            char password[MAX_PASSWORD];
            if (fgets(password, MAX_PASSWORD, stdin)) {
                password[strcspn(password, "\n")] = 0;
                if (strlen(password) > 0) {
                    strncpy(server.server_password, password, MAX_PASSWORD - 1);
                    server.server_password[MAX_PASSWORD - 1] = '\0';
                    server.require_auth = 1;
                    
                    set_color(10);
                    printf("\n  Password set successfully. Authentication enabled.\n");
                    set_color(7);
                    
                    add_log("SECURITY: Server password changed");
                }
            }
            printf("\n  Press any key to continue...");
            _getch();
        } else if (ch == '3') {
            printf("\n\n  Enter channel ID (0-9999): ");
            int channel_id;
            scanf("%d", &channel_id);
            getchar(); // consume newline
            
            if (channel_id >= 0 && channel_id < MAX_CHANNELS) {
                printf("  Enter channel password: ");
                char password[MAX_PASSWORD];
                if (fgets(password, MAX_PASSWORD, stdin)) {
                    password[strcspn(password, "\n")] = 0;
                    set_channel_password(channel_id, password);
                    
                    set_color(10);
                    printf("\n  Channel %04d password set.\n", channel_id);
                    set_color(7);
                }
            } else {
                set_color(12);
                printf("\n  Invalid channel ID!\n");
                set_color(7);
            }
            printf("\n  Press any key to continue...");
            _getch();
        } else if (ch == '4') {
            printf("\n\n  Enter channel ID to remove password (0-9999): ");
            int channel_id;
            scanf("%d", &channel_id);
            getchar();
            
            if (channel_id >= 0 && channel_id < MAX_CHANNELS) {
                set_channel_password(channel_id, NULL);
                set_color(10);
                printf("\n  Channel %04d password removed.\n", channel_id);
                set_color(7);
            }
            printf("\n  Press any key to continue...");
            _getch();
        }
    }
}

// ============================================================================
// BAN MANAGEMENT MENU
// ============================================================================

void draw_ban_menu() {
    clear_screen();
    
    set_color(15);
    printf("================================================================================\n");
    printf("                            BAN MANAGEMENT                                     \n");
    printf("================================================================================\n");
    set_color(7);
    
    printf("\n");
    printf("  Banned IPs (%d total):\n", server.banned_ip_count);
    printf("  +---------------------------------------------------------------------------+\n");
    
    EnterCriticalSection(&server.ban_lock);
    
    if (server.banned_ip_count == 0) {
        printf("  |  No banned IPs                                                            |\n");
    } else {
        for (int i = 0; i < server.banned_ip_count && i < 15; i++) {
            time_t remaining = 0;
            if (!server.banned_ips[i].permanent) {
                remaining = 3600 - (time(NULL) - server.banned_ips[i].ban_time);
                if (remaining < 0) remaining = 0;
            }
            
            printf("  |  %-15s  %-20s  %s%s\n",
                   server.banned_ips[i].ip,
                   server.banned_ips[i].reason,
                   server.banned_ips[i].permanent ? "PERMANENT" : "",
                   !server.banned_ips[i].permanent ? 
                       (char[32]){0} : "");
            
            if (!server.banned_ips[i].permanent) {
                printf("                                                   (%ld min remaining)\n",
                       remaining / 60);
            }
        }
    }
    
    LeaveCriticalSection(&server.ban_lock);
    
    printf("  +---------------------------------------------------------------------------+\n");
    
    printf("\n");
    printf("  +---------------------------------------------------------------------------+\n");
    printf("  |  [1] Ban IP (temporary - 1 hour)                                          |\n");
    printf("  |  [2] Ban IP (permanent)                                                   |\n");
    printf("  |  [3] Unban IP                                                             |\n");
    printf("  |  [4] Clear all bans                                                       |\n");
    printf("  |  [B] Return to main menu                                                  |\n");
    printf("  +---------------------------------------------------------------------------+\n");
    printf("\n");
    printf("  Select option: ");
}

void handle_ban_menu() {
    while (1) {
        draw_ban_menu();
        
        char ch = _getch();
        
        if (ch == 'b' || ch == 'B') {
            break;
        } else if (ch == '1' || ch == '2') {
            int permanent = (ch == '2');
            printf("\n\n  Enter IP address to ban: ");
            char ip[16];
            if (fgets(ip, 16, stdin)) {
                ip[strcspn(ip, "\n")] = 0;
                printf("  Enter reason: ");
                char reason[128];
                if (fgets(reason, 128, stdin)) {
                    reason[strcspn(reason, "\n")] = 0;
                    ban_ip(ip, reason, permanent);
                    
                    set_color(10);
                    printf("\n  IP %s banned %s.\n", ip, permanent ? "permanently" : "for 1 hour");
                    set_color(7);
                }
            }
            printf("\n  Press any key to continue...");
            _getch();
        } else if (ch == '3') {
            printf("\n\n  Enter IP address to unban: ");
            char ip[16];
            if (fgets(ip, 16, stdin)) {
                ip[strcspn(ip, "\n")] = 0;
                unban_ip(ip);
                
                set_color(10);
                printf("\n  IP %s unbanned.\n", ip);
                set_color(7);
            }
            printf("\n  Press any key to continue...");
            _getch();
        } else if (ch == '4') {
            EnterCriticalSection(&server.ban_lock);
            server.banned_ip_count = 0;
            LeaveCriticalSection(&server.ban_lock);
            
            set_color(10);
            printf("\n\n  All bans cleared.\n");
            set_color(7);
            add_log("SECURITY: All IP bans cleared");
            
            printf("\n  Press any key to continue...");
            _getch();
        }
    }
}

// ...existing code for draw_logs_menu, draw_users_menu, draw_channels_menu, etc...

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
            
            // Highlight security logs
            if (strstr(server.logs[i].message, "SECURITY:") != NULL) {
                set_color(12);
            } else {
                set_color(7);
            }
            printf("%s\n", server.logs[i].message);
            set_color(7);
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
    printf("  ID    USERNAME          CHANNEL    IP ADDRESS        AUTH      \n");
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
            
            printf("%-17s ", server.clients[i].ip_address);
            
            if (server.clients[i].authenticated) {
                set_color(10);
                printf("YES\n");
            } else {
                set_color(12);
                printf("NO\n");
            }
            set_color(7);
            
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
    printf("  CHANNEL ID    PROTECTED    USER COUNT    USERS\n");
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
            printf("  %04d          ", ch);
            
            if (is_channel_protected(ch)) {
                set_color(14);
                printf("YES          ");
            } else {
                set_color(8);
                printf("NO           ");
            }
            
            set_color(7);
            printf("%-13d ", channels[ch]);
            
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
    char password[MAX_PASSWORD] = "";
    
    // Format: channel:username or channel:username:password
    int parsed = sscanf(data, "%d:%31[^:]:%63s", &new_channel, username, password);
    
    if (parsed < 2) {
        send_to_client(client, "ERROR:Invalid join format");
        return;
    }
    
    if (new_channel < 0 || new_channel >= MAX_CHANNELS) {
        send_to_client(client, "ERROR:Invalid channel ID");
        return;
    }
    
    // Check channel password
    if (is_channel_protected(new_channel)) {
        if (!verify_channel_password(new_channel, password)) {
            send_to_client(client, "ERROR:Invalid channel password");
            
            char log_msg[256];
            snprintf(log_msg, 256, "SECURITY: Failed channel password for %04d by %s", 
                     new_channel, client->ip_address);
            add_log(log_msg);
            return;
        }
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
    
    // Check rate limit
    int rate_check = check_rate_limit(client);
    if (rate_check <= 0) {
        return; // Rate limited
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
    
    // If authentication is required, wait for AUTH command first
    if (server.require_auth) {
        send_to_client(client, "AUTH:REQUIRED");
    } else {
        client->authenticated = 1;
    }
    
    while (server.running && server.server_active && client->active) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes = recv(client->socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes <= 0) {
            break;
        }
        
        buffer[bytes] = '\0';
        
        // Handle AUTH command
        if (strncmp(buffer, "AUTH:", 5) == 0) {
            int result = handle_auth(client, buffer + 5);
            if (result == -1) {
                break; // Disconnect due to too many failed attempts
            }
            continue;
        }
        
        // Check if authenticated before allowing other commands
        if (server.require_auth && !client->authenticated) {
            send_to_client(client, "ERROR:Authentication required");
            continue;
        }
        
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
        
        char *client_ip = inet_ntoa(client_addr.sin_addr);
        
        // Check if IP is banned
        if (is_ip_banned(client_ip)) {
            send(client_sock, "ERROR:You are banned from this server", 38, 0);
            closesocket(client_sock);
            
            char log_msg[256];
            snprintf(log_msg, 256, "SECURITY: Banned IP %s attempted connection", client_ip);
            add_log(log_msg);
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
        strcpy(server.clients[slot].ip_address, client_ip);
        server.clients[slot].port = ntohs(client_addr.sin_port);
        server.clients[slot].username[0] = '\0';
        
        // Initialize security fields
        server.clients[slot].authenticated = 0;
        server.clients[slot].message_count = 0;
        server.clients[slot].rate_limit_start = time(NULL);
        server.clients[slot].failed_auth_attempts = 0;
        
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
    InitializeCriticalSection(&server.ban_lock);
    InitializeCriticalSection(&server.channel_lock);
    
    server.running = 1;
    server.server_active = 0;
    server.next_client_id = 0;
    server.start_time = time(NULL);
    server.server_port = 8888;
    server.listen_socket = INVALID_SOCKET;
    server.require_auth = 0;
    server.banned_ip_count = 0;
    
    get_local_ipv4(server.server_ip);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        server.clients[i].active = 0;
        server.clients[i].socket = INVALID_SOCKET;
        server.clients[i].channel_id = -1;
        server.clients[i].authenticated = 0;
        server.clients[i].message_count = 0;
        server.clients[i].failed_auth_attempts = 0;
    }
    
    for (int i = 0; i < MAX_CHANNELS; i++) {
        server.channel_passwords[i].password_protected = 0;
        server.channel_passwords[i].password[0] = '\0';
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
    // filepath: c:\VSC-Foler\tcp_chat_server.c
    if (server.log_file) {
        fprintf(server.log_file, "\n==========================================\n");
        fprintf(server.log_file, "Server shutdown at %s", ctime(&(time_t){time(NULL)}));
        fprintf(server.log_file, "==========================================\n");
        fclose(server.log_file);
        server.log_file = NULL;
    }
    
    DeleteCriticalSection(&server.lock);
    DeleteCriticalSection(&server.log_lock);
    DeleteCriticalSection(&server.ban_lock);
    DeleteCriticalSection(&server.channel_lock);
}

int main() {
    SetConsoleTitle("TCP Chat Server v4.0 - Security Edition");
    
    initialize_server();
    
    add_log("Application started");
    
    while (server.running) {
        draw_main_menu();
        
        char ch = _getch();
        
        switch (ch) {
            case '1':
                while (1) {
                    draw_logs_menu();
                    char c = _getch();
                    if (c == 'b' || c == 'B') break;
                }
                break;
                
            case '2':
                while (1) {
                    draw_users_menu();
                    char c = _getch();
                    if (c == 'b' || c == 'B') break;
                    Sleep(1000);
                }
                break;
                
            case '3':
                while (1) {
                    draw_channels_menu();
                    char c = _getch();
                    if (c == 'b' || c == 'B') break;
                    Sleep(1000);
                }
                break;
                
            case '4':
                handle_logfile_menu();
                break;
                
            case '5':
                if (server.server_active) {
                    stop_server();
                } else {
                    start_server();
                }
                break;
                
            case '6':
                handle_security_menu();
                break;
                
            case '7':
                handle_ban_menu();
                break;
                
            case 'q':
            case 'Q':
                set_color(14);
                printf("\n\n  Are you sure you want to quit? (Y/N): ");
                set_color(7);
                char confirm = _getch();
                if (confirm == 'y' || confirm == 'Y') {
                    server.running = 0;
                    add_log("Application shutdown requested");
                }
                break;
        }
    }
    
    cleanup_server();
    
    clear_screen();
    set_color(10);
    printf("\n  Server shutdown complete. Goodbye!\n\n");
    set_color(7);
    
    return 0;
}
