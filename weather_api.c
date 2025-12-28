#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>

//This code enables ANSI colors and UTF-8 in Windows console
#pragma comment(lib, "wininet.lib")

/* ANSI color codes for Windows */
#define RESET "\033[0m"
#define BOLD "\033[1m"
#define RED "\033[91m"
#define GREEN "\033[92m"
#define YELLOW "\033[93m"
#define BLUE "\033[94m"
#define MAGENTA "\033[95m"
#define CYAN "\033[96m"
#define WHITE "\033[97m"
#define BG_BLUE "\033[44m"
#define BG_CYAN "\033[46m"
#define BG_GRADIENT "\033[48;5;39m"

/* Weather emoji definitions */
#define EMOJI_SUN "☀️"
#define EMOJI_MOON "🌙"
#define EMOJI_CLOUD "☁️"
#define EMOJI_RAIN "🌧️"
#define EMOJI_SNOW "❄️"
#define EMOJI_SHOWER "🌦️"
#define EMOJI_THUNDER "⛈️"
#define EMOJI_FOG "🌫️"
#define EMOJI_THERMOMETER "🌡️"
#define EMOJI_DROPLET "💧"
#define EMOJI_WIND "💨"
#define EMOJI_PRESSURE "🔽"
#define EMOJI_LOCATION "📍"

/* Structure to hold weather data */
typedef struct {
    char temperature[32];
    char humidity[32];
    char wind_speed[32];
    char wind_direction[32];
    char weather_code[32];
    char is_day[32];
    char pressure_msl[32];
    char surface_pressure[32];
} WeatherData;

/* Clear console screen */
void clear_screen(void) {
    system("cls");
}

/* Get current time string */
void get_current_time(char *buffer, size_t size) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buffer, size, "%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
}

/* Enable ANSI colors and UTF-8 in Windows console */
void enable_console_features(void) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    
    /* Enable ANSI/VT100 escape sequences */
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
    
    /* Set console to UTF-8 for emoji support */
    SetConsoleOutputCP(CP_UTF8);
}

/* Download data from URL using WinINet */
char* download_from_url(const char *url) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    char *buffer = NULL;
    DWORD bytes_read = 0;
    DWORD total_size = 0;
    DWORD buffer_size = 8192;
    char temp_buffer[2048];
    
    /* Initialize WinINet */
    hInternet = InternetOpenA("WeatherStation/1.0", 
                             INTERNET_OPEN_TYPE_DIRECT, 
                             NULL, NULL, 0);
    
    if (!hInternet) {
        printf(RED "Error: Failed to initialize WinINet\n" RESET);
        return NULL;
    }
    
    /* Open URL connection */
    hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, 
                               INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    
    if (!hConnect) {
        printf(RED "Error: Failed to connect to API\n" RESET);
        InternetCloseHandle(hInternet);
        return NULL;
    }
    
    /* Allocate initial buffer */
    buffer = (char*)malloc(buffer_size);
    if (!buffer) {
        printf(RED "Error: Memory allocation failed\n" RESET);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return NULL;
    }
    
    /* Read data from URL */
    while (InternetReadFile(hConnect, temp_buffer, sizeof(temp_buffer) - 1, &bytes_read) 
           && bytes_read > 0) {
        
        /* Expand buffer if needed */
        if (total_size + bytes_read >= buffer_size) {
            buffer_size *= 2;
            char *new_buffer = (char*)realloc(buffer, buffer_size);
            if (!new_buffer) {
                free(buffer);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return NULL;
            }
            buffer = new_buffer;
        }
        
        /* Copy data to buffer */
        memcpy(buffer + total_size, temp_buffer, bytes_read);
        total_size += bytes_read;
    }
    
    /* Null terminate the buffer */
    if (buffer) {
        buffer[total_size] = '\0';
    }
    
    /* Cleanup */
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return buffer;
}

/* Extract value from simple JSON string */
char* extract_json_value(const char *json, const char *key) {
    char search_pattern[256];
    char *start = NULL;
    char *current_start = NULL;
    char *end = NULL;
    int len = 0;
    char *result = NULL;
    
    // /* Modify 1 to find value inside "current" object
    // */
    // current_start = strstr(json, "\"current\":");
    // if (!current_start){
    //     return NULL;
    // }

    // char *current_units_check = strstr(json, "\"current_units\":");
    // if (current_units_check && start < current_start) {

    //     start = strstr(current_start, search_pattern);
    //     if (!start) {
    //         return NULL;
    //     }
    // }






    /* Create search pattern */
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":", key);

    
    /* Find the key after "current" object starts
    Note: +391 is to skip the first "xxxxxx_2m" as there are two for some reason idk
    lowkey this is a simple solution lmao but it works
    */
    start = strstr(json+391, search_pattern);
    if (!start) {
        return NULL;
    }

    /* Move past the key */
    //modified to ensure we search within the "current" object
    start += strlen(search_pattern);
    
    /* Skip whitespace
    This function extracts the value associated with a given key from a simple JSON string.
    */
    while (*start == ' ' || *start == '\t' || *start == '\n') {
        start++;
    }
    
    /* Handle string values (quoted) */
    if (*start == '"') {
        start++;
        end = strchr(start, '"');
        if (!end) {
            return NULL;
        }
        
        len = (int)(end - start);
        result = (char*)malloc(len + 1);
        if (result) {
            strncpy(result, start, len);
            result[len] = '\0';
        }
        return result;
    }
    
    /* Handle numeric values (not quoted) */
    end = start;
    while (*end && *end != ',' && *end != '}' && *end != '\n' && *end != '\r') {
        end++;
    }
    
    len = (int)(end - start);
    result = (char*)malloc(len + 1);
    if (result) {
        strncpy(result, start, len);
        result[len] = '\0';
    }
    
    return result;
}

/* Get weather description from WMO weather code */
const char* get_weather_description(int code) {
    switch(code) {
        case 0: return "Clear sky";
        case 1: return "Mainly clear";
        case 2: return "Partly cloudy";
        case 3: return "Overcast";
        case 45: 
        case 48: return "Foggy";
        case 51: 
        case 53: 
        case 55: return "Drizzle";
        case 61: 
        case 63: 
        case 65: return "Rain";
        case 71: 
        case 73: 
        case 75: return "Snow fall";
        case 77: return "Snow grains";
        case 80: 
        case 81: 
        case 82: return "Rain showers";
        case 85: 
        case 86: return "Snow showers";
        case 95: return "Thunderstorm";
        case 96: 
        case 99: return "Thunderstorm with hail";
        default: return "Unknown condition";
    }
}

/* Get weather emoji based on WMO code and day/night */
const char* get_weather_emoji(int code, int is_day) {
    if (code == 0 || code == 1) {
        return is_day ? EMOJI_SUN : EMOJI_MOON;
    }
    if (code == 2 || code == 3) {
        return EMOJI_CLOUD;
    }
    if (code == 45 || code == 48) {
        return EMOJI_FOG;
    }
    if (code >= 51 && code <= 65) {
        return EMOJI_RAIN;
    }
    if (code >= 71 && code <= 77) {
        return EMOJI_SNOW;
    }
    if (code >= 80 && code <= 86) {
        return EMOJI_SHOWER;
    }
    if (code >= 95) {
        return EMOJI_THUNDER;
    }
    return EMOJI_THERMOMETER;
}

/* Convert wind direction in degrees to compass direction */
const char* get_wind_direction(int degrees) {
    if (degrees >= 337 || degrees < 23) return "North";
    if (degrees >= 23 && degrees < 68) return "Northeast";
    if (degrees >= 68 && degrees < 113) return "East";
    if (degrees >= 113 && degrees < 158) return "Southeast";
    if (degrees >= 158 && degrees < 203) return "South";
    if (degrees >= 203 && degrees < 248) return "Southwest";
    if (degrees >= 248 && degrees < 293) return "West";
    if (degrees >= 293 && degrees < 337) return "Northwest";
    return "North";
}

/* Print decorative header */
void print_header(void) {
    printf("\n");
    printf(BOLD BG_CYAN "                                                                " RESET "\n");
    printf(BOLD BG_CYAN "            " EMOJI_THERMOMETER " WEATHER INFORMATION SYSTEM " EMOJI_THERMOMETER "                " RESET "\n");
    printf(BOLD BG_CYAN "                      Taichung, Taiwan " EMOJI_LOCATION "                   " RESET "\n");
    printf(BOLD BG_CYAN "                                                                " RESET "\n");
    printf("\n");
}

/* Print decorative separator */
void print_separator(void) {
    printf(CYAN "================================================================\n" RESET);
}

/* Print weather information */
void display_weather(WeatherData *data) {
    int weather_code = 0;
    int is_day_val = 0;
    int wind_deg = 0;
    
    if (!data) {
        printf(RED "Error: No weather data available\n" RESET);
        return;
    }
    
    /* Parse weather code and day/night status */
    if (data->weather_code[0] != '\0') {
        weather_code = atoi(data->weather_code);
    }
    if (data->is_day[0] != '\0') {
        is_day_val = atoi(data->is_day);
    }
    if (data->wind_direction[0] != '\0') {
        wind_deg = atoi(data->wind_direction);
    }
    
    /* Print header */
    print_header();
    
    /* Current conditions */
    printf(BOLD YELLOW "  %s  %s\n" RESET, 
           get_weather_emoji(weather_code, is_day_val),
           get_weather_description(weather_code));
    
    printf(CYAN "  %s\n\n" RESET, is_day_val ? "☀ Daytime" : "🌙 Nighttime");
    
    print_separator();
    
    /* Temperature */
    if (data->temperature[0] != '\0') {
        printf(BOLD "\n  %s Temperature:\n" RESET, EMOJI_THERMOMETER);
        printf(YELLOW "     %s°C\n" RESET, data->temperature);
    }
    
    /* Humidity */
    if (data->humidity[0] != '\0') {
        printf(BOLD "\n  %s Humidity:\n" RESET, EMOJI_DROPLET);
        printf(CYAN "     %s%%\n" RESET, data->humidity);
    }
    
    /* Wind information */
    if (data->wind_speed[0] != '\0' && data->wind_direction[0] != '\0') {
        printf(BOLD "\n  %s Wind:\n" RESET, EMOJI_WIND);
        printf(GREEN "     Speed: %s km/h\n" RESET, data->wind_speed);
        printf(GREEN "     Direction: %s (%s°)\n" RESET, 
               get_wind_direction(wind_deg), data->wind_direction);
    }
    
    /* Pressure information */
    if (data->pressure_msl[0] != '\0' && data->surface_pressure[0] != '\0') {
        printf(BOLD "\n  %s Atmospheric Pressure:\n" RESET, EMOJI_PRESSURE);
        printf(MAGENTA "     Sea Level: %s hPa\n" RESET, data->pressure_msl);
        printf(MAGENTA "     Surface:   %s hPa\n" RESET, data->surface_pressure);
    }
    
    printf("\n");
    print_separator();
    printf("\n");
}

/* Parse JSON response into WeatherData structure */
int parse_weather_data(const char *json, WeatherData *data) {
    char *temp = NULL;
    
    if (!json || !data) {
        return 0;
    }
    
    /* Initialize all fields to empty strings */
    memset(data, 0, sizeof(WeatherData));
    
    /* Extract temperature */
    temp = extract_json_value(json, "temperature_2m");
    if (temp) {
        strncpy(data->temperature, temp, sizeof(data->temperature) - 1);
        free(temp);
    }
    
    /* Extract humidity */
    temp = extract_json_value(json, "relative_humidity_2m");
    if (temp) {
        strncpy(data->humidity, temp, sizeof(data->humidity) - 1);
        free(temp);
    }
    
    /* Extract wind speed */
    temp = extract_json_value(json, "wind_speed_10m");
    if (temp) {
        strncpy(data->wind_speed, temp, sizeof(data->wind_speed) - 1);
        free(temp);
    }
    
    /* Extract wind direction */
    temp = extract_json_value(json, "wind_direction_10m");
    if (temp) {
        strncpy(data->wind_direction, temp, sizeof(data->wind_direction) - 1);
        free(temp);
    }
    
    /* Extract weather code */
    temp = extract_json_value(json, "weather_code");
    if (temp) {
        strncpy(data->weather_code, temp, sizeof(data->weather_code) - 1);
        free(temp);
    }
    
    /* Extract day/night indicator */
    temp = extract_json_value(json, "is_day");
    if (temp) {
        strncpy(data->is_day, temp, sizeof(data->is_day) - 1);
        free(temp);
    }
    
    /* Extract sea level pressure */
    temp = extract_json_value(json, "pressure_msl");
    if (temp) {
        strncpy(data->pressure_msl, temp, sizeof(data->pressure_msl) - 1);
        free(temp);
    }
    
    /* Extract surface pressure */
    temp = extract_json_value(json, "surface_pressure");
    if (temp) {
        strncpy(data->surface_pressure, temp, sizeof(data->surface_pressure) - 1);
        free(temp);
    }
    
    return 1;
}

/* Clear console screen */
void clearScreen(void) {
    system("cls");
}

/* Main program */
int main(void) {
    const char *api_url = "https://api.open-meteo.com/v1/forecast?"
                         "latitude=24.1469&longitude=120.6839"
                         "&current=temperature_2m,relative_humidity_2m,"
                         "wind_speed_10m,wind_direction_10m,"
                         "pressure_msl,surface_pressure,is_day"
                         "&timezone=Asia%2FSingapore";
    
    char *json_response = NULL;
    WeatherData weather_data;
    char time_str[32];
    int update_interval = 60; /* seconds */
    int countdown = 0;
    
    /* Enable console features */
    enable_console_features();
    
    printf(BOLD CYAN "\n╔════════════════════════════════════════════════════════════════╗\n" RESET);
    printf(BOLD CYAN "║     🌤️  REAL-TIME WEATHER MONITORING SYSTEM 🌤️                ║\n" RESET);
    printf(BOLD CYAN "╚════════════════════════════════════════════════════════════════╝\n" RESET);
    printf(YELLOW "\n⚙️  Auto-refresh: Every %d seconds\n" RESET, update_interval);
    printf(GREEN "✓  Press Ctrl+C to exit\n\n" RESET);
    
    Sleep(2000); /* Wait 2 seconds before starting */
    
    /* Main update loop */
    while (1) {
        clear_screen();
        
        /* Get current time */
        get_current_time(time_str, sizeof(time_str));
        
        /* Show loading message */
        printf(YELLOW "🌐 Connecting to weather API...\n" RESET);
        printf(CYAN "📡 Fetching current weather data [%s]...\n\n" RESET, time_str);
        
        /* Download weather data */
        json_response = download_from_url(api_url);
        
        if (!json_response) {
            printf(RED "❌ Failed to fetch weather data from API\n" RESET);
            printf(YELLOW "⚠️  Retrying in %d seconds...\n" RESET, update_interval);
            
            /* Wait and retry */
            Sleep(update_interval * 1000);
            continue;
        }
        
        /* Parse the JSON response */
        if (!parse_weather_data(json_response, &weather_data)) {
            printf(RED "❌ Failed to parse weather data\n" RESET);
            free(json_response);
            
            /* Wait and retry */
            Sleep(update_interval * 1000);
            continue;
        }
        
        /* Display weather information */
        display_weather(&weather_data);
        
        /* Cleanup */
        free(json_response);
        json_response = NULL;
        
        /* Show update info */
        printf(GREEN "✓ Weather data updated successfully at %s\n" RESET, time_str);
        printf(CYAN "⏱️  Next update in: " RESET);
        
        /* Countdown timer */
        for (countdown = update_interval; countdown > 0; countdown--) {
            printf(BOLD YELLOW "%d seconds " RESET, countdown);
            fflush(stdout);
            Sleep(1000);
            
            /* Clear countdown line */
            printf("\r                                                \r");
            printf(CYAN "⏱️  Next update in: " RESET);
        }
        
        printf("\n");
    }
    
    return 0;
    printf("\n");
    scanf("");
}
