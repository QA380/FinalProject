# Final Project C Langguage

Requirement:
- Create a connection with TCP or UDP
- Support more than 2 users
- Text Interface with GUI as optional
- Programmed in C langguage 

# Note for future me :3
1. Simple messaging system, TCP connection, with LAN network only<br>
Using ws2_32 compiler low level langguage focused on network communication and socket management<br>
- gcc file_name.c -o app_name.exe -lws2_32<br>
add -liphlpapi for the server (IP detector)

2. Creating the UI in python and compile it into exe file<br>
To compile python into exe using PyInstaller
- pyinstaller --onefile --windowed --name="exe_name" file_name.py
