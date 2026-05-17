@echo off
C:\msys64\msys2_shell.cmd -ucrt64 -defterm -no-start -here -c "gcc 'C:/Users/emili/OneDrive/Desktop/ID_LOGIN/backend/server.c' -o 'C:/Users/emili/OneDrive/Desktop/ID_LOGIN/backend/server.exe' -lws2_32 -O2" > backend\build_out.txt 2>&1
echo Exit: %ERRORLEVEL% >> backend\build_out.txt
