#pragma once
#include <iostream>
#include <cstdio>
#include <string>

inline void Log(const std::string& message) {
    std::cout << message << std::endl;
}

inline void LogF(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    std::cout << buf << std::endl;
}
