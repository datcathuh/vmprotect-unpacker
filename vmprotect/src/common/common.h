#pragma once
#include <Windows.h>
#include <iostream>
#include <cstring>
#include <winternl.h>
#include <string>
#include <tlhelp32.h>
#include <cstdio>
#include <memory>
#include <psapi.h>
#include <fstream>
#include <vector>
#include <chrono>
#include <random>
#include <shellapi.h>

/* general stuff */
#include "../resources/resource.h"
#include "../utils/log.h"

/* string encryption & callstack spoofer */
#include "protect/enc.h"
#include "protect/spoof.h"

/* core implementation */
//#include "../core/pe/defs.h"
#include "../core/pe/pe.h"
#include "../core/pe/injection.h"


/* libs */
#pragma comment(lib, "ntdll.lib")