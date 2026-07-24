#pragma once
#include <Windows.h>
#include <winternl.h>

namespace antidebug {

bool PatchPeb();
bool PatchHeapFlags();
bool PatchNtQueryInfo();
bool PatchNtRaiseHardError();
bool PatchNtTerminateProcess();
bool ClearHardwareBreakpoints();
bool InstallVehHandler();
bool RemoveVehHandler();
void RemoveAll();

}
