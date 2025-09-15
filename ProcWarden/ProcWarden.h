#pragma once
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <chrono>
#include <ctime>
#include <string>
#include <psapi.h>

class ProcWarden {
public:
	bool update();
	bool getProcList();
	std::time_t getTime();
	ULARGE_INTEGER ToULI(FILETIME var);
};