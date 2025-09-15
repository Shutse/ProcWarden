#include "ProcWarden.h"

bool ProcWarden::update() {
	if (getProcList()) {

	}
	return true;
}

bool ProcWarden::getProcList() {
	HANDLE ProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if (ProcSnapshot == INVALID_HANDLE_VALUE)
	{
		std::cerr << "WARN: Can't get proc list." << std::endl;
		return false;
	}

	PROCESSENTRY32 ProcPtr;
	ProcPtr.dwSize = sizeof(PROCESSENTRY32);
	std::time_t time = getTime();
	char strTime[26];
	ctime_s(strTime, sizeof(strTime), &time);
	strTime[13] = '-';
	strTime[16] = '-';
	strTime[24] = 0;
	std::ofstream file(strTime, std::ios::out | std::ios::trunc);

	if (!file.is_open())
	{
		std::cerr << "WARN: Can't create/open log file. Err code: " << GetLastError() << std::endl;
		return false;
	}

	if (Process32First(ProcSnapshot, &ProcPtr)) {
		do {
			FILETIME procBirth;
			FILETIME procDeath;
			FILETIME procKernelTime;
			FILETIME procUserTime;
			SYSTEMTIME sysBirth;
			SYSTEMTIME sysDeath;
			SYSTEMTIME sysLocalBirth;
			SYSTEMTIME sysLocalDeath;
			char procName[256];
			DWORD nameSize = 256;
			PROCESS_MEMORY_COUNTERS RAM;

			HANDLE Proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, ProcPtr.th32ProcessID);

			if (!Proc) {
				continue;
			}

			if (GetProcessTimes(Proc, &procBirth, &procDeath, &procKernelTime, &procUserTime)) {
				FileTimeToSystemTime(&procBirth, &sysBirth);
				FileTimeToSystemTime(&procDeath, &sysDeath);
				SystemTimeToTzSpecificLocalTime(NULL, &sysBirth, &sysLocalBirth);
				SystemTimeToTzSpecificLocalTime(NULL, &sysDeath, &sysLocalDeath);
			}
			else {
				std::cerr << "WARN: " << GetLastError() << std::endl;
			}

			if (!GetProcessMemoryInfo(Proc, &RAM, sizeof(RAM)))
			{
				std::cerr << "WARN: Can't get RAM info. " << GetLastError() << std::endl;
			}

			ULARGE_INTEGER kernelTime = ToULI(procKernelTime);
			ULARGE_INTEGER userTime = ToULI(procUserTime);

			if (!QueryFullProcessImageNameA(Proc, NULL, procName, &nameSize)) 
			{
				std::cerr << "WARN: " << GetLastError() << std::endl;
			}

			file << procName << " " << ProcPtr.cntThreads << " " << ProcPtr.pcPriClassBase << " " 
				 << kernelTime.QuadPart << " " << userTime.QuadPart << " " << RAM.PagefileUsage 
			 	 << " " << RAM.PageFaultCount << " " << RAM.PageFaultCount << RAM.QuotaPagedPoolUsage << " "
			 	 << RAM.QuotaNonPagedPoolUsage << std::endl; // Name,Threads,Priority,kernTime,userTime,commitRAM,errCount,pagePool,nonPagePool

			CloseHandle(Proc);
		} while (Process32Next(ProcSnapshot, &ProcPtr));
	}

	file.close();
	CloseHandle(ProcSnapshot);
	return true;
}

ULARGE_INTEGER ProcWarden::ToULI(FILETIME var) {
	ULARGE_INTEGER result;
	
	result.LowPart = var.dwLowDateTime;
	result.HighPart = var.dwHighDateTime;
	
	return result;
}

std::time_t ProcWarden::getTime() {
	auto now = std::chrono::system_clock::now();
	std::time_t t = std::chrono::system_clock::to_time_t(now); 
	
	return t;
}