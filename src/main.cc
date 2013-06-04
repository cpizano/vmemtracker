//  Copyright (c) 2013, Carlos Pizano (carlos.pizano@gmail.com)
//  All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met: 
//  
//  1. Redistributions of source code must retain the above copyright notice, this
//     list of conditions and the following disclaimer. 
//  2. Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution. 
//  
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
//  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//  
//  The views and conclusions contained in the software and documentation are those
//  of the authors and should not be interpreted as representing official policies, 
//  either expressed or implied, of the FreeBSD Project.

// main.cc: this is the entire vmemtracker application, which tracks
// a set of binaries use of memory across time, generating log files
// in csv format.

#include <Windows.h>
#include <Psapi.h>
#include <winioctl.h>
#include <RestartManager.h>

#include <stdlib.h>
#include <algorithm>
#include <string>
#include <vector>
#include <memory>
#include <sstream>

#pragma comment(lib,"rstrtmgr.lib")

template <typename T, typename U>
bool Verify(T actual, U success) {
  if (actual == success)
    return true;

  volatile ULONG err = ::GetLastError();
  if (::IsDebuggerPresent()) {
    __debugbreak();
  } else {
    ::ExitProcess(1);
  }
  __assume(0);
}

template <class string_type>
inline typename string_type::value_type* WriteInto(string_type* str,
                                                   size_t length_with_null) {
  if (length_with_null < 2)
    __debugbreak();
  str->reserve(length_with_null);
  str->resize(length_with_null - 1);
  return &((*str)[0]);
}

std::wstring MakeFileName(const SYSTEMTIME& st, const wchar_t* name, DWORD lotime) {
  std::wstring result;
  wsprintf(WriteInto(&result, 512), L"%s_%d_%02d_%02d_%02d%02d_%x.csv", name,
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, lotime);
  return result;
}

std::string PrettyPrintTime(const SYSTEMTIME& st) {
  std::string result_date;
  int size = GetDateFormatA(LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, NULL, NULL, 0) + 1;
  GetDateFormatA(LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, NULL, WriteInto(&result_date, size), size);
  result_date.append(" ");
  std::string result_time;
  size = GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, NULL, 0) + 1;
  GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, WriteInto(&result_time, size), size);
  return result_date + result_time;
}

BOOL WriteStringStream(HANDLE file, std::stringstream& ss) {
  ss.flush();
  DWORD to_write = ss.str().size();
  DWORD written;
  return ::WriteFile(file, ss.str().c_str(), to_write, &written, NULL);
}

void LogEvent(const char* str1, const char* str2, size_t extra1, size_t extra2) {
  static HANDLE file = INVALID_HANDLE_VALUE;

  if (file == INVALID_HANDLE_VALUE) {
    FILETIME ct, et, kt, ut;
    ::GetProcessTimes(::GetCurrentProcess(), &ct, &et, &kt, &ut);
    std::wstring path(reinterpret_cast<const wchar_t*>(str1));
    path.append(L"\\");

    SYSTEMTIME st = {0};
    if (!::FileTimeToSystemTime(&ct, &st))
      __debugbreak();

    path.append(MakeFileName(st, L"vmemtracker_", ct.dwLowDateTime));
    const DWORD share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    file = ::CreateFileW(path.c_str(), GENERIC_WRITE, share_mode,
                         NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
      __debugbreak();

    std::stringstream hss;
    hss << "vmemtrack event log";
    hss << " p(" << ::GetCurrentProcessId() << ") ";
    hss << " t(" << PrettyPrintTime(st) << ")";

    std::string machine_name;
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    ::GetComputerNameA(WriteInto(&machine_name, size ), &size);
    hss << " m(" << machine_name << ")\n";
    WriteStringStream(file, hss);
    return;
  }

  std::stringstream oss;
  oss << ::GetTickCount64() << ", " << str1 << ", ";
  if (str2)
    oss << str2;
  oss << extra1 << ", " << std::hex << extra2 << "\n";
  WriteStringStream(file, oss);
}

struct TrackedProcess {
  std::wstring name;
  RM_UNIQUE_PROCESS id;
  HANDLE process;
  HANDLE logfile;
  bool alarm_vm;
  bool alarm_ws;

  TrackedProcess(const wchar_t* name, RM_UNIQUE_PROCESS id, HANDLE ph)
      : name(name), id(id), process(ph),
        logfile(INVALID_HANDLE_VALUE), alarm_vm(false), alarm_ws(false) {
  }

  ~TrackedProcess() {
    ::CloseHandle(process);
    ::CloseHandle(logfile);
  }
};

typedef std::unique_ptr<TrackedProcess> TrackedPtr;

void GetProcesses(DWORD session_id,
                  std::vector<TrackedPtr>& tracked) {
  DWORD reason = 0;
  UINT n_needed = 0;
  RM_PROCESS_INFO rmpi[64];
  UINT n_rmpi = _countof(rmpi);
  Verify(::RmGetList(session_id, &n_needed,
                     &n_rmpi, rmpi, &reason), ERROR_SUCCESS);

  for (size_t ix = 0; ix != n_rmpi; ++ix) {
    // Ignore dead and unnamed processes. Unnamed processes can be services
    // which can be very hard to track, memory-wise.
    if (rmpi[ix].AppStatus != RmStatusRunning)
      continue;
    if (rmpi[ix].strAppName[0] == 0)
      continue;

    const RM_UNIQUE_PROCESS up = rmpi[ix].Process;
    if (up.dwProcessId == ::GetCurrentProcessId())
      continue;

    auto it = std::find_if(begin(tracked), end(tracked),
        [&up](TrackedPtr& e) {
            return (e->id.dwProcessId == up.dwProcessId) &&
                   (::CompareFileTime(&up.ProcessStartTime,
                                      &e->id.ProcessStartTime) == 0);
        }
    );

    if (it != tracked.end()) {
      continue;
    }

    // An aplication (not a service) not seen before has the file open.
    HANDLE handle = ::OpenProcess(PROCESS_QUERY_INFORMATION |
                                  PROCESS_VM_READ | SYNCHRONIZE,
                                  FALSE, up.dwProcessId);
    if (!handle) {
      LogEvent("OpenProcess error", nullptr, up.dwProcessId, ::GetLastError());
      continue;
    }

    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (::GetProcessTimes(handle, &ftCreate, &ftExit, &ftKernel, &ftUser) &&
       (::CompareFileTime(&up.ProcessStartTime, &ftCreate) == 0)) {
        tracked.push_back(TrackedPtr(new TrackedProcess(rmpi[ix].strAppName,
                                                        rmpi[ix].Process,
                                                        handle)));
        LogEvent("tracking start", nullptr, up.dwProcessId,
                 up.ProcessStartTime.dwLowDateTime); 
    } else {
      ::CloseHandle(handle);
    }

  }
}

size_t CalculateVMemusage(HANDLE process) {
  size_t used = 0;
  char* address = 0;
  char* oldaddr = 0;
  MEMORY_BASIC_INFORMATION mbi;
  do {
    if (!::VirtualQueryEx(process, address, &mbi, sizeof(mbi)))
      break;
    if (mbi.State != MEM_FREE)
      used += mbi.RegionSize;
    oldaddr = address;
    address = reinterpret_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
  } while (address > oldaddr);

  return used;
}

bool LogMemUsage(const wchar_t* dir, TrackedProcess* tracked) {

  PROCESS_MEMORY_COUNTERS_EX pmcx = {sizeof(pmcx)};
  if (!::GetProcessMemoryInfo(tracked->process, 
                              reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmcx),
                              sizeof(pmcx))) {
    LogEvent("GetProcessMemoryInfo error", nullptr, tracked->id.dwProcessId, ::GetLastError());
    return false;
  }

  size_t used_vm = CalculateVMemusage(tracked->process);

  if (tracked->logfile == INVALID_HANDLE_VALUE) {

    SYSTEMTIME st = {0};
    if (!::FileTimeToSystemTime(&tracked->id.ProcessStartTime, &st))
      __debugbreak();

    std::wstring path(dir);
    path.append(L"\\");
    path.append(MakeFileName(st, tracked->name.c_str(), tracked->id.ProcessStartTime.dwLowDateTime));
    const DWORD share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    tracked->logfile = ::CreateFileW(path.c_str(), GENERIC_WRITE, share_mode,
                                     NULL, CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (tracked->logfile == INVALID_HANDLE_VALUE) {
      LogEvent("fileIO creation error", nullptr, tracked->id.dwProcessId, ::GetLastError()); 
      return false;
    }
    // Write header.
    std::stringstream hss;
    hss << "memtrack v1.0.1 ";
    hss << " p(" << tracked->id.dwProcessId << ") ";
    hss << " t(" << PrettyPrintTime(st) << ")\n";
    hss << "tickcount, peak_working_set, current_working_set, private_mem, virtual_memory\n";
    if (!WriteStringStream(tracked->logfile, hss)) {
      LogEvent("fileIO write error", nullptr, tracked->id.dwProcessId, ::GetLastError());
      return false;
    }
  }

  std::stringstream oss;
  oss << ::GetTickCount64() << ", ";
  oss << pmcx.PeakWorkingSetSize / 1024 << ", ";
  oss << pmcx.WorkingSetSize / 1024 << ", ";
  oss << pmcx.PrivateUsage / 1024 << ", ";
  oss << used_vm / 1024 << "\n";

  if ((tracked->alarm_ws == false) &&
      pmcx.WorkingSetSize > (1024 * 1024 * 1024)) {
    tracked->alarm_ws = true;
    LogEvent("high workingset", nullptr,  tracked->id.dwProcessId,
                                          tracked->id.ProcessStartTime.dwLowDateTime);
  }

  if ((tracked->alarm_vm == false) &&
      used_vm > (512 * 1024 * 1024 * 3)) {
    tracked->alarm_vm = true;
    LogEvent("high virtualmem", nullptr,  tracked->id.dwProcessId,
                                          tracked->id.ProcessStartTime.dwLowDateTime);
  }

  DWORD status = ::WaitForSingleObject(tracked->process, 0);
  bool still_alive = (WAIT_TIMEOUT == status);
  if (!still_alive) {
    DWORD ecode = 0;
    ::GetExitCodeProcess(tracked->process, &ecode);
    LogEvent("tracking end", nullptr, tracked->id.dwProcessId, ecode);
    oss << "exit, rc=" << std::hex << ecode << "\n";
  }

  WriteStringStream(tracked->logfile, oss);
  return still_alive;
}

int __stdcall wWinMain(HINSTANCE module, HINSTANCE, wchar_t* cc, int) {

  if (__argc != 3) {
    wprintf(L"tracks memory usage of processes spawned for a particular binary\n"\
            L"logging the memmory usage on csv files\n"
            L"usage: vmemtracker <path_for_logs> <path_to_binary_to_track>\n\n");
    return 1;
  }

  const wchar_t* dir_for_logs = __wargv[1];
  const wchar_t* bin_to_track = __wargv[2];

  const DWORD kLongInterval =  4000;
  const DWORD kShortInterval = 1000;

  DWORD session_id = 0;
  wchar_t session_key[CCH_RM_SESSION_KEY + 1] = { 0 };

  std::vector<TrackedPtr> tracked;
  DWORD sleep_interval = 200;
  size_t max_count = 0;

  LogEvent(reinterpret_cast<const char*>(dir_for_logs), nullptr, 0, 0);

  while (true) {
    Verify(::RmStartSession(&session_id, 0, session_key), ERROR_SUCCESS);
    Verify(::RmRegisterResources(session_id, 1, &bin_to_track,
                                 0, NULL, 0, NULL), ERROR_SUCCESS);
    size_t big_loop_count = 300;

    LogEvent("big loop", nullptr, session_id, max_count);

    while (big_loop_count) {
      GetProcesses(session_id, tracked);
      if (tracked.empty()) {
        sleep_interval = kLongInterval;
        --big_loop_count;
      } else {
        max_count = max(tracked.size(), max_count);
        for (auto it = begin(tracked); it != end(tracked);) {
          if (!LogMemUsage(dir_for_logs, it->get()))
            it = tracked.erase(it);
          else
            ++it;
        }
        sleep_interval = kShortInterval;
      }
      ::Sleep(sleep_interval);
    }

    // We need to close the restart session every so often because it leaks
    // process handles and accumulates processes (with status != RmStatusRunning) 
    // which is very confusing for the code.
    ::RmEndSession(session_id);
    ::Sleep(kShortInterval * 2);
  }
 
  return 0;
}
