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

struct TrackedProcess {
  std::wstring name;
  RM_UNIQUE_PROCESS id;
  HANDLE process;
  HANDLE logfile;

  TrackedProcess(const wchar_t* name, RM_UNIQUE_PROCESS id, HANDLE ph)
      : name(name), id(id), process(ph), logfile(INVALID_HANDLE_VALUE) {
  }

  ~TrackedProcess() {
    ::CloseHandle(process);
    ::CloseHandle(logfile);
  }
};

typedef std::unique_ptr<TrackedProcess> TrackedPtr;

bool GetProcesses(DWORD session_id,
                  std::vector<TrackedPtr>& tracked) {
  DWORD reason = 0;
  UINT n_needed = 0;
  RM_PROCESS_INFO rmpi[64];
  UINT n_rmpi = _countof(rmpi);
  Verify(::RmGetList(session_id, &n_needed,
                     &n_rmpi, rmpi, &reason), ERROR_SUCCESS);

  size_t process_count = 0;

  for (size_t ix = 0; ix != n_rmpi; ++ix) {
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
      //$$ log the event.
      continue;
    }

    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (::GetProcessTimes(handle, &ftCreate, &ftExit, &ftKernel, &ftUser) &&
       (::CompareFileTime(&up.ProcessStartTime, &ftCreate) == 0)) {
        ++process_count; 
        tracked.push_back(TrackedPtr(new TrackedProcess(rmpi[ix].strAppName,
                                                        rmpi[ix].Process,
                                                        handle)));
    } else {
      ::CloseHandle(handle);
    }

  }
  return (process_count != 0);
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
    __debugbreak();
  }

  size_t used_vm = CalculateVMemusage(tracked->process);

  DWORD to_write = 0;
  DWORD written = 0;

  if (tracked->logfile == INVALID_HANDLE_VALUE) {
    SYSTEMTIME st;
    ::FileTimeToSystemTime(&tracked->id.ProcessStartTime, &st);
    wchar_t buff[512];
    wsprintf(buff, L"%s_%d_%.2d_%.2d_%.2d%.2d_%x.csv", tracked->name.c_str(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
        tracked->id.ProcessStartTime.dwLowDateTime);
    std::wstring path(dir);
    path.append(L"\\");
    path.append(buff);
    const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    tracked->logfile = ::CreateFileW(path.c_str(), GENERIC_ALL, share,
                                     NULL, CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (tracked->logfile == INVALID_HANDLE_VALUE) {
      // $$ log this.
      return false;
    }
    // Write header.
    std::stringstream hss;
    hss << "memtrack v1.0.1 ";
    hss << " p:" << tracked->id.dwProcessId;
    ULARGE_INTEGER ptime = { 
        tracked->id.ProcessStartTime.dwLowDateTime,
        tracked->id.ProcessStartTime.dwHighDateTime
    };
    hss << " t:" << ptime.QuadPart << "\n";
    hss << "cols: peak_ws, ws, priv\n";
    hss.flush();
    to_write = hss.str().size();
    ::WriteFile(tracked->logfile, hss.str().c_str(), to_write, &written, NULL);
  }

  std::stringstream oss;
  oss << ::GetTickCount64() << ": ";
  oss << pmcx.PeakWorkingSetSize / 1024 << ", ";
  oss << pmcx.WorkingSetSize / 1024 << ", ";
  oss << pmcx.PrivateUsage / 1024 << ", ";
  oss << used_vm / 1024 << "\n";

  DWORD status = ::WaitForSingleObject(tracked->process, 0);
  bool still_alive = (WAIT_TIMEOUT == status);
  if (!still_alive) {
    DWORD ecode = 0;
    ::GetExitCodeProcess(tracked->process, &ecode);
    oss << "exit, rc=" << std::hex << ecode << "\n";
  }

  oss.flush();
  to_write = oss.str().size();
  if (!::WriteFile(tracked->logfile, oss.str().c_str(), to_write, &written, NULL)) {
    return false;
  }

  return still_alive;
}

int __stdcall wWinMain(HINSTANCE module, HINSTANCE, wchar_t* cc, int) {

  if (__argc < 3) {
    return 1;
  }

  const wchar_t* bin_to_track = __wargv[1];
  const wchar_t* dir_for_logs = __wargv[2];

  DWORD session_id = 0;
  wchar_t session_key[CCH_RM_SESSION_KEY + 1] = { 0 };

  std::vector<TrackedPtr> tracked;
  DWORD sleep_interval = 200;

  while (true) {

    Verify(::RmStartSession(&session_id, 0, session_key), ERROR_SUCCESS);

    Verify(::RmRegisterResources(session_id, 1, &bin_to_track,
                                 0, NULL, 0, NULL), ERROR_SUCCESS);
    size_t big_loop_count = 300;

    while (big_loop_count) {
      GetProcesses(session_id, tracked);
      if (tracked.empty()) {
        sleep_interval = 3000;
        --big_loop_count;
      } else {
        for (auto it = begin(tracked); it != end(tracked);) {
          if (!LogMemUsage(dir_for_logs, it->get()))
            it = tracked.erase(it);
          else
            ++it;
        }
        sleep_interval = 500;
      }
      ::Sleep(sleep_interval);
    }

    // We need to close the restart session every 15 minutes because it leaks
    // process handles and accumulates processes (with status != RmStatusRunning) 
    // which is very confusing for the code.
    ::RmEndSession(session_id);
    ::Sleep(4000);
  }
 
  return 0;
}
