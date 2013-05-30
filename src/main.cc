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

extern "C" IMAGE_DOS_HEADER __ImageBase;

HINSTANCE ThisModule() {
  return reinterpret_cast<HINSTANCE>(&__ImageBase);
}

template <typename T, typename U>
T VerifyNot(T actual, U error) {
  if (actual != error)
    return actual;

  volatile ULONG err = ::GetLastError();
  if (::IsDebuggerPresent()) {
    __debugbreak();
  } else {
    ::ExitProcess(1);
  }
  __assume(0);
}

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

bool WaitForFileAccess(const wchar_t* bin_to_track) {
  OVERLAPPED ov = {0};
  ov.hEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);

  HANDLE file = CreateFileW(bin_to_track, GENERIC_READ, FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }

  REQUEST_OPLOCK_INPUT_BUFFER ibuff = {
    REQUEST_OPLOCK_CURRENT_VERSION,
    sizeof(ibuff),
    OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE,
    REQUEST_OPLOCK_INPUT_FLAG_REQUEST,
  };

  REQUEST_OPLOCK_OUTPUT_BUFFER obuff = {
    REQUEST_OPLOCK_CURRENT_VERSION,
    sizeof(obuff),
  };

  ::DeviceIoControl(file, FSCTL_REQUEST_OPLOCK,
                    &ibuff, sizeof(ibuff),
                    &obuff, sizeof(obuff),
                    nullptr, &ov);
  if (GetLastError() != ERROR_IO_PENDING) {
    return false;
  }

  DWORD bytes = 0;
  if (!GetOverlappedResult(file, &ov, &bytes, TRUE)) {
    return false;
  }

  ::CloseHandle(file);
  ::CloseHandle(ov.hEvent);
  return true;
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

  for (size_t ix = 0; ix != n_rmpi; ++n_rmpi) {
    const RM_UNIQUE_PROCESS up = rmpi[ix].Process;
    if (up.dwProcessId == ::GetCurrentProcessId())
      continue;
    if (rmpi[ix].strAppName[0] = 0)
      continue;

    // An aplication (not a service) has the file open.
    HANDLE handle = ::OpenProcess(PROCESS_QUERY_INFORMATION |
                                  PROCESS_VM_READ,
                                  FALSE, up.dwProcessId);
    if (!handle) {
      //$$ log the event.
      continue;
    }

    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (::GetProcessTimes(handle, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
      if (::CompareFileTime(&up.ProcessStartTime, &ftCreate) == 0) {
        // Process is still alive.
        ++process_count;

        auto it = std::find_if(begin(tracked), end(tracked),
            [&up](TrackedPtr& e) {
                return (e->id.dwProcessId == up.dwProcessId) &&
                       (::CompareFileTime(&up.ProcessStartTime,
                                          &e->id.ProcessStartTime) == 0);
            }
        );

        if (it == tracked.end()) {
          // Never seen this one before. Track it.
          tracked.push_back(TrackedPtr(new TrackedProcess(rmpi[ix].strAppName,
                                                          rmpi[ix].Process,
                                                          handle)));
          continue;
        }
      }
    }
    ::CloseHandle(handle);
  }
  return (process_count != 0);
}

bool LogMemUsage(const wchar_t* dir, TrackedProcess* tracked) {
  PROCESS_MEMORY_COUNTERS_EX pmcx = {sizeof(pmcx)};
  if (::GetProcessMemoryInfo(tracked->process, 
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmcx),
                             sizeof(pmcx)) == FALSE) {
    __debugbreak();
  }

  ULONGLONG time = ::GetTickCount64();
  DWORD to_write = 0;
  DWORD written = 0;
  std::stringstream oss;

  if (tracked->logfile == INVALID_HANDLE_VALUE) {
    SYSTEMTIME st;
    ::FileTimeToSystemTime(&tracked->id.ProcessStartTime, &st);
    wchar_t buff[512];
    wsprintf(buff, L"%s_%d_%.2d_%.2d_%.2d%.2d", tracked->name.c_str(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    std::wstring path(dir);
    path.append(L"\\");
    path.append(buff);
    DWORD share = FILE_SHARE_READ | FILE_SHARE_DELETE;
    tracked->logfile = ::CreateFileW(path.c_str(), GENERIC_ALL, share,
                                     NULL, CREATE_ALWAYS, 0, NULL);
    if (tracked->logfile == INVALID_HANDLE_VALUE) {
      // $$ log this.
      return false;
    }
    // Write header.

    oss << "memtrack v1.0.0," << time << "\n";
    oss << tracked->name.c_str() << "," << tracked->id.dwProcessId;
    oss << tracked->id.ProcessStartTime.dwHighDateTime << ".";
    oss << tracked->id.ProcessStartTime.dwLowDateTime << "\n";
    oss.flush();
    to_write = oss.str().size();
    ::WriteFile(tracked->logfile, oss.str().c_str(), to_write, &written, NULL);
  }

  oss << ::GetTickCount64() << ",";
  oss << pmcx.PeakWorkingSetSize << L"," << pmcx.WorkingSetSize << L",";
  oss << pmcx.PrivateUsage << L"\n";

  oss.flush();
  to_write = oss.str().size();
  if (!::WriteFile(tracked->logfile, oss.str().c_str(), to_write, &written, NULL)) {
    return false;
  }

  DWORD ecode = 0;
  ::GetExitCodeProcess(tracked->process, &ecode);
  ::Sleep(1);
  return true;
}

int __stdcall wWinMain(HINSTANCE module, HINSTANCE, wchar_t* cc, int) {

  if (__argc < 3) {
    return 1;
  }

  const wchar_t* bin_to_track = __wargv[1];
  const wchar_t* dir_for_logs = __wargv[2];

  // Restart manager initialization.
  ULONGLONG start = ::GetTickCount64();

  DWORD session_id = 0;
  wchar_t session_key[CCH_RM_SESSION_KEY + 1] = { 0 };
  Verify(::RmStartSession(&session_id, 0, session_key), ERROR_SUCCESS);

  Verify(::RmRegisterResources(session_id, 1, &bin_to_track,
                               0, NULL, 0, NULL), ERROR_SUCCESS);

  std::vector<TrackedPtr> tracked;
  UINT timer = ::SetTimer(NULL, 666, 200, NULL); 

  MSG msg = {0};
  while (::GetMessageW(&msg, NULL, 0, 0)) {

    if (msg.message == WM_TIMER) {
      GetProcesses(session_id, tracked);
      if (tracked.empty()) {
        Verify(::KillTimer(NULL, timer), TRUE);
        timer = ::SetTimer(NULL, 666, 3000, NULL);
      } else {

        for (auto it = begin(tracked); it != end(tracked); ++it) {
          if (!LogMemUsage(dir_for_logs, it->get())) {
            it = tracked.erase(it);
          }
        }
        
        Verify(::KillTimer(NULL, timer), TRUE);
        timer = ::SetTimer(NULL, 666, 500, NULL);
      }
    }

    ::DispatchMessageW(&msg);
  }



 
  return 0;
}
