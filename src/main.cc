#include <Windows.h>
#include <winioctl.h>
#include <RestartManager.h>
#include <stdlib.h>
#include <string>
#include <map>

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
      : name(name), id(id), process(ph), logfile(NULL) {
  }
  TrackedProcess()
      : name(name), id(), process(NULL), logfile(NULL) {
  }
};

bool GetProcesses(DWORD session_id,
                  std::map<UINT, TrackedProcess>& tracked_map) {
  DWORD reason = 0;
  UINT n_needed = 0;
  RM_PROCESS_INFO rmpi[64];
  UINT n_rmpi = _countof(rmpi);
  Verify(::RmGetList(session_id, &n_needed,
                     &n_rmpi, rmpi, &reason), ERROR_SUCCESS);

  size_t watched_count = 0;

  for (size_t ix = 0; ix != n_rmpi; ++n_rmpi) {
    const RM_UNIQUE_PROCESS up = rmpi[ix].Process;
    if (up.dwProcessId == ::GetCurrentProcessId())
      continue;
    // Someone has the file open.
    HANDLE process = ::OpenProcess(PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_READ,
                                   FALSE, up.dwProcessId);
    if (process) {
      FILETIME ftCreate, ftExit, ftKernel, ftUser;
      if (::GetProcessTimes(process, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
        if (::CompareFileTime(&up.ProcessStartTime, &ftCreate) == 0) {
          // Process is still alive.
          TrackedProcess& tp = tracked_map[up.dwProcessId];
          if (!tp.process) {
            tp = TrackedProcess();
            continue;
          }

          if (::CompareFileTime(&up.ProcessStartTime, &tp.id.ProcessStartTime) == 0) {

          }
  
          ++watched_count;
        }
      }
      ::CloseHandle(process);
    }
  }
  return (watched_count != 0);
}

int __stdcall wWinMain(HINSTANCE module, HINSTANCE, wchar_t* cc, int) {

  if (__argc < 2) {
    return 1;
  }

  const wchar_t* bin_to_track = __wargv[1];

  // Restart manager initialization.

  DWORD session_id = 0;
  wchar_t session_key[CCH_RM_SESSION_KEY + 1] = { 0 };
  Verify(::RmStartSession(&session_id, 0, session_key), ERROR_SUCCESS);

  Verify(::RmRegisterResources(session_id, 1, &bin_to_track,
                               0, NULL, 0, NULL), ERROR_SUCCESS);


  ::SetTimer(NULL, 666, 500, NULL); 
  std::map<UINT, TrackedProcess> tracked_map;


  MSG msg = {0};
  while (::GetMessageW(&msg, NULL, 0, 0)) {

    if (msg.message == WM_TIMER) {
      if (tracked_map.empty()) {
        if(!GetProcesses(session_id, tracked_map))
          ::SetTimer(NULL, 666, 3000, NULL);
      }
    }

    ::DispatchMessageW(&msg);
  }



 
  return 0;
}
