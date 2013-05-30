#include <Windows.h>
#include <winioctl.h>
#include <RestartManager.h>
#include <stdlib.h>

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


typedef LRESULT (* MsgCallBack)(HWND, WPARAM, LPARAM);
struct MessageHandler {
  UINT message;
  MsgCallBack callback;
};


HWND MakeWindow(const wchar_t* title, ULONG style, HWND parent, 
                HMENU menu, const SIZE& size, MessageHandler* handlers) {
  WNDCLASSEXW wcex = {sizeof(wcex)};
  wcex.hCursor = ::LoadCursorW(NULL, IDC_ARROW);
  wcex.hInstance = ThisModule();
  wcex.lpszClassName = __FILEW__;
  wcex.lpfnWndProc = [] (HWND window, UINT message,
                         WPARAM wparam, LPARAM lparam) -> LRESULT {
    static MessageHandler* s_handlers =
        reinterpret_cast<MessageHandler*>(lparam);
    size_t ix = 0;
    while (s_handlers[ix].message != -1) {
      if (s_handlers[ix].message == message)
        return s_handlers[ix].callback(window, wparam, lparam);
      ++ix;
    }

    return ::DefWindowProcW(window, message, wparam, lparam);
  };

  wcex.lpfnWndProc(NULL, 0, 0, reinterpret_cast<UINT_PTR>(handlers));
  ATOM atom = VerifyNot(::RegisterClassExW(&wcex), 0);
  int pos_def = CW_USEDEFAULT;
  return ::CreateWindowExW(0, MAKEINTATOM(atom), title, style,
                           pos_def, pos_def, size.cx, size.cy,
                           parent, menu, ThisModule(), NULL); 
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
  const wchar_t* name;
  UINT pid;
  HANDLE ph;

  TrackedProcess(const wchar_t* name, UINT pid, HANDLE ph)
      : name(name), pid(pid), ph(ph) {
  }
};

bool GetProcessesUsingResources(DWORD session_id) {
  DWORD reason = 0;
  UINT n_needed = 0;
  RM_PROCESS_INFO rmpi[64];
  UINT n_rmpi = _countof(rmpi);
  Verify(::RmGetList(session_id, &n_needed,
                     &n_rmpi, rmpi, &reason), ERROR_SUCCESS);

 if (n_rmpi) {
   // Somebody has the file open.
   for (size_t ix = 0; ix != n_rmpi; ++n_rmpi) {
     HANDLE process = ::OpenProcess(PROCESS_QUERY_INFORMATION |
                                    PROCESS_VM_READ,
                                    FALSE, rmpi[ix].Process.dwProcessId);
     if (process) {
        FILETIME ftCreate, ftExit, ftKernel, ftUser;
        if (::GetProcessTimes(process, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
          if (::CompareFileTime(&rmpi[ix].Process.ProcessStartTime, &ftCreate) == 0) {
            // Process is still alive.
          }
        }
        ::CloseHandle(process);
     }
   }
 } 
 return false;
}

int __stdcall wWinMain(HINSTANCE module, HINSTANCE, wchar_t* cc, int) {

  if (__argc < 2) {
    return 1;
  }

  const wchar_t* bin_to_track = __wargv[1];

  DWORD session_id = 0;
  wchar_t session_key[CCH_RM_SESSION_KEY + 1] = { 0 };
  Verify(::RmStartSession(&session_id, 0, session_key), ERROR_SUCCESS);

  Verify(::RmRegisterResources(session_id, 1, &bin_to_track,
                               0, NULL, 0, NULL), ERROR_SUCCESS);

  if (GetProcessesUsingResources(session_id)) {
  } else {
   WaitForFileAccess(bin_to_track);
  }
 
#if 0
  MessageHandler msg_handlers[] = {
    { WM_CLOSE, [] (HWND window, WPARAM, LPARAM) -> LRESULT {
      ::PostQuitMessage(0);
      return 0;
    }},

    { WM_ENDSESSION, [] (HWND window, WPARAM, LPARAM) -> LRESULT {
      ::PostQuitMessage(0);
      return 0;
    }},

    {-1, NULL}
  };

  SIZE size = {200, 200};
  HWND main_window = VerifyNot(
    MakeWindow(L"vmt", 0, HWND_MESSAGE, NULL, size, msg_handlers), HWND(0));

  MSG msg = {0};
  while (::GetMessageW(&msg, NULL, 0, 0)) {
    ::DispatchMessageW(&msg);
  }
#endif


  return 0;
}
