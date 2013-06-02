// vmemtest.cpp : Defines the entry point for the console application.
//

#include <SDKDDKVer.h>
#include <Windows.h>

#include <stdio.h>
#include <tchar.h>
#include <memory>
#include <vector>
#include <new>

int _tmain(int argc, _TCHAR* argv[]) {

  const size_t kMB_chunk = 16 * 1024 * 1024;
  const size_t kCount = 12;
  const size_t kSleep_ms = 3000;
  size_t loops = 60;
  
  wprintf(L"test program to use with vmemtracker\n"\
          L"this program just allocates memory in a seesaw pattern\n"\
          L"for %d loops of %d allocations of %d bytes\n",
          loops, kCount, kMB_chunk);

  typedef std::unique_ptr<char[]> scoped_mem;
  std::vector<scoped_mem> memory;

  while (loops) {
    size_t count = kCount;
    while (count) {
#if 0
      char* alloc = new (std::nothrow) char[kMB_chunk];
      if (!alloc) {
        wprintf(L"error: failed allocating %d\n", kMB_chunk);
        exit(1);
      }
      memory.push_back(scoped_mem(alloc));
#else
      DWORD at = (count%2) ?  MEM_RESERVE | MEM_COMMIT : MEM_RESERVE;
      void* p = ::VirtualAlloc(NULL, 64 * 1024, at, PAGE_READWRITE);
#endif
      wprintf(L".");
      _sleep(kSleep_ms);
      --count;
    }
    wprintf(L"\n- freeing %d bytes\n", kMB_chunk * kCount);
    memory.clear();
    --loops;
  }
  wprintf(L"done. exiting\n");

	return 0;
}

