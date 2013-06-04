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

// vmemtest.cpp: Simple application that uses memory in predictable ways, it is
// meant to be used for manual testing memory trackers.

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
      // In this mode we allocate heap memory and then we free it.
      char* alloc = new (std::nothrow) char[kMB_chunk];
      if (!alloc) {
        wprintf(L"error: failed allocating %d\n", kMB_chunk);
        exit(1);
      }
      memory.push_back(scoped_mem(alloc));
      wprintf(L".");
#else
      // In this mode we allocate virtual memory, sometimes
      // commited and sometimes reserved and never free it.
      DWORD at = (count%2) ?  MEM_RESERVE | MEM_COMMIT : MEM_RESERVE;
      void* p = ::VirtualAlloc(NULL, 5 * 64 * 1024, at, PAGE_READWRITE);
      wprintf(L"+");
#endif
      ::Sleep(kSleep_ms);
      --count;
    }
    wprintf(L"\n- freeing %d bytes\n", kMB_chunk * kCount);
    memory.clear();
    --loops;
  }
  wprintf(L"done. exiting\n");

	return 0;
}

