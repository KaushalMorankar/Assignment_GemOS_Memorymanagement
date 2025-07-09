# GemOS Memory Management

A teaching‐operating‐system project implementing user‐space VM area management, lazy page allocation, and copy-on-write fork in GemOS.

## Features
1. **`mmap` / `munmap` / `mprotect`**  
   – Create, remove and change protection of VM areas (page‐aligned, merge/split, dummy head).  
2. **Lazy allocation**  
   – Page faults (`vm_area_pagefault`) allocate physical frames on first access.  
3. **Copy-on-Write fork (`cfork`)**  
   – Shared read‐only mappings after fork; write faults duplicate frames.  

## Building
```bash
cd gemOS
make clean all
