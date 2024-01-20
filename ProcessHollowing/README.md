## Process Hollowing

### Process Hollowing another process injection technique where the executable section of the legitimate process is replaced with the malicious executable.

A. The replacement is in-memory. <br>
B. The malicious code executes from the context of legitimate process. <br>
C. The path of hollowed process still points to legitimate executable. 

### Steps of Process Hollowing & Respective Win APIs
1. Create the legitimate process in suspended mode.
    <br>*CreateProcessA*
2. Get image base of the legitimate process.
    <br>*NtQueryProcessInformation, ReadProcessMemory*
3. Hollow or Unmap the section of the legitimate process.
    <br>*ZwUnmapViewOfSection*
4. Allocate new memory in target process for the payload (malicious executable)
    <br>*VirtualAllocEx*
5. Copy the malicious executable code to the allocated memory
    <br>*WriteProcessMemory*
6. Get context of the legitimate process
    <br>*GetThreadContext*
7. Set entrypoint of the malicious code in the legitimate process's context
    <br>*Entrypoint - EAX in x86 and RCX in x64*
8. Set the modified context in the legitimate process (Context can short of be thought as the metadata for the process)
    <br>*SetThreadContext*
9. Resume the main thread of the legitimate hollowed process
    <br>*ResumeThread*