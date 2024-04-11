## Process Herpaderping

## Steps:
1. Create a temporary or decoy file (`CreateFileA`) - this file is written to the disk unlike process doppenganging or transacted hollowing.
2. Write payload (`WriteFile`) to that file, do not close the file as we need handle to it.
3. Create an image section from that file (`NtCreateSection`).
4. Create a process using the newly created section (`NtCreateProcessEx`).
5. Modify the temporary file in step 1 (`SetFilePointer`, `WriteFile`).
6. Setup Process Parameters (`RtlCreateProcessParametersEx`).
7. Create New thread (`NtCreateThreadEx`). Here, AV will scan the file on disk but does not detect it because we have over-written the file on the disk in `step 5`.
8. Close temporary file handle (`CloseHandle`).
