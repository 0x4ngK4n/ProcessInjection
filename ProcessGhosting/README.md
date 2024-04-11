## Process Ghosting

# Steps as below:
1. Open or create a dummy file (`CreateFileA`)
2. Put the file in a delete-pending state (`NTSetInformationFile` API)
    2a. `FileDispositionInformation` class is used here.
3. Write payload into the delete-pending file (`WriteFile`).
4. Create a section from the delete-pending file (`NtCreateSection`).
5. Once we have a section, we delete the file (if process created from the section, the file will be scanned, thus we delete the file) using `CloseHandle` API.
6. Now we have a file-less section. Create a process with this section using `NtCreateProcessEx` API.
7. Update/fix process params (similar to process Doppleganging & Herpaderping).
8. Create new thread in the process. 