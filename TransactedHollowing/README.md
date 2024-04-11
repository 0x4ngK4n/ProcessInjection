## Transacted Hollowing.

### Notes:
This technique is a hybrid of process doppleganging and process hollowing.
Steps are as follows:

1. Create a transaction object and a file to the transaction object.
2. Write payload to the transaction object file.
3. Create a section mapping the file transaction object and save it's handle.
4. Rollback the transaction, just keep the section.
5. Create victim process in a suspended state.
6. Map the section of step 3 to the victim process.
7. Next, find the address of the entrypoint in the section relative to the address space of the victim process.
8. Do a thread hijacking to change the original entrypoint to that in step 7.
9. Change the image base address (located at 0x10 offset of the PEB) to the address of the mapped section payload.
10. Ta-da! resume the process.