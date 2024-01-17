## Earlybird APC Injection
### What is it?
> A Process is created in a suspended state. This in turn has the main thread as well as other child threads be created in a suspended state as well. When an APC is queued to such a thread and then the thread resumed, it reliably triggers the APC queued code.

### Why does it work?
> Whenever the thread is resumed, it calls the ntdll!LdrInitializeThunk which in turn calls the LdrpInitialze method, eventally firing off NtTestAlert. It is `NtTestAlert` which check for any queued APCs before resuming its thread.<br>
<br>
One can over WinDbg, set a breakpoint on `ntdll!LdrInitializeThunk` which when analysed shows that the rcx register contains the context. <br>
<br>
Analysing the context inside rcx registers, we see values of rip and rcx inside the context. rip is the address of the instruction `ntdll!NtContinue` when the thread resumes. Wherease, the rcx holds value of the start address which the thread will execute once it resumes.<br>
<br>
On our case, the rcx register inside context holds address of the shellcode awaiting execution via Earlybird APC.
