## Process Doppleganging

### Process Hollowing another process injection technique where the executable section of the legitimate process is replaced with the malicious executable.

#### Notes about the technique:
```It is dead in the context of the current operating system. But is useful concept-wise to learn other injection techniques such as process haederpining or process ghosting. Defender detects this technique quite easy because when technique is run, File Object is created in kernel space. At its botton is a field called FileObjectExtension. When file is opened with transaction, this is not null and the first item of the FileObjectExtension points to the _TXN_PARAMETER_BLOCK_. This in turn holds the pointer to the TRANSACTIONOBJECT. Anti-virus or defenders scans the section created by the transaction object. We do not have any primitive to set the FileObjectExtension to null owing to limited permission in the user-land.```

This technique consists of `four` parts:
- Transact
- Load
- Rollback
- Animate


