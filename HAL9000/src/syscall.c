#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread.h"
#include "process.h"
#include "cl_string.h"
#include "io.h"
#include "iomu.h"

extern void SyscallEntry();

char*
cl_strcat(
    INOUT char* destination,
    IN char* source
)
{

    ASSERT(NULL != destination);
    ASSERT(NULL != source);
    // make `ptr` point to the end of the destination string
    char* ptr = destination + cl_strlen(destination);

    // appends characters of the source to the destination string
    while (*source != '\0') {
        *ptr++ = *source++;
    }

    // null terminate destination string
    *ptr = '\0';

    // the destination is returned by standard `strcat()`
    return destination;
}

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION
#define TAG_MAP_PROCESS 'PAMP'
#define TAG_MAP_FILE 'PAMF'
#define STR_ALOC 'RTS'
#define STR_APP 'RTSA'
#define STR_APP_NEW 'RTSN'

#define UM_HANDLE_INCREMENT   2

STATUS
InsertInUM_HandleMapProcess(
    IN UM_HANDLE* ProcessHandle,
    IN PPROCESS     Process
);

STATUS
FindProcessByUM_HANDLE(
    IN UM_HANDLE ProcessHandle,
    OUT PPROCESS* Process
);

STATUS
InsertInUM_HandleMapFile(
    IN UM_HANDLE* FileHandle,
    IN PFILE_OBJECT     FileObject
);

STATUS
FindFileByUM_HANDLE(
    IN UM_HANDLE FileHandle,
    OUT PFILE_OBJECT* FileObject
);

STATUS
DeleteFileByUM_HANDLE(
    IN UM_HANDLE FileHandle
);

STATUS
DeleteProcessByUM_HANDLE(
    IN UM_HANDLE FileHandle
);

STATUS
IncrementUM_HandleValueForProcess(
    INOUT PPROCESS Process
);


typedef struct _UM_HANDLE_PROCESS_ELEMENT {
    UM_HANDLE   Um_Handle;
    PPROCESS    Pprocess;
    LIST_ENTRY  ListEntry;
}UM_HANDLE_PROCESS_ELEMENT, * PUM_HANDLE_PROCESS_ELEMENT;

typedef struct _UM_HANDLE_FILE_ELEMENT {
    UM_HANDLE   Um_Handle;
    PFILE_OBJECT    FileObject;
    LIST_ENTRY  ListEntry;
}UM_HANDLE_FILE_ELEMENT, * PUM_HANDLE_FILE_ELEMENT;


void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        //LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);
        //LOG("System call ID is %u\n", sysCallId);
        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
        // STUDENT TODO: implement the rest of the syscalls
        case SyscallIdFileWrite:
            status = SyscallFileWrite(
                    (UM_HANDLE)pSyscallParameters[0],
                    (PVOID)pSyscallParameters[1],
                    (QWORD)pSyscallParameters[2],
                    (QWORD*)pSyscallParameters[3]
                    );
            break;
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdProcessCreate:
            status = SyscallProcessCreate(
                (char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (char*)pSyscallParameters[2],
                (QWORD)pSyscallParameters[3],
                (UM_HANDLE*)pSyscallParameters[4]
            );
            break;
        case SyscallIdProcessGetPid:
            status = SyscallProcessGetPid(
                (UM_HANDLE)pSyscallParameters[0],
                (PID*)pSyscallParameters[1]
            );
            break;
        case SyscallIdProcessWaitForTermination:
            status = SyscallProcessWaitForTermination(
                (UM_HANDLE)pSyscallParameters[0],
                (STATUS*)pSyscallParameters[1]
            );
            break;
        case SyscallIdProcessCloseHandle:
            status = SyscallProcessCloseHandle(
                (UM_HANDLE)*pSyscallParameters
            );
            break;
        case SyscallIdFileCreate:
            status = SyscallFileCreate(
                (char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (BOOLEAN)pSyscallParameters[2],
                (BOOLEAN)pSyscallParameters[3],
                (UM_HANDLE*)pSyscallParameters[4]
            );
            break;
        case SyscallIdFileRead:
            status = SyscallFileRead(
                (UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]
            );
            break;
        case SyscallIdFileClose:
            status = SyscallFileClose(
                (UM_HANDLE)*pSyscallParameters
            );
            break;
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls
STATUS
SyscallFileWrite(
    IN  UM_HANDLE               FileHandle,
    IN_READS_BYTES(BytesToWrite)
        PVOID                   Buffer,
    IN  QWORD                   BytesToWrite,
    OUT QWORD*                  BytesWritten
)
{

    //LOGL("FILEWRITE1");
    if (BytesWritten == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
 
    //LOGL("FILEWRITE3");
    if (FileHandle == UM_FILE_HANDLE_STDOUT && GetCurrentProcess()->StdOutDisabled == FALSE) {

        *BytesWritten = BytesToWrite;
        LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);
        return STATUS_SUCCESS;

    }
    //LOGL("FILEWRITE4");
    *BytesWritten = BytesToWrite;
    //LOGL("FILEWRITE5");
    return STATUS_SUCCESS;
}

STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    PPROCESS Process;
    //get the head list of ProcessMapByUM_Handle and chek it it si empy otherwise will have zombie processes
    //LOGL("ProcessExit1\n");
    Process = GetCurrentProcess();
    //LOGL("ProcessExit2\n");
    Process->TerminationStatus = ExitStatus;
    ProcessTerminate(Process);
    //LOGL("ProcessExit3\n");
   return STATUS_SUCCESS;
    
}

STATUS
SyscallThreadExit(
    IN  STATUS                      ExitStatus
)
{
    //LOGL("ThreadExi1t\n");
    ThreadExit(ExitStatus);
    //LOGL("ThreadExit2\n");
    return STATUS_SUCCESS;
}

STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)
    char* ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength)
    char* Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE* ProcessHandle
)
{
    //LOGL("Create\n");

    PPROCESS Process;
    STATUS status;
    const char* SystemDrive;
    char* AppPath;
    char* NewPath;

    if (ProcessPath == NULL || ProcessHandle == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("Create1\n");
    if (MmuIsBufferValid((char*)ProcessPath, sizeof(char) * PathLength, PAGE_RIGHTS_READ, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("Create2\n");
    if (MmuIsBufferValid((UM_HANDLE*)ProcessHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_READWRITE, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("Create3\n");
    if (ArgLength != 0) {
        if (Arguments == NULL) {
            return STATUS_UNSUCCESSFUL;
        }
        //LOGL("Create4\n");
        if (MmuIsBufferValid((char*)Arguments, sizeof(char) * ArgLength, PAGE_RIGHTS_READ, GetCurrentProcess()) != STATUS_SUCCESS) {
            return STATUS_UNSUCCESSFUL;
        }
        //LOGL("Create5\n");
        if (cl_strlen(Arguments) + 1 != ArgLength) {
            return STATUS_UNSUCCESSFUL;
        }

    }
    //LOGL("Create6\n");
    if (cl_strlen(ProcessPath) + 1 != PathLength) {
        return STATUS_UNSUCCESSFUL;
    }

    //LOGL("Create7\n");
    SystemDrive = IomuGetSystemPartitionPath();

    AppPath = (char*)ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(char) * 14, STR_APP, PAGE_SIZE);
    AppPath = "Applications\\";
    NewPath = (char*)ExAllocatePoolWithTag(PoolAllocateZeroMemory, cl_strlen(ProcessPath) + cl_strlen(AppPath) + cl_strlen(SystemDrive) + 1, STR_APP_NEW, PAGE_SIZE);
    cl_strcpy(NewPath, SystemDrive);
    if (NewPath != NULL) {
        NewPath = cl_strcat(NewPath, AppPath);
        NewPath = cl_strcat(NewPath, ProcessPath);
    }

    status = ProcessCreate(NewPath, Arguments, &Process);

    if (status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("Create8\n");
    //Assign the UM_HANDLE_VALUE
    *ProcessHandle = getUM_HandleValueProcess();
    //Increment the UM_HANDLE of the process
    updateUM_HandleValueProcess();
    //LOGL("Creat9\n");
    if (Process != NULL){
        InsertInUM_HandleMapProcess(ProcessHandle, Process);
    }
    //LOGL("ccreate succcess\n");
    return status;
}

STATUS
SyscallProcessGetPid(
    IN_OPT  UM_HANDLE               ProcessHandle,
    OUT     PID* ProcessId
)
{
    //LOGL("GetPid1\n");
    //creaza list in SystemInit in care tin UM_Handle/PProcess
    //caut in lista dupa UM_handle si ia procesul pe care il bagi ca parametru in processGetId
    //verficre memorie ProcessId
    //verificare cu 0 UM_Handle??
    PPROCESS Process;
    STATUS Status;
    //LOGL("GetPid2\n");
    if (ProcessId == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("GetPid3\n");
    if (MmuIsBufferValid((PID*)ProcessId, sizeof(PID), PAGE_RIGHTS_WRITE, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    Status = FindProcessByUM_HANDLE(ProcessHandle, &Process);
    //LOGL("GetPid4\n");
    if (Status != STATUS_SUCCESS) {

        *ProcessId = ProcessGetId(NULL);
        return STATUS_SUCCESS;
    }
    //LOGL("GetPid5\n");
    *ProcessId = ProcessGetId(Process);
    //LOGL("GetPid6\n");
    return Status;
}

STATUS
SyscallProcessWaitForTermination(
    IN      UM_HANDLE               ProcessHandle,
    OUT     STATUS* TerminationStatus
)
{

    //LOGL("Functie executata la inceput\n");

   //asteapta sa se execute ceva process inainte sa se execue el
    //ia procesul dorit din lista dupa UM_Handle
    //scrue ub Terination status Statusul dupa care astept.
    //verificare TerminationStatus != NUll si permisiune write ok 
    STATUS Status;
    PPROCESS Process;
    //LOGL("ProcessWaitFortermination1\n");
    if ( TerminationStatus == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("ProcessWaitFortermination2\n");
    if (MmuIsBufferValid((STATUS*)TerminationStatus, sizeof(STATUS), PAGE_RIGHTS_WRITE, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("ProcessWaitFortermination3\n");

    Status = FindProcessByUM_HANDLE(ProcessHandle, &Process);
    if (Status != STATUS_SUCCESS || Process == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("ProcessWaitFortermination4\n");

    ProcessWaitForTermination(Process, TerminationStatus);
    //LOGL("ProcessWaitFortermination5\n");
    return Status;
}

STATUS
SyscallProcessCloseHandle(
    IN      UM_HANDLE               ProcessHandle
)
{
   // LOGL("Functie executata la inceput\n");

    //cauta in list ade mapare processul
    //validare processHandle != NULL
    STATUS Status;
    PPROCESS Process;

    Status = FindProcessByUM_HANDLE(ProcessHandle, &Process);
    //LOGL("ClodeHandle1\n");

    if (Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("ClodeHandle12\n");

    ProcessCloseHandle(Process);
   // LOGL("ClodeHandle3\n");
    Status = DeleteProcessByUM_HANDLE(ProcessHandle);
   // LOGL("ClodeHandle4\n");
    return Status;
}


STATUS
SyscallFileCreate(
    IN_READS_Z(PathLength)
    char* Path,
    IN          QWORD                   PathLength,
    IN          BOOLEAN                 Directory,
    IN          BOOLEAN                 Create,
    OUT         UM_HANDLE* FileHandle
)
{
    //decalre a pfile object and do the same with a list of handlers and pfile obj
    //create a file
    //asyncronus false
    //LOGL("Functie executata la inceput\n");

    STATUS Status;
    PFILE_OBJECT FileObject;
    const char* SystemDrive;
    char* NewPath;


    //LOG("ceva is: with length");

    if (FileHandle == NULL || Path == NULL) {
        //LOGL("\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    if (MmuIsBufferValid((UM_HANDLE*)FileHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_WRITE, GetCurrentProcess()) != STATUS_SUCCESS) {
        //LOGL("\n");
        return STATUS_UNSUCCESSFUL;

    }

    if (MmuIsBufferValid((char*)Path, sizeof(char) * PathLength, PAGE_RIGHTS_READ, GetCurrentProcess()) != STATUS_SUCCESS) {
        //LOGL("\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (cl_strlen(Path) +1  != PathLength) {
        //LOGL("\n");
        return STATUS_UNSUCCESSFUL;
    }

    SystemDrive = IomuGetSystemPartitionPath();

    
    NewPath = (char*)ExAllocatePoolWithTag(
        PoolAllocateZeroMemory, 
        cl_strlen(Path) + cl_strlen(SystemDrive) + 1,
        STR_APP_NEW, PAGE_SIZE
    );

    cl_strcpy(NewPath, SystemDrive);
    if (NewPath != NULL) {
        NewPath = cl_strcat(NewPath, Path);
    }
    
    //LOG("Ce printeaza %s", NewPath);
    //create file
    Status = IoCreateFile(&FileObject, NewPath, Directory, Create, FALSE);

    if (Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    *FileHandle = GetCurrentProcess()->UM_HANDLE_VALUE;
    //Increment the UM_HANDLE of the process
    IncrementUM_HandleValueForProcess(GetCurrentProcess());
    //insert in list
    Status = InsertInUM_HandleMapFile(FileHandle, FileObject);
    //LOGL("Functie executata cu succcess\n");
    return Status;
}


// SyscallIdFileClose
STATUS
SyscallFileClose(
    IN          UM_HANDLE               FileHandle
)
{
    //LOGL("Functie executata la inceput\n");

    //ia din lista 
    STATUS Status;
    PFILE_OBJECT FileObject;
    //LOGL("File Close 1\n");
    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        GetCurrentProcess()->StdOutDisabled = TRUE;
        return STATUS_UNSUCCESSFUL;
    }

    Status = FindFileByUM_HANDLE(FileHandle, &FileObject);
    //LOGL("File Close 2\n");
    if (Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    //LOGL("File Close 3\n");
    Status = DeleteFileByUM_HANDLE(FileHandle);
    if (Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
   // LOGL("File Close 4\n");
    //LOGL("Functie executata cu succcess\n");
    return  IoCloseFile(FileObject);
}

// SyscallIdFileRead
STATUS
SyscallFileRead(
    IN  UM_HANDLE                   FileHandle,
    OUT_WRITES_BYTES(BytesToRead)
    PVOID                       Buffer,
    IN  QWORD                       BytesToRead,
    OUT QWORD* BytesRead
)
{
        //LOGL("Functie executata la inceput\n");

    STATUS Status;
    PFILE_OBJECT FileObject;
    
    //LOGL("read1");
    if (BytesRead == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (BytesToRead == 0) {
        Buffer = (char)'\0';
        *BytesRead = 0;
        return STATUS_SUCCESS;
    }

   // LOGL("read12");
    if (MmuIsBufferValid((QWORD*)BytesRead, BytesToRead, PAGE_RIGHTS_WRITE, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

   // LOGL("read3");
    if (MmuIsBufferValid((PVOID)Buffer, BytesToRead, PAGE_RIGHTS_WRITE, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

   // LOGL("read4");
    Status = FindFileByUM_HANDLE(FileHandle, &FileObject);
   // LOGL("read5");
    if (Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    
    //LOGL("Functie executata cu succcess\n");
    //LOGL("read6");
    Status = IoReadFile(FileObject, BytesToRead, NULL, Buffer, BytesRead);
    //LOGL("read7");
    return Status;
}


STATUS
InsertInUM_HandleMapProcess(
    IN UM_HANDLE*    ProcessHandle,
    IN PPROCESS     Process
)
{
    STATUS Status;

    Status = STATUS_SUCCESS;
    //insereaza in list care mapeaza um_Handle la PPRoCESS
    PUM_HANDLE_PROCESS_ELEMENT map_elem = (PUM_HANDLE_PROCESS_ELEMENT)ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(UM_HANDLE_PROCESS_ELEMENT), TAG_MAP_PROCESS, PAGE_SIZE);

    //verify that the elem is not null
    if (map_elem == NULL) {
        LOG_FUNC_ERROR("ExAllocatePoolWithTag", STATUS_HEAP_INSUFFICIENT_RESOURCES);
    }
    else {
        //assign the respective values to the 
        map_elem->Um_Handle = *ProcessHandle;
        map_elem->Pprocess = Process;
        PLIST_ENTRY UM_HandleMapProcessList = getUM_HandleMapProcess();
        InsertTailList(UM_HandleMapProcessList, &map_elem->ListEntry);
    }

    return Status;
}


STATUS
FindProcessByUM_HANDLE(
    IN UM_HANDLE ProcessHandle, 
    OUT PPROCESS* Process
)
{
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry;
    PLIST_ENTRY UM_HandleMapProcessList;
    BOOLEAN Found;
    PUM_HANDLE_PROCESS_ELEMENT MapElement;

    Found = FALSE;
    UM_HandleMapProcessList = getUM_HandleMapProcess();

    ListIteratorInit(UM_HandleMapProcessList, &ListIterator); 
    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {
        MapElement = CONTAINING_RECORD(pListEntry, UM_HANDLE_PROCESS_ELEMENT, ListEntry);
        if (MapElement->Um_Handle == ProcessHandle) {
            *Process = MapElement->Pprocess;
            Found = TRUE;
            break;
        }
    }

    if (Found) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_NO_DATA_AVAILABLE;
    }
}

STATUS
InsertInUM_HandleMapFile(
    IN UM_HANDLE* FileHandle,
    IN PFILE_OBJECT     FileObject
    
)
{
    STATUS Status;

    Status = STATUS_SUCCESS;
    //insereaza in list care mapeaza um_Handle la PPRoCESS
    PUM_HANDLE_FILE_ELEMENT map_elem = (PUM_HANDLE_FILE_ELEMENT)ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(UM_HANDLE_FILE_ELEMENT), TAG_MAP_FILE, PAGE_SIZE);

    //verify that the elem is not null
    if (map_elem == NULL) {
        LOG_FUNC_ERROR("ExAllocatePoolWithTag", STATUS_HEAP_INSUFFICIENT_RESOURCES);
    }
    else {
        //assign the respective values to the 
        map_elem->Um_Handle = *FileHandle;
        map_elem->FileObject = FileObject;
        PLIST_ENTRY UM_HandleMapFilesList = &GetCurrentProcess()->UM_HandleMapFile;
        InsertTailList(UM_HandleMapFilesList, &map_elem->ListEntry);
    }

    return Status;
}


STATUS
FindFileByUM_HANDLE(
    IN UM_HANDLE FileHandle,
    OUT PFILE_OBJECT*     FileObject
)
{
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry;
    PLIST_ENTRY UM_HandleMapFileList;
    BOOLEAN Found;
    PUM_HANDLE_FILE_ELEMENT MapElement;

    Found = FALSE;
    UM_HandleMapFileList = &GetCurrentProcess()->UM_HandleMapFile;

    ListIteratorInit(UM_HandleMapFileList, &ListIterator);
    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {
        MapElement = CONTAINING_RECORD(pListEntry, UM_HANDLE_FILE_ELEMENT, ListEntry);
        if (MapElement->Um_Handle == FileHandle) {
            *FileObject = MapElement->FileObject;
            Found = TRUE;
            break;
        }
    }

    if (Found) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_NO_DATA_AVAILABLE;
    }
}

STATUS
DeleteProcessByUM_HANDLE(
    IN UM_HANDLE ProcessHandle
)
{
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry;
    PLIST_ENTRY UM_HandleMapProcessList;
    PUM_HANDLE_PROCESS_ELEMENT MapElement;
    BOOLEAN found;
    UM_HandleMapProcessList = getUM_HandleMapProcess();

    found = FALSE;
    ListIteratorInit(UM_HandleMapProcessList, &ListIterator);
    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {
        MapElement = CONTAINING_RECORD(pListEntry, UM_HANDLE_PROCESS_ELEMENT, ListEntry);
        if (MapElement->Um_Handle == ProcessHandle) {
            RemoveEntryList(pListEntry);
            found = TRUE;
            break;
        }
    }

    if (found) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_UNSUCCESSFUL;
    }
    
}

STATUS
DeleteFileByUM_HANDLE(
    IN UM_HANDLE FileHandle
)
{
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry;
    PLIST_ENTRY UM_HandleMapFileList;
    PUM_HANDLE_FILE_ELEMENT MapElement;
    BOOLEAN found;
    UM_HandleMapFileList = &GetCurrentProcess()->UM_HandleMapFile;

    found = FALSE;

    ListIteratorInit(UM_HandleMapFileList, &ListIterator);
    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {
        MapElement = CONTAINING_RECORD(pListEntry, UM_HANDLE_FILE_ELEMENT, ListEntry);
        if (MapElement->Um_Handle == FileHandle) {
            RemoveEntryList(pListEntry);
            found = TRUE;
            break;
        }
    }

    if (found) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_UNSUCCESSFUL;
    }
}



STATUS
IncrementUM_HandleValueForProcess(
    INOUT PPROCESS Process
)
{
    Process->UM_HANDLE_VALUE += UM_HANDLE_INCREMENT;
    return STATUS_SUCCESS;
}