#ifndef MBRP_HEADER_NTDRIVER
#define MBRP_HEADER_NTDRIVER

#ifndef BOOL
typedef int BOOL;
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE !TRUE
#endif

#define MBRBootSection 437
#define BufferSize 512

NTSTATUS MBRReadDevice(PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length);
NTSTATUS MBRWriteDevice(PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length);

#endif