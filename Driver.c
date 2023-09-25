#include <ntifs.h>
#include <ntstrsafe.h>
#include "Driver.h"

PMMPTE MiGetPteAddress(PVOID VirtualAddress);
NTSTATUS MemeNullingPfn(PVOID BaseAddress, SIZE_T NumberOfBytes);
NTSTATUS RealNullingPfn(PVOID BaseAddress, SIZE_T NumberOfBytes);


NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObject, PUNICODE_STRING RegistryPath) {
	NTSTATUS Status;
	PMDL AllocatedMdl;
	WCHAR String[] = L"Hello, world!";
	PVOID BaseAddress;
	PHYSICAL_ADDRESS PhysicalAddress;
	PHYSICAL_ADDRESS Lowest = { 0 };
	PHYSICAL_ADDRESS Highest = { MAXULONGLONG };

	UNREFERENCED_PARAMETER(DrvObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	Status = STATUS_NO_MEMORY;
	AllocatedMdl = MmAllocatePagesForMdl(Lowest, Highest, Lowest, PAGE_SIZE);
	if (AllocatedMdl != NULL) {
		BaseAddress = MmGetSystemAddressForMdlSafe(AllocatedMdl, HighPagePriority);

		if (BaseAddress == NULL)
		{

			MmFreePagesFromMdl(AllocatedMdl);
			ExFreePool(AllocatedMdl);

			DbgPrint("[!] Memory not mapped!.");
			return Status;
		}

		RtlCopyMemory(BaseAddress, String, sizeof(String));

		PhysicalAddress = MmGetPhysicalAddress(BaseAddress);

		DbgPrint("[+] Translating result before nulling: 0x%llX.", PhysicalAddress.QuadPart);

		Status = MemeNullingPfn(BaseAddress, PAGE_SIZE);
		if NT_SUCCESS(Status) {
			PhysicalAddress = MmGetPhysicalAddress(BaseAddress);

			DbgPrint("[+] Translating result after meme nulling: 0x%llX.", PhysicalAddress.QuadPart);
		}

		Status = RealNullingPfn(BaseAddress, PAGE_SIZE);
		if NT_SUCCESS(Status) {
			PhysicalAddress = MmGetPhysicalAddress(BaseAddress);

			DbgPrint("[+] Translating result after real nulling: 0x%llX.", PhysicalAddress.QuadPart);

			DbgPrint("[+] String from invalid memory: %ws.", (LPWSTR)BaseAddress);
		}
	}
	else {
		DbgPrint("[!] Mdl not allocated!.");
	}

	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS MemeNullingPfn(PVOID BaseAddress, SIZE_T NumberOfBytes)
{
	PMDL mdl = IoAllocateMdl(BaseAddress, (ULONG)NumberOfBytes, FALSE, FALSE, NULL);
	UNREFERENCED_PARAMETER(NumberOfBytes);

	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	if (!mdl_pages) {
		return Status;
	}

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG null_pfn = 0x0;
	MM_COPY_ADDRESS source_address = { 0 };
	source_address.VirtualAddress = &null_pfn;

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		size_t bytes = 0;
		Status = MmCopyMemory(&mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}

	IoFreeMdl(mdl);
	return Status;
}

NTSTATUS RealNullingPfn(PVOID BaseAddress, SIZE_T NumberOfBytes) {
	NTSTATUS Status = STATUS_NO_MEMORY;

	SIZE_T NumberOfPages = BYTES_TO_PAGES(NumberOfBytes);
	PMMPTE PointerPte = MiGetPteAddress(BaseAddress);

	if (PointerPte == NULL)
	{
		DbgPrint("[!] Failed initializing MiGetPteAddress.");
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	while (NumberOfPages) {
		PointerPte->u.Hard.PageFrameNumber = 0;

		PointerPte += 1;
		NumberOfPages -= 1;
	}

	if (NumberOfPages == 0)
		Status = STATUS_SUCCESS;

	return Status;
}

PMMPTE MiGetPteAddress(PVOID VirtualAddress) {
	CONTEXT Context;
	PDUMP_HEADER DumpHeader;
	KDDEBUGGER_DATA DebuggerData;

	DumpHeader = ExAllocatePool2(POOL_FLAG_NON_PAGED, DUMP_BLOCK_SIZE, 'kddh');
	if (DumpHeader != NULL)
	{
		Context.ContextFlags = CONTEXT_FULL;
		RtlCaptureContext(&Context);
		KeCapturePersistentThreadState(&Context, NULL, 0, 0, 0, 0, 0, DumpHeader);
		RtlCopyMemory(&DebuggerData, RtlOffsetToPointer(DumpHeader, KDDEBUGGER_DATA_OFFSET), sizeof(KDDEBUGGER_DATA));
		ExFreePool(DumpHeader);

		if (DebuggerData.PteBase)
		{
			return (PMMPTE)(DebuggerData.PteBase + (((ULONGLONG)VirtualAddress >> 9) & 0x7FFFFFFFF8));
		}
	}

	return NULL;
}