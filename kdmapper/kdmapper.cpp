#include "kdmapper.hpp"
#include <Windows.h>
#include <iostream>

#include "utils.hpp"
#include "intel_driver.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"
#include "wnbios.h"

void RelocateImageByDelta(portable_executable::vec_relocs relocs, const ULONG64 delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<ULONG64*>(current_reloc.address + offset) += delta;
		}
	}
}

// Fix cookie by @Jerem584
bool FixSecurityCookie(void* local_image, ULONG64 kernel_image_base)
{
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		Log(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		Log(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		Log(L"[-] StackCookie already fixed!? this probably wrong" << std::endl);
		return false;
	}

	Log(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId(); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
	return true;
}

bool ResolveImports(portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = utils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			ULONG64 function_address = intel_driver::GetKernelModuleExport(Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(intel_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
#if !defined(DISABLE_OUTPUT)
						std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
#endif
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

ULONG64 kdmapper::AllocateLegitRwxKernelMem()
{
	HMODULE rwx_mod = LoadLibrary(L"rwx.dll");

	std::cout << "RWX Dll allocated @ " << std::hex << rwx_mod << std::endl;

	PIMAGE_NT_HEADERS64 nt = portable_executable::GetNtHeaders(rwx_mod);

	uintptr_t rwx_section = 0; size_t page_count = 0;
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(nt);
	for (UINT i = 0; i != nt->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
		//if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE && pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ && pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
		//	std::cout << pSectionHeader->Name << std::endl;

		if (strcmp((const char*)pSectionHeader->Name, "citasvzg") == 0)
		{
			//std::cout << pSectionHeader->PointerToRawData << std::endl;
			rwx_section = (uintptr_t)rwx_mod + pSectionHeader->PointerToRawData;
			page_count = std::ceil(pSectionHeader->SizeOfRawData / 0x1000);
		}
	}
	std::cout << "RWX Section @ " << rwx_section << std::endl;
	std::cout << "RWX Page count " << page_count << std::endl;

	wnbios_lib wnbios;
	uintptr_t base = wnbios.get_process_base(L"kdmapper_Release.exe");
	std::cout << "Process base @ " << base << std::endl;

	uintptr_t pt = wnbios.get_pt(rwx_section);
	std::cout << "RWX PT @ " << pt << std::endl;

	unsigned short Table = (unsigned short)((rwx_section >> 12) & 0x1FF);
	std::cout << "PT Table " << Table << std::endl;

	for (int i = Table; i < min(Table + page_count, 512); i++)
	{
		_PTE PTE;
		PTE.Value = 0;
		wnbios.read_physical_memory((pt + i * sizeof(uintptr_t)), &PTE, sizeof(PTE));
		PTE.UserSupervisor = 0;
		wnbios.write_physical_memory((pt + i * sizeof(uintptr_t)), &PTE, sizeof(PTE));
	}

	return rwx_section;
}

ULONG64 kdmapper::MapDriver(BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);

	if (!nt_headers) {
		Log(L"[-] Invalid format of PE image" << std::endl);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Log(L"[-] Image is not 64 bit" << std::endl);
		return 0;
	}

	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	ULONG64 kernel_image_base = kdmapper::AllocateLegitRwxKernelMem();
	std::cout << "kernel image base @ " << std::hex << kernel_image_base << std::endl;

	system("pause");
	

	if (!kernel_image_base) {
		Log(L"[-] Failed to allocate remote image in kernel" << std::endl);

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		Log(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<ULONG64>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		ULONG64 realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			Log(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header" << std::endl);
		}

		// Resolve relocs and imports

		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!FixSecurityCookie(local_image_base, kernel_image_base ))
		{
			Log(L"[-] Failed to fix cookie" << std::endl);
			return 0;
		}

		if (!ResolveImports(portable_executable::GetImports(local_image_base))) {
			Log(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// Write fixed image to kernel

		if (!intel_driver::WriteMemory(realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			Log(L"[-] Failed to write local image to remote image" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (mode == AllocationMode::AllocateIndependentPages)
		{
			auto ProtectionToString = [](ULONG prot) -> const char* {
				switch (prot)
				{
				case PAGE_NOACCESS: return "NOACCESS";
				case PAGE_READONLY: return "READONLY";
				case PAGE_READWRITE: return "READWRITE";
				case PAGE_EXECUTE: return "EXECUTE";
				case PAGE_EXECUTE_READ: return "EXECUTE_READ";
				case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
				default: return "UNKNOWN";
				}
				};

			for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
				auto sec = &IMAGE_FIRST_SECTION(nt_headers)[i];
				uintptr_t secAddr = kernel_image_base + sec->VirtualAddress;
				uint32_t secSize = sec->Misc.VirtualSize;

				if (secSize <= 0) {
					Log(L"[*] Skipping empty section: " << (char*)sec->Name << std::endl);
					continue;
				}

				ULONG prot = PAGE_READONLY;

				if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
					prot = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ?
						PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
					prot = PAGE_READWRITE;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_READ) {
					prot = PAGE_READONLY;
				}

				Log(L"[+] Setting protection for section: "
					<< (char*)sec->Name
					<< L" Base: 0x" << std::hex << secAddr
					<< L" Size: 0x" << secSize
					<< L" Prot: " << ProtectionToString(prot)
					<< std::dec << std::endl);

				if (!intel_driver::MmSetPageProtection(secAddr, secSize, prot)) {
					Log(L"[-] Failed to set protection for section: " << (char*)sec->Name << std::endl);
				}
			}
		}

		// Call driver entry point

		const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		Log(L"[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);

		if (callback) {
			if (!callback(&param1, &param2, realBase, image_size)) {
				Log(L"[-] Callback returns false, failed!" << std::endl);
				kernel_image_base = realBase;
				break;
			}
		}

		std::cout << "Real base @ " << realBase << std::endl;

		NTSTATUS status = 0;
		if (!intel_driver::CallKernelFunction(&status, address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2)) {
			Log(L"[-] Failed to call driver entry" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (exitCode)
			*exitCode = status;

		Log(L"[+] DriverEntry returned 0x" << std::hex << status << std::endl);

		// Free memory
		if (free) {
			Log(L"[+] Freeing memory" << std::endl);
			bool free_status = false;

			if (mode == AllocationMode::AllocateIndependentPages)
			{
				free_status = intel_driver::MmFreeIndependentPages(realBase, image_size);
			}
			else {
				free_status = intel_driver::FreePool(realBase);
			}

			if (free_status) {
				Log(L"[+] Memory has been released" << std::endl);
			}
			else {
				Log(L"[-] WARNING: Failed to free memory!" << std::endl);
			}
		}



		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);

	Log(L"[+] Freeing memory" << std::endl);
	bool free_status = false;

	if (mode == AllocationMode::AllocateIndependentPages)
	{
		free_status = intel_driver::MmFreeIndependentPages(kernel_image_base, image_size);
	}
	else {
		free_status = intel_driver::FreePool(kernel_image_base);
	}

	if (free_status) {
		Log(L"[+] Memory has been released" << std::endl);
	}
	else {
		Log(L"[-] WARNING: Failed to free memory!" << std::endl);
	}

	return 0;
}


