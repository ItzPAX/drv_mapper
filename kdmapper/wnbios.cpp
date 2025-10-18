#include "wnbios.h"
#include <cstdlib>
#include <cwchar>

bool wnbios_lib::to_file()
{
	if (std::filesystem::exists(store_at + "\\" + drv_name))
		return 1;

	std::filesystem::create_directories(store_at);

	std::ofstream out_driver(store_at + "\\" + drv_name, std::ios::beg | std::ios::binary);
	if (!out_driver.is_open())
		return 0;

	for (auto& c : driver::wnbios64)
		out_driver << c;
	out_driver.close();

	return 1;
}

bool wnbios_lib::create_service()
{
	SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (sc_manager == NULL)
		return 0;

	auto service = CreateServiceA(sc_manager, service_name.c_str(), NULL,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		(store_at + drv_name).c_str(),
		NULL,
		NULL,
		NULL,
		NULL,
		NULL);

	if (service == NULL) {

		service = OpenServiceA(sc_manager, service_name.c_str(), SERVICE_ALL_ACCESS);

		if (service == NULL) {
			CloseServiceHandle(sc_manager);
			return 0;
		}
	}

	CloseServiceHandle(sc_manager);

	return 1;
}

bool wnbios_lib::start_service()
{
	SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (sc_manager == NULL)
		return 0;

	auto service = OpenServiceA(sc_manager, service_name.c_str(), SERVICE_ALL_ACCESS);

	if (service == NULL) {
		CloseServiceHandle(sc_manager);
		return 0;
	}

	if (StartService(service, 0, NULL) == NULL) {
		CloseServiceHandle(sc_manager);
		CloseServiceHandle(service);
		return 0;
	}

	CloseServiceHandle(sc_manager);
	return 1;
}

bool wnbios_lib::stop_service()
{
	SERVICE_STATUS ss;
	SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (sc_manager == NULL)
		return 0;

	auto service = OpenServiceA(sc_manager, service_name.c_str(), SERVICE_ALL_ACCESS);

	if (service == NULL) {
		CloseServiceHandle(sc_manager);
		return 0;
	}

	if (ControlService(service, SERVICE_CONTROL_STOP, &ss) == NULL) {
		CloseServiceHandle(sc_manager);
		CloseServiceHandle(service);
		return 0;

	}

	CloseServiceHandle(sc_manager);
	CloseServiceHandle(service);
	return 1;
}

bool wnbios_lib::delete_service()
{
	SC_HANDLE sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (sc_manager == NULL)
		return 0;

	auto service = OpenServiceA(sc_manager, service_name.c_str(), SERVICE_ALL_ACCESS);

	if (service == NULL) {
		CloseServiceHandle(sc_manager);
		return 0;
	}

	DeleteService(service);
	CloseServiceHandle(sc_manager);

	return 1;
}

void wnbios_lib::get_eprocess_offsets() {

	NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);
	OSVERSIONINFOEXW osInfo;

	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"),
		"RtlGetVersion");

	DWORD build = 0;

	if (NULL != RtlGetVersion)
	{
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		RtlGetVersion(&osInfo);
		build = osInfo.dwBuildNumber;
	}

	switch (build)
	{
	case 22000: //WIN11
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 19045: // WIN10_22H2
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 19044: //WIN10_21H2
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 19043: //WIN10_21H1
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 19042: //WIN10_20H2
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 19041: //WIN10_20H1
		EP_UNIQUEPROCESSID = 0x440;
		EP_ACTIVEPROCESSLINK = 0x448;
		EP_VIRTUALSIZE = 0x498;
		EP_SECTIONBASE = 0x520;
		EP_IMAGEFILENAME = 0x5a8;
		break;
	case 18363: //WIN10_19H2
		EP_UNIQUEPROCESSID = 0x2e8;
		EP_ACTIVEPROCESSLINK = 0x2f0;
		EP_VIRTUALSIZE = 0x340;
		EP_SECTIONBASE = 0x3c8;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 18362: //WIN10_19H1
		EP_UNIQUEPROCESSID = 0x2e8;
		EP_ACTIVEPROCESSLINK = 0x2f0;
		EP_VIRTUALSIZE = 0x340;
		EP_SECTIONBASE = 0x3c8;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 17763: //WIN10_RS5
		EP_UNIQUEPROCESSID = 0x2e0;
		EP_ACTIVEPROCESSLINK = 0x2e8;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 17134: //WIN10_RS4
		EP_UNIQUEPROCESSID = 0x2e0;
		EP_ACTIVEPROCESSLINK = 0x2e8;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 16299: //WIN10_RS3
		EP_UNIQUEPROCESSID = 0x2e0;
		EP_ACTIVEPROCESSLINK = 0x2e8;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 15063: //WIN10_RS2
		EP_UNIQUEPROCESSID = 0x2e0;
		EP_ACTIVEPROCESSLINK = 0x2e8;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	case 14393: //WIN10_RS1
		EP_UNIQUEPROCESSID = 0x2e8;
		EP_ACTIVEPROCESSLINK = 0x2f0;
		EP_VIRTUALSIZE = 0x338;
		EP_SECTIONBASE = 0x3c0;
		EP_IMAGEFILENAME = 0x450;
		break;
	default:
		exit(0);
		break;
	}
}

uintptr_t wnbios_lib::get_ntos_vba()
{
	uintptr_t driver_bases[500];
	DWORD num_bytes = 0;

	if (EnumDeviceDrivers((LPVOID*)driver_bases, sizeof(driver_bases), &num_bytes)) {
		return driver_bases[0]; /*ntos virtual base address*/
	}

	return 0;
}

uint64_t wnbios_lib::leak_kprocess()
{
	cr3 = get_system_dirbase();
	if (!cr3)
		return 0;

	HMODULE ntos = LoadLibraryA("ntoskrnl.exe");
	if (!ntos) {
		return 0;
	}

	uintptr_t ntos_vba = get_ntos_vba();
	if (!ntos_vba) {
		return 0;
	}

	uintptr_t ps_isp = (uintptr_t)GetProcAddress(ntos, "PsInitialSystemProcess");

	if (!ntos_vba) {
		return 0;
	}

	FreeLibrary(ntos);

	uintptr_t system_eprocess_va = 0;
	if (!read_virtual_memory((ps_isp - (uintptr_t)ntos) + ntos_vba, &system_eprocess_va, sizeof(uintptr_t))) {
		return 0;
	}

	return system_eprocess_va;
}

uintptr_t wnbios_lib::map_physical(uint64_t address, size_t size, wnbios_mem& mem)
{
	memset(&mem, 0, sizeof(wnbios_mem));
	mem.addr = address;
	mem.size = size;
	DWORD retSize;
	auto status = DeviceIoControl(hHandle, 0x80102040, &mem, sizeof(wnbios_mem), &mem, sizeof(wnbios_mem), &retSize, 0);
	if (!status)
		return 0;

	return mem.outPtr;
}

uintptr_t wnbios_lib::unmap_physical(wnbios_mem& mem)
{
	DWORD bytes_returned;
	auto status = DeviceIoControl(hHandle, 0x80102044, &mem, sizeof(wnbios_mem), 0, 0, &bytes_returned, 0);
	if (!status)
		return 0;

	return 1;
}

uintptr_t wnbios_lib::get_pt(uint64_t v_address)
{
	uintptr_t va = v_address;

	unsigned short PML4 = (unsigned short)((va >> 39) & 0x1FF);
	uintptr_t PML4E = 0;
	read_physical_memory((cr3 + PML4 * sizeof(uintptr_t)), &PML4E, sizeof(PML4E));

	if (PML4E == 0)
		return 0;

	unsigned short DirectoryPtr = (unsigned short)((va >> 30) & 0x1FF);
	uintptr_t PDPTE = 0;
	read_physical_memory(((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(uintptr_t)), &PDPTE, sizeof(PDPTE));

	if (PDPTE == 0)
		return 0;

	if ((PDPTE & (1 << 7)) != 0)
		return (PDPTE & 0xFFFFFC0000000) + (va & 0x3FFFFFFF);

	unsigned short Directory = (unsigned short)((va >> 21) & 0x1FF);

	uintptr_t PDE = 0;
	read_physical_memory(((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(uintptr_t)), &PDE, sizeof(PDE));

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0)
	{
		return (PDE & 0xFFFFFFFE00000) + (va & 0x1FFFFF);
	}

	return (PDE & 0xFFFFFFFFFF000);
}

uintptr_t wnbios_lib::get_system_dirbase()
{
	for (int i = 0; i < 10; i++)
	{
		wnbios_mem mem;
		uintptr_t lpBuffer = map_physical(i * 0x10000, 0x10000, mem);

		for (int uOffset = 0; uOffset < 0x10000; uOffset += 0x1000)
		{
			if (0x00000001000600E9 ^ (0xffffffffffff00ff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset)))
				continue;
			if (0xfffff80000000000 ^ (0xfffff80000000000 & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0x70)))
				continue;
			if (0xffffff0000000fff & *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0))
				continue;

			return *reinterpret_cast<uintptr_t*>(lpBuffer + uOffset + 0xa0);
		}

		unmap_physical(mem);
	}

	return NULL;
}

uintptr_t wnbios_lib::get_process_id(const wchar_t* image_name)
{
	HANDLE hsnap;
	PROCESSENTRY32 pt;
	DWORD PiD;
	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	do {
		if (!wcscmp(pt.szExeFile, image_name)) {
			CloseHandle(hsnap);
			PiD = pt.th32ProcessID;
			return PiD;
			if (PiD != NULL) {
				return 0;
			}
		}
	} while (Process32Next(hsnap, &pt));
	return 1;
}

uintptr_t wnbios_lib::get_process_base(const wchar_t* image_name)
{
	get_eprocess_offsets();
	cr3 = get_system_dirbase();

	if (!cr3)
		return NULL;

	uintptr_t kprocess_initial = leak_kprocess();

	if (!kprocess_initial)
		return NULL;

	//printf("system_kprocess: %llx\n", kprocess_initial);
	//printf("system_cr3: %llx\n", cr3);

	const unsigned long limit = 400;

	uintptr_t link_start = kprocess_initial + EP_ACTIVEPROCESSLINK;
	uintptr_t flink = link_start;
	uintptr_t image_base_out = 0;


	for (int a = 0; a < limit; a++)
	{
		read_virtual_memory(flink, &flink, sizeof(PVOID));

		uintptr_t kprocess = flink - EP_ACTIVEPROCESSLINK;
		uintptr_t virtual_size = read_virtual_memory<uintptr_t>(kprocess + EP_VIRTUALSIZE);

		if (virtual_size == 0)
			continue;

		uintptr_t directory_table = read_virtual_memory<uintptr_t>(kprocess + EP_DIRECTORYTABLE);
		uintptr_t base_address = read_virtual_memory<uintptr_t>(kprocess + EP_SECTIONBASE);

		char name[16] = { };
		read_virtual_memory(kprocess + EP_IMAGEFILENAME, &name, sizeof(name));

		int process_id = 0;
		read_virtual_memory(kprocess + EP_UNIQUEPROCESSID, &process_id, sizeof(process_id));

		char image_name_mb[100];
		std::wcstombs(image_name_mb, image_name, sizeof(image_name_mb));
		if (strstr(image_name_mb, name) && process_id == get_process_id(image_name))
		{
			//printf("process_id: %i\n", process_id);
			//printf("process_base: %llx\n", base_address);
			//printf("process_cr3: %llx\n", directory_table);

			image_base_out = base_address;
			cr3 = directory_table;
			attached_proc = process_id;

			break;
		}
	}

	return image_base_out;
}

bool wnbios_lib::read_physical_memory(uintptr_t physical_address, void* output, unsigned long size)
{
	wnbios_mem mem;
	uintptr_t virtual_address = map_physical(physical_address, size, mem);

	if (!virtual_address)
		return false;

	memcpy(output, reinterpret_cast<void*>(virtual_address), size);
	unmap_physical(mem);
	return true;
}

bool wnbios_lib::write_physical_memory(uintptr_t physical_address, void* data, unsigned long size)
{
	if (!data)
		return false;

	wnbios_mem mem;
	uintptr_t virtual_address = map_physical(physical_address, size, mem);

	if (!virtual_address)
		return false;

	memcpy(reinterpret_cast<void*>(virtual_address), reinterpret_cast<void*>(data), size);
	unmap_physical(mem);
	return true;
}

uintptr_t wnbios_lib::convert_virtual_to_physical(uintptr_t virtual_address)
{
	uintptr_t va = virtual_address;

	unsigned short PML4 = (unsigned short)((va >> 39) & 0x1FF);
	uintptr_t PML4E = 0;
	read_physical_memory((cr3 + PML4 * sizeof(uintptr_t)), &PML4E, sizeof(PML4E));

	if (PML4E == 0)
		return 0;

	unsigned short DirectoryPtr = (unsigned short)((va >> 30) & 0x1FF);
	uintptr_t PDPTE = 0;
	read_physical_memory(((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(uintptr_t)), &PDPTE, sizeof(PDPTE));

	if (PDPTE == 0)
		return 0;

	if ((PDPTE & (1 << 7)) != 0)
		return (PDPTE & 0xFFFFFC0000000) + (va & 0x3FFFFFFF);

	unsigned short Directory = (unsigned short)((va >> 21) & 0x1FF);

	uintptr_t PDE = 0;
	read_physical_memory(((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(uintptr_t)), &PDE, sizeof(PDE));

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0)
	{
		return (PDE & 0xFFFFFFFE00000) + (va & 0x1FFFFF);
	}

	unsigned short Table = (unsigned short)((va >> 12) & 0x1FF);
	uintptr_t PTE = 0;

	read_physical_memory(((PDE & 0xFFFFFFFFFF000) + Table * sizeof(uintptr_t)), &PTE, sizeof(PTE));

	if (PTE == 0)
		return 0;

	return (PTE & 0xFFFFFFFFFF000) + (va & 0xFFF);
}

bool wnbios_lib::read_virtual_memory(uintptr_t address, LPVOID output, unsigned long size)
{
	if (!address)
		return false;

	if (!size)
		return false;

	uintptr_t physical_address = convert_virtual_to_physical(address);

	if (!physical_address)
		return false;

	read_physical_memory(physical_address, output, size);
	return true;
}

bool wnbios_lib::write_virtual_memory(uintptr_t address, LPVOID data, unsigned long size)
{
	uintptr_t physical_address = convert_virtual_to_physical(address);

	if (!physical_address)
		return false;

	write_physical_memory(physical_address, data, size);
	return true;
}