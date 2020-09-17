#include <Windows.h>
#include <stdio.h>
#include "urmem/urmem.hpp"

#define FS_INVALID_FILE	0xFFFFFFFF

class IArchiveFS
{
public:
	virtual ~IArchiveFS() = 0;
	virtual bool Load(const char* szFileName) = 0;
	virtual void Unload() = 0;
	virtual DWORD GetFileIndex(const char* szFileName) = 0;
	virtual DWORD GetFileSize(DWORD dwFileIndex) = 0;
	virtual BYTE* GetFileData(DWORD dwFileIndex) = 0;
	virtual bool LoadFromMemory(BYTE* pbData, DWORD nLength) = 0;
	virtual DWORD GetFileIndexFromHash(DWORD dwFileHash) = 0;
	virtual void UnloadData(DWORD dwFileIndex) = 0;
};

const char* GetKnownFileName(IArchiveFS *pFileSystem, DWORD dwFileIndex)
{
	static const char* knownFileNames[] = {
		"ar_stats.dat",
		"bindat.bin",
		"carmods.dat",
		"default.dat",
		"default.ide",
		"gta.dat",
		"handling.cfg",
		"lan2.ide",
		"law2.ide",
		"laxref.ide",
		"loadscs.txd",
		"loadscv.txd",
		"logo.png",
		"main.scm",
		"melee.dat",
		"object.dat",
		"ped.dat",
		"peds.ide",
		"props.ide",
		"script.img",
		"shopping.dat",
		"stream.ini",
		"surface.dat",
		"timecyc.dat",
		"tracks2.dat",
		"tracks4.dat",
		"vehicle.txd",
		"vehicles.ide",
		"weapon.dat"
	};

	for (int i = 0; i != _countof(knownFileNames); ++i) {
		const char* szFileName = knownFileNames[i];

		if (dwFileIndex == pFileSystem->GetFileIndex(szFileName)) {
			return szFileName;
		}
	}
	return nullptr;
}

HANDLE WINAPI Detour_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	return 0;
}


LPCSTR WINAPI Detour_GetCommandLineA(void)
{
	return "-c";
}

HMODULE LoadSAMPDll()
{
	urmem::hook hook_CreateThread(
		(urmem::address_t)GetProcAddress(GetModuleHandleW(L"kernel32"), "CreateThread"),
		urmem::get_func_addr(Detour_CreateThread)
	);
	urmem::hook hook_GetCommandLineA(
		(urmem::address_t)GetProcAddress(GetModuleHandleW(L"kernel32"), "GetCommandLineA"),
		urmem::get_func_addr(Detour_GetCommandLineA)
	);

	return LoadLibraryW(L"samp.dll");
}

IArchiveFS* GetArchiveFSInstance(HMODULE hSAMPDll)
{
	// pFileSystem @ CSpawnScreen::RestoreDeviceObjects
	static const char* szPattern = "\x8B\x0D\x00\x00\x00\x00\x8B\x11\x68\x6B\xEA\xDD\xBA\xFF\x52\x1C";
	static const char* szMask = "xx????xxxxxxxxxx";

	urmem::sig_scanner sigScanner;
	urmem::address_t addr;

	if (!sigScanner.init((urmem::address_t)hSAMPDll) || 
		!sigScanner.find(szPattern, szMask, addr)) {
		return nullptr;
	}

	return **(IArchiveFS***)(addr + 2);
}

void DumpFile(IArchiveFS *pFileSystem, DWORD dwFileIndex, DWORD dwFileHash, const char *szDirectory)
{
	const char* szKnownName = GetKnownFileName(pFileSystem, dwFileIndex);
	BYTE* pFileData = pFileSystem->GetFileData(dwFileIndex);
	DWORD dwFileSize = pFileSystem->GetFileSize(dwFileIndex);
	char szExportedFileName[MAX_PATH];
	FILE* pFile = nullptr;

	if (szKnownName)
		sprintf_s(szExportedFileName, "%s/%s", szDirectory, szKnownName);
	else
		sprintf_s(szExportedFileName, "%s/0x%X", szDirectory, dwFileHash);

	if (!pFileData) {
		printf("Damaged SAA2 entry: %s (0x%X)\n", szKnownName, dwFileHash);
		return;
	}

	if (!fopen_s(&pFile, szExportedFileName, "wb") && pFile) {
		fwrite(pFileData, 1, dwFileSize, pFile);
		fclose(pFile);

		printf("Exported: %s (0x%X)\n", szExportedFileName, dwFileHash);
	}
	else {
		printf("Can't open file for write: %s (0x%X)\n", szExportedFileName, dwFileHash);
	}
}

void DumpArchive(IArchiveFS* pFileSystem, const char* szDirectory)
{
	puts("--- SAA2 dump started ---");

	CreateDirectoryA(szDirectory, nullptr);
	for (DWORD dwFileHash = 0; dwFileHash != 0xFFFFFFFF; dwFileHash++) {
		DWORD dwFileIndex = pFileSystem->GetFileIndexFromHash(dwFileHash);

		if (dwFileIndex != FS_INVALID_FILE) {
			DumpFile(pFileSystem, dwFileIndex, dwFileHash, szDirectory);
		}
	}

	puts("--- SAA2 dump finished ---");
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		puts("USAGE: samp-saa2-extract [output directory]");
		return 0;
	}

	HMODULE hSAMPDll = LoadSAMPDll();
	if (!hSAMPDll) {
		puts("Can't load samp.dll");
		puts("Make sure all SA-MP dependencies are met (samp.saa, bass.dll and d3dx9_25.dll)");
		return 0;
	}

	IArchiveFS* pFileSystem = GetArchiveFSInstance(hSAMPDll);
	if (!pFileSystem) {
		puts("pFileSystem instance not found");
		return 0;
	}

	DumpArchive(pFileSystem, argv[1]);
	return 0;
}
