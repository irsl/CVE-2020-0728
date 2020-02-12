
#include <iostream>

#include <string>
#include <strsafe.h>

#include <comdef.h>

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
	/* Offset: 0 */ int flgs;
	/* Offset: 4 */ int Member4;
	/* Offset: 8 */ GUID guid;
	/* Offset: 24 */ /* unique */wchar_t* name;
	/* Offset: 32 */ /* unique */wchar_t* ncdata;
};

class __declspec(uuid("8601319a-d7cf-40f3-9025-7f77125453c6")) ISxsStore : public IUnknown {
public:
	virtual HRESULT __stdcall BeginAssemblyInstall(int64_t p0);
	virtual HRESULT __stdcall InstallAssembly(int64_t p0, wchar_t* manifestFile, struct Sxs_Src_Struct* p2, struct Sxs_Dst_Struct* p3);
	virtual HRESULT __stdcall EndAssemblyInstall(int64_t p0, int64_t* p1);
	virtual HRESULT __stdcall UninstallAssembly(int64_t p0, wchar_t* manifestFile, struct Sxs_Src_Struct* p2, int64_t* p3);
};

_COM_SMARTPTR_TYPEDEF(ISxsStore, __uuidof(ISxsStore));
// ----------------------------------------------------------------------------------------------- Sxs Store Class end


void RunManifest(char* manifestFile, BOOL useLastInstaller)
{
	CoInit coinit;

	try
	{
		ISxsStorePtr service = InitRemoteComStuff<ISxsStorePtr>(CLSID_SxsStoreClass);

		uint64_t srcMember0 = 0x0101010010101011;
		Sxs_Src_Struct src;
		src.Member0 = &srcMember0;
		src.Member8 = 0x02020202;
		src.Member10 = const_cast<LPWSTR>(L"src.Member10");
		src.Member18 = const_cast<LPWSTR>(L"src.Member18");
		src.Member20 = const_cast<LPWSTR>(L"src.Member20");


		wchar_t fullManifestPath[MAX_PATH];
		size_t converted;
		size_t cSize = strlen(manifestFile) + 1;
		mbstowcs_s(&converted, fullManifestPath, manifestFile, cSize);

		printf("BeginAssemblyInstall\n");
		ThrowOnError(service->BeginAssemblyInstall(3)); // this could be 0..3 
		if (manifestFile[0] != ':')
		{
			Sxs_Dst_Struct dst;
			dst.flgs = 0x03030303;
			dst.Member4 = 0; // must be zero

			// client = WinMgmt = installer!
			// Info                00000011 The installer id {2ec93463-b0c3-45e1-8364-327e96aea856} is not allowed to install non-sxs components
			/* known guids:
			2ec93463-b0c3-45e1-8364-327e96aea856 - primitive installer
			8CEDC215-AC4B-488B-93C0-A50A49CB2FB8 - primitive installer
			B02F9D65-FB77-4F7A-AFA5-B391309F11C9 - primitive installer
			27DEC61E-B43C-4AC8-88DB-E209A8242D90 - dst.name must be null!, assembly's versionScope must be not nonSxS

			2020-02-02 09:22:01, Error                 CSI    00000050 (F) Illegal advanced installer {81a34a10-4256-436a-89d6-794b97ca407c} found in isolated component[gle=0x80004005]
			*/
			if (useLastInstaller)
			{
				printf("Using last installer (one that does not accept nonSxS stuff)\n");
				CLSIDFromString(L"{27DEC61E-B43C-4AC8-88DB-E209A8242D90}", (LPCLSID)&dst.guid);
				dst.name = NULL; //  const_cast<LPWSTR>(L"some.name"); // name
			}
			else {
				printf("Using first installer (one that requires deployment node to be present)\n");
				CLSIDFromString(L"{8CEDC215-AC4B-488B-93C0-A50A49CB2FB8 }", (LPCLSID)&dst.guid);
				dst.name = const_cast<LPWSTR>(L"some.name"); // name
			}
			


			dst.ncdata = const_cast<LPWSTR>(L"C:\\WINDOWS\\system32\\msiexec.exe"); // ncdata

			/*
			// client = ???
			// https://stackoverflow.com/questions/26657638/unable-to-install-managed-dll-assembly-from-msi-installer-error-1935-hresult-0/26738720
			CLSIDFromString(L"{27dec61e-b43c-4ac8-88db-e209a8242d90}", (LPCLSID)&dst.guid); 
			dst.name = const_cast<LPWSTR>(L""); // name
			dst.ncdata = const_cast<LPWSTR>(L"C:\\WINDOWS\\system32\\msiexec.exe"); // ncdata
			*/

			// yet another hardcoded magic:
// 1001001100000010000000  0x24C080
			int64_t p1 = 0x24c080; // 0x24c080;

			printf("InstallAssembly\n");
			ThrowOnError(service->InstallAssembly(p1, fullManifestPath, &src, &dst));

			/*
11111111 11111111 11101111 11110111  = 0xffffeff7
                     10000 00001000  = 0x1008

Potential flags:
0x1008   1 1           10000 00001000
0x1000   1 0           10000 00000000
0x0008   0 1           00000 00001000

			*/
			int64_t end_install_p0 = 0x1008; // 0x1008 or 0x08 or 0x1000
			int64_t end_install_p1 = 0x0505050505050505;

			printf("EndAssemblyInstall %I64x\n", end_install_p0);
			ThrowOnError(service->EndAssemblyInstall(end_install_p0, &end_install_p1));
			printf("EndAssemblyInstall returned: %I64d\n", end_install_p1);
		}
		else {
			printf("Trigger sent\n");
		}


	}
	catch (const _com_error& error)
	{
		printf("%ls\n", error.ErrorMessage());
		printf("%08X\n", error.Error());
		exit(-3);
	}

}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("Usage: %s c:\\absolute\\path\\to\\file.manifest\nYou can use :: as path to trigger launching a TiWorker.exe process without installing anything\n\n", argv[0]);
		return -1;
	}

	if (argv[1][1] != ':') {
		printf("Use an absolute path.\n");
		return -2;
	}

	RunManifest(argv[1], argc > 2);
}
