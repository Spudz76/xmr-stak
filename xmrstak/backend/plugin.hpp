#pragma once

#include "xmrstak/misc/environment.hpp"
#include "xmrstak/params.hpp"

#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include "iBackend.hpp"
#include <iostream>

#ifndef USE_PRECOMPILED_HEADERS
#	ifdef WIN32
#		include <direct.h>
#		include <windows.h>
#	else
#		include <sys/types.h>
#		include <dlfcn.h>
#	endif
#	include <iostream>
#endif

namespace xmrstak
{

struct plugin
{

	plugin(const std::string backendName, const std::string libName) : fn_testBackend(nullptr), fn_startBackend(nullptr), m_backendName(backendName)
	{
#ifdef WIN32
		libBackend = LoadLibrary(TEXT((libName + ".dll").c_str()));
		if(!libBackend)
		{
			std::cerr << "WARNING: "<< m_backendName <<" cannot load backend library: " << (libName + ".dll") << std::endl;
			return;
		}
#else
		// `.so` linux file extention for dynamic libraries
		std::string fileExtension = ".so";
#	if defined(__APPLE__)
		// `.dylib` Mac OS X file extention for dynamic libraries
		fileExtension = ".dylib";
#	endif
		// search library in working directory
		libBackend = dlopen(("./lib" + libName + fileExtension).c_str(), RTLD_LAZY);
		// fallback to binary directory
		if(!libBackend)
			libBackend = dlopen((params::inst().executablePrefix + "lib" + libName + fileExtension).c_str(), RTLD_LAZY);
		// try use LD_LIBRARY_PATH
		if(!libBackend)
			libBackend = dlopen(("lib" + libName + fileExtension).c_str(), RTLD_LAZY);
		if(!libBackend)
		{
			std::cerr << "WARNING: "<< m_backendName <<" cannot load backend library: " << dlerror() << std::endl;
			return;
		}
#endif

#ifdef WIN32
		fn_testBackend = (testBackend_t) GetProcAddress(libBackend, "xmrstak_test_backend");
		if (!fn_testBackend)
		{
			std::cerr << "WARNING: backend plugin " << libName << " contains no entry 'xmrstak_test_backend': " <<GetLastError()<< std::endl;
		}
		fn_startBackend = (startBackend_t) GetProcAddress(libBackend, "xmrstak_start_backend");
		if (!fn_startBackend)
		{
			std::cerr << "WARNING: backend plugin " << libName << " contains no entry 'xmrstak_start_backend': " <<GetLastError()<< std::endl;
		}
#else
		const char* dlsym_error;
		// reset last error
		dlerror();
		fn_testBackend = (testBackend_t) dlsym(libBackend, "xmrstak_test_backend");
		dlsym_error = dlerror();
		if(dlsym_error)
		{
			std::cerr << "WARNING: backend plugin " << libName << " contains no entry 'xmrstak_test_backend': " << dlsym_error << std::endl;
		}
		// reset last error
		dlerror();
		fn_startBackend = (startBackend_t) dlsym(libBackend, "xmrstak_start_backend");
		dlsym_error = dlerror();
		if(dlsym_error)
		{
			std::cerr << "WARNING: backend plugin " << libName << " contains no entry 'xmrstak_start_backend': " << dlsym_error << std::endl;
		}
#endif
	}

	bool testBackend(environment& env)
	{
		if(fn_testBackend == nullptr)
			return true;
		return fn_testBackend(env);
	}

	std::vector<iBackend*>* startBackend(uint32_t threadOffset, miner_work& pWork, environment& env)
	{
		if(fn_startBackend == nullptr)
		{
			std::vector<iBackend*>* pvThreads = new std::vector<iBackend*>();
			std::cerr << "WARNING: " << m_backendName << " Backend disabled"<< std::endl;
			return pvThreads;
		}

		return fn_startBackend(threadOffset, pWork, env);
	}

	std::string m_backendName;

	typedef bool (*testBackend_t)(environment& env);
	typedef std::vector<iBackend*>* (*startBackend_t)(uint32_t threadOffset, miner_work& pWork, environment& env);

	testBackend_t fn_testBackend;
	startBackend_t fn_startBackend;

#ifdef WIN32
	HINSTANCE libBackend;
#else
	void *libBackend;
#endif

/* \todo add unload to destructor and change usage of plugin that libs kept open until the miner ends
#ifdef WIN32
	FreeLibrary(libBackend);
#else
	dlclose(libBackend);
#endif
 * */
};

} // namespace xmrstak
