#pragma once

#include "xmrstak/params.hpp"

#include <stdlib.h>
#include <string>
#if defined(__APPLE__)
#include <OpenCL/cl_platform.h>
#else
#include <CL/cl_platform.h>
#endif

namespace xmrstak
{
namespace amd
{

class jconf
{
public:
	static jconf* inst()
	{
		if (oInst == nullptr) oInst = new jconf;
		return oInst;
	};

	bool parse_config(const char* sFilename = params::inst().configFileAMD.c_str());

	struct thd_cfg {
		cl_uint index;
		cl_uint intensity;
		cl_uint w_size;
		long long cpu_aff;
		int stridedIndex;
		int memChunk;
		bool compMode;
	};

	cl_uint GetThreadCount();
	bool GetThreadConfig(size_t id, thd_cfg &cfg);

	size_t GetPlatformIdx();

private:
	jconf();
	static jconf* oInst;

	struct opaque_private;
	opaque_private* prv;

};

} // namespace amd
} // namespace xmrstak
