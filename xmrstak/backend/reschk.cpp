/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */

#include "cpu/crypto/cryptonight_aesni.h"

#include "xmrstak/misc/console.hpp"
#include "xmrstak/backend/iBackend.hpp"
#include "xmrstak/backend/globalStates.hpp"
#include "xmrstak/misc/configEditor.hpp"
#include "xmrstak/params.hpp"
#include "cpu/jconf.hpp"

#include "xmrstak/misc/executor.hpp"
#include "reschk.hpp"
#include "xmrstak/jconf.hpp"

#include "cpu/hwlocMemory.hpp"
#include "xmrstak/backend/miner_work.hpp"

#ifndef CONF_NO_HWLOC
#   include "cpu/autoAdjustHwloc.hpp"
#else
#   include "cpu/autoAdjust.hpp"
#endif

#include <assert.h>
#include <cmath>
#include <chrono>
#include <cstring>
#include <thread>
#include <bitset>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>

#if defined(__APPLE__)
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"
#elif defined(__FreeBSD__)
#include <pthread_np.h>
#endif //__APPLE__

#endif //_WIN32

namespace xmrstak
{
namespace cpu
{

#ifdef WIN32
	HINSTANCE lib_handle;
#else
	void *lib_handle;
#endif

bool reschk::thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id)
{
#if defined(_WIN32)
	// we can only pin up to 64 threads
	if(cpu_id < 64)
	{
		return SetThreadAffinityMask(h, 1ULL << cpu_id) != 0;
	}
	else
	{
		printer::inst()->print_msg(L0, "WARNING: Windows supports only affinity up to 63.");
		return false;
	}
#elif defined(__APPLE__)
	thread_port_t mach_thread;
	thread_affinity_policy_data_t policy = { static_cast<integer_t>(cpu_id) };
	mach_thread = pthread_mach_thread_np(h);
	return thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1) == KERN_SUCCESS;
#elif defined(__FreeBSD__)
	cpuset_t mn;
	CPU_ZERO(&mn);
	CPU_SET(cpu_id, &mn);
	return pthread_setaffinity_np(h, sizeof(cpuset_t), &mn) == 0;
#elif defined(__OpenBSD__)
        printer::inst()->print_msg(L0,"WARNING: thread pinning is not supported under OPENBSD.");
        return true;
#else
	cpu_set_t mn;
	CPU_ZERO(&mn);
	CPU_SET(cpu_id, &mn);
	return pthread_setaffinity_np(h, sizeof(cpu_set_t), &mn) == 0;
#endif
}

cryptonight_ctx* reschk::reschk_alloc_ctx()
{
	// we don't need special speed features for this single-result checker
	// just use slow memory and ignore warnings
	return cryptonight_alloc_ctx(0, 0, NULL);
}

static constexpr size_t MAX_N = 1;
bool reschk::self_test()
{
	alloc_msg msg = { 0 };
	size_t res;
	bool fatal = false;

	res = cryptonight_init(0, 0, &msg);

	if(msg.warning != nullptr)
		printer::inst()->print_msg(L0, "MEMORY INIT ERROR: %s", msg.warning);

	if(res == 0 && fatal)
		return false;

	cryptonight_ctx *ctx[MAX_N] = {0};
	for (int i = 0; i < MAX_N; i++)
	{
		if ((ctx[i] = reschk_alloc_ctx()) == nullptr)
		{
			for (int j = 0; j < i; j++)
				cryptonight_free_ctx(ctx[j]);
			return false;
		}
	}

	bool bResult = true;

	if(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo() == cryptonight)
	{
		unsigned char out[32 * MAX_N];
		cn_hash_fun hashf;

		hashf = func_selector(xmrstak_algo::cryptonight);
		hashf("This is a test", 14, out, ctx[0]);
		bResult = memcmp(out, "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9\xb3\x25\x36\x49\xc0\xbe\x66\x05", 32) == 0;

	}
	else if(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo() == cryptonight_lite)
	{
	}
	else if(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo() == cryptonight_monero)
	{
	}
	else if(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo() == cryptonight_aeon)
	{
	}
	else if(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo() == cryptonight_ipbc)
	{
	}
	else if(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo() == cryptonight_stellite)
	{
	}
	else if(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo() == cryptonight_masari)
	{
	}
	else if(::jconf::inst()->GetCurrentCoinSelection().GetDescription(1).GetMiningAlgo() == cryptonight_bittube2)
	{
		unsigned char out[32 * MAX_N];
		cn_hash_fun hashf;

		hashf = func_selector(xmrstak_algo::cryptonight_bittube2);

		hashf("\x38\x27\x4c\x97\xc4\x5a\x17\x2c\xfc\x97\x67\x98\x70\x42\x2e\x3a\x1a\xb0\x78\x49\x60\xc6\x05\x14\xd8\x16\x27\x14\x15\xc3\x06\xee\x3a\x3e\xd1\xa7\x7e\x31\xf6\xa8\x85\xc3\xcb\xff\x01\x02\x03\x04", 48, out, ctx[0]);
		bResult = memcmp(out, "\x18\x2c\x30\x41\x93\x1a\x14\x73\xc6\xbf\x7e\x77\xfe\xb5\x17\x9b\xa8\xbe\xa9\x68\xba\x9e\xe1\xe8\x24\x1a\x12\x7a\xac\x81\xb4\x24", 32) == 0;

		hashf("\x04\x04\xb4\x94\xce\xd9\x05\x18\xe7\x25\x5d\x01\x28\x63\xde\x8a\x4d\x27\x72\xb1\xff\x78\x8c\xd0\x56\x20\x38\x98\x3e\xd6\x8c\x94\xea\x00\xfe\x43\x66\x68\x83\x00\x00\x00\x00\x18\x7c\x2e\x0f\x66\xf5\x6b\xb9\xef\x67\xed\x35\x14\x5c\x69\xd4\x69\x0d\x1f\x98\x22\x44\x01\x2b\xea\x69\x6e\xe8\xb3\x3c\x42\x12\x01", 76, out, ctx[0]);
		bResult = bResult && memcmp(out, "\x7f\xbe\xb9\x92\x76\x87\x5a\x3c\x43\xc2\xbe\x5a\x73\x36\x06\xb5\xdc\x79\xcc\x9c\xf3\x7c\x43\x3e\xb4\x18\x56\x17\xfb\x9b\xc9\x36", 32) == 0;

		hashf("\x85\x19\xe0\x39\x17\x2b\x0d\x70\xe5\xca\x7b\x33\x83\xd6\xb3\x16\x73\x15\xa4\x22\x74\x7b\x73\xf0\x19\xcf\x95\x28\xf0\xfd\xe3\x41\xfd\x0f\x2a\x63\x03\x0b\xa6\x45\x05\x25\xcf\x6d\xe3\x18\x37\x66\x9a\xf6\xf1\xdf\x81\x31\xfa\xf5\x0a\xaa\xb8\xd3\xa7\x40\x55\x89", 64, out, ctx[0]);
		bResult = bResult && memcmp(out, "\x90\xdc\x65\x53\x8d\xb0\x00\xea\xa2\x52\xcd\xd4\x1c\x17\x7a\x64\xfe\xff\x95\x36\xe7\x71\x68\x35\xd4\xcf\x5c\x73\x56\xb1\x2f\xcd", 32) == 0;
	}
	for (int i = 0; i < MAX_N; i++)
		cryptonight_free_ctx(ctx[i]);

	if(!bResult)
		printer::inst()->print_msg(L0,
			"Cryptonight hash self-test failed. This might be caused by bad compiler optimizations.");

	return bResult;
}

reschk::cn_hash_fun reschk::func_selector(xmrstak_algo algo)
{
	// we don't need special speed features for this single-result checker
	bool bHaveAes = false;
	bool bNoPrefetch = true;

	uint8_t algv;
	switch(algo)
	{
	case cryptonight:
		algv = 2;
		break;
	case cryptonight_lite:
		algv = 1;
		break;
	case cryptonight_monero:
		algv = 0;
		break;
	case cryptonight_heavy:
		algv = 3;
		break;
	case cryptonight_aeon:
		algv = 4;
		break;
	case cryptonight_ipbc:
		algv = 5;
		break;
	case cryptonight_stellite:
		algv = 6;
		break;
	case cryptonight_masari:
		algv = 7;
		break;
	case cryptonight_haven:
		algv = 8;
		break;
	case cryptonight_bittube2:
		algv = 9;
		break;
	default:
		algv = 2;
		break;
	}

	static const cn_hash_fun func_table[] = {
		cryptonight_hash<cryptonight_monero, false, false>,
		cryptonight_hash<cryptonight_monero, true, false>,
		cryptonight_hash<cryptonight_monero, false, true>,
		cryptonight_hash<cryptonight_monero, true, true>,
		cryptonight_hash<cryptonight_lite, false, false>,
		cryptonight_hash<cryptonight_lite, true, false>,
		cryptonight_hash<cryptonight_lite, false, true>,
		cryptonight_hash<cryptonight_lite, true, true>,
		cryptonight_hash<cryptonight, false, false>,
		cryptonight_hash<cryptonight, true, false>,
		cryptonight_hash<cryptonight, false, true>,
		cryptonight_hash<cryptonight, true, true>,
		cryptonight_hash<cryptonight_heavy, false, false>,
		cryptonight_hash<cryptonight_heavy, true, false>,
		cryptonight_hash<cryptonight_heavy, false, true>,
		cryptonight_hash<cryptonight_heavy, true, true>,
		cryptonight_hash<cryptonight_aeon, false, false>,
		cryptonight_hash<cryptonight_aeon, true, false>,
		cryptonight_hash<cryptonight_aeon, false, true>,
		cryptonight_hash<cryptonight_aeon, true, true>,
		cryptonight_hash<cryptonight_ipbc, false, false>,
		cryptonight_hash<cryptonight_ipbc, true, false>,
		cryptonight_hash<cryptonight_ipbc, false, true>,
		cryptonight_hash<cryptonight_ipbc, true, true>,
		cryptonight_hash<cryptonight_stellite, false, false>,
		cryptonight_hash<cryptonight_stellite, true, false>,
		cryptonight_hash<cryptonight_stellite, false, true>,
		cryptonight_hash<cryptonight_stellite, true, true>,
		cryptonight_hash<cryptonight_masari, false, false>,
		cryptonight_hash<cryptonight_masari, true, false>,
		cryptonight_hash<cryptonight_masari, false, true>,
		cryptonight_hash<cryptonight_masari, true, true>,
		cryptonight_hash<cryptonight_haven, false, false>,
		cryptonight_hash<cryptonight_haven, true, false>,
		cryptonight_hash<cryptonight_haven, false, true>,
		cryptonight_hash<cryptonight_haven, true, true>,
		cryptonight_hash<cryptonight_bittube2, false, false>,
		cryptonight_hash<cryptonight_bittube2, true, false>,
		cryptonight_hash<cryptonight_bittube2, false, true>,
		cryptonight_hash<cryptonight_bittube2, true, true>
	};

	std::bitset<2> digit;
	digit.set(0, !bHaveAes);
	digit.set(1, !bNoPrefetch);

	return func_table[ algv << 2 | digit.to_ulong() ];
}

} // namespace cpu
} // namespace xmrstak
