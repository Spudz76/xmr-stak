#pragma once

#include "xmrstak/jconf.hpp"
#include "cpu/crypto/cryptonight.h"
#include "xmrstak/backend/miner_work.hpp"
#include "xmrstak/backend/iBackend.hpp"

#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <future>


namespace xmrstak
{
namespace cpu
{

class reschk : public iBackend
{
public:

	static bool self_test();

	typedef void (*cn_hash_fun)(const void*, size_t, void*, cryptonight_ctx*);

	static cn_hash_fun func_selector(xmrstak_algo algo);
	static bool thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id);

	static cryptonight_ctx* reschk_alloc_ctx();

};

} // namespace cpu
} // namespace xmrstak
