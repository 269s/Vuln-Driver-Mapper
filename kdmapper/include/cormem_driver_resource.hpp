#pragma once
#include <cstdint>

namespace cormem_driver_resource
{
	// This will be populated with the actual Cormem.sys driver binary
	// For now, we'll use an external file reference
	extern const uint8_t driver[];
	extern const size_t driver_size;
}
