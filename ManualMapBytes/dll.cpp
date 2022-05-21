#include "globals.h"
#include "rawData.h"

void ManualMapper::load_dll()
{
	meDllsize = (sizeof(binary) / sizeof(binary[0]));
	meSuccess("DLL Size: %d", meDllsize);
	meDllCopy = reinterpret_cast<char*>(binary);
	if (!meDllCopy)
		meError("Error allocating memory in local process");
	meSuccess("Allocated memory for dll in local process at: 0x%p", meDllCopy);
}