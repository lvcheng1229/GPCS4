#include "VirtualGPU.h"
#include "Sce/SceVideoOut.h"
#include "Sce/SceGnmDriver.h"
#include "sce_errors.h"
#include "SceUserService/user_service_defs.h"

LOG_CHANNEL(VirtualGPU);

namespace sce
{

VirtualGPU::VirtualGPU()
{
	m_gnmDriver = std::make_unique<SceGnmDriver>();
}

VirtualGPU::~VirtualGPU()
{

}

int VirtualGPU::videoOutOpen(SceUserServiceUserId userId, int32_t type, int32_t index, const void* param)
{
	int result = SCE_ERROR_UNKNOWN;
	const static uint32_t typeIndexTable[SCE_VIDEO_OUT_BUS_TYPE_COUNT] = { 0, 0, 0, 0, 0, 1, 2 };
	do 
	{
		if ((userId != 0 && userId != SCE_USER_SERVICE_USER_ID_SYSTEM) || index != 0)
		{
			// Document states that userId must be SCE_USER_SERVICE_USER_ID_SYSTEM
			// but sample code use 0
			LOG_WARN("invalid userId %d", userId);
			result = SCE_VIDEO_OUT_ERROR_INVALID_VALUE;
			break;
		}

		uint32_t index = typeIndexTable[type];
		if (m_videoOutSlots[index] != nullptr)
		{
			result = SCE_VIDEO_OUT_ERROR_RESOURCE_BUSY;
			break;
		}
		
		m_videoOutSlots[index] = std::make_unique<SceVideoOut>(type, param);

		result = SceVideoOutPortBase + index;
	} while (false);
	return result;
}

int VirtualGPU::videoOutClose(int32_t handle)
{
	uint32_t index = handle - SceVideoOutPortBase;
	m_videoOutSlots[index].reset();
	return SCE_OK;
}

SceVideoOut& VirtualGPU::videoOutGet(int32_t handle)
{
	uint32_t index = handle - SceVideoOutPortBase;
	return *m_videoOutSlots[index];
}


SceGnmDriver& VirtualGPU::gnmDriver()
{
	return *m_gnmDriver;
}

}  // namespace sce