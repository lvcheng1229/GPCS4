#include "VltDevice.h"
#include "VltInstance.h"

namespace sce::vlt
{

	VltDevice::VltDevice(
		const Rc<VltInstance>&     instance,
		const Rc<VltAdapter>&      adapter,
		VkDevice                   device,
		const VltDeviceExtensions& extensions,
		const VltDeviceFeatures&   features) :
		m_device(device),
		m_instance(instance),
		m_adapter(adapter),
		m_extensions(extensions),
		m_features(features),
		m_properties(adapter->devicePropertiesExt())
	{
		auto queueFamilies = m_adapter->findQueueFamilies();
		m_queues.graphics  = getQueue(queueFamilies.graphics, 0);
		m_queues.graphics  = getQueue(queueFamilies.compute, 0);
		m_queues.transfer  = getQueue(queueFamilies.transfer, 0);
	}

	VltDevice::~VltDevice()
	{
		// Wait for all pending Vulkan commands to be
		// executed before we destroy any resources.
		this->waitForIdle();
	}

	bool VltDevice::isUnifiedMemoryArchitecture() const
	{
		return m_adapter->isUnifiedMemoryArchitecture();
	}

	VkPipelineStageFlags VltDevice::getShaderPipelineStages() const
	{
		VkPipelineStageFlags result = 
			VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT |
			VK_PIPELINE_STAGE_VERTEX_SHADER_BIT | 
			VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT;

		if (m_features.core.features.geometryShader)
			result |= VK_PIPELINE_STAGE_GEOMETRY_SHADER_BIT;

		if (m_features.core.features.tessellationShader)
		{
			result |= 
				VK_PIPELINE_STAGE_TESSELLATION_CONTROL_SHADER_BIT | 
				VK_PIPELINE_STAGE_TESSELLATION_EVALUATION_SHADER_BIT;
		}

		return result;
	}

	void VltDevice::waitForIdle()
	{
		if (vkDeviceWaitIdle(m_device) != VK_SUCCESS)
			Logger::err("DxvkDevice: waitForIdle: Operation failed");
	}

	//void VltDevice::recycleCommandList(const Rc<DxvkCommandList>& cmdList)
	//{
	//	m_recycledCommandLists.returnObject(cmdList);
	//}

	//void VltDevice::recycleDescriptorPool(const Rc<DxvkDescriptorPool>& pool)
	//{
	//	m_recycledDescriptorPools.returnObject(pool);
	//}

	VltDeviceQueue VltDevice::getQueue(
		uint32_t family,
		uint32_t index) const
	{
		VkQueue queue = VK_NULL_HANDLE;
		vkGetDeviceQueue(m_device, family, index, &queue);
		return VltDeviceQueue{ queue, family, index };
	}

}  // namespace sce::vlt