#pragma once

#include "GnmCommandBuffer.h"
#include "GnmCommon.h"
#include "GnmRenderState.h"

#include "Gcn/GcnShaderBinary.h"
#include "Violet/VltContextState.h"

namespace sce::Gnm
{
	class GnmShader;
	// This class is designed for graphics development,
	// no reverse engineering knowledge should be required.
	// It's responsible for mapping Gnm input/structures to Violet input/structures,
	// and convert Gnm calls into Violet calls.

	class GnmCommandBufferDraw : public GnmCommandBuffer
	{
	public:
		GnmCommandBufferDraw(vlt::VltDevice* device,
							 SceObjects&     objects);

		virtual ~GnmCommandBufferDraw();

		virtual void initializeDefaultHardwareState() override;

		virtual void setViewportTransformControl(ViewportTransformControl vportControl) override;

		virtual void setPrimitiveSetup(PrimitiveSetup reg) override;

		virtual void setScreenScissor(int32_t left, int32_t top, int32_t right, int32_t bottom) override;

		virtual void setViewport(uint32_t viewportId, float dmin, float dmax, const float scale[3], const float offset[3]) override;

		virtual void setHardwareScreenOffset(uint32_t offsetX, uint32_t offsetY) override;

		virtual void setGuardBands(float horzClip, float vertClip, float horzDiscard, float vertDiscard) override;

		virtual void setPsShaderUsage(const uint32_t* inputTable, uint32_t numItems) override;

		virtual void setActiveShaderStages(ActiveShaderStages activeStages) override;

		virtual void setPsShader(const gcn::PsStageRegisters* psRegs) override;

		virtual void updatePsShader(const gcn::PsStageRegisters* psRegs) override;

		virtual void setVsShader(const gcn::VsStageRegisters* vsRegs, uint32_t shaderModifier) override;

		virtual void setEmbeddedVsShader(EmbeddedVsShader shaderId, uint32_t shaderModifier) override;

		virtual void updateVsShader(const gcn::VsStageRegisters* vsRegs, uint32_t shaderModifier) override;

		virtual void setVsharpInUserData(ShaderStage stage, uint32_t startUserDataSlot, const Buffer* buffer) override;

		virtual void setTsharpInUserData(ShaderStage stage, uint32_t startUserDataSlot, const Texture* tex) override;

		virtual void setSsharpInUserData(ShaderStage stage, uint32_t startUserDataSlot, const Sampler* sampler) override;

		virtual void setPointerInUserData(ShaderStage stage, uint32_t startUserDataSlot, void* gpuAddr) override;

		virtual void setUserDataRegion(ShaderStage stage, uint32_t startUserDataSlot, const uint32_t* userData, uint32_t numDwords) override;

		virtual void setRenderTarget(uint32_t rtSlot, RenderTarget const* target) override;

		virtual void setDepthRenderTarget(DepthRenderTarget const* depthTarget) override;

		virtual void setDepthClearValue(float clearValue) override;

		virtual void setStencilClearValue(uint8_t clearValue) override;

		virtual void setRenderTargetMask(uint32_t mask) override;

		virtual void setBlendControl(uint32_t rtSlot, BlendControl blendControl) override;

		virtual void setDepthStencilControl(DepthStencilControl depthControl) override;

		virtual void setDbRenderControl(DbRenderControl reg) override;

		virtual void setVgtControl(uint8_t primGroupSizeMinusOne) override;

		virtual void setPrimitiveType(PrimitiveType primType) override;

		virtual void setIndexSize(IndexSize indexSize, CachePolicy cachePolicy) override;

		virtual void drawIndexAuto(uint32_t indexCount, DrawModifier modifier) override;

		virtual void drawIndexAuto(uint32_t indexCount) override;

		virtual void drawIndex(uint32_t indexCount, const void* indexAddr, DrawModifier modifier) override;

		virtual void drawIndex(uint32_t indexCount, const void* indexAddr) override;

		virtual void dispatch(uint32_t threadGroupX, uint32_t threadGroupY, uint32_t threadGroupZ) override;

		virtual void dispatchWithOrderedAppend(uint32_t threadGroupX, uint32_t threadGroupY, uint32_t threadGroupZ, DispatchOrderedAppendMode orderedAppendMode) override;

		virtual void writeDataInline(void* dstGpuAddr, const void* data, uint32_t sizeInDwords, WriteDataConfirmMode writeConfirm) override;

		virtual void writeDataInlineThroughL2(void* dstGpuAddr, const void* data, uint32_t sizeInDwords, CachePolicy cachePolicy, WriteDataConfirmMode writeConfirm) override;

		virtual void writeAtEndOfPipe(EndOfPipeEventType eventType, EventWriteDest dstSelector, void* dstGpuAddr, EventWriteSource srcSelector, uint64_t immValue, CacheAction cacheAction, CachePolicy cachePolicy) override;

		virtual void writeAtEndOfPipeWithInterrupt(EndOfPipeEventType eventType, EventWriteDest dstSelector, void* dstGpuAddr, EventWriteSource srcSelector, uint64_t immValue, CacheAction cacheAction, CachePolicy cachePolicy) override;

		virtual void writeAtEndOfShader(EndOfShaderEventType eventType, void* dstGpuAddr, uint32_t immValue) override;

		virtual void waitOnAddress(void* gpuAddr, uint32_t mask, WaitCompareFunc compareFunc, uint32_t refValue) override;

		virtual void waitOnAddressAndStallCommandBufferParser(void* gpuAddr, uint32_t mask, uint32_t refValue) override;

		virtual void flushShaderCachesAndWait(CacheAction cacheAction, uint32_t extendedCacheMask, StallCommandBufferParserMode commandBufferStallMode) override;

		virtual void waitUntilSafeForRendering(uint32_t videoOutHandle, uint32_t displayBufferIndex) override;

		virtual void prepareFlip() override;

		virtual void prepareFlip(void* labelAddr, uint32_t value) override;

		virtual void prepareFlipWithEopInterrupt(EndOfPipeEventType eventType, CacheAction cacheAction) override;

		virtual void prepareFlipWithEopInterrupt(EndOfPipeEventType eventType, void* labelAddr, uint32_t value, CacheAction cacheAction) override;

		virtual void setCsShader(const gcn::CsStageRegisters* computeData, uint32_t shaderModifier) override;

		virtual void setVgtControlForNeo(uint8_t primGroupSizeMinusOne, WdSwitchOnlyOnEopMode wdSwitchOnlyOnEopMode, VgtPartialVsWaveMode partialVsWaveMode) override;

		virtual void waitForGraphicsWrites(uint32_t baseAddr256, uint32_t sizeIn256ByteBlocks, uint32_t targetMask, CacheAction cacheAction, uint32_t extendedCacheMask, StallCommandBufferParserMode commandBufferStallMode) override;

		virtual void setDepthStencilDisable() override;

		virtual void setClipControl(ClipControl reg) override;

		virtual void setDbCountControl(DbCountControlPerfectZPassCounts perfectZPassCounts, uint32_t log2SampleRate) override;

		virtual void setBorderColorTableAddr(void* tableAddr) override;

		virtual void* allocateFromCommandBuffer(uint32_t sizeInBytes, EmbeddedDataAlignment alignment) override;

		virtual void setStencilSeparate(StencilControl front, StencilControl back) override;

		virtual void setCbControl(CbMode mode, RasterOp op) override;

		virtual void setStencilOpControl(StencilOpControl stencilControl) override;

		virtual void triggerEvent(EventType eventType) override;

		virtual void prefetchIntoL2(void* dataAddr, uint32_t sizeInBytes) override;

		virtual void setStencil(StencilControl stencilControl) override;

		virtual void pushMarker(const char* debugString) override;

		virtual void pushMarker(const char* debugString, uint32_t argbColor) override;

		virtual void popMarker() override;

	private:

		void bindIndexBuffer();

		void bindVertexBuffer(
			const Buffer* vsharp, uint32_t binding);

		void bindVertexBuffers(
			gcn::VertexInputSemanticTable& semantic,
			const uint32_t*                vertexTable,
			uint32_t                       bufferCount);

		void updateInputLayout(
			gcn::VertexInputSemanticTable& semantic,
			const uint32_t*                vertexTable,
			uint32_t                       bufferCount);

		void updateIndexBuffer(
			const void* indexAddr,
			uint32_t    indexCount);
		void updateVertexBinding(GnmShader& shader);
		template<bool Indexed>
		void updateVertexShaderStage();
		void updatePixelShaderStage();

		template <bool Indexed>
		void commitGraphicsState();
		void commitComputeState();

		void onPrepareFlip();

		virtual void updateMetaBufferInfo(
			VkPipelineStageFlags stage,
			uint32_t             startRegister,
			const Buffer*        vsharp) override;

		virtual void updateMetaTextureInfo(
			VkPipelineStageFlags stage,
			uint32_t             startRegister,
			bool                 isDepth,
			const Texture*       tsharp) override;

		void clearDepthStencil(
			const vlt::Rc<vlt::VltImageView>& view);

		void applyRenderState();

		void applyPrimitiveTopology();

		void applyBlendState();

		void applyBlendFactor();

		void applyDepthStencilState();

		void applyStencilRef();

		void applyRasterizerState();

		void applyViewportState();

		void appplyRenderTargets();

		void initDefaultRenderState();

		static void initDefaultPrimitiveTopology(
			vlt::VltInputAssemblyState* iaState);

		static void initDefaultRasterizerState(
			vlt::VltRasterizerState* rsState);

		static void initDefaultDepthStencilState(
			vlt::VltDepthStencilState* dsState);

		static void initDefaultBlendState(
			vlt::VltBlendMode*        cbState,
			vlt::VltLogicOpState*     loState,
			vlt::VltMultisampleState* msState);

		const void* findFetchShader(
			const gcn::GcnShaderResourceTable& table,
			const UserDataSlot&                userData);

		bool isSingleVertexBinding(
			const uint32_t*                      vtxTable,
			const gcn::VertexInputSemanticTable& semanticTable);

		vlt::Rc<vlt::VltBuffer> generateIndexBuffer(
			const void* data,
			uint32_t    size);

		vlt::Rc<vlt::VltBuffer> generateIndexBufferAuto(
			uint32_t indexCount);

		vlt::VltRenderTargets      getRenderTargets();
		vlt::Rc<vlt::VltImageView> getColorTarget(
			const RenderTarget& target);
		vlt::Rc<vlt::VltImageView> getDepthTarget(
			const DepthRenderTarget& depthTarget);


	private:
	};

}  // namespace sce::Gnm
