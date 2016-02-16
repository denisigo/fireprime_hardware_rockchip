/*
 * Copyright (C) 2010 ARM Limited. All rights reserved.
 *
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define ENABLE_DEBUG_LOG
#include <log/custom_log.h>

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>

#include <cutils/log.h>
#include <cutils/atomic.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>

#include "gralloc_priv.h"
#include "alloc_device.h"
#include "framebuffer_device.h"

#if GRALLOC_ARM_UMP_MODULE
#include <ump/include/ump/ump_ref_drv.h>
static int s_ump_is_open = 0;
#endif

#if GRALLOC_ARM_DMA_BUF_MODULE
#include <linux/ion.h>
#include <ion/ion.h>
#include <sys/mman.h>
#endif
#include <cutils/properties.h>

#define RK_FBIOGET_IOMMU_STA        0x4632
int g_MMU_stat = 0;
#define RK_GRALLOC_VERSION "1.1.5"

static pthread_mutex_t s_map_lock = PTHREAD_MUTEX_INITIALIZER;

static int gralloc_device_open(const hw_module_t *module, const char *name, hw_device_t **device)
{
	int status = -EINVAL;
    property_set("sys.ggralloc.version", RK_GRALLOC_VERSION);
	
    I("to open device '%s' in gralloc_module with ver '%s', built at '%s', on '%s'.",
        name,
        RK_GRALLOC_VERSION,
        __TIME__,
        __DATE__);

#if GRALLOC_ARM_DMA_BUF_MODULE
    int fd;

    fd = open("/dev/graphics/fb0", O_RDONLY, 0);
    if(fd > 0)
    {
        ioctl(fd, RK_FBIOGET_IOMMU_STA, &g_MMU_stat);
        close(fd);
    }
    else
    {
        ALOGE("gralloc_debug fb0 open err in gralloc_device_open!");
    }
#endif

	if (!strcmp(name, GRALLOC_HARDWARE_GPU0))
	{
		status = alloc_device_open(module, name, device);
	}
	else if (!strcmp(name, GRALLOC_HARDWARE_FB0))
	{
		status = framebuffer_device_open(module, name, device);
	}

	return status;
}

static int gralloc_register_buffer(gralloc_module_t const *module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("Registering invalid buffer 0x%x, returning error", (int)handle);
		return -EINVAL;
	}

	// if this handle was created in this process, then we keep it as is.
	private_handle_t *hnd = (private_handle_t *)handle;

	int retval = -EINVAL;


	pthread_mutex_lock(&s_map_lock);

#if GRALLOC_ARM_UMP_MODULE

	if (!s_ump_is_open)
	{
		ump_result res = ump_open(); // MJOLL-4012: UMP implementation needs a ump_close() for each ump_open

		if (res != UMP_OK)
		{
			pthread_mutex_unlock(&s_map_lock);
			AERR("Failed to open UMP library with res=%d", res);
			return retval;
		}

		s_ump_is_open = 1;
	}

#endif

	hnd->pid = getpid();

	if (hnd->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER)
	{
		AERR("Can't register buffer 0x%x as it is a framebuffer", (unsigned int)handle);
	}
	else if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP)
	{
#if GRALLOC_ARM_UMP_MODULE
		hnd->ump_mem_handle = (int)ump_handle_create_from_secure_id(hnd->ump_id);

		if (UMP_INVALID_MEMORY_HANDLE != (ump_handle)hnd->ump_mem_handle)
		{
			hnd->base = (int)ump_mapped_pointer_get((ump_handle)hnd->ump_mem_handle);

			if (0 != hnd->base)
			{
				hnd->lockState = private_handle_t::LOCK_STATE_MAPPED;
				hnd->writeOwner = 0;
				hnd->lockState = 0;

				pthread_mutex_unlock(&s_map_lock);
				return 0;
			}
			else
			{
				AERR("Failed to map UMP handle 0x%x", hnd->ump_mem_handle);
			}

			ump_reference_release((ump_handle)hnd->ump_mem_handle);
		}
		else
		{
			AERR("Failed to create UMP handle 0x%x", hnd->ump_mem_handle);
		}

#else
		AERR("Gralloc does not support UMP. Unable to register UMP memory for handle 0x%x", (unsigned int)hnd);
#endif
	}
	else if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_ION)
	{
#if GRALLOC_ARM_DMA_BUF_MODULE
		int ret;
		unsigned char *mappedAddress;
		size_t size = hnd->size;
		hw_module_t *pmodule = NULL;
		private_module_t *m = NULL;

		if (hw_get_module(GRALLOC_HARDWARE_MODULE_ID, (const hw_module_t **)&pmodule) == 0)
		{
			m = reinterpret_cast<private_module_t *>(pmodule);
		}
		else
		{
			AERR("Could not get gralloc module for handle: 0x%x", (unsigned int)hnd);
			retval = -errno;
			goto cleanup;
		}
        #ifdef USE_X86	
        if (hnd->usage & GRALLOC_USAGE_PROTECTED)  //secrue memery
        {
            pthread_mutex_unlock(&s_map_lock);
            return 0;
        }
        #endif    

		/* the test condition is set to m->ion_client <= 0 here, because:
		 * 1) module structure are initialized to 0 if no initial value is applied
		 * 2) a second user process should get a ion fd greater than 0.
		 */
		if (m->ion_client <= 0)
		{
			/* a second user process must obtain a client handle first via ion_open before it can obtain the shared ion buffer*/
			m->ion_client = ion_open();

			if (m->ion_client < 0)
			{
				AERR("Could not open ion device for handle: 0x%x", (unsigned int)hnd);
				retval = -errno;
				goto cleanup;
			}
		}
		mappedAddress = (unsigned char *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, hnd->share_fd, 0);

		if (MAP_FAILED == mappedAddress)
		{
			AERR("mmap( share_fd:%d ) failed with %s",  hnd->share_fd, strerror(errno));
			retval = -errno;
			goto cleanup;
		}

		hnd->base = intptr_t(mappedAddress) + hnd->offset;
		pthread_mutex_unlock(&s_map_lock);
		return 0;
#endif
	}
	else
	{
		AERR("registering non-UMP buffer not supported. flags = %d", hnd->flags);
	}

cleanup:
	pthread_mutex_unlock(&s_map_lock);
	return retval;
}

static int gralloc_unregister_buffer(gralloc_module_t const *module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("unregistering invalid buffer 0x%x, returning error", (int)handle);
		return -EINVAL;
	}

	private_handle_t *hnd = (private_handle_t *)handle;

	AERR_IF(hnd->lockState & private_handle_t::LOCK_STATE_READ_MASK, "[unregister] handle %p still locked (state=%08x)", hnd, hnd->lockState);

	if (hnd->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER)
	{
		AERR("Can't unregister buffer 0x%x as it is a framebuffer", (unsigned int)handle);
	}
	else if (hnd->pid == getpid()) // never unmap buffers that were not registered in this process
	{
		pthread_mutex_lock(&s_map_lock);

		if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP)
		{
#if GRALLOC_ARM_UMP_MODULE
			ump_mapped_pointer_release((ump_handle)hnd->ump_mem_handle);
			ump_reference_release((ump_handle)hnd->ump_mem_handle);
			hnd->ump_mem_handle = (int)UMP_INVALID_MEMORY_HANDLE;
#else
			AERR("Can't unregister UMP buffer for handle 0x%x. Not supported", (unsigned int)handle);
#endif
		}
		else if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_ION)
		{
#if GRALLOC_ARM_DMA_BUF_MODULE
			void *base = (void *)hnd->base;
			size_t size = hnd->size;
            #ifdef USE_X86	
            if (hnd->usage & GRALLOC_USAGE_PROTECTED)  //secrue memery
            {
                hnd->base = 0;
                hnd->lockState  = 0;
                hnd->writeOwner = 0;
                pthread_mutex_unlock(&s_map_lock);
                return 0;
            }
            #endif    

			if (munmap(base, size) < 0)
			{
				AERR("Could not munmap base:0x%x size:%d '%s'", (unsigned int)base, size, strerror(errno));
			}

#else
			AERR("Can't unregister DMA_BUF buffer for hnd %p. Not supported", hnd);
#endif

		}
		else
		{
			AERR("Unregistering unknown buffer is not supported. Flags = %d", hnd->flags);
		}

		hnd->base = 0;
		hnd->lockState  = 0;
		hnd->writeOwner = 0;

		pthread_mutex_unlock(&s_map_lock);
	}
	else
	{
		AERR("Trying to unregister buffer 0x%x from process %d that was not created in current process: %d", (unsigned int)hnd, hnd->pid, getpid());
	}

	return 0;
}

static int gralloc_lock(gralloc_module_t const *module, buffer_handle_t handle, int usage, int l, int t, int w, int h, void **vaddr)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("Locking invalid buffer 0x%x, returning error", (int)handle);
		return -EINVAL;
	}
      
	private_handle_t *hnd = (private_handle_t *)handle;

	if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP || hnd->flags & private_handle_t::PRIV_FLAGS_USES_ION)
	{
		hnd->writeOwner = usage & GRALLOC_USAGE_SW_WRITE_MASK;
             if ( hnd->flags & private_handle_t::PRIV_FLAGS_USES_ION)
                hnd->writeOwner |= (usage & GRALLOC_USAGE_HW_CAMERA_WRITE);    
	}

	if (usage & GRALLOC_USAGE_PROTECTED) {
		*vaddr = NULL;
	}
	else if (usage & (GRALLOC_USAGE_SW_READ_MASK | GRALLOC_USAGE_SW_WRITE_MASK))
	{
		*vaddr = (void *)hnd->base;
	}
        
	return 0;
}

static int gralloc_unlock(gralloc_module_t const *module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		AERR("Unlocking invalid buffer 0x%x, returning error", (int)handle);
		return -EINVAL;
	}

	private_handle_t *hnd = (private_handle_t *)handle;
	int32_t current_value;
	int32_t new_value;
	int retry;

	if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP && hnd->writeOwner)
	{
#if GRALLOC_ARM_UMP_MODULE
		ump_cpu_msync_now((ump_handle)hnd->ump_mem_handle, UMP_MSYNC_CLEAN_AND_INVALIDATE, (void *)hnd->base, hnd->size);
#else
		AERR("Buffer 0x%x is UMP type but it is not supported", (unsigned int)hnd);
#endif
	}
	else if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_ION && hnd->writeOwner)
	{
#if GRALLOC_ARM_DMA_BUF_MODULE
		hw_module_t *pmodule = NULL;
		private_module_t *m = NULL;

		if (hw_get_module(GRALLOC_HARDWARE_MODULE_ID, (const hw_module_t **)&pmodule) == 0)
		{
			m = reinterpret_cast<private_module_t *>(pmodule);
			ion_sync_fd(m->ion_client, hnd->share_fd);
		}
		else
		{
			AERR("Couldnot get gralloc module for handle 0x%x\n", (unsigned int)handle);
		}

#endif
	}

	return 0;
}

// There is one global instance of the module

int gralloc_lock_ycbcr(gralloc_module_t const* module,
        buffer_handle_t handle, int usage,
        int l, int t, int w, int h,
        struct android_ycbcr *ycbcr)
{
    // this is called when a buffer is being locked for software
    // access. in thin implementation we only fill ycbcr since
    // not synchronization with the h/w is needed.
    // typically this is used to wait for the h/w to finish with
    // this buffer if relevant. the data cache may need to be
    // flushed or invalidated depending on the usage bits and the
    // hardware.

    if (private_handle_t::validate(handle) < 0)
    {
        ALOGE("handle valid");
        return -EINVAL;

    }

    private_handle_t* hnd = (private_handle_t*)handle;
    if (!hnd->base)
    {
        ALOGE("base null");
        return -EINVAL;
    }
    // this is currently only used by camera for yuv420sp
    // if in future other formats are needed, store to private
    // handle and change the below code based on private format.

#if 0    
    int ystride = hnd->stride;
    ycbcr->y  = (void*)hnd->base;
    ycbcr->cr = (void*)(hnd->base + ystride * hnd->height);
    ycbcr->cb = (void*)(hnd->base + ystride * hnd->height + 1);
    ycbcr->ystride = ystride;
    ycbcr->cstride = ystride;
    ycbcr->chroma_step = 2;
    memset(ycbcr->reserved, 0, sizeof(ycbcr->reserved));
#else
    int ystride;
    switch (hnd->format) {
        case HAL_PIXEL_FORMAT_YCrCb_420_SP:
		case HAL_PIXEL_FORMAT_YCrCb_NV12:
		case HAL_PIXEL_FORMAT_YCbCr_420_888:
            ystride = hnd->stride;
            ycbcr->y  = (void*)hnd->base;
            ycbcr->cr = (void*)(hnd->base + ystride * hnd->height);
            ycbcr->cb = (void*)(hnd->base + ystride * hnd->height + 1);
            ycbcr->ystride = ystride;
            ycbcr->cstride = ystride;
            ycbcr->chroma_step = 2;
            memset(ycbcr->reserved, 0, sizeof(ycbcr->reserved));
            break;

        case HAL_PIXEL_FORMAT_YV12:
            ystride = hnd->stride;
            ycbcr->ystride = ystride;
            ycbcr->cstride = (ystride/2 + 15) & ~15;
            ycbcr->y  = (void*)hnd->base;
            ycbcr->cr = (void*)(hnd->base + ystride * hnd->height);
            ycbcr->cb = (void*)(hnd->base + ystride * hnd->height + ycbcr->cstride * hnd->height/2);
            ycbcr->chroma_step = 1;
            memset(ycbcr->reserved, 0, sizeof(ycbcr->reserved));
            break;

        case HAL_PIXEL_FORMAT_YCbCr_422_SP:
            ystride = hnd->stride;
            ycbcr->y  = (void*)hnd->base;
            ycbcr->cb = (void*)(hnd->base + ystride * hnd->height);
            ycbcr->cr = (void*)(hnd->base + ystride * hnd->height + 1);
            ycbcr->ystride = ystride;
            ycbcr->cstride = ystride;
            ycbcr->chroma_step = 2;
            memset(ycbcr->reserved, 0, sizeof(ycbcr->reserved));
            break;
        default:
            ALOGE("%s: Invalid format passed: 0x%x", __FUNCTION__, hnd->format);
            break;
    }
#endif
    return 0;
}
static struct hw_module_methods_t gralloc_module_methods =
{
open:
	gralloc_device_open
};

private_module_t::private_module_t()
{
#define INIT_ZERO(obj) (memset(&(obj),0,sizeof((obj))))

	base.common.tag = HARDWARE_MODULE_TAG;
	base.common.version_major = 1;
	base.common.version_minor = 0;
	base.common.id = GRALLOC_HARDWARE_MODULE_ID;
	base.common.name = "Graphics Memory Allocator Module";
	base.common.author = "ARM Ltd.";
	base.common.methods = &gralloc_module_methods;
	base.common.dso = NULL;
	INIT_ZERO(base.common.reserved);

	base.registerBuffer = gralloc_register_buffer;
	base.unregisterBuffer = gralloc_unregister_buffer;
	base.lock = gralloc_lock;
	base.unlock = gralloc_unlock;
	base.lock_ycbcr = gralloc_lock_ycbcr;
	base.perform = NULL;
	INIT_ZERO(base.reserved_proc);

	framebuffer = NULL;
	flags = 0;
	numBuffers = 0;
	bufferMask = 0;
	pthread_mutex_init(&(lock), NULL);
	currentBuffer = NULL;
	INIT_ZERO(info);
	INIT_ZERO(finfo);
	xdpi = 0.0f;
	ydpi = 0.0f;
	fps = 0.0f;

#undef INIT_ZERO
};

/*
 * HAL_MODULE_INFO_SYM will be initialized using the default constructor
 * implemented above
 */
struct private_module_t HAL_MODULE_INFO_SYM;

