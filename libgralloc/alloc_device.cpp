/*
 * Copyright (C) 2010 ARM Limited. All rights reserved.
 *
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <cutils/log.h>
#include <cutils/atomic.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>
#include <sys/ioctl.h>
#include "alloc_device.h"
#include "gralloc_priv.h"
#include "gralloc_helper.h"
#include "framebuffer_device.h"

#if GRALLOC_ARM_UMP_MODULE
#include <ump/include/ump/ump.h>
#include <ump/include/ump/ump_ref_drv.h>
#endif

#if GRALLOC_ARM_DMA_BUF_MODULE
#include <linux/ion.h>
#include <ion/ion.h>
#include <linux/rockchip_ion.h>
#endif

//zxl:for vpu info
#if !GET_VPU_INTO_FROM_HEAD
#include "../libon2/vpu_global.h"
#endif

#define GRALLOC_ALIGN( value, base ) (((value) + ((base) - 1)) & ~((base) - 1))


#include <cutils/properties.h>

#if GRALLOC_SIMULATE_FAILURES
#include <cutils/properties.h>

/* system property keys for controlling simulated UMP allocation failures */
#define PROP_MALI_TEST_GRALLOC_FAIL_FIRST     "mali.test.gralloc.fail_first"
#define PROP_MALI_TEST_GRALLOC_FAIL_INTERVAL  "mali.test.gralloc.fail_interval"

static int __ump_alloc_should_fail()
{

	static unsigned int call_count  = 0;
	unsigned int        first_fail  = 0;
	int                 fail_period = 0;
	int                 fail        = 0;

	++call_count;

	/* read the system properties that control failure simulation */
	{
		char prop_value[PROPERTY_VALUE_MAX];

		if (property_get(PROP_MALI_TEST_GRALLOC_FAIL_FIRST, prop_value, "0") > 0)
		{
			sscanf(prop_value, "%u", &first_fail);
		}

		if (property_get(PROP_MALI_TEST_GRALLOC_FAIL_INTERVAL, prop_value, "0") > 0)
		{
			sscanf(prop_value, "%u", &fail_period);
		}
	}

	/* failure simulation is enabled by setting the first_fail property to non-zero */
	if (first_fail > 0)
	{
		LOGI("iteration %u (fail=%u, period=%u)\n", call_count, first_fail, fail_period);

		fail = (call_count == first_fail) ||
		       (call_count > first_fail && fail_period > 0 && 0 == (call_count - first_fail) % fail_period);

		if (fail)
		{
			AERR("failed ump_ref_drv_allocate on iteration #%d\n", call_count);
		}
	}

	return fail;
}
#endif

//return property value of pcProperty
int hwc_get_int_property(const char* pcProperty, const char* default_value)
{
    char value[PROPERTY_VALUE_MAX];
    int new_value = 0;

    if (pcProperty == NULL || default_value == NULL)
    {
        return -1;
    }

    property_get(pcProperty, value, default_value);
    new_value = atoi(value);

    return new_value;
}


int is_out_log( void )
{
    return hwc_get_int_property("sys.gralloc.log","0");
}
extern int g_MMU_stat;

//static int gralloc_alloc_buffer(alloc_device_t* dev, size_t size, int usage, buffer_handle_t* pHandle, bool reserve)
static int gralloc_alloc_buffer(alloc_device_t* dev, size_t size, int usage, buffer_handle_t* pHandle, int reserve)
{
#if GRALLOC_ARM_DMA_BUF_MODULE
	{
		private_module_t *m = reinterpret_cast<private_module_t *>(dev->common.module);
		ion_user_handle_t ion_hnd;
		unsigned char *cpu_ptr;
		int shared_fd;
		int ret;
		unsigned int heap_mask;
		int Ion_type;
		bool Ishwc = false;
        int Ion_flag = 0;   
        if(usage == (GRALLOC_USAGE_HW_COMPOSER|GRALLOC_USAGE_HW_RENDER))
            Ishwc = true;

		//ret = ion_alloc(m->ion_client, size, 0, ION_HEAP_SYSTEM_MASK, 0, &ion_hnd);
        #ifdef USE_X86	
        
        if(usage & (GRALLOC_USAGE_SW_READ_MASK | GRALLOC_USAGE_SW_WRITE_MASK))
            Ion_flag = (ION_FLAG_CACHED|ION_FLAG_CACHED_NEEDS_SYNC);

        if(is_out_log())
            ALOGD("usage=%x,protect=%x,ion_flag=%x,mmu=%d",usage,GRALLOC_USAGE_PROTECTED,Ion_flag,g_MMU_stat);
        if (usage & GRALLOC_USAGE_PROTECTED)  //secrue memery
        {
            unsigned long phys;
            ret = ion_secure_alloc(m->ion_client, size,&phys);
            //ALOGD("secure_alloc ret=%d,phys=%x",ret,(int)phys);
            if(ret != 0)
            {
                AERR("Failed to ion_alloc from ion_client:%d, size: %d", m->ion_client, size);
                return -1;
            }    
	        private_handle_t *hnd = new private_handle_t(private_handle_t::PRIV_FLAGS_USES_ION, usage, size, 0, 0);

    		if (NULL != hnd)
    		{
    			hnd->share_fd = 0;
    			hnd->ion_hnd = 0;
    			hnd->type = 0;
    			hnd->phy_addr = (int)phys;
    			*pHandle = hnd;
                if(is_out_log())
                    ALOGD("secure_alloc_ok phy=%x",usage,hnd->phy_addr);
    			
    			return 0;
    		}
    		else
    		{
    			AERR("Gralloc out of mem for ion_client:%d", m->ion_client);
    		}

    		close(shared_fd);

    		return -1;
        }
        #endif
		//ret = ion_alloc(m->ion_client, size, 0, ION_HEAP_SYSTEM_MASK, 0, &ion_hnd);
        #ifdef USE_X86		
		if(g_MMU_stat
		    && ((usage&GRALLOC_USAGE_HW_CAMERA_WRITE)==0)
		    && !(usage & GRALLOC_USAGE_PRIVATE_2)
		    && !Ishwc)
        #else
		if(g_MMU_stat)
		#endif
		{
		    heap_mask = ION_HEAP(ION_VMALLOC_HEAP_ID);
            #ifdef USE_X86		
		    if (usage & GRALLOC_USAGE_PRIVATE_2)
		    {
		        heap_mask |=  ION_HEAP(ION_SECURE_HEAP_ID);
		    }
            #endif
		    ret = ion_alloc(m->ion_client, size, 0, heap_mask, Ion_flag, &ion_hnd);
		    Ion_type = 1;
		} else {
		    heap_mask = ION_HEAP(ION_CMA_HEAP_ID);
            #ifdef USE_X86		
		    if (usage & GRALLOC_USAGE_PRIVATE_2)
		    {
		        heap_mask |=  ION_HEAP(ION_SECURE_HEAP_ID);
		    }
            #endif

		    if (usage == (GRALLOC_USAGE_HW_CAMERA_WRITE|GRALLOC_USAGE_SW_READ_OFTEN)) {
                     ret = ion_alloc(m->ion_client, size, 0,heap_mask, 
                        (ION_FLAG_CACHED|ION_FLAG_CACHED_NEEDS_SYNC), &ion_hnd);   
		    } else {
                     ret = ion_alloc(m->ion_client, size, 0,heap_mask, Ion_flag, &ion_hnd);
		    }
            #ifdef USE_X86		
		    if(g_MMU_stat && Ishwc)
		    {
		        Ion_type = 1; 
		    }    
		    else    
		    #endif
		        Ion_type = 0;
		}

		if (ret != 0)
		{
            if( (heap_mask & ION_HEAP(ION_CMA_HEAP_ID))
#ifdef USE_X86
            && !Ishwc
#endif
            )
            {
#ifdef BOARD_WITH_IOMMU
                heap_mask = ION_HEAP(ION_VMALLOC_HEAP_ID);
#else
                heap_mask = ION_HEAP(ION_CARVEOUT_HEAP_ID);
#endif
                ret = ion_alloc(m->ion_client, size, 0, heap_mask, 0, &ion_hnd );
                {
                    if( ret != 0)
                    {
                        AERR("Force to VMALLOC fail ion_client:%d", m->ion_client);
                        return -1;
                    }
                    else
                    {
                        ALOGD("Force to VMALLOC sucess !");
                        Ion_type = 1;
                    }
                }
            }
            else
            {
                AERR("Failed to ion_alloc from ion_client:%d, size: %d", m->ion_client, size);
                return -1;
            }
		}

		ret = ion_share(m->ion_client, ion_hnd, &shared_fd);

		if (ret != 0)
		{
			AERR("ion_share( %d ) failed", m->ion_client);

			if (0 != ion_free(m->ion_client, ion_hnd))
			{
				AERR("ion_free( %d ) failed", m->ion_client);
			}

			return -1;
		}
		cpu_ptr = (unsigned char *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);
		#ifdef USE_X86
		//memset(cpu_ptr, 0, size);
		#endif
		if (MAP_FAILED == cpu_ptr)
		{
			AERR("ion_map( %d ) failed", m->ion_client);

			if (0 != ion_free(m->ion_client, ion_hnd))
			{
				AERR("ion_free( %d ) failed", m->ion_client);
			}

			close(shared_fd);
			return -1;
		}

		private_handle_t *hnd = new private_handle_t(private_handle_t::PRIV_FLAGS_USES_ION, usage, size, (int)cpu_ptr, private_handle_t::LOCK_STATE_MAPPED);

		if (NULL != hnd)
		{
		    unsigned long cma_phys = 0;
			hnd->share_fd = shared_fd;
			hnd->ion_hnd = ion_hnd;
			hnd->type = Ion_type;
			if(!Ion_type)
			{
			    int pret;
			    pret = ion_get_phys(m->ion_client, ion_hnd, &cma_phys);
			    //ALOGD("ion_get_phy ret=%d,cma_phys=%x",pret,cma_phys);
			}    
			    
			hnd->phy_addr = (int)cma_phys;
			*pHandle = hnd;
            if(is_out_log())
                ALOGD("alloc_info fd[%d],type=%d,phy=%x",hnd->share_fd,hnd->type,hnd->phy_addr);
			
			return 0;
		}
		else
		{
			AERR("Gralloc out of mem for ion_client:%d", m->ion_client);
		}

		close(shared_fd);
		ret = munmap(cpu_ptr, size);

		if (0 != ret)
		{
			AERR("munmap failed for base:%p size: %d", cpu_ptr, size);
		}

		ret = ion_free(m->ion_client, ion_hnd);

		if (0 != ret)
		{
			AERR("ion_free( %d ) failed", m->ion_client);
		}

		return -1;
	}
#endif

#if GRALLOC_ARM_UMP_MODULE
	{
		ump_handle ump_mem_handle;
		void *cpu_ptr;
		ump_secure_id ump_id;
		int constraints;

		size = round_up_to_page_size(size);

		if ((usage & GRALLOC_USAGE_SW_READ_MASK) == GRALLOC_USAGE_SW_READ_OFTEN)
		{
			constraints =  UMP_REF_DRV_CONSTRAINT_USE_CACHE;
		}
		else
		{
			constraints = UMP_REF_DRV_CONSTRAINT_NONE;
		}
	    if ( reserve & 0x01)
		{
		
		    constraints |= UMP_REF_DRV_CONSTRAINT_PRE_RESERVE;
		}
		
		if( reserve & 0x02)
		{
            constraints |= UMP_REF_DRV_UK_CONSTRAINT_MEM_SWITCH;

		}
#ifdef GRALLOC_SIMULATE_FAILURES
		/* if the failure condition matches, fail this iteration */
		if (__ump_alloc_should_fail())
		{
			ump_mem_handle = UMP_INVALID_MEMORY_HANDLE;
		}
		else
#endif
		{
			ump_mem_handle = ump_ref_drv_allocate(size, (ump_alloc_constraints)constraints);

			if (UMP_INVALID_MEMORY_HANDLE != ump_mem_handle)
			{
				cpu_ptr = ump_mapped_pointer_get(ump_mem_handle);

				if (NULL != cpu_ptr)
				{
					ump_id = ump_secure_id_get(ump_mem_handle);

					if (UMP_INVALID_SECURE_ID != ump_id)
					{
						private_handle_t *hnd = new private_handle_t(private_handle_t::PRIV_FLAGS_USES_UMP, usage, size, (int)cpu_ptr,
						private_handle_t::LOCK_STATE_MAPPED, ump_id, ump_mem_handle);

						if (NULL != hnd)
						{
						#ifdef  USE_LCDC_COMPOSER
            		 		if( reserve & 0x02)
					  		{
	                    		hnd->phy_addr = 0;   
					  		}
					  		else
					  		{
                    		    hnd->phy_addr = ump_phy_addr_get(ump_mem_handle);        
                    		}   
                    	#endif
							*pHandle = hnd;
							return 0;
						}
						else
						{
							AERR("gralloc_alloc_buffer() failed to allocate handle. ump_handle = %p, ump_id = %d", ump_mem_handle, ump_id);
						}
					}
					else
					{
						AERR("gralloc_alloc_buffer() failed to retrieve valid secure id. ump_handle = %p", ump_mem_handle);
					}

					ump_mapped_pointer_release(ump_mem_handle);
				}
				else
				{
					AERR("gralloc_alloc_buffer() failed to map UMP memory. ump_handle = %p", ump_mem_handle);
				}

				ump_reference_release(ump_mem_handle);
			}
			else
			{
				AERR("gralloc_alloc_buffer() failed to allocate UMP memory. size:%d constraints: %d", size, constraints);
			}
		}
		return -1;
	}
#endif

}

static int gralloc_alloc_framebuffer_locked(alloc_device_t *dev, size_t size, int usage, buffer_handle_t *pHandle)
{
	private_module_t *m = reinterpret_cast<private_module_t *>(dev->common.module);

	// allocate the framebuffer
	if (m->framebuffer == NULL)
	{
		// initialize the framebuffer, the framebuffer is mapped once and forever.
		int err = init_frame_buffer_locked(m);

		if (err < 0)
		{
			return err;
		}
	}

	const uint32_t bufferMask = m->bufferMask;
	const uint32_t numBuffers = m->numBuffers;
	const size_t bufferSize = m->finfo.line_length * m->info.yres;

	if (numBuffers == 1)
	{
		// If we have only one buffer, we never use page-flipping. Instead,
		// we return a regular buffer which will be memcpy'ed to the main
		// screen when post is called.
		int newUsage = (usage & ~GRALLOC_USAGE_HW_FB) | GRALLOC_USAGE_HW_2D;
		AERR("fallback to single buffering. Virtual Y-res too small %d", m->info.yres);
		return gralloc_alloc_buffer(dev, bufferSize, newUsage, pHandle, false);
	}

	if (bufferMask >= ((1LU << numBuffers) - 1))
	{
		// We ran out of buffers.
		return -ENOMEM;
	}

	int vaddr = m->framebuffer->base;

	// find a free slot
	for (uint32_t i = 0 ; i < numBuffers ; i++)
	{
		if ((bufferMask & (1LU << i)) == 0)
		{
			m->bufferMask |= (1LU << i);
			break;
		}

		vaddr += bufferSize;
	}

	ALOGV("vaddr=%x",vaddr);
	// The entire framebuffer memory is already mapped, now create a buffer object for parts of this memory
	private_handle_t *hnd = new private_handle_t(private_handle_t::PRIV_FLAGS_FRAMEBUFFER, usage, size, vaddr,
	        0, dup(m->framebuffer->fd), vaddr - m->framebuffer->base);
#if GRALLOC_ARM_UMP_MODULE
	hnd->ump_id = m->framebuffer->ump_id;

	/* create a backing ump memory handle if the framebuffer is exposed as a secure ID */
	if ((int)UMP_INVALID_SECURE_ID != hnd->ump_id)
	{
		hnd->ump_mem_handle = (int)ump_handle_create_from_secure_id(hnd->ump_id);

		if ((int)UMP_INVALID_MEMORY_HANDLE == hnd->ump_mem_handle)
		{
			AINF("warning: unable to create UMP handle from secure ID %i\n", hnd->ump_id);
		}
	}

#endif

#if GRALLOC_ARM_DMA_BUF_MODULE
	{
        int share_fd = -1;
        if (ioctl(m->framebuffer->fd, /*FBIOGET_DMABUF*/0x5003, &share_fd) == 0)
        {
            AINF("framebuffer accessed with dma buf (fd 0x%x)\n", (int)share_fd);
            hnd->share_fd = share_fd;
        }
	}
#endif

	*pHandle = hnd;

	return 0;
}

static int gralloc_alloc_framebuffer(alloc_device_t *dev, size_t size, int usage, buffer_handle_t *pHandle)
{
	private_module_t *m = reinterpret_cast<private_module_t *>(dev->common.module);
	pthread_mutex_lock(&m->lock);
	int err = gralloc_alloc_framebuffer_locked(dev, size, usage, pHandle);
	pthread_mutex_unlock(&m->lock);
	return err;
}

static unsigned int memsizealloc = 0;
static int alloc_device_alloc(alloc_device_t *dev, int w, int h, int format, int usage, buffer_handle_t *pHandle, int *pStride)
{
	if (!pHandle || !pStride)
	{
		return -EINVAL;
	}

	size_t size;
	size_t stride;
	size_t bpr = 0;
	int reserve = true;
	int fmt_bak = format;
	bool fmt_chg = false;

    #ifdef USE_X86	

	if(format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED  )
	{
	    if(usage & GRALLOC_USAGE_HW_VIDEO_ENCODER )
	    {
	        //ALOGD("(usage & GRALLOC_USAGE_HW_VIDEO_ENCODER treat as NV12");
	        format = HAL_PIXEL_FORMAT_YCrCb_NV12;
	    }
	    else
	    {
	        //ALOGD("treat as NV12 888");
	        format = HAL_PIXEL_FORMAT_RGBX_8888;
	        fmt_chg = true;	        
	    }
	}
	#endif
	if (format == HAL_PIXEL_FORMAT_YCrCb_420_SP
                        || format == HAL_PIXEL_FORMAT_YV12
						|| format == HAL_PIXEL_FORMAT_YCrCb_NV12
						|| format == HAL_PIXEL_FORMAT_YCrCb_NV12_VIDEO
						|| format == HAL_PIXEL_FORMAT_YCbCr_420_888) 	
	{
        int align = 8;
        int bpp = 0;
        char property[PROPERTY_VALUE_MAX];
		int gpuformat = HAL_PIXEL_FORMAT_RGB_565;
		switch (format)
		{
			case HAL_PIXEL_FORMAT_YCrCb_420_SP:
			case HAL_PIXEL_FORMAT_YV12:
			case HAL_PIXEL_FORMAT_YCbCr_420_888:
				stride = GRALLOC_ALIGN(w, 16);
				size = h * (stride + GRALLOC_ALIGN(stride / 2, 16));
				break;
			case HAL_PIXEL_FORMAT_YCrCb_NV12:
				//stride = GRALLOC_ALIGN(w, 16);
				//size = h * (stride + GRALLOC_ALIGN(stride/2,16));
				bpp = 2;
	            bpr = (w*bpp + (align-1)) & ~(align-1);
				size = bpr * h;
				stride = bpr / bpp;				

				break;
			case HAL_PIXEL_FORMAT_YCrCb_NV12_VIDEO:
                property_set("sys.gmali.performance","video");
				bpp = 2;

				if (property_get("sys.yuv.rgb.format", property, NULL) > 0) {
					gpuformat = atoi(property);
				}
				if(gpuformat == HAL_PIXEL_FORMAT_RGBA_8888 || gpuformat == HAL_PIXEL_FORMAT_RGBX_8888)
					bpp = 4;
				else if(gpuformat == HAL_PIXEL_FORMAT_RGB_565)
					bpp = 2;
				
				bpr = (w*bpp + (align-1)) & ~(align-1);
#if GET_VPU_INTO_FROM_HEAD
				size = bpr * h;
#else
                //zxl:add tVPU_FRAME at the end of allocated buffer
                size = bpr * h + sizeof(tVPU_FRAME);
#endif
				stride = bpr / bpp;

				break;
			default:
				return -EINVAL;
		}
	}
	else
	{
		int align = 8;
		int bpp = 0;

		switch (format)
		{
			case HAL_PIXEL_FORMAT_RGBA_8888:
			case HAL_PIXEL_FORMAT_RGBX_8888:
			case HAL_PIXEL_FORMAT_BGRA_8888:
			case HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED:
				bpp = 4;
				break;

			case HAL_PIXEL_FORMAT_RGB_888:
				bpp = 3;
				break;

			case HAL_PIXEL_FORMAT_RGB_565:
			case HAL_PIXEL_FORMAT_YCbCr_422_I:
			case HAL_PIXEL_FORMAT_YCbCr_422_SP:
			case HAL_PIXEL_FORMAT_RAW_SENSOR:
#if PLATFORM_SDK_VERSION < 18
			case HAL_PIXEL_FORMAT_RGBA_5551:
			case HAL_PIXEL_FORMAT_RGBA_4444:
#endif
				bpp = 2;
				break;
			case HAL_PIXEL_FORMAT_BLOB:
				bpp = 1;
				break;
			default:
				return -EINVAL;
		}

	int w_e = w, h_e = h;

#ifdef USE_LCDC_COMPOSER

        if (!(usage & GRALLOC_USAGE_HW_FB)) {
        #ifndef LCDC_COMPOSER_LANDSCAPE_ONLY
            private_module_t* m = reinterpret_cast<private_module_t*>(dev->common.module);
            uint32_t rot = (usage & GRALLOC_USAGE_ROT_MASK) >> 24;
            int bar = 0;    
           
            if(rot & 0x08) {
                rot &= ~0x08;
                switch(rot) {
                case 0:
                case HAL_TRANSFORM_ROT_180:
                    bar = m->info.yres - h;            
                    //ALOGD("bar=%d",bar);
           
                    if((w == m->info.xres) && (bar > 0) && (bar < 100)) {
                        if(0 == rot)
                            h_e += bar;
                        else
                            reserve = true;
                    }

                    //ALOGI("rot=%d [0/180]bar=%d,w=%d,h=%d,w_e=%d,h_e=%d",rot,bar,w,h,w_e,h_e);
                    break;
                case HAL_TRANSFORM_ROT_90:
                case HAL_TRANSFORM_ROT_270:
                    bar = m->info.xres - w;
                    if((h == m->info.yres) && (bar > 0) && (bar < 100)) {
                        w_e += bar;
                    }
                    if (rot == HAL_TRANSFORM_ROT_270)
                    {
						 reserve = true;
                    }

                   // ALOGI("rot=%d  [90/270]bar=%d,w=%d,h=%d,w_e=%d,h_e=%d",rot,bar,w,h,w_e,h_e);

                    break;
                default:
                    break;
                }
            }
            else
            {
                int bar_h;
                int bar_w;
                bar_h = m->info.yres - h;   
                bar_w = m->info.xres - w;
                    //ALOGD("bar=%d",bar);           
                if((w == m->info.xres) && (bar_h > 0) && (bar_h < 100)) 
                {
                     h_e += bar_h;
                }
                else if((h == m->info.yres) && (bar_w > 0) && (bar_w < 100))
                {
                     w_e += bar_w;
                }
                reserve = true;

               // ALOGI("[other rot=%x]bar_w=%d,bar_h=%d,w=%d,h=%d,w_e=%d,h_e=%d",rot,bar_w,bar_h,w,h,w_e,h_e);                            
            }
            //ALOGD("rot[%d]: %d x %d => %d x %d, reserve=%d", rot, w, h, w_e, h_e, (int)reserve);
        #else
            h_e += 100;
        #endif
        }
        if(w_e % 16) {
            //ALOGD("alloc_device_alloc, w[%d] not align, aligned to %d", w_e, (w + 31) & (~31));
            w_e = (w + 15) & (~15);
        }
#endif
		if (!(usage & GRALLOC_USAGE_HW_FB))
		{
			//zxl:fix failed of cts DecodeEditEncodeTest
			if(usage == 0x10702)
			{
				if(w_e % 32) {
					w_e=GRALLOC_ALIGN(w_e,32);
				}
			}
			else
			{
				if(w_e % 16) {
					w_e=GRALLOC_ALIGN(w_e,16);
				}
			}
		}
		else
		{
		    if(w_e % 32) 
		    {
				w_e=GRALLOC_ALIGN(w_e,32);
			}
		}

	//	bpr = (w_e*bpp + (align-1)) & ~(align-1);
	 	bpr = GRALLOC_ALIGN(w_e * bpp, 64);
		size = bpr * h_e;
		stride = bpr / bpp;

		if (format == HAL_PIXEL_FORMAT_BLOB) {
			bpp = 1;
			size = w*h;
			stride = w;
			if (GRALLOC_USAGE_HW_CAMERA_WRITE & usage) {
				/* take count from private usage flags */
				int count = (usage & GRALLOC_USAGE_PRIVATE_MASK ) >> 28;
				size += count * GRALLOC_EXTRA_ALLOCATION_UNIT_SIZE;
			}
		}
		
	}

	int err;
	char memstr[100] = {0,};
#ifndef MALI_600

	if (usage & GRALLOC_USAGE_HW_FB)
	{
		err = gralloc_alloc_framebuffer(dev, size, usage, pHandle);
	}
	else
#endif

	{
		#ifdef USE_LCDC_COMPOSER	
	    if(usage == (GRALLOC_USAGE_HW_TEXTURE | GRALLOC_USAGE_SW_WRITE_OFTEN | GRALLOC_USAGE_SW_READ_OFTEN ))
	    {
	        reserve |= 0x02;  // force Brower GraphicBufferAllocator to logics memery
	    }
	    #endif
		err = gralloc_alloc_buffer(dev, size  , usage, pHandle, reserve);
		#ifdef USE_LCDC_COMPOSER
		if( err == 0)
		{
			memsizealloc += size;
			sprintf(memstr,"%d KB",memsizealloc/1024);
			property_set("sys.memsize",memstr);
		}
		else if(!(reserve & 0x02))
		{
		    ALOGW("phy alloc fail ,alloc second time2");
		    err = gralloc_alloc_buffer(dev, size , usage, pHandle, reserve | 0x02);
		    ALOGW(" second alloc err=%d",err);		
		}
		#endif
	}

	if (err < 0)
	{
		return err;
	}

	/* match the framebuffer format */
	if (usage & GRALLOC_USAGE_HW_FB)
	{
		format = HAL_PIXEL_FORMAT_BGRA_8888;
	}

	private_handle_t *hnd = (private_handle_t *)*pHandle;
	int               private_usage = usage & (GRALLOC_USAGE_PRIVATE_0 |
	                                  GRALLOC_USAGE_PRIVATE_1);

	switch (private_usage)
	{
		case 0:
			hnd->yuv_info = MALI_YUV_BT601_NARROW;
			break;

		case GRALLOC_USAGE_PRIVATE_1:
			hnd->yuv_info = MALI_YUV_BT601_WIDE;
			break;

		case GRALLOC_USAGE_PRIVATE_0:
			hnd->yuv_info = MALI_YUV_BT709_NARROW;
			break;

		case (GRALLOC_USAGE_PRIVATE_0 | GRALLOC_USAGE_PRIVATE_1):
			hnd->yuv_info = MALI_YUV_BT709_WIDE;
			break;
	}

	hnd->width = w;
	hnd->height = h;
	hnd->format = fmt_chg ? fmt_bak:format;
	hnd->stride = stride;

    if(is_out_log())
        ALOGD("alloc_device_alloc_ok [%d,%d,%d]",w,h,hnd->format);

	*pStride = stride;
	return 0;
}

static int alloc_device_free(alloc_device_t *dev, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		return -EINVAL;
	}

	private_handle_t const *hnd = reinterpret_cast<private_handle_t const *>(handle);

    if (hnd->format == HAL_PIXEL_FORMAT_YCrCb_NV12_VIDEO)
    {
        property_set("sys.gmali.performance","ui");
    }
	if (hnd->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER)
	{
		// free this buffer
		private_module_t *m = reinterpret_cast<private_module_t *>(dev->common.module);
		const size_t bufferSize = m->finfo.line_length * m->info.yres;
		int index = (hnd->base - m->framebuffer->base) / bufferSize;
		m->bufferMask &= ~(1 << index);
		close(hnd->fd);

#if GRALLOC_ARM_UMP_MODULE

		if ((int)UMP_INVALID_MEMORY_HANDLE != hnd->ump_mem_handle)
		{
			ump_reference_release((ump_handle)hnd->ump_mem_handle);
		}

#endif
	}
	else if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP)
	{
#if GRALLOC_ARM_UMP_MODULE
		int align = 8;
		int bpp = 0;
		int w, h;
		size_t size;
		char memstr[100] = {0,};

		/* Buffer might be unregistered so we need to check for invalid ump handle*/
		if ((int)UMP_INVALID_MEMORY_HANDLE != hnd->ump_mem_handle)
		{
			ump_mapped_pointer_release((ump_handle)hnd->ump_mem_handle);
			ump_reference_release((ump_handle)hnd->ump_mem_handle);
		}
		#ifdef USE_LCDC_COMPOSER

		w = hnd->width;
		h = hnd->height; 	 

		switch (hnd->format)
		{
			case HAL_PIXEL_FORMAT_RGBA_8888:
			case HAL_PIXEL_FORMAT_RGBX_8888:
			case HAL_PIXEL_FORMAT_BGRA_8888:
				bpp = 4;
				break;
			case HAL_PIXEL_FORMAT_RGB_888:
				bpp = 3;
				break;
			case HAL_PIXEL_FORMAT_RGB_565:
				bpp = 2;
				break;
			case HAL_PIXEL_FORMAT_YCrCb_NV12_VIDEO:
				bpp = 2;
				break;
			default:
				return -EINVAL;
		}
	 	size_t bpr = GRALLOC_ALIGN(w * bpp, 64);
		
		size = bpr * h ;
		memsizealloc -= size;
		sprintf(memstr,"%d KB",memsizealloc/1024);
		property_set("sys.memsize",memstr);		
		#endif
#else
		AERR("Can't free ump memory for handle:0x%x. Not supported.", (unsigned int)hnd);
#endif
	}
	else if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_ION)
	{
#if GRALLOC_ARM_DMA_BUF_MODULE
		private_module_t *m = reinterpret_cast<private_module_t *>(dev->common.module);

		/* Buffer might be unregistered so we need to check for invalid ump handle*/
		if (0 != hnd->base)
		{
			if (0 != munmap((void *)hnd->base, hnd->size))
			{
				AERR("Failed to munmap handle 0x%x", (unsigned int)hnd);
			}
		}

        #ifdef USE_X86	
        if (hnd->usage & GRALLOC_USAGE_PROTECTED)  //secrue memery
        {
            if (0 != ion_secure_free(m->ion_client, hnd->size,(unsigned long)hnd->phy_addr))
            {
                AERR("Failed to ion_free( ion_client: %d [%d,%d] )", m->ion_client, hnd->size,hnd->phy_addr);
            }
            memset((void *)hnd, 0, sizeof(*hnd));      
            return 0;
        }
        #endif    
		close(hnd->share_fd);

		if (0 != ion_free(m->ion_client, hnd->ion_hnd))
		{
			AERR("Failed to ion_free( ion_client: %d ion_hnd: %p )", m->ion_client, hnd->ion_hnd);
		}

		memset((void *)hnd, 0, sizeof(*hnd));
#else
		AERR("Can't free dma_buf memory for handle:0x%x. Not supported.", (unsigned int)hnd);
#endif

	}

	delete hnd;

	return 0;
}

static int alloc_device_close(struct hw_device_t *device)
{
	alloc_device_t *dev = reinterpret_cast<alloc_device_t *>(device);

	if (dev)
	{
#if GRALLOC_ARM_DMA_BUF_MODULE
		private_module_t *m = reinterpret_cast<private_module_t *>(device->module);

		if (0 != ion_close(m->ion_client))
		{
			AERR("Failed to close ion_client: %d", m->ion_client);
		}

		close(m->ion_client);
#endif
		delete dev;
#if GRALLOC_ARM_UMP_MODULE
		ump_close(); // Our UMP memory refs will be released automatically here...
#endif
	}

	return 0;
}

int alloc_device_open(hw_module_t const *module, const char *name, hw_device_t **device)
{
	alloc_device_t *dev;

	dev = new alloc_device_t;

	if (NULL == dev)
	{
		return -1;
	}

#if GRALLOC_ARM_UMP_MODULE
	ump_result ump_res = ump_open();

	if (UMP_OK != ump_res)
	{
		AERR("UMP open failed with %d", ump_res);
		delete dev;
		return -1;
	}

#endif

	/* initialize our state here */
	memset(dev, 0, sizeof(*dev));

	/* initialize the procs */
	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 0;
	dev->common.module = const_cast<hw_module_t *>(module);
	dev->common.close = alloc_device_close;
	dev->alloc = alloc_device_alloc;
	dev->free = alloc_device_free;

#if GRALLOC_ARM_DMA_BUF_MODULE
	private_module_t *m = reinterpret_cast<private_module_t *>(dev->common.module);
	m->ion_client = ion_open();

	if (m->ion_client < 0)
	{
		AERR("ion_open failed with %s", strerror(errno));
		delete dev;
		return -1;
	}

#endif

	*device = &dev->common;

	return 0;
}
