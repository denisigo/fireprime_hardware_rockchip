/*

* rockchip hwcomposer( 2D graphic acceleration unit) .

*

* Copyright (C) 2015 Rockchip Electronics Co., Ltd.

*/




#ifndef __rk_hwcomposer_h_
#define __rk_hwcomposer_h_

/* Set 0 to enable LOGV message. See cutils/log.h */
#include <cutils/log.h>

#include <hardware/hwcomposer.h>
//#include <ui/android_native_buffer.h>

#include <hardware/rga.h>
#include <utils/Thread.h>
#include <linux/fb.h>
#include <hardware/rk_fh.h>
#include "hwc_ipp.h"
#include <vpu_global.h>


#define hwcDEBUG                0
#define hwcUseTime              0
#define hwcBlitUseTime          0
#define hwcDumpSurface          0
#define  ENABLE_HWC_WORMHOLE    1
#define  DUMP_SPLIT_AREA        0
#define FB1_IOCTL_SET_YUV_ADDR	0x5002
#define RK_FBIOSET_VSYNC_ENABLE 0x4629
//#define USE_LCDC_COMPOSER
#define USE_HW_VSYNC            1
#define FBIOSET_OVERLAY_STATE   0x5018
#define bakupbufsize            4
#define FB_BUFFERS_NUM          (3)
#define EN_VIDEO_UI_MIX         0
#define ONLY_USE_FB_BUFFERS     (0)  //zxl:If close this macro,you need remove hasBlitComposition condition in DisplayDevice::swapBuffers

#ifdef TARGET_BOARD_PLATFORM_RK30XXB
 #define GPU_BASE           handle->iBase
 #define GPU_WIDTH          handle->iWidth
 #define GPU_HEIGHT         handle->iHeight
 #define GPU_FORMAT         handle->iFormat
 #define GPU_DST_FORMAT     DstHandle->iFormat
 #define private_handle_t   IMG_native_handle_t
#else
 #define GPU_BASE           handle->base
 #define GPU_WIDTH          handle->width
 #define GPU_HEIGHT         handle->height
 #define GPU_FORMAT         handle->format
 #define GPU_DST_FORMAT     DstHandle->format
#endif
#define rkmALIGN(n, align) \
( \
    ((n) + ((align) - 1)) & ~((align) - 1) \
)


/** 属性 sys.video.fullscreen 的有效取值. */
#define VIDEO_UI            (1)     // 有 UI 要显示
#define VIDEO_FULLSCREEN    (2)     // 全屏视屏

#define GHWC_VERSION  "1.23"
//HWC version Tag
//Get commit info:  git log --format="Author: %an%nTime:%cd%nCommit:%h%n%n%s%n%n"
//Get version: busybox strings /system/lib/hw/hwcomposer.rk30board.so | busybox grep HWC_VERSION
//HWC_VERSION Author:zxl Time:Tue Aug 12 17:27:36 2014 +0800 Version:1.17 Branch&Previous-Commit:rk/rk312x/mid/4.4_r1/develop-9533348.
#define HWC_VERSION "HWC_VERSION  \
Author:zxl \
Previous-Time:Fri Nov 28 17:11:15 2014 +0800 \
Version:1.23 \
Branch&Previous-Commit:rk/rk312x/mid/4.4_r1/develop-46aa4e4."

/* Set it to 1 to enable swap rectangle optimization;
 * Set it to 0 to disable. */
/* Set it to 1 to enable pmem cache flush.
 * For linux kernel 3.0 later, you may not be able to flush PMEM cache in a
 * different process (surfaceflinger). Please add PMEM cache flush in gralloc
 * 'unlock' function, which will be called in the same process SW buffers are
 * written/read by software (Skia) */

#ifdef __cplusplus
extern "C" {
#endif


#if PLATFORM_SDK_VERSION >= 17

#define  hwc_layer_list_t	 	hwc_display_contents_1_t
#endif
enum
{
    /* NOTE: These enums are unknown to Android.
     * Android only checks against HWC_FRAMEBUFFER.
     * This layer is to be drawn into the framebuffer by hwc blitter */
    //HWC_TOWIN0 = 0x10,
    //HWC_TOWIN1,
    HWC_BLITTER = 100,
    HWC_DIM,
    HWC_CLEAR_HOLE
    
};


typedef enum _hwcSTATUS
{
	hwcSTATUS_OK					= 	 0,
	hwcSTATUS_INVALID_ARGUMENT      =   -1,
	hwcSTATUS_IO_ERR 			    = 	-2,
	hwcRGA_OPEN_ERR                 =   -3,
	hwcTHREAD_ERR                   =   -4,
	hwcMutex_ERR                    =   -5,

}
hwcSTATUS;

typedef struct _hwcRECT
{
    int                    left;
    int                    top;
    int                    right;
    int                    bottom;
}
hwcRECT;

typedef struct _hwbkupinfo
{
    buffer_handle_t phd_bk;
    int membk_fd;
    int buf_fd;
    unsigned int pmem_bk;
    unsigned int buf_addr;
    void* pmem_bk_log;
    void* buf_addr_log;
    int xoffset;
    int yoffset;
    int w_vir;
    int h_vir;
    int w_act;
    int h_act;
    int format;
}
hwbkupinfo;
typedef struct _hwbkupmanage
{
    int count;
    buffer_handle_t phd_drt;
    int          direct_fd;
    unsigned int direct_addr;
    void* direct_addr_log;    
    int invalid;
    int needrev;
    int dstwinNo;
    int skipcnt;
    unsigned int ckpstcnt;
    unsigned int inputspcnt;    
	char LayerName[LayerNameLength + 1];    
    unsigned int crrent_dis_fd;
    hwbkupinfo bkupinfo[bakupbufsize];
    struct private_handle_t *handle_bk;
}
hwbkupmanage;

#define MaxMixUICnt 6
typedef struct _videomix
{
    int mixflag;
    int uicnt;
    int addr[MaxMixUICnt];
    int alpha[MaxMixUICnt];

}
videomix;



/* Area struct. */
struct hwcArea
{
    /* Area potisition. */
    hwcRECT                          rect;

    /* Bit field, layers who own this Area. */
    int                        owners;

    /* Point to next area. */
    struct hwcArea *                 next;
};


/* Area pool struct. */
struct hwcAreaPool
{
    hwcArea *                        areas;

    hwcArea *                        freeNodes;

    hwcAreaPool *                    next;
};

struct DisplayAttributes {
    uint32_t vsync_period; //nanos
    uint32_t xres;
    uint32_t yres;
    uint32_t stride;
    float xdpi;
    float ydpi;
    int fd;
	int fd1;
	int fd2;
	int fd3;
    bool connected; //Applies only to pluggable disp.
    //Connected does not mean it ready to use.
    //It should be active also. (UNBLANKED)
    bool isActive;
    // In pause state, composition is bypassed
    // used for WFD displays only
    bool isPause;
};

typedef struct tVPU_FRAME_v2
{
    uint32_t          FrameBusAddr[2];    // 0: Y address; 1: UV address;
    uint32_t         FrameWidth;         // 16 aligned frame width
    uint32_t         FrameHeight;        // 16 aligned frame height
};

typedef struct 
{
   tVPU_FRAME vpu_frame;
   void*      vpu_handle;
} vpu_frame_t;

typedef struct
{
  //ion_buffer_t *pion;
  //ion_device_t *ion_device; 
  unsigned int  offset;
  unsigned int  last_offset;
} hwc_ion_t;
typedef struct _hwcContext
{
    hwc_composer_device_1_t device;

    /* Reference count. Normally: 1. */
    unsigned int reference;


    /* Raster engine */
    int   engine_fd;
    /* Feature: 2D PE 2.0. */
    /* Base address. */
    unsigned int baseAddress;

    /* Framebuffer stuff. */
    int       fbFd;
    int       fbFd1;
    int       vsync_fd;
    int       fbWidth;
    int       fbHeight;
    bool      fb1_cflag;
    char      cupcore_string[16];
    DisplayAttributes              dpyAttr[HWC_NUM_DISPLAY_TYPES];
     struct                         fb_var_screeninfo info;
    hwc_procs_t *procs;
    ipp_device_t *ippDev;
    pthread_t hdmi_thread;
    pthread_mutex_t lock;
    nsecs_t         mNextFakeVSync;
    float           fb_fps;
    unsigned int fbPhysical;
    unsigned int fbStride;
	int          wfdOptimize;
    /* PMEM stuff. */
    unsigned int pmemPhysical;
    unsigned int pmemLength;
	  vpu_frame_t  video_frame[2];
	  unsigned int fbSize;
	  unsigned int lcdSize;
	  char *pbakupbuf[bakupbufsize];
#if ENABLE_HWC_WORMHOLE
    /* Splited composition area queue. */
    hwcArea *                        compositionArea;

    /* Pre-allocated area pool. */
    hwcAreaPool                      areaMem;
#endif
    int     flag;
    int     fb_blanked;
    bool    IsRk3188;
    bool    IsRk3126;
    int     IsInput;
    int     mFbFd;
    int     mFbBase;
    alloc_device_t  *mAllocDev;
    int membk_fds[FB_BUFFERS_NUM];
    int membk_base[FB_BUFFERS_NUM];
    int membk_type[FB_BUFFERS_NUM];
    
    int membk_index;
    int membk_last_index;
    buffer_handle_t phd_bk;
    unsigned long phy_addr;
    struct private_handle_t fbhandle ;
}
hwcContext;

#define hwcMIN(x, y)			(((x) <= (y)) ?  (x) :  (y))
#define hwcMAX(x, y)			(((x) >= (y)) ?  (x) :  (y))

#define hwcIS_ERROR(status)			(status < 0)


#define _hwcONERROR(prefix, func) \
    do \
    { \
        status = func; \
        if (hwcIS_ERROR(status)) \
        { \
            LOGD( "ONERROR: status=%d @ %s(%d) in ", \
                status, __FUNCTION__, __LINE__); \
            goto OnError; \
        } \
    } \
    while (false)
#define hwcONERROR(func)            _hwcONERROR(hwc, func)

#ifdef  ALOGD
#define LOGV        ALOGV
#define LOGE        ALOGE
#define LOGD        ALOGD
#define LOGI        ALOGI
#endif
/******************************************************************************\
 ********************************* Blitters ***********************************
\******************************************************************************/

/* 2D blit. */
hwcSTATUS
hwcBlitRga(
     hwcContext * Context,
     hwc_layer_1_t * Src,
     struct private_handle_t * DstHandle,
     hwc_rect_t * SrcRect,
     hwc_rect_t * DstRect,
     hwc_region_t * Region
    );


hwcSTATUS
hwcDimRga(
     hwcContext * Context,
     hwc_layer_1_t * Src,
     struct private_handle_t * DstHandle,
     hwc_rect_t * DstRect,
     hwc_region_t * Region
    );

hwcSTATUS
hwcLayerToWin(
    hwcContext * Context,
    hwc_layer_1_t * Src,
    struct private_handle_t * DstHandle,
    hwc_rect_t * SrcRect,
	hwc_rect_t * DstRect,
    hwc_region_t * Region,
    int Index,
    int Win,
    struct rk_fb_win_cfg_data* pFbInfo
    );
hwcSTATUS
hwcClearRga(
    hwcContext * Context,
    unsigned int Color,
    hwc_layer_1_t * Src,
    struct private_handle_t * DstHandle,
    hwc_rect_t * DstRect,
    hwc_region_t * Region
    );


/******************************************************************************\
 ************************** Native buffer handling ****************************
\******************************************************************************/

hwcSTATUS
hwcGetBufFormat(
      struct private_handle_t * Handle,
     RgaSURF_FORMAT * Format
    );

hwcSTATUS
hwcGetBufferInfo(
      hwcContext *  Context,
      struct private_handle_t * Handle,
     void * *  Logical,
     unsigned int* Physical,
     unsigned int* Width,
     unsigned int* Height,
     unsigned int* Stride,
     void * *  Info
    );



int
_HasAlpha(RgaSURF_FORMAT Format);

int closeFb(int fd);
int  getHdmiMode();
void init_hdmi_mode();
/******************************************************************************\
 ****************************** Rectangle split *******************************
\******************************************************************************/
/* Split rectangles. */


hwcSTATUS
WormHole(
     hwcContext * Context,
     hwcRECT * Rect
    );

void
ZoneFree(
     hwcContext * Context,
     hwcArea* Head
    );

void
DivArea(
     hwcContext * Context,
     hwcArea * Area,
     hwcRECT * Rect,
     int Owner
    );

hwcArea *
zone_alloc(
     hwcContext * Context,
     hwcArea * Slibing,
     hwcRECT * Rect,
     int Owner
    );



extern "C" int clock_nanosleep(clockid_t clock_id, int flags,
                           const struct timespec *request,
                           struct timespec *remain);

#ifdef __cplusplus
}
#endif

#endif 

