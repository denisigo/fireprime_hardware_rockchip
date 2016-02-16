#ifndef ANDROID_HARDWARE_COMMONTYPE_H
#define ANDROID_HARDWARE_COMMONTYPE_H
//Ŀǰֻ��CameraAdapterΪframe provider��display��event��������frame�󣬿�ͨ������
//��buffer���ظ�CameraAdapter,CameraAdapterʵ�ָýӿڡ�

//����֡��Ϣ����width��height��bufaddr��fmt������֡�������յ�֡������������
//����zoom����Ϣ
typedef struct FramInfo
{
    ulong_t phy_addr;
    ulong_t vir_addr;
    int frame_width;
    int frame_height;
    ulong_t frame_index;
    int frame_fmt;
    int zoom_value;
    ulong_t used_flag;
    int frame_size;
    void* res;
}FramInfo_s;

typedef int (*func_displayCBForIsp)(void* frameinfo,void* cookie);

#endif
