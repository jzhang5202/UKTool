# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:9:04
# 设备管理

from ctypes import c_bool, c_uint, pointer, c_ulong, byref


from utils.constant import DEVINFO, ArrChar100, szNameList, LABEL
from utils.globals import g
from utils.guomi import gm
from utils.logs import logger
from crypto_service.message import code_to_str, Message
from PyQt5.QtWidgets import QWidget, QInputDialog, QFileDialog

class Device(QWidget):
    def SKF_EnumDev(self):
        try:
            bPresent = c_bool(True)
            pulSize = pointer(c_uint(128))
            code = gm.SKF_EnumDev(bPresent, szNameList, pulSize)
            if 0 == code and szNameList.value != b'':
                logger.info(Message.ENUMERATE_DEV_SUCCESS + str(szNameList.value))
                g.textBrowser.append(Message.ENUMERATE_DEV_SUCCESS + str(szNameList.value))
            else:
                logger.error(Message.ENUMERATE_DEV_FAILED + code_to_str(code))
                g.textBrowser.append(Message.ENUMERATE_DEV_FAILED + code_to_str(code))
        except BaseException as e:
            logger.exception(e)

    def SKF_ConnectDev(self):
        code = gm.SKF_ConnectDev(szNameList, byref(g.phDev))
        if 0 == code:
            logger.info(Message.CONNECT_DEV_SUCCESS + code_to_str(code))
            g.textBrowser.append(Message.CONNECT_DEV_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.CONNECT_DEV_FAILED + code_to_str(code))
            g.textBrowser.append(Message.CONNECT_DEV_FAILED + code_to_str(code))


    def SKF_DisConnectDev(self):
        code = gm.SKF_DisConnectDev(g.phDev)
        if 0 == code:
            logger.info(Message.DISCONNECT_DEV_SUCCESS + code_to_str(code))
            g.textBrowser.append(Message.DISCONNECT_DEV_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.DISCONNECT_DEV_FAILED + code_to_str(code))
            g.textBrowser.append(Message.DISCONNECT_DEV_FAILED + code_to_str(code))


    def SKF_GetDevState(self):
        szDevName = szNameList.value
        pulDevState = c_ulong()
        code = gm.SKF_GetDevState(szDevName, byref(pulDevState))
        if 0 == code:
            if pulDevState.value == 0x01:
                logger.info(Message.DEV_STATUS_TRUE + code_to_str(code))
                g.textBrowser.append(Message.DEV_STATUS_TRUE + code_to_str(code))
            elif pulDevState.value == 0x0:
                logger.info(Message.DEV_STATUS_FALSE)
                g.textBrowser.append(Message.DEV_STATUS_FALSE)
        else:
            g.textBrowser.append(Message.GET_DEV_STATUS_FAILED + code_to_str(code))
            logger.error(Message.GET_DEV_STATUS_FAILED + code_to_str(code))


    def SKF_SetLabel(self):
        set_label = LABEL
        code = gm.SKF_SetLabel(g.phDev, set_label.encode())
        if 0 == code:
            g.textBrowser.append(Message.SET_DEV_LABEL_SUCCESS + code_to_str(code))
            logger.info(Message.SET_DEV_LABEL_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.SET_DEV_LABEL_FAILED + code_to_str(code))
            logger.error(Message.SET_DEV_LABEL_FAILED + code_to_str(code))


    def SKF_GetDevInfo(self):
        devInfo = DEVINFO()
        code = gm.SKF_GetDevInfo(g.phDev, byref(devInfo))
        if 0 == code:
            g.textBrowser.append(Message.GET_DEV_INFO_SUCCESS + code_to_str(code))
            g.textBrowser.append(
                "设备厂商信息: %s" % devInfo.Manufacturer.decode()
                + "\n" + "应用发行者信恿: %s" % devInfo.Issuer.decode()
                + "\n" + "设备标签: %s" % devInfo.Label.decode()
                + "\n" + "序列号: %s" % devInfo.SerialNumber
                + "\n" + "设备硬件版本: %02x%02x" % (devInfo.HWVersion.major, devInfo.HWVersion.minor)
                + "\n" + "设备本身固件版本: %02x%02x" % (devInfo.FirmwareVersion.major, devInfo.FirmwareVersion.minor)
                + "\n" + "分组密码算法标识: 0x%08x" % devInfo.AlgSymCap
                + "\n" + "非对称密码算法标识: 0x%08x" % devInfo.AlgAsymCap
                + "\n" + "密码杂凑算法标识: 0x%08x" % devInfo.AlgHashCap
                + "\n" + "设备认证使用的分组算法标识: 0x%08x" % devInfo.DevAuthAlgId
                + "\n" + "设备总空间大小: 0x%08x" % devInfo.TotalSpace
                + "\n" + "用户可用空间大小: 0x%08x" % devInfo.FreeSpace
                + "\n" + "MaxECCBufferSize: 0x%08x" % devInfo.MaxECCBufferSize
                + "\n" + "MaxBufferSize: 0x%08x" % devInfo.MaxBufferSize)
            logger.info(Message.GET_DEV_INFO_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.GET_DEV_INFO_FAILED + code_to_str(code))
            logger.error(Message.GET_DEV_INFO_FAILED + code_to_str(code))


    def SKF_LockDev(self):
        ulTimeOut = c_ulong(0x0000EA60)
        code = gm.SKF_LockDev(g.phDev, ulTimeOut)
        if 0 == code:
            g.textBrowser.append(Message.LOCK_DEV_SUCCESS + code_to_str(code))
            logger.info(Message.LOCK_DEV_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.LOCK_DEV_FAILED + code_to_str(code))
            logger.error(Message.LOCK_DEV_FAILED + code_to_str(code))


    def SKF_UnlockDev(self):
        code = gm.SKF_UnlockDev(g.phDev)
        if 0 == code:
            g.textBrowser.append(Message.UNLOCK_DEV_SUCCESS + code_to_str(code))
            logger.info(Message.UNLOCK_DEV_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.UNLOCK_DEV_FAILED + code_to_str(code))
            logger.error(Message.UNLOCK_DEV_FAILED + code_to_str(code))


    def SKF_WaitForDevEvent(self):
        pulDevNameLen = c_ulong()
        pulEvent = c_ulong()
        szDevName = ArrChar100()
        code = gm.SKF_WaitForDevEvent(szDevName, byref(pulDevNameLen), byref(pulEvent))
        if 0 == code:
            g.textBrowser.append(Message.WAITING_DEV_ACTION + code_to_str(code))
            logger.info(Message.WAITING_DEV_ACTION + code_to_str(code))
            if pulEvent.value == 1:
                g.textBrowser.append(Message.DEV_INSERT + code_to_str(pulEvent.value))
                logger.info(Message.DEV_INSERT + code_to_str(pulEvent.value))
            else:
                g.textBrowser.append(Message.DEV_PULLOUT + code_to_str(pulEvent.value))
                logger.info(Message.DEV_PULLOUT + code_to_str(pulEvent.value))
        else:
            g.textBrowser.append(Message.WAITING_DEV_FAILED + code_to_str(code))
            logger.error(Message.WAITING_DEV_FAILED + code_to_str(code))


    def SKF_CancelWaitForDevEvent(self):
        code = gm.SKF_CancelWaitForDevEvent()
        if 0 == code:
            g.textBrowser.append(Message.CANCEL_WAITING_DEV_ACTION + code_to_str(code))
            logger.info(Message.CANCEL_WAITING_DEV_ACTION + code_to_str(code))
        else:
            g.textBrowser.append(Message.CANCEL_WAITING_DEV_FAILED + code_to_str(code))
            logger.error(Message.CANCEL_WAITING_DEV_FAILED + code_to_str(code))
