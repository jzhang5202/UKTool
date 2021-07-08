# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:11:22
# 容器管理

from ctypes import byref, pointer, c_ulong, c_void_p, POINTER, c_char_p, c_uint

from utils.constant import Arr2048, szContainerName, CONTAINER_NAME, CER_FILE_PATH, SIGN_CER_TYPE
from utils.globals import g
from utils.guomi import gm
from utils.logs import logger
from crypto_service.message import code_to_str, Message
from PyQt5.QtWidgets import QWidget, QInputDialog

class Container(QWidget):
    def SKF_CreateContainer(self):
        gm.SKF_CreateContainer.argtypes = [c_void_p, c_char_p, POINTER(c_void_p)]
        # container_name = input("输入容器名(默认dmsUK1)：")
        # if not container_name:
        container_name = CONTAINER_NAME
        code = gm.SKF_CreateContainer(g.phApplication, container_name.encode(), g.phContainer)
        if 0 == code:
            g.textBrowser.append(Message.CREATE_CONTAINER_SUCCESS + code_to_str(code))
            logger.info(Message.CREATE_CONTAINER_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.CREATE_CONTAINER_FAILED + code_to_str(code))
            logger.error(Message.CREATE_CONTAINER_FAILED + code_to_str(code))


    def SKF_DeleteContainer(self):
        # container_name = input("输入容器名(默认dmsUK1)：")
        # if not container_name:
        container_name = CONTAINER_NAME
        code = gm.SKF_DeleteContainer(g.phApplication, container_name.encode())
        if 0 == code:
            g.textBrowser.append(Message.DEL_CONTAINER_SUCCESS + code_to_str(code))
            logger.info(Message.DEL_CONTAINER_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DEL_CONTAINER_FAILED + code_to_str(code))
            logger.error(Message.DEL_CONTAINER_FAILED + code_to_str(code))


    def SKF_OpenContainer(self):
        gm.SKF_OpenContainer.argtypes = [c_void_p, c_char_p, POINTER(c_void_p)]
        container_name = CONTAINER_NAME
        code = gm.SKF_OpenContainer(g.phApplication, container_name.encode(), g.phContainer)
        if 0 == code:
            g.textBrowser.append(Message.OPEN_CONTAINER_SUCCESS + code_to_str(code))
            logger.info(Message.OPEN_CONTAINER_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.OPEN_CONTAINER_FAILED + code_to_str(code))
            logger.error(Message.OPEN_CONTAINER_FAILED + code_to_str(code))


    def SKF_CloseContainer(self):
        code = gm.SKF_CloseContainer(g.phContainer)
        if 0 == code:
            g.textBrowser.append(Message.CLOSE_CONTAINER_SUCCESS + code_to_str(code))
            logger.info(Message.CLOSE_CONTAINER_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.CLOSE_CONTAINER_FAILED + code_to_str(code))
            logger.error(Message.CLOSE_CONTAINER_FAILED + code_to_str(code))


    def SKF_GetContainerType(self):
        pulContainerType = c_ulong()
        code = gm.SKF_GetContainerType(g.phApplication, szContainerName, byref(pulContainerType))
        if 0 == code:
            g.textBrowser.append(Message.GET_CONTAINER_TYPE_SUCCESS + code_to_str(code))
            logger.info(Message.GET_CONTAINER_TYPE_SUCCESS + code_to_str(code))
            if pulContainerType.value == 2:
                g.textBrowser.append("容器类型为ECC容器:2")
                # logger.info("容器类型为ECC容器:2")
            elif pulContainerType.value == 1:
                g.textBrowser.append("容器类型为RSA容器:1")
            elif pulContainerType.value == 0:
                g.textBrowser.append("未定、尚未分配类型或者为空容器未定:0")
        else:
            g.textBrowser.append(Message.GET_CONTAINER_TYPE_FAILED + code_to_str(code))
            logger.error(Message.GET_CONTAINER_TYPE_FAILED + code_to_str(code))


    def SKF_EnumContainer(self):
        pulSize = pointer(c_uint())
        code = gm.SKF_EnumContainer(g.phApplication, szContainerName, pulSize)
        if 0 == code:
            g.textBrowser.append(Message.ENUM_CONTAINER_SUCCESS + code_to_str(code) + repr(szContainerName.raw.decode()))
            logger.info(Message.ENUM_CONTAINER_SUCCESS + code_to_str(code) + repr(szContainerName.raw.decode()))
        else:
            g.textBrowser.append(Message.ENUM_CONTAINER_FAILED + code_to_str(code))
            logger.error(Message.ENUM_CONTAINER_FAILED + code_to_str(code))


    def SKF_ImportCertificate(self):
        pbCert = Arr2048()
        # path = input("输入.cer文件路径：")
        path = CER_FILE_PATH
        try:
            with open(path, 'rb+') as f:
                sr = f.read()
        except BaseException as e:
            g.textBrowser.append("当前工作目录没有找到证书！")
            logger.exception(e)
        arr = list(sr)
        for i, d in enumerate(arr):
            pbCert[i] = d
        # bSignFlag = input("输入证书类型：").strip()
        bSignFlag = SIGN_CER_TYPE
        # while not bSignFlag:
        #     g.textBrowser.append("输入无效！0数字证书 or 1签名证书...")
        #     logger.warning("输入无效！0数字证书 or 1签名证书...")
        #     bSignFlag = input("输入证书类型：").strip()
        ulCertLen = len(arr)
        code = gm.SKF_ImportCertificate(g.phContainer, int(bSignFlag), byref(pbCert), ulCertLen)
        if code == 0 and int(bSignFlag) == 1:
            g.textBrowser.append("导入签名证书成功，code=" + code_to_str(code))
            logger.info("导入签名证书成功，code=" + code_to_str(code))
        elif code == 0 and int(bSignFlag) == 0:
            g.textBrowser.append("导入加密证书成功，code=" + code_to_str(code))
            logger.info("导入加密证书成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("导入数字证书失败，code=" % code_to_str(code))
            logger.error("导入数字证书失败，code=" % code_to_str(code))


    def SKF_ExportCertificate(self):
        pbCert = Arr2048()
        pulCertLen = c_uint()
        # bSignFlag = input("输入证书类型：").strip()
        # while not bSignFlag:
        #     g.textBrowser.append("输入无效！0数字证书 or 1签名证书...")
        #     logger.warning("输入无效！0数字证书 or 1签名证书...")
        #     bSignFlag = input("输入证书类型：").strip()
        bSignFlag = SIGN_CER_TYPE

        code = gm.SKF_ExportCertificate(g.phContainer, int(bSignFlag), byref(pbCert), byref(pulCertLen))
        if code == 0 and int(bSignFlag) == 1:
            g.textBrowser.append("导出签名证书成功，code=" + code_to_str(code))
            logger.info("导出签名证书成功，code=" + code_to_str(code))
            certFile = open("C:\\Users\\zhangjuan\\Downloads\\newcertSign.cer", "wb+")
            certFile.write(pbCert)
            certFile.close()
        elif code == 0 and int(bSignFlag) == 0:
            g.textBrowser.append("导出加密证书成功，code=" + code_to_str(code))
            logger.info("导出加密证书成功，code=" + code_to_str(code))
            certFile = open("C:\\Users\\zhangjuan\\Downloads\\newcertEnc.cer", "wb+")
            certFile.write(pbCert)
            certFile.close()
        else:
            g.textBrowser.append("导出数字证书失败，code=0x%x" % code)
            logger.error("导出数字证书失败，code=0x%x" % code)
            return
        try:
            with open('./export.cer', 'wb') as f:
                f.write(pbCert)
        except BaseException as e:
            logger.exception("写入文件错误...", e)
