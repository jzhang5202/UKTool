# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:11:22
# 文件管理
from ctypes import create_string_buffer, c_uint, byref, pointer, c_ulong
from utils.constant import FILEATTRIBUTE, Arr2048, Arr128, FILE_NAME, SECURE_USER_ACCOUNT, SECURE_ADM_ACCOUNT
from utils.globals import g
from utils.guomi import gm
from utils.logs import logger
from crypto_service.message import code_to_str, Message
from PyQt5.QtWidgets import QWidget, QInputDialog

class File(QWidget):
    def SKF_CreateFile(self):
        read_rights = SECURE_USER_ACCOUNT
        write_rights = SECURE_ADM_ACCOUNT
        code = gm.SKF_CreateFile(g.phApplication, FILE_NAME.encode(), 20480, read_rights, write_rights)
        if code == 0:
            g.textBrowser.append(Message.CREATE_FILE_SUCCESS + code_to_str(code))
            logger.info(Message.CREATE_FILE_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.CREATE_FILE_FAILED + code_to_str(code))
            logger.error(Message.CREATE_FILE_FAILED + code_to_str(code))


    def SKF_DeleteFile(self):
        print("----------1---------")
        code = gm.SKF_DeleteFile(g.phApplication, FILE_NAME.encode())
        print("----------2---------")
        if code == 0:
            g.textBrowser.append(Message.DEL_FILE_SUCCESS + code_to_str(code))
            logger.info(Message.DEL_FILE_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DEL_FILE_FAILED + code_to_str(code))
            logger.error(Message.DEL_FILE_FAILED + code_to_str(code))


    def SKF_EnumFiles(self):
        FileList = create_string_buffer(16)
        pulSize = pointer(c_ulong())
        code = gm.SKF_EnumFiles(g.phApplication, FileList, pulSize)
        if code == 0:
            g.textBrowser.append(Message.ENUM_FILE_SUCCESS + repr(FileList.raw.decode()))
            logger.info(Message.ENUM_FILE_SUCCESS + repr(FileList.raw.decode()))
        else:
            g.textBrowser.append(Message.ENUM_FILE_FAILED + code_to_str(code))
            logger.error(Message.ENUM_FILE_FAILED + code_to_str(code))


    def SKF_GetFileInfo(self):
        pFileInfo = FILEATTRIBUTE()
        code = gm.SKF_GetFileInfo(g.phApplication, FILE_NAME.encode(), byref(pFileInfo))
        if code == 0:
            g.textBrowser.append(Message.GET_FILE_INFO_SUCCESS + code_to_str(code))
            logger.info(Message.GET_FILE_INFO_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.GET_FILE_INFO_FAILED + code_to_str(code))
            logger.error(Message.GET_FILE_INFO_FAILED + code_to_str(code))


    def SKF_ReadFile(self):
        pbOutData = Arr2048()
        pulOutLen = c_uint()
        code = gm.SKF_ReadFile(g.phApplication, FILE_NAME.encode(), 0, 128, pbOutData, byref(pulOutLen))
        if code == 0:
            g.textBrowser.append(Message.READ_FILE_SUCCESS + code_to_str(code))
            logger.info(Message.READ_FILE_SUCCESS + code_to_str(code))
            for i in range(128):
                g.textBrowser.append(pbOutData[i], end=' ')
        else:
            g.textBrowser.append(Message.READ_FILE_FAILED + code_to_str(code))
            logger.error(Message.READ_FILE_FAILED + code_to_str(code))

    def SKF_WriteFile(self):
        Indata = Arr128(0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF)
        code = gm.SKF_WriteFile(g.phApplication, FILE_NAME.encode(), 1024, Indata, 128)
        if code == 0:
            g.textBrowser.append(Message.WRITE_FILE_SUCCESS + code_to_str(code))
            logger.info(Message.WRITE_FILE_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.WRITE_FILE_FAILED + code_to_str(code))
            logger.error(Message.WRITE_FILE_FAILED + code_to_str(code))
