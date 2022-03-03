# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:11:22
# 应用管理


from ctypes import pointer, c_ulong, byref
from utils.constant import APP_NAME, ADM_PIN, USER_PIN, SECURE_USER_ACCOUNT, szAppNameList
from utils.globals import g
from utils.guomi import gm
from utils.logs import logger
from crypto_service.message import code_to_str, Message
from PyQt5.QtWidgets import QWidget, QInputDialog

class Application(QWidget):
    def SKF_CreateApplication(self):
        # app_name = input("输入应用名(默认dmsUK)：")
        create_file_rights = SECURE_USER_ACCOUNT
        # if not app_name:
        app_name = APP_NAME.encode()
        try:
            code = gm.SKF_CreateApplication(g.phDev, app_name, ADM_PIN.encode(), 15, USER_PIN.encode(), 10,
                                              create_file_rights, byref(g.phApplication))
            if 0 == code:
                g.textBrowser.append(Message.CREATE_APP_SUCCESS + code_to_str(code))
                logger.info(Message.CREATE_APP_SUCCESS + code_to_str(code))
            else:
                g.textBrowser.append(Message.CREATE_APP_FAILED + code_to_str(code))
                logger.error(Message.CREATE_APP_FAILED + code_to_str(code))
        except BaseException as e:
            logger.exception(e)


    def SKF_EnumApplication(self):
        try:
            pulSize = pointer(c_ulong(128))
            code = gm.SKF_EnumApplication(g.phDev, szAppNameList, pulSize)
            if 0 == code:
                g.textBrowser.append(Message.ENUM_APP_SUCCESS + repr(szAppNameList.raw.decode()))
                logger.info(Message.ENUM_APP_SUCCESS + repr(szAppNameList.raw.decode()))
            else:
                g.textBrowser.append(Message.ENUM_APP_FAILED + code_to_str(code))
                logger.error(Message.ENUM_APP_FAILED + code_to_str(code))
        except BaseException as e:
            logger.exception(e)


    def SKF_DeleteApplication(self):
        # app_name = input("输入应用名(默认dmsUK)：")
        # if not app_name:
        code = gm.SKF_DeleteApplication(g.phDev, APP_NAME.encode())
        if 0 == code:
            g.textBrowser.append(Message.DEL_APP_SUCCESS + code_to_str(code))
            logger.info(Message.DEL_APP_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DEL_APP_FAILED + code_to_str(code))
            logger.error(Message.DEL_APP_FAILED + code_to_str(code))


    def SKF_OpenApplication(self):
        try:
            code = gm.SKF_OpenApplication(g.phDev, APP_NAME.encode(), byref(g.phApplication))
            if 0 == code:
                g.textBrowser.append(Message.OPEN_APP_SUCCESS + code_to_str(code))
                logger.info(Message.OPEN_APP_SUCCESS + code_to_str(code))
            else:
                g.textBrowser.append(Message.OPEN_APP_FAILED + code_to_str(code))
                logger.error(Message.OPEN_APP_FAILED + code_to_str(code))
        except BaseException as e:
            logger.exception(e)


    def SKF_CloseApplication(self):
        code = gm.SKF_CloseApplication(g.phApplication)
        if 0 == code:
            g.textBrowser.append(Message.CLOSE_APP_SUCCESS + code_to_str(code))
            logger.info(Message.CLOSE_APP_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.CLOSE_APP_FAILED + code_to_str(code))
            logger.error(Message.CLOSE_APP_FAILED + code_to_str(code))
