# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:11:22
# 访问控制

from ctypes import pointer, c_uint, c_ulong, c_bool, byref

from utils.constant import DEV_PIN, USER_PIN, ADM_PIN, USER_TYPE, ADM_TYPE, NEW_DEV_PIN, NEW_USER_PIN, NEW_ADM_PIN
from utils.globals import g
from utils.guomi import gm
from utils.logs import logger
from crypto_service.message import code_to_str, Message
from PyQt5.QtWidgets import QWidget, QInputDialog

class Authority(QWidget):
    def SKF_ChangeDevAuthKey(self):
        # DEV_PIN = input("输入新设备PIN：").strip()
        #g.dev_pin = NEW_DEV_PIN
        g.dev_pin, ok = QInputDialog.getText(self, "设备PIN码输入", "请输入新设备PIN：")
        code = gm.SKF_ChangeDevAuthKey(g.phDev, g.dev_pin.encode(), len(g.dev_pin))
        if code == 0:
            g.textBrowser.append(Message.CHANGE_AUTH_PIN_SUCCESS + code_to_str(code))
            logger.info(Message.CHANGE_AUTH_PIN_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.CHANGE_AUTH_PIN_FAILED + code_to_str(code))
            logger.error(Message.CHANGE_AUTH_PIN_FAILED + code_to_str(code))


    def SKF_DevAuth(self):
        try:
            if hasattr(g, 'dev_pin'):
                dev_pin = g.dev_pin
            else:
                dev_pin = DEV_PIN
            code = gm.SKF_DevAuth(g.phDev, dev_pin.encode(), len(dev_pin))
            if 0 == code:
                g.textBrowser.append(Message.DEV_AUTH_SUCCESS + code_to_str(code))
                logger.info(Message.DEV_AUTH_SUCCESS + code_to_str(code))
            else:
                g.textBrowser.append(Message.DEV_AUTH_FAILED + code_to_str(code))
                logger.error(Message.DEV_AUTH_FAILED + code_to_str(code))
        except BaseException as e:
            logger.exception(e)


    def SKF_VerifyUserPIN(self):
        pulRetryCount = pointer(c_uint())
        if hasattr(g, "u_flag"):
            user_pin = NEW_USER_PIN
        else:
            user_pin = USER_PIN
        code = gm.SKF_VerifyPIN(g.phApplication, USER_TYPE, user_pin.encode(), pulRetryCount)
        if 0 == code:
            g.textBrowser.append(Message.VERIFY_USER_PIN_SUCCESS + code_to_str(code))
            logger.info(Message.VERIFY_USER_PIN_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.VERIFY_USER_PIN_FAILED + code_to_str(code))
            logger.error(Message.VERIFY_USER_PIN_FAILED + code_to_str(code))


    def SKF_VerifyAdminPIN(self):
        pulRetryCount = pointer(c_uint())
        if hasattr(g, 'adm_flag'):
            admin_pin = NEW_ADM_PIN
        else:
            admin_pin = ADM_PIN
        code = gm.SKF_VerifyPIN(g.phApplication, ADM_TYPE, admin_pin.encode(), pulRetryCount)
        if 0 == code:
            g.textBrowser.append(Message.VERIFY_ADMIN_PIN_SUCCESS + code_to_str(code))
            logger.info(Message.VERIFY_ADMIN_PIN_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.VERIFY_ADMIN_PIN_FAILED + code_to_str(code))
            logger.error(Message.VERIFY_ADMIN_PIN_FAILED + code_to_str(code))


    def SKF_ChangeUserPIN(self):
        pulRetryCount = c_uint()
        if not hasattr(g, "u_flag"):
            old_pin = USER_PIN
            new_pin = NEW_USER_PIN
            code = gm.SKF_ChangePIN(g.phApplication, USER_TYPE, old_pin.encode(), new_pin.encode(), byref(pulRetryCount))
        else:
            old_pin = NEW_USER_PIN
            new_pin = USER_PIN
            code = gm.SKF_ChangePIN(g.phApplication, ADM_TYPE, old_pin.encode(), new_pin.encode(), byref(pulRetryCount))
        if code == 0:
            g.u_flag = True
            g.textBrowser.append(Message.CHANGE_USER_PIN_SUCCESS + code_to_str(code))
            logger.info(Message.CHANGE_USER_PIN_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.CHANGE_USER_PIN_FAILED + code_to_str(code))
            logger.error(Message.CHANGE_USER_PIN_FAILED + code_to_str(code))


    def SKF_ChangeAdminPIN(self):
        # admin_pin = input("输入管理员PIN：").strip()
        # g.admin_pin = input("输入新管理PIN：").strip()
        pulRetryCount = c_uint()
        if not hasattr(g, "adm_flag"):
            old_pin = ADM_PIN
            new_pin = NEW_ADM_PIN
            code = gm.SKF_ChangePIN(g.phApplication, ADM_TYPE, old_pin.encode(), new_pin.encode(), byref(pulRetryCount))
        else:
            old_pin = NEW_ADM_PIN
            new_pin = ADM_PIN
            code = gm.SKF_ChangePIN(g.phApplication, ADM_TYPE, old_pin.encode(), new_pin.encode(), byref(pulRetryCount))
        if code == 0:
            g.adm_flag = True
            g.textBrowser.append(Message.CHANGE_ADMIN_PIN_SUCCESS + code_to_str(code))
            logger.info(Message.CHANGE_ADMIN_PIN_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.CHANGE_ADMIN_PIN_FAILED + code_to_str(code))
            logger.error(Message.CHANGE_ADMIN_PIN_FAILED + code_to_str(code))


    def SKF_GetPINInfo(self):
        """
        pin_type = int(input("输入PIN类型"))
        while pin_type != 0 and pin_type != 1:
            logger.warning("请输入正确的UserType:1 or 0 ")
            pin_type = int(input("输入PIN类型"))
        """

        pulMaxRetryCount = c_ulong()
        pulRemainRetryCount = c_ulong()
        pbDefaultPin = c_bool()
        if not hasattr(g, 'pin_type'):
            pin_type = ADM_TYPE
            code = gm.SKF_GetPINInfo(g.phApplication, pin_type, byref(pulMaxRetryCount), byref(pulRemainRetryCount),
                                       byref(pbDefaultPin))
            g.pin_type = True

        else:
            pin_type = USER_TYPE
            code = gm.SKF_GetPINInfo(g.phApplication, pin_type, byref(pulMaxRetryCount), byref(pulRemainRetryCount),
                                       byref(pbDefaultPin))
            delattr(g, "pin_type")
        if code == 0 and pin_type == ADM_TYPE:
            g.textBrowser.append(Message.GET_ADMIN_PIN_INFO_SUCCESS + "\n"
                                 + "最大重试次数：%d" % pulMaxRetryCount.value + "\n"
                                 + "剩余重试次数：%d" % pulRemainRetryCount.value + "\n"
                                 + "PIN码状态:%d" % pbDefaultPin.value)
            logger.info(Message.GET_ADMIN_PIN_INFO_SUCCESS + "\n"
                        + "最大重试次数：%d" % pulMaxRetryCount.value + "\n"
                        + "剩余重试次数：%d" % pulRemainRetryCount.value + "\n"
                        + "PIN码状态:%d" % pbDefaultPin.value)
        elif code == 0 and pin_type == USER_TYPE:
            g.textBrowser.append("获取User PIN信息成功" + "\n"
                                 + "最大重试次数：%d" % pulMaxRetryCount.value + "\n"
                                 + "剩余重试次数：%d" % pulRemainRetryCount.value + "\n"
                                 + "PIN码状态:%d" % pbDefaultPin.value)
            logger.info("获取User PIN信息成功" + "\n"
                        + "最大重试次数：%d" % pulMaxRetryCount.value + "\n"
                        + "剩余重试次数：%d" % pulRemainRetryCount.value + "\n"
                        + "PIN码状态:%d" % pbDefaultPin.value)
        else:
            g.textBrowser.append(Message.GET_ADMIN_PIN_INFO_FAILED + code_to_str(code))
            logger.error(Message.GET_ADMIN_PIN_INFO_FAILED + code_to_str(code))


    def SKF_UnblockPIN(self):
        # szAdminPIN = input("输入管理员PIN：")
        # szNewUserPIN = input("输入用户PIN：")
        user_pin = USER_PIN.encode()
        if hasattr(g, "adm_flag"):
            admin_pin = NEW_ADM_PIN.encode()
        else:
            admin_pin = ADM_PIN.encode()
        pulRetryCount = c_uint()
        code = gm.SKF_UnblockPIN(g.phApplication, admin_pin, user_pin, byref(pulRetryCount))
        if code == 0:
            g.textBrowser.append(Message.UNLOCK_PIN_SUCCESS + code_to_str(code))
            logger.info(Message.UNLOCK_PIN_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(f"{Message.UNLOCK_PIN_FAILED}{pulRetryCount}，" + code_to_str(code))
            logger.error(f"{Message.UNLOCK_PIN_FAILED}{pulRetryCount}，" + code_to_str(code))


    def SKF_ClearSecureState(self):
        code = gm.SKF_ClearSecureState(g.phApplication)
        if code == 0:
            g.textBrowser.append(Message.CLEAR_SECURE_STATE_SUCCESS + code_to_str(code))
            logger.info(Message.CLEAR_SECURE_STATE_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.CLEAR_SECURE_STATE_FAILED + code_to_str(code))
            logger.error(Message.CLEAR_SECURE_STATE_FAILED + code_to_str(code))
