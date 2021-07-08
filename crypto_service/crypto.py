# -*- coding:utf8 -*-
# @author：lhb
# @time：2020/11/18:9:04
# 密码接口
from crypto_service.iki import iki
from crypto_service.performance import Performance
from crypto_service.device import Device
from crypto_service.authority import Authority
from crypto_service.container import Container
from crypto_service.file import File
from crypto_service.skf import Skf
from crypto_service.application import Application
from PyQt5.QtWidgets import QMessageBox

class Crypto(Application, Skf, File, Container, Authority, Device, iki, Performance):
    def device_reset(self):  # 设备重置
        reply = QMessageBox.warning(self, "警告", "是否执行设备初始化？", QMessageBox.Yes | QMessageBox.No)
        if reply == 16384:
            try:
                self.SKF_EnumDev()
                self.SKF_ConnectDev()
                self.SKF_DevAuth()
                self.SKF_DeleteApplication()
            except BaseException as e:
                pass
            return True
        else:
            return False
