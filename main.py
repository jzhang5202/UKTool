# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main.py'
#
# Created by: PyQt5 UI code generator 5.13.2
#
# WARNING! All changes made in this file will be lost!

# -*- coding:utf8 -*-
# @author lhb
# @time 2020/11/18:13:38


import sys
from PyQt5.QtWidgets import QApplication
from utils.tool_cnn import Test


if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = Test()
    win.show()
    sys.exit(app.exec_())
    print("2222")
