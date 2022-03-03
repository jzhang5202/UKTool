# -*- coding:utf8 -*-
# @author：huangbaoliu
# @time：2020/11/18:9:07
import os
import sys
import time
from ctypes import CDLL, windll,cdll
from utils.logs import logger
#
def load_lib():
    if os.path.exists("./GUOMI.dll"):
        path = "./GUOMI.dll"
    elif os.path.exists("../GUOMI.dll"):
        path = "../GUOMI.dll"
    else:
        logger.error("当前项目下未找到库文件！3s 后程序退出...")
        time.sleep(3)
        sys.exit(0)
    try:
        # return cdll.LoadLibrary(path)
        return windll.LoadLibrary(path)
    except BaseException as e:
        logger.exception(e)
        sys.exit(0)



gm = load_lib()