# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:9:25


import logging
import sys
from pathlib import Path
from utils.globals import g
from crypto_service.util import mkdir, get_today

mkdir("log")
logger = logging.getLogger(__name__)  # 实例化logger对象
logger.setLevel(logging.INFO)  # 设置日志输出级别
logfile = Path('./log') / f"{get_today()}.log"  # 日志文件路径
formatter = logging.Formatter('%(asctime)s [%(levelname)s]: #  %(message)s')  # 日志输出格式
file_handle = logging.FileHandler(filename=logfile, encoding='utf8')
# file_handle.setLevel(logging.INFO)
file_handle.setFormatter(formatter)
control_handle = logging.StreamHandler(sys.stdout)
control_handle.setFormatter(formatter)

logger.addHandler(file_handle)
logger.addHandler(control_handle)
g.set_log_file(logfile)




