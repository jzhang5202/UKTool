# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/19:9:04

import os
import sys
from datetime import datetime
from pathlib import Path
from utils.globals import g

def mkdir(directory):
    path = Path(directory)
    if not path.is_dir():
        path.mkdir()
    return str(path)


def get_today():
    now = datetime.now()
    return now.strftime('%Y%m%d')


# def open_file():
#     num = input("输入查看行数：").strip()
#     if not num:
#         num = 10
#     try:
#         with open(Path('./log') / f"{get_today()}.log", 'r', encoding='utf8') as f:
#             data = f.readlines()
#             # print(data)
#             file_line = len(data)
#             if file_line > int(num):
#                 flag = file_line - int(num)
#                 print('\n'.join(data[flag:]))
#             else:
#                 print('\n'.join(data))
#     except BaseException as e:
#         print(e)
#
# def open_file():
#     try:
#         rst = win32api.ShellExecute('9', 'open', r'E:\UK\dist\log\20201123.log', '', '', 1)
#         return rst
#     except BaseException as e:
#         print(e)


def open_log_file():
    try:
        os.startfile(g.logfile)
    except BaseException as e:
        print("open log file error")


def restart_program():
    from .logs import logger
    try:
        _command = sys.executable
        os.execl(_command, _command, *sys.argv)
    except BaseException as e:
        logger.exception(e)

