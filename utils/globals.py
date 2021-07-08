# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:9:07
from utils.constant import ECCPUBLICKEYBLOB, ECCCIPHERBLOB, ECCSIGNATUREBLOB
from ctypes import c_void_p,c_uint

class Globals:
    def __init__(self):
        self.phDev = c_void_p()
        self.phApplication = c_void_p()
        self.phContainer = c_void_p()
        self.SessionKey = c_void_p()
        self.PKH = ECCPUBLICKEYBLOB()  # 保护公钥
        self.pBlob = ECCPUBLICKEYBLOB()  # 签名公钥
        self.pData = ECCCIPHERBLOB()  # 会话密钥密文
        self.pSignature = ECCSIGNATUREBLOB()  # 签名值

        self.logfile = None
        self.pkmHash = c_uint()
        self.IdentityPubBlob = ECCPUBLICKEYBLOB  #标识公钥
        self.Identity = "012006303531393436FFFF1928" #用户标识
        self.useSignData = "dmschangshahonghuo"   # 签名使用的原文数据
        self.PA = ECCPUBLICKEYBLOB() # PA


    def set_log_file(self, file):
        self.logfile = file

g = Globals()

