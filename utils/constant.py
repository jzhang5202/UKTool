# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:9:00

from ctypes import c_ubyte, c_char, Structure, c_ulong, c_long, c_void_p, c_uint, create_string_buffer

ECC_MAX_XCOORDINATE_BITS_LEN = 512
ECC_MAX_YCOORDINATE_BITS_LEN = 512
ECC_MAX_MODULUS_BITS_LEN = 512
MAX_IV_LEN = 32

Arr64K = c_ubyte * 65536  # 64k
Arr2048 = c_ubyte * 2048
Arr1024 = c_ubyte * 1024
ArrX = c_ubyte * (int(ECC_MAX_XCOORDINATE_BITS_LEN / 8))
ArrY = c_ubyte * (int(ECC_MAX_YCOORDINATE_BITS_LEN / 8))

ArrXS = create_string_buffer(int(ECC_MAX_XCOORDINATE_BITS_LEN / 8))
ArrYS = create_string_buffer(int(ECC_MAX_YCOORDINATE_BITS_LEN / 8))
ArrIV = c_ubyte * (MAX_IV_LEN)
Arr200 = c_ubyte * 200
Arr180 = c_ubyte * 180
Arr132 = c_ubyte * 132
Arr128 = c_ubyte * 128
Arr100 = c_ubyte * 100
Arr65 = c_ubyte * 65
Arr64 = c_ubyte * 64
Arr54 = c_ubyte * 54
Arr32 = c_ubyte * 32
Arr16 = c_ubyte * 16
Arr8 = c_ubyte * 8
Arr4 = c_ubyte * 4
Arr1 = c_ubyte * 1
ArrPKM = c_ubyte * 34000
ArrChar32 = c_char * 32
ArrChar64 = c_char * 64
ArrChar100 = c_char * 100


class VERSION(Structure):
    _fields_ = [('major', c_ubyte),
                ('minor', c_ubyte)]


class DEVINFO(Structure):
    _fields_ = [('Version', VERSION),
                ('Manufacturer', ArrChar64),
                ('Issuer', ArrChar64),
                ('Label', ArrChar32),
                ('SerialNumber', ArrChar32),
                ('HWVersion', VERSION),
                ('FirmwareVersion', VERSION),
                ('AlgSymCap', c_ulong),
                ('AlgAsymCap', c_ulong),
                ('AlgHashCap', c_ulong),
                ('DevAuthAlgId', c_ulong),
                ('TotalSpace', c_ulong),
                ('FreeSpace', c_ulong),
                ('MaxECCBufferSize', c_ulong),
                ('MaxBufferSize', c_ulong),
                ('Reserved', Arr64)]


class ECCPUBLICKEYBLOB(Structure):
    _fields_ = [('BitLen', c_ulong),
                ('XCoordinate', ArrX),
                ('YCoordinate', ArrY)]


class ECCCIPHERBLOB(Structure):
    _fields_ = [('XCoordinate', ArrX),
                ('YCoordinate', ArrY),
                ('HASH', Arr32),
                ('CipherLen', c_ulong),
                ('Cipher', Arr1)]


class ENVELOPEDKEYBLOB(Structure):
    _fields_ = [('Version', c_ulong),
                ('ulSymmAlgID', c_ulong),
                ('ulBits', c_ulong),
                ('cbEncryptedPriKey', Arr64),
                ('PubKey', ECCPUBLICKEYBLOB),
                ('ECCCipherBlob', ECCCIPHERBLOB)]


class BLOCKCIPHERPARAM(Structure):
    _fields_ = [('IV', ArrIV),
                ('IVLen', c_ulong),
                ('PaddingType', c_long),
                ('FeedBitLen', c_ulong)]


class ECCSIGNATUREBLOB(Structure):
    _fields_ = [('r', ArrX),
                ('s', ArrY)]



class FILEATTRIBUTE(Structure):
    _fields_ = [('FileName', ArrChar32),
                ('FileSize', c_ulong),
                ('ReadRights', c_ulong),
                ('WriteRights', c_ulong)]


szNameList = create_string_buffer(32)
szAppNameList = create_string_buffer(16)
szContainerName = create_string_buffer(16)
LABEL = "dmsUK123"
APP_NAME = "dmsUK"
CONTAINER_NAME = "dmsUK1"
FILE_NAME = "dms2020"
DEV_PIN = "12345678"
NEW_DEV_PIN = "88888888"
USER_PIN = "12345678"
NEW_USER_PIN = "88888888"
ADM_PIN = "12345678"
NEW_ADM_PIN = "88888888"
USER_TYPE = 1
ADM_TYPE = 0

CER_FILE_PATH = ""  # 证书路径
SIGN_CER_TYPE = 0  # 签名证书类型

SECURE_USER_ACCOUNT = 0x00000010  # 用户权限
SECURE_ADM_ACCOUNT = 0x00000001  # 管理员权限

pbRandom = (c_ubyte * 2048)()
ulRandomLen = 8  # 随机数长度

SGD_ECB = 0x00000001
SGD_SM3 = 0x00000001
SGD_SM2_1 = 0x00020200
SGD_SM2_3 = 0x00020800
SGD_SM2_2 = 0x00020400
SGD_SMS4_ECB = 0x00000401  # SMS4算法ECB加密模式
SGD_SMS4_CBC = 0x00000402  # SM4算法CBC加密模式
SGD_SMS4_CFB = 0x00000404  # SM4算法CFB加密模式
SGD_SMS4_OFB = 0x00000408  # SM4算法OFB加密模式

gl_Digest_hHash = c_void_p()  # HASH句柄
cipherText = Arr1024()
cipherLen = c_uint()

pSessionKeyData = ECCCIPHERBLOB()  # 生成并导出的会话密钥
# SessionKey = c_void_p()

Agreement_hostID = Arr64(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8)
Agreement_hostTempPubkey = ECCPUBLICKEYBLOB()
Agreement_slaveID = Arr64(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8)
Agreement_slaveTempPubkey = ECCPUBLICKEYBLOB()
phAgreementHandle = c_void_p()
phAgreementHandleVPN = c_void_p()

plainTextXN = Arr64K()
cipherTextXN = Arr64K()
