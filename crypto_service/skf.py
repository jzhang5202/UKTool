# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:11:22
# 密钥服务


from ctypes import byref, memset, memmove, pointer, POINTER, c_int
from utils.constant import *
from utils.globals import g
from utils.guomi import gm
from utils.logs import logger
from crypto_service.message import code_to_str, Message
from PyQt5.QtWidgets import QWidget, QInputDialog
from .func import xor, rotl, get_uint32_be, put_uint32_be, \
        bytes_to_list, list_to_bytes, padding, unpadding

class Skf(QWidget):
    # 生成随机数
    def SKF_GenRandom(self):
        # ulRandomLen = int(input("输入随机数长度："))
        num, ok = QInputDialog.getInt(self, "随机数长度", "请输入随机数长度")
        if ok:
            code = gm.SKF_GenRandom(g.phDev, pbRandom, ulRandomLen)
            if 0 == code:
                g.textBrowser.append(Message.GENERATE_RANDOM_SUCCESS + code_to_str(code))
                logger.info(Message.GENERATE_RANDOM_SUCCESS + code_to_str(code))
                seq = []
                for i in range(ulRandomLen):
                    seq.append(code_to_str(pbRandom[i]))
                g.textBrowser.append("随机数：\n%s" % seq)
                logger.info("随机数：\n%s" % seq)
            else:
                g.textBrowser.append(Message.GENERATE_RANDOM_FAILED + code_to_str(code))
                logger.error(Message.GENERATE_RANDOM_FAILED + code_to_str(code))


    # 生成保护密钥对
    def SKF_GenECCKeyPairH(self):
        print("11111");
        code = gm.SKF_GenECCKeyPairH(g.phContainer, SGD_SM2_3, byref(g.PKH))
        if 0 == code:
            g.textBrowser.append(Message.GENERATE_PROTECT_SUCCESS + code_to_str(code))
            logger.info(Message.GENERATE_PROTECT_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.GENERATE_PROTECT_FAILED + code_to_str(code))
            logger.error(Message.GENERATE_PROTECT_FAILED + code_to_str(code))


    #  生成ECC签名密钥对
    def SKF_GenECCKeyPair(self):
        code = gm.SKF_GenECCKeyPair(g.phContainer, SGD_SM2_1, byref(g.pBlob))
        if 0 == code:
            g.textBrowser.append(Message.GENERATE_ECC_SUCCESS + code_to_str(code))
            logger.info(Message.GENERATE_ECC_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.GENERATE_ECC_FAILED + code_to_str(code))
            logger.error(Message.GENERATE_ECC_FAILED + code_to_str(code))


    # 导入ECC加密密钥对
    def SKF_ImportECCKeyPair(self):
        try:
            code = gm.SKF_ECCExportSessionKey(g.phContainer, SGD_SMS4_ECB, byref(g.PKH), byref(g.pData), byref(g.SessionKey))
            if code == 0:
                g.textBrowser.append(Message.ECC_EXPORT_SESSION_KEY_SUCCESS + code_to_str(code))
                logger.info(Message.ECC_EXPORT_SESSION_KEY_SUCCESS + code_to_str(code))
            else:
                g.textBrowser.append(Message.ECC_EXPORT_SESSION_KEY_FAILED + code_to_str(code))
                logger.error(Message.ECC_EXPORT_SESSION_KEY_FAILED + code_to_str(code))
            # **********加密初始化**********************
            EncryptParam = BLOCKCIPHERPARAM()
            EncryptParam.IVLen = 16
            memset(EncryptParam.IV, 0x11, 16)
            EncryptParam.PaddingType = SGD_ECB
            code = gm.SKF_EncryptInit(g.SessionKey, EncryptParam)
            if code == 0:
                g.textBrowser.append(Message.ENCRYPT_INIT_SUCCESS + code_to_str(code))
                logger.info(Message.ENCRYPT_INIT_SUCCESS + code_to_str(code))
            else:
                g.textBrowser.append(Message.ENCRYPT_INIT_FAILED + code_to_str(code))
                logger.error(Message.ENCRYPT_INIT_FAILED + code_to_str(code))
            # ***********多组数据加密**********************
            X = Arr64(0X09, 0XF9, 0XDF, 0X31, 0X1E, 0X54, 0X21, 0XA1, 0X50, 0XDD, 0X7D, 0X16, 0X1E, 0X4B, 0XC5, 0XC6,
                      0X72, 0X17, 0X9F, 0XAD, 0X18, 0X33, 0XFC, 0X07, 0X6B, 0XB0, 0X8F, 0XF3, 0X56, 0XF3, 0X50, 0X20,
                      0XCC, 0XEA, 0X49, 0X0C, 0XE2, 0X67, 0X75, 0XA5, 0X2D, 0XC6, 0XEA, 0X71, 0X8C, 0XC1, 0XAA, 0X60,
                      0X0A, 0XED, 0X05, 0XFB, 0XF3, 0X5E, 0X08, 0X4A, 0X66, 0X32, 0XF6, 0X07, 0X2D, 0XA9, 0XAD, 0X13)

            Y = Arr32(0X39, 0X45, 0X20, 0X8F, 0X7B, 0X21, 0X44, 0XB1, 0X3F, 0X36, 0XE3, 0X8A, 0XC6, 0XD3, 0X9F, 0X95,
                      0X88, 0X93, 0X93, 0X69, 0X28, 0X60, 0XB5, 0X1A, 0X42, 0XFB, 0X81, 0XEF, 0X4D, 0XF7, 0XC5, 0XB8)
            plainText = Arr1024()
            plainTextLen = 32
            cipherText = Arr1024()
            cipherLen = c_uint()
            memmove(plainText, Y, 32)
            # gm.SKF_EncryptUpdate.argtypes = [c_void_p,  POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint)]
            code = gm.SKF_EncryptUpdate(g.SessionKey, plainText, plainTextLen, cipherText, byref(cipherLen))
            if code == 0:
                g.textBrowser.append(Message.ENCRYPT_UPDATE_SUCCESS + code_to_str(code))
                logger.info(Message.ENCRYPT_UPDATE_SUCCESS + code_to_str(code))
            else:
                g.textBrowser.append(Message.ENCRYPT_UPDATE_FAILED + code_to_str(code))
                logger.error(Message.ENCRYPT_UPDATE_FAILED + code_to_str(code))

            # ************结束加密********************
            code = gm.SKF_EncryptFinal(g.SessionKey, cipherText, byref(cipherLen))
            if code == 0:
                g.textBrowser.append(Message.ENCRYPT_FINAL_SUCCESS + code_to_str(code))
                logger.info(Message.ENCRYPT_FINAL_SUCCESS + code_to_str(code))
            else:
                g.textBrowser.append(Message.ENCRYPT_FINAL_FAILED + code_to_str(code))
                logger.error(Message.ENCRYPT_FINAL_FAILED + code_to_str(code))

            # *********销毁会话密钥*********************
            code = gm.SKF_DestroySessionKey(g.SessionKey)
            if code == 0:
                g.textBrowser.append(Message.DESTROY_SESSION_KEY_SUCCESS + code_to_str(code))
                logger.info(Message.DESTROY_SESSION_KEY_SUCCESS + code_to_str(code))
            else:
                g.textBrowser.append(Message.DESTROY_SESSION_KEY_FAILED + code_to_str(code))
                logger.info(Message.DESTROY_SESSION_KEY_FAILED + code_to_str(code))

            # *************数据复制************************
            pEnvelopedKeyBlob = ENVELOPEDKEYBLOB()
            pEnvelopedKeyBlob.ulSymmAlgID = SGD_SMS4_ECB
            memmove(pEnvelopedKeyBlob.cbEncryptedPriKey, cipherText, 32)
            pEnvelopedKeyBlob.PubKey.BitLen = 32 * 8
            memmove(pEnvelopedKeyBlob.PubKey.XCoordinate, X, 32)
            memmove(pEnvelopedKeyBlob.PubKey.YCoordinate, byref(X, 32), 32)

            pEnvelopedKeyBlob.ECCCipherBlob.CipherLen = g.pData.CipherLen
            memmove(pEnvelopedKeyBlob.ECCCipherBlob.Cipher, g.pData.Cipher, g.pData.CipherLen)
            memmove(pEnvelopedKeyBlob.ECCCipherBlob.XCoordinate, g.pData.XCoordinate, 32)
            memmove(pEnvelopedKeyBlob.ECCCipherBlob.YCoordinate, g.pData.YCoordinate, 32)
            memmove(pEnvelopedKeyBlob.ECCCipherBlob.HASH, g.pData.HASH, 64)

            code = gm.SKF_ImportECCKeyPair(g.phContainer, byref(pEnvelopedKeyBlob))
            if code == 0:
                g.textBrowser.append(Message.IMPORT_ECC_SUCCESS + code_to_str(code))
                logger.info(Message.IMPORT_ECC_SUCCESS + code_to_str(code))
            else:
                g.textBrowser.append(Message.IMPORT_ECC_FAILED + code_to_str(code))
                logger.error(Message.IMPORT_ECC_FAILED + code_to_str(code))
        except BaseException as e:
            logger.exception(e)


    # ECC签名
    def SKF_ECCSignData(self):
        pSignData = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53,
                          0x8E,
                          0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7,
                          0xA6)
        ulSignDataLen = 32
        g.pSignature = Arr128()
        code = gm.SKF_ECCSignData(g.phContainer, byref(pSignData), ulSignDataLen, g.pSignature)
        if code == 0:
            g.textBrowser.append(Message.ECC_SING_DATA_SUCCESS + code_to_str(code))
            logger.info(Message.ECC_SING_DATA_SUCCESS + code_to_str(code))
            pSignatureStr = ""
            for i in range(len(g.pSignature)):
                # print("SM2 签名 r = %s"% (g.pSignature.r)[i])
                pSignatureStr = pSignatureStr + str((g.pSignature)[i])
            print("pSignatureStr =%s" % (pSignatureStr))
        else:
            g.textBrowser.append(Message.ECC_SING_DATA_FAILED + code_to_str(code))
            logger.error(Message.ECC_SING_DATA_FAILED + code_to_str(code))


    # ECC验签
    def SKF_ECCVerify(self):
        # 导出签名公钥
        PUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        # bSignFlag = True
        bSignFlag = False # TODO 2.0.6 false 表示签名公钥与3.0.7相反
        code = gm.SKF_ExportPublicKey(g.phContainer, bSignFlag, PUBK, pulBlobLen)
        if code == 0:
            g.textBrowser.append(Message.EXPORT_SIGN_KEY_SUCCESS + code_to_str(code))
            logger.info(Message.EXPORT_SIGN_KEY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.EXPORT_SIGN_KEY_FAILED + code_to_str(code))
            logger.error(Message.EXPORT_SIGN_KEY_FAILED + code_to_str(code))
        # 验证签名
        HASH = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53, 0x8E,
                     0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7, 0xA6)
        g.pBlob = ECCPUBLICKEYBLOB()
        g.pBlob.BitLen = 256
        memmove(g.pBlob.XCoordinate, byref(PUBK, 4), 64)
        memmove(g.pBlob.YCoordinate, byref(PUBK, 68), 64)
        Signature = ECCSIGNATUREBLOB()
        memmove(Signature.r, g.pSignature, 64)
        memmove(Signature.s, byref(g.pSignature, 64), 64)
        code = gm.SKF_ECCVerify(g.phDev, byref(g.pBlob), HASH, 32, Signature)
        if code == 0:
            g.textBrowser.append(Message.ECC_VERIFY_SUCCESS + code_to_str(code))
            logger.info(Message.ECC_VERIFY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.ECC_VERIFY_FAILED + code_to_str(code))
            logger.error(Message.ECC_VERIFY_FAILED + code_to_str(code))


    # 生成并导出会话密钥
    def SKF_ECCExportSessionKey(self):
        code = gm.SKF_ECCExportSessionKey(g.phContainer, SGD_SMS4_ECB, byref(g.PKH), byref(pSessionKeyData),
                                            byref(g.SessionKey))
        if code == 0:
            g.textBrowser.append(Message.ECC_EXPORT_SESSION_KEY_SUCCESS + code_to_str(code))
            logger.info(Message.ECC_EXPORT_SESSION_KEY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.ECC_EXPORT_SESSION_KEY_FAILED + code_to_str(code))
            logger.error(Message.ECC_EXPORT_SESSION_KEY_FAILED + code_to_str(code))


    # 导入会话密钥
    def SKF_ImportSessionKey(self):
        # 导出加密公钥
        encPUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        # bSignFlag = False
        bSignFlag = True  # TODO 2.0.6 true代表加密公钥与3.0.7相反
        code = gm.SKF_ExportPublicKey(g.phContainer, bSignFlag, encPUBK, pulBlobLen)
        if code == 0:
            g.textBrowser.append(Message.EXPORT_ENCRYPT_KEY_SUCCESS + code_to_str(code))
            logger.info(Message.EXPORT_ENCRYPT_KEY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.EXPORT_ENCRYPT_KEY_FAILED + code_to_str(code))
            logger.error(Message.EXPORT_ENCRYPT_KEY_FAILED + code_to_str(code))
        # 生成并导出会话密钥
        pSessionKeyData = Arr180()
        code = gm.SKF_ECCExportSessionKey(g.phContainer, SGD_SMS4_ECB, byref(encPUBK), pSessionKeyData,
                                            byref(g.SessionKey))
        if code == 0:
            g.textBrowser.append(Message.ECC_EXPORT_SESSION_KEY_SUCCESS + code_to_str(code))
            logger.info(Message.ECC_EXPORT_SESSION_KEY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.ECC_EXPORT_SESSION_KEY_FAILED + code_to_str(code))
            logger.error(Message.ECC_EXPORT_SESSION_KEY_FAILED + code_to_str(code))
        # 销毁会话密钥
        code = gm.SKF_DestroySessionKey(g.SessionKey)
        if code == 0:
            g.textBrowser.append(Message.DESTROY_SESSION_KEY_SUCCESS + code_to_str(code))
            logger.info(Message.DESTROY_SESSION_KEY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DESTROY_SESSION_KEY_FAILED + code_to_str(code))
            logger.error(Message.DESTROY_SESSION_KEY_FAILED + code_to_str(code))
        # 导入会话密钥
        ulAlgId = SGD_SMS4_CBC
        phKey = c_void_p()
        code = gm.SKF_ImportSessionKey(g.phContainer, ulAlgId, pSessionKeyData, 180, byref(phKey))
        if code == 0:
            g.textBrowser.append(Message.IMPORT_SESSION_KEY_SUCCESS + code_to_str(code))
            logger.info(Message.IMPORT_SESSION_KEY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.IMPORT_SESSION_KEY_FAILED + code_to_str(code))
            logger.error(Message.IMPORT_SESSION_KEY_FAILED + code_to_str(code))


    # 导出签名公钥
    def SKF_ExportSignPublicKey(self):
        pulBlobLen = pointer(c_void_p())
        bSignFlag = c_ubyte(True)
        code = gm.SKF_ExportPublicKey(g.phContainer, bSignFlag, g.pBlob, pulBlobLen)
        if code == 0:
            g.textBrowser.append(Message.EXPORT_SIGN_KEY_SUCCESS + code_to_str(code))
            logger.info(Message.EXPORT_SIGN_KEY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.EXPORT_SIGN_KEY_FAILED + code_to_str(code))
            logger.error(Message.EXPORT_SIGN_KEY_FAILED + code_to_str(code))


    # 导出加密公钥
    def SKF_ExportEncrypPublicKey(self):
        pEncrypBlob = ECCPUBLICKEYBLOB()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = c_ubyte(False)
        code = gm.SKF_ExportPublicKey(g.phContainer, bSignFlag, pEncrypBlob, pulBlobLen)
        if code == 0:
            g.textBrowser.append(Message.EXPORT_ENCRYPT_KEY_SUCCESS + code_to_str(code))
            logger.info(Message.EXPORT_ENCRYPT_KEY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.EXPORT_ENCRYPT_KEY_FAILED + code_to_str(code))
            logger.error(Message.EXPORT_ENCRYPT_KEY_FAILED + code_to_str(code))


    # 导出保护公钥
    def SKF_ExportPublicKeyH(self):
        pbBlob = ECCCIPHERBLOB()
        pulBlobLen = pointer(c_uint())
        code = gm.SKF_ExportPublicKeyH(g.phContainer, pbBlob, pulBlobLen)
        if 0 == code:
            g.textBrowser.append(Message.EXPORT_PUBLIC_KEY_SUCCESS + code_to_str(code))
            logger.info(Message.EXPORT_PUBLIC_KEY_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.EXPORT_PUBLIC_KEY_FAILED + code_to_str(code))
            logger.error(Message.EXPORT_PUBLIC_KEY_FAILED + code_to_str(code))


    # ECC外来公钥加密
    def SKF_ExtECCEncrypt(self):
        X = Arr32(0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda, 0x8d,
                  0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a)
        Y = Arr32(0x1a, 0x37, 0xa2, 0xc4, 0x5b, 0xfd, 0x14, 0xa4, 0x43, 0x84, 0x10, 0xe3, 0x48, 0xae, 0x54, 0x3f, 0x60,
                  0xb0, 0x47, 0xb8, 0x7f, 0x75, 0xc8, 0xbd, 0xab, 0xc4, 0xbf, 0x77, 0xca, 0xbb, 0x95, 0x3a)
        ECCPubKeyBlob = ECCPUBLICKEYBLOB()
        ECCPubKeyBlob.BitLen = 256
        memmove(ECCPubKeyBlob.XCoordinate, X, 32)
        memmove(ECCPubKeyBlob.YCoordinate, Y, 32)
        # 外部公钥加密数据
        pbPlainText = (c_ubyte * 2048)()
        # ulPlainTextLen = int(input("输入加密数据长度："))
        ulPlainTextLen = 16
        code = gm.SKF_GenRandom(g.phDev, pbPlainText, ulPlainTextLen)
        if 0 == code:
            g.textBrowser.append("加密数据长度：%d" % ulPlainTextLen)
            logger.info("加密数据长度：%d" % ulPlainTextLen)
            seq = []
            for i in range(ulPlainTextLen):
                seq.append(code_to_str(pbPlainText[i]))
            g.textBrowser.append("加密数据：%s" % seq)
            logger.info("加密数据：%s" % seq)
        else:
            g.textBrowser.append("生成加密数据失败，code=" + code_to_str(code))
            logger.info("生成加密数据失败，code=" + code_to_str(code))
        pCipherText = ECCCIPHERBLOB()
        code = gm.SKF_ExtECCEncrypt(g.phDev, byref(ECCPubKeyBlob), pbPlainText, ulPlainTextLen, pCipherText)
        g.textBrowser.append("加密结果", pCipherText)
        if code == 0:
            g.textBrowser.append(Message.EXT_PUBKEY_ENCRYPT_SUCCESS + code_to_str(code))
            logger.info(Message.EXT_PUBKEY_ENCRYPT_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.EXT_PUBKEY_ENCRYPT_FAILED + code_to_str(code))
            logger.error(Message.EXT_PUBKEY_ENCRYPT_FAILED + code_to_str(code))


    # 发方生成协商参数
    def SKF_GenerateAgreementDataWithECC(self):
        code = gm.SKF_GenerateAgreementDataWithECC(g.phContainer, SGD_SMS4_ECB, byref(Agreement_hostTempPubkey),
                                                     Agreement_hostID, 32, byref(phAgreementHandle))
        if code == 0:
            g.textBrowser.append(Message.GENERATE_AGREEMENT_ECC_SUCCESS + code_to_str(code))
            logger.info(Message.GENERATE_AGREEMENT_ECC_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.GENERATE_AGREEMENT_ECC_FAILED + code_to_str(code))
            logger.error(Message.GENERATE_AGREEMENT_ECC_FAILED + code_to_str(code))


    # 收方计算会话密钥
    def SKF_GenerateAgreementDataAndKeyWithECC(self):
        ulAlgId = SGD_SMS4_CBC
        pSponsorECCPubKeyBlob = ECCPUBLICKEYBLOB()
        A = Arr132(0x00, 0x00, 0x10, 0x00,
                   0xea, 0x84, 0x2e, 0x90, 0x93, 0xaf, 0xbb, 0x20, 0xa3, 0xf8, 0x98, 0x26, 0x14, 0xe4, 0x70, 0x28,
                   0x06, 0x6f, 0x71, 0x07, 0xf7, 0xf8, 0xd1, 0xdf, 0xdb, 0x40, 0x51, 0x40, 0xd9, 0xe4, 0xe4, 0xa6,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26, )
        # 发起方固有公钥
        pSponsorECCPubKeyBlob.BitLen = 256
        memmove(pSponsorECCPubKeyBlob.XCoordinate, byref(A, 4), 64)
        memmove(pSponsorECCPubKeyBlob.YCoordinate, byref(A, 68), 64)
        code = gm.SKF_GenerateAgreementDataAndKeyWithECC(
            g.phContainer, ulAlgId, byref(pSponsorECCPubKeyBlob), byref(Agreement_hostTempPubkey),
            byref(Agreement_slaveTempPubkey), Agreement_hostID, 32, Agreement_slaveID, 32, byref(g.SessionKey))
        if code == 0:
            g.textBrowser.append(Message.GENERATE_AGREEMENT_DATA_SUCCESS + code_to_str(code))
            logger.info(Message.GENERATE_AGREEMENT_DATA_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.GENERATE_AGREEMENT_DATA_FAILED + code_to_str(code))
            logger.error(Message.GENERATE_AGREEMENT_DATA_FAILED + code_to_str(code))


    # 发方计算会话密钥
    def SKF_GenerateKeyWithECC(self):
        # 响应方固定公钥
        reponseECCPubKeyBlob = ECCPUBLICKEYBLOB()
        B = Arr132(0x00, 0x00, 0x10, 0x00,
                   0xea, 0x84, 0x2e, 0x90, 0x93, 0xaf, 0xbb, 0x20, 0xa3, 0xf8, 0x98, 0x26, 0x14, 0xe4, 0x70, 0x28,
                   0x06, 0x6f, 0x71, 0x07, 0xf7, 0xf8, 0xd1, 0xdf, 0xdb, 0x40, 0x51, 0x40, 0xd9, 0xe4, 0xe4, 0xa6,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26, )
        reponseECCPubKeyBlob.BitLen = 256
        memmove(reponseECCPubKeyBlob.XCoordinate, byref(B, 4), 64)
        memmove(reponseECCPubKeyBlob.YCoordinate, byref(B, 68), 64)
        code = gm.SKF_GenerateKeyWithECC(phAgreementHandle, byref(reponseECCPubKeyBlob),
                                           byref(Agreement_slaveTempPubkey), Agreement_slaveID, 32, byref(g.SessionKey))
        if code == 0:
            g.textBrowser.append(Message.GENERATE_KEY_WITH_ECC_SUCCESS + code_to_str(code))
            logger.info(Message.GENERATE_KEY_WITH_ECC_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.GENERATE_KEY_WITH_ECC_FAILED + code_to_str(code))
            logger.error(Message.GENERATE_KEY_WITH_ECC_FAILED + code_to_str(code))


    # 加密初始化
    def SKF_EncryptInit(self):
        # **********加密初始化**********************
        EncryptParam = BLOCKCIPHERPARAM()
        EncryptParam.IVLen = 16
        SGD_ECB = 0x00000001
        memset(EncryptParam.IV, 0X11, 16)
        EncryptParam.PaddingType = SGD_ECB
        code = gm.SKF_EncryptInit(g.SessionKey, EncryptParam)
        if code == 0:
            g.textBrowser.append(Message.ENCRYPT_INIT_SUCCESS + code_to_str(code))
            logger.info(Message.ENCRYPT_INIT_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.ENCRYPT_INIT_FAILED + code_to_str(code))
            logger.error(Message.ENCRYPT_INIT_FAILED + code_to_str(code))


    # 多组加密
    def SKF_EncryptUpdate(self):
        # ***********多组数据加密**********************
        X = Arr64(0X09, 0XF9, 0XDF, 0X31, 0X1E, 0X54, 0X21, 0XA1, 0X50, 0XDD, 0X7D, 0X16, 0X1E, 0X4B, 0XC5, 0XC6,
                  0X72, 0X17, 0X9F, 0XAD, 0X18, 0X33, 0XFC, 0X07, 0X6B, 0XB0, 0X8F, 0XF3, 0X56, 0XF3, 0X50, 0X20,
                  0XCC, 0XEA, 0X49, 0X0C, 0XE2, 0X67, 0X75, 0XA5, 0X2D, 0XC6, 0XEA, 0X71, 0X8C, 0XC1, 0XAA, 0X60,
                  0X0A, 0XED, 0X05, 0XFB, 0XF3, 0X5E, 0X08, 0X4A, 0X66, 0X32, 0XF6, 0X07, 0X2D, 0XA9, 0XAD, 0X13)

        Y = Arr32(0X39, 0X45, 0X20, 0X8F, 0X7B, 0X21, 0X44, 0XB1, 0X3F, 0X36, 0XE3, 0X8A, 0XC6, 0XD3, 0X9F, 0X95,
                  0X88, 0X93, 0X93, 0X69, 0X28, 0X60, 0XB5, 0X1A, 0X42, 0XFB, 0X81, 0XEF, 0X4D, 0XF7, 0XC5, 0XB8)
        plainText = Arr1024()
        plainTextLen = 32
        memmove(plainText, Y, 32)
        # gm.SKF_EncryptUpdate.argtypes = [c_void_p, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint)]
        code = gm.SKF_EncryptUpdate(g.SessionKey, plainText, plainTextLen, cipherText, byref(cipherLen))
        if code == 0:
            g.textBrowser.append(Message.ENCRYPT_UPDATE_SUCCESS + code_to_str(code))
            g.textBrowser.append(cipherText[:])
            g.textBrowser.append(cipherLen)
            logger.info(Message.ENCRYPT_UPDATE_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.ENCRYPT_UPDATE_FAILED + code_to_str(code))


    # 加密结束
    def SKF_EncryptFinal(self):
        # ************结束加密********************
        # SF_EncryptFinal(HANDLE Key, BYTE * pbEncryptedData, LONG * ulEncryptedDataLen);
        code = gm.SKF_EncryptFinal(g.SessionKey, cipherText, byref(cipherLen))
        if code == 0:
            g.textBrowser.append(Message.ENCRYPT_FINAL_SUCCESS + code_to_str(code))
            logger.info(Message.ENCRYPT_FINAL_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.ENCRYPT_FINAL_FAILED + code_to_str(code))
            logger.error(Message.ENCRYPT_FINAL_FAILED + code_to_str(code))


    # 解密初始化
    def SKF_DecryptInit(self):
        # **********解密初始化**********************
        DecryptParam = BLOCKCIPHERPARAM()
        DecryptParam.IVLen = 16
        memset(DecryptParam.IV, 0X11, 16)
        DecryptParam.PaddingType = SGD_ECB
        code = gm.SKF_DecryptInit(g.SessionKey, DecryptParam)
        if code == 0:
            g.textBrowser.append(Message.DECRYPT_INIT_SUCCESS + code_to_str(code))
            logger.info(Message.DECRYPT_INIT_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DECRYPT_INIT_FAILED + code_to_str(code))
            logger.error(Message.DECRYPT_INIT_FAILED + code_to_str(code))


    # 多组解密
    def SKF_DecryptUpdate(self):
        X = Arr64(0X09, 0XF9, 0XDF, 0X31, 0X1E, 0X54, 0X21, 0XA1, 0X50, 0XDD, 0X7D, 0X16, 0X1E, 0X4B, 0XC5, 0XC6,
                  0X72, 0X17, 0X9F, 0XAD, 0X18, 0X33, 0XFC, 0X07, 0X6B, 0XB0, 0X8F, 0XF3, 0X56, 0XF3, 0X50, 0X20,
                  0XCC, 0XEA, 0X49, 0X0C, 0XE2, 0X67, 0X75, 0XA5, 0X2D, 0XC6, 0XEA, 0X71, 0X8C, 0XC1, 0XAA, 0X60,
                  0X0A, 0XED, 0X05, 0XFB, 0XF3, 0X5E, 0X08, 0X4A, 0X66, 0X32, 0XF6, 0X07, 0X2D, 0XA9, 0XAD, 0X13)

        Y = Arr32(0X39, 0X45, 0X20, 0X8F, 0X7B, 0X21, 0X44, 0XB1, 0X3F, 0X36, 0XE3, 0X8A, 0XC6, 0XD3, 0X9F, 0X95,
                  0X88, 0X93, 0X93, 0X69, 0X28, 0X60, 0XB5, 0X1A, 0X42, 0XFB, 0X81, 0XEF, 0X4D, 0XF7, 0XC5, 0XB8)
        plainText = Arr1024()
        plainTextLen = c_uint()
        gm.SKF_DecryptUpdate.argtypes = [c_void_p, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint)]
        code = gm.SKF_DecryptUpdate(g.SessionKey, cipherText, cipherLen, plainText, byref(plainTextLen))
        if code == 0:
            g.textBrowser.append(Message.DECRYPT_UPDATE_SUCCESS + code_to_str(code))
            logger.info(Message.DECRYPT_UPDATE_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DECRYPT_UPDATE_FAILED + code_to_str(code))
            logger.error(Message.DECRYPT_UPDATE_FAILED + code_to_str(code))


    # 解密结束
    def SKF_DecryptFinal(self):
        pbDecryptedData = Arr100()
        ulDecryptedDataLen = c_uint()
        code = gm.SKF_DecryptFinal(g.SessionKey, pbDecryptedData, byref(ulDecryptedDataLen))
        if code == 0:
            g.textBrowser.append(Message.DECRYPT_FINA_SUCCESS + code_to_str(code))
            logger.info(Message.DECRYPT_FINA_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DECRYPT_FINA_FAILED + code_to_str(code))
            logger.error(Message.DECRYPT_FINA_FAILED + code_to_str(code))


    # 杂凑初始化
    def SKF_DigestInit(self):
        # pInput = input("输入签名者ID：")
        pInput = "12345678"
        pPubKey = ECCPUBLICKEYBLOB()
        pInputLen = 0  # 表示进行标准的杂凑
        code = gm.SKF_DigestInit(g.phDev, SGD_SM3, byref(pPubKey), pInput, pInputLen, byref(gl_Digest_hHash))
        if code == 0:
            g.textBrowser.append(Message.DIGEST_INIT_SUCCESS + code_to_str(code))
            logger.info(Message.DIGEST_INIT_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DIGEST_INIT_FAILED + code_to_str(code))
            logger.error(Message.DIGEST_INIT_FAILED + code_to_str(code))


    # 单组杂凑
    def SKF_Digest(self):
        ulDataLen = 64
        pbHashData = Arr32()
        ulHashLen = c_int()
        code = gm.SKF_Digest(gl_Digest_hHash, pbHashData, ulDataLen, pbHashData, byref(ulHashLen))
        if code == 0:
            g.textBrowser.append(Message.DIGEST_SUCCESS + code_to_str(code))
            logger.info(Message.DIGEST_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DIGEST_SUCCESS + code_to_str(code))
            logger.error(Message.DIGEST_SUCCESS + code_to_str(code))


    # 多组杂凑
    def SKF_DigestUpdate(self):
        phData = Arr128(0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67,
                        0x68, )
        ulDataLen = 128
        code = gm.SKF_DigestUpdate(gl_Digest_hHash, phData, ulDataLen)
        if code == 0:
            g.textBrowser.append(Message.DIGEST_UPDATE_SUCCESS + code_to_str(code))
            logger.info(Message.DIGEST_UPDATE_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.DIGEST_UPDATE_FAILED + code_to_str(code))
            logger.error(Message.DIGEST_UPDATE_FAILED + code_to_str(code))


    # 杂凑结束
    def SKF_DigestFinal(self):
        pbData = Arr200(0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67,
                        0x68, )
        SM3_BLOCK_SIZE = 64
        group = int(176 / SM3_BLOCK_SIZE)
        ulDataLen = int(176 % SM3_BLOCK_SIZE)
        pbHashData = Arr64()
        ulHashLen = c_uint()
        memmove(pbHashData, byref(pbData, group * SM3_BLOCK_SIZE), ulDataLen)
        code = gm.SKF_DigestFinal(gl_Digest_hHash, pbHashData, byref(ulHashLen))
        if code == 0:
            g.textBrowser.append(Message.DIGEST_FINAL_SUCCESS + code_to_str(code))
            logger.info(Message.DIGEST_FINAL_SUCCESS + code_to_str(code))
            # for i in pbHashData:
            pbHashDataHex = list_to_bytes(pbHashData)
            print("杂凑结果:%s" % pbHashDataHex.hex())
        else:
            g.textBrowser.append(Message.DIGEST_FINAL_FAILED + code_to_str(code))
            logger.error(Message.DIGEST_FINAL_FAILED + code_to_str(code))


    def SKF_MacInit(self):
        pMacParam = BLOCKCIPHERPARAM()
        memset(pMacParam.IV, 0, 32)
        pMacParam.IVLen = 16
        pMacParam.PaddingType = 0x00000001
        # global phMac
        g.phMac = c_void_p()
        code = gm.SKF_MacInit(g.SessionKey, byref(pMacParam), byref(g.phMac))
        if code == 0:
            g.textBrowser.append(Message.MAC_INIT_SUCCESS + code_to_str(code))
            logger.info(Message.MAC_INIT_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.MAC_INIT_FAILED + code_to_str(code))
            logger.error(Message.MAC_INIT_FAILED + code_to_str(code))


    def SKF_Mac(self):
        pbData = Arr32(0xD1, 0xC4, 0x20, 0xF4, 0x25, 0xC0, 0xC7, 0xBD, 0x50, 0xBA, 0x40, 0x4E, 0x95, 0x42, 0x46, 0x88,
                       0x07, 0xB2, 0x32, 0xE0, 0x5D, 0xA3, 0x0E, 0xB8, 0x02, 0x38, 0x6A, 0xA3, 0x93, 0x7D, 0xC3, 0x0D)
        ulDataLen = 16
        pbMacData = Arr4()
        pulMacDataLen = c_uint()
        code = gm.SKF_Mac(g.phMac, pbData, ulDataLen, pbMacData, byref(pulMacDataLen))
        if code == 0:
            g.textBrowser.append(Message.MAC_SUCCESS + code_to_str(code))
            logger.info(Message.MAC_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.MAC_FAILED + code_to_str(code))
            logger.error(Message.MAC_FAILED + code_to_str(code))


    def SKF_MacUpdate(self):
        pbData = Arr32(0xD1, 0xC4, 0x20, 0xF4, 0x25, 0xC0, 0xC7, 0xBD, 0x50, 0xBA, 0x40, 0x4E, 0x95, 0x42, 0x46, 0x88,
                       0x07, 0xB2, 0x32, 0xE0, 0x5D, 0xA3, 0x0E, 0xB8, 0x02, 0x38, 0x6A, 0xA3, 0x93, 0x7D, 0xC3, 0x0D)
        ulDataLen = 32
        code = gm.SKF_MacUpdate(g.phMac, pbData, ulDataLen)
        if code == 0:
            g.textBrowser.append(Message.MAC_UPDATE_SUCCESS + code_to_str(code))
            logger.info(Message.MAC_UPDATE_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.MAC_UPDATE_FAILED + code_to_str(code))
            logger.error(Message.MAC_UPDATE_FAILED + code_to_str(code))


    def SKF_MacFinal(self):
        pbMacData = Arr4()
        code = gm.SKF_MacFinal(g.phMac, pbMacData, pbMacData)
        if code == 0:
            g.textBrowser.append(Message.MAC_FINAL_SUCCESS + code_to_str(code))
            logger.info(Message.MAC_FINAL_SUCCESS + code_to_str(code))
        else:
            g.textBrowser.append(Message.MAC_FINAL_FAILED + code_to_str(code))
            logger.error(Message.MAC_FINAL_FAILED + code_to_str(code))
