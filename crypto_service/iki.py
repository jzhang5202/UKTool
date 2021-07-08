# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:11:43
# IKI自定义接口


from ctypes import c_char_p, byref, sizeof, memmove, pointer

from crypto_service.func import list_to_bytes
from utils.constant import *
from utils.globals import g
from utils.guomi import gm
from utils.logs import logger
from crypto_service.message import code_to_str, Message
from PyQt5.QtWidgets import QWidget, QInputDialog, QFileDialog

class iki(QWidget):
    def SKF_ImportIdentify(self):
        pbKeyValue, ok = QInputDialog.getText(self, "文件名输入", "请输入文件名：")
        if ok:
            try:
                pbIden = c_char_p(pbKeyValue.encode())
                code = gm.SKF_ImportIdentify(g.phContainer, pbIden, len(pbKeyValue.encode()))
                if code == 0:
                    g.textBrowser.append("导入实体标识成功，code=" + code_to_str(code))
                    logger.info("导入实体标识成功，code=" + code_to_str(code))
                else:
                    g.textBrowser.append("导入实体标识失败，code=" + code_to_str(code))
                    logger.error("导入实体标识失败，code=" + code_to_str(code))
            except BaseException as e:
                logger.exception(e)


    def SKF_ExportIdentify(self):
        pbIden = ArrChar32()
        len = c_ulong()
        code = gm.SKF_ExportIdentify(g.phContainer, pbIden, byref(len))
        if code == 0:
            g.textBrowser.append("导出实体标识成功，code=" + code_to_str(code))
            logger.info("导出实体标识成功，code=" + code_to_str(code))
            for i in pbIden: print(i)
        else:
            g.textBrowser.append("导出实体标识失败，code=" + code_to_str(code))
            logger.error("导出实体标识失败，code=" + code_to_str(code))


    def SKF_ImportPubMatrix(self):
        try:
            pbPubMatrix = ArrPKM()
            #path = input("输入Pkm文件路径：")
            path, filetype = QFileDialog.getOpenFileName(self, "选取文件", './', "All Files (*)")
            with open(path, 'rb+') as f:
                sr = f.read()
            arr = list(sr)
            for i, d in enumerate(arr):
                pbPubMatrix[i] = d
            Flag = True
            ulMatLen = len(arr)
            code = gm.SKF_ImportPubMatrix(g.phApplication, byref(pbPubMatrix), ulMatLen, Flag)
            if code == 0:
                g.textBrowser.append("导入矩阵成功，code=" + code_to_str(code))
                logger.info("导入矩阵成功，code=" + code_to_str(code))
            else:
                g.textBrowser.append("导入矩阵失败，code=" + code_to_str(code))
                logger.error("导入矩阵失败，code=" + code_to_str(code))
        except BaseException as e:
            logger.exception(e)


    def SKF_ExportPubMatrix(self):
        pbPubMatrix = ArrPKM()
        ulMatLen = c_uint()
        Flag = True
        code = gm.SKF_ExportPubMatrix(g.phApplication, byref(pbPubMatrix), byref(ulMatLen), Flag)
        if code == 0:
            g.textBrowser.append("导出矩阵成功，code=" + code_to_str(code))
            logger.info("导出矩阵成功，code=" + code_to_str(code))
        else:
            logger.error("导出矩阵失败，code=" + hex(code))


    def SKF_DeletePubMatrix(self):
        code = gm.SKF_DeletePubMatrix(g.phApplication, 2)
        if code == 0:
            g.textBrowser.append("删除矩阵成功，code=" + code_to_str(code))
            logger.info("删除矩阵成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("删除矩阵失败，code=" + code_to_str(code))
            logger.error("删除矩阵失败，code=" + code_to_str(code))


    def SKF_CalculatePubKey(self):
        pass


    def SKF_CalculatePubKeyAddField(self):
        pbKeyValue = "12345678"
        pbIden = c_char_p(pbKeyValue.encode())
        ECCPubKeyBlob = ECCPUBLICKEYBLOB()
        field = c_ubyte(11)
        code = gm.SKF_CalculatePubKeyAddField(g.phApplication, pbIden, len(pbKeyValue.encode()), field,
                                                byref(ECCPubKeyBlob))
        if code == 0:
            # print(ECCPubKeyBlob.BitLen)
            # print(ECCPubKeyBlob.XCoordinate)
            g.textBrowser.append("加域计算实体标识成功，code=" + code_to_str(code))
            logger.info("加域计算实体标识成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("加域计算实体标识失败，code=" + code_to_str(code))
            logger.error("加域计算实体标识失败，code=" + code_to_str(code))


    def SKF_ECCExportSessionKeyEx(self):
        pPubKey = ECCPUBLICKEYBLOB()
        g.pData = ECCCIPHERBLOB()
        code = gm.SKF_ECCExportSessionKeyEx(g.SessionKey, byref(pPubKey), byref(g.pData))
        if code == 0:
            g.textBrowser.append("IKI导出会话密钥成功，code=" + code_to_str(code))
            logger.info("IKI导出会话密钥成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("IKI导出会话密钥失败，code=" + code_to_str(code))
            logger.error("IKI导出会话密钥失败，code=" + code_to_str(code))


    def SKF_GenerateKDFSessionKey(self):
        uiKeyBits = 128
        Rs = b'12345678'
        rsLen = 8
        Rc = b'12345678'
        rcLen = 8
        keyHandle = g.SessionKey
        keyCipher = g.pData
        newKeyHandle = c_void_p()
        symAlgID = c_uint()
        iv = c_ubyte()
        code = gm.SKF_GenerateKDFSessionKey(g.phContainer, uiKeyBits, Rs, rsLen, Rc, rcLen, keyHandle, byref(keyCipher),
                                              byref(newKeyHandle), symAlgID, iv)
        if code == 0:
            g.textBrowser.append("导出会话密钥成功，code=" + code_to_str(code))
            logger.info("导出会话密钥成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("导出会话密钥失败，code=" + code_to_str(code))
            logger.error("导出会话密钥失败，code=" + code_to_str(code))


    def SKF_DestroySessionKey(self):
        code = gm.SKF_DestroySessionKey(g.SessionKey)
        if code == 0:
            g.textBrowser.append("销毁会话密钥成功，code=" + code_to_str(code))
            logger.info("销毁会话密钥成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("销毁会话密钥失败，code=" + code_to_str(code))
            logger.error("销毁会话密钥失败，code=" + code_to_str(code))


    def SKF_ImportPublicKeyRPK(self):
        pkm = ArrPKM()
        code = gm.SKF_ImportPublicKeyRPK(g.phContainer, pkm, sizeof(ArrPKM))
        if 0 == code:
            g.textBrowser.append("导入RPK成功，code=" + code_to_str(code))
            logger.info("导入RPK成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("导入RPK失败，code=" + code_to_str(code))
            logger.error("导入RPK失败，code=" + code_to_str(code))


    def SKF_ExportPublicKeyRPK(self):
        pkmLen = c_ulong()
        pkm = ArrPKM()
        code = gm.SKF_ExportPublicKeyRPK(g.phContainer, pkm, byref(pkmLen))
        if 0 == code:
            g.textBrowser.append("导出RPK成功，code=" + code_to_str(code))
            logger.info("导出RPK成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("导出RPK失败，code=" + code_to_str(code))
            logger.error("导出RPK失败，code=" + code_to_str(code))


    def SKF_UkeyRandomTest(self):
        # mode = input("输入检测模式（1、2、3）：")
        mode = 3
        try:
            code = gm.SKF_UkeyRandomTest(g.phDev, int(mode))
            if 0 == code:
                g.textBrowser.append("随机数检测成功，code=" + code_to_str(code))
                logger.info("随机数检测成功，code=" + code_to_str(code))
            else:
                g.textBrowser.append("随机数检测失败，code=" + code_to_str(code))
                logger.error("随机数检测失败，code=" + code_to_str(code))
        except BaseException as e:
            logger.exception(e)


    def SKF_RandomSingleTest(self):
        code = gm.SKF_GenRandom(g.phDev, byref(pbRandom), ulRandomLen)
        if 0 == code:
            g.textBrowser.append("随机数单次检测成功，code=" + code_to_str(code))
            logger.info("随机数单次检测成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("随机数单次检测失败，code=" + code_to_str(code))
            logger.error("随机数单次检测失败，code=" + code_to_str(code))


    def SKF_HashInitFast(self):
        uiAlgID = SGD_SM3
        code = gm.SKF_HashInitFast(uiAlgID, byref(g.pBlob), None, 0)
        if 0 == code:
            g.textBrowser.append("快速Hash初始化成功，code=" + code_to_str(code))
            logger.info("快速Hash初始化成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("快速Hash初始化失败，code=" + code_to_str(code))
            logger.error("快速Hash初始化失败，code=" + code_to_str(code))


    def SKF_HashUpdateFast(self):
        # pucData = input("输入Hash数据：")
        pucData = "12345678abcdef"
        uiDataLength = len(pucData)
        code = gm.SKF_HashUpdateFast(pucData.encode(), uiDataLength)
        if 0 == code:
            g.textBrowser.append("多组快速Hash初始化成功，code=" + code_to_str(code))
            logger.info("多组快速Hash初始化成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("多组快速Hash初始化失败，code=" + code_to_str(code))
            logger.error("多组快速Hash初始化失败，code=" + code_to_str(code))


    def SKF_HashFinalFast(self):
        pHashData = Arr32()
        puiHashLength = c_uint()
        code = gm.SKF_HashFinalFast(pHashData, byref(puiHashLength))
        if 0 == code:
            g.textBrowser.append("结束多组快速Hash成功，code=" + code_to_str(code))
            logger.info("结束多组快速Hash成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("结束多组快速Hash失败，code=" + code_to_str(code))
            logger.error("结束多组快速Hash失败，code=" + code_to_str(code))


    def SKF_GenerateAgreementDataWithECC_VPN(self):
        SkeyLen = 16
        code = gm.SKF_GenerateAgreementDataWithECC_VPN(g.phContainer, SGD_SMS4_ECB, SkeyLen,
                                                         byref(Agreement_hostTempPubkey), Agreement_hostID, 32,
                                                         byref(phAgreementHandleVPN))
        if code == 0:
            g.textBrowser.append("VPN发方生成密钥协商参数成功，code=" + code_to_str(code))
            logger.info("VPN发方生成密钥协商参数成功，code=" + code_to_str(code))
        else:
            g.textBrowser.append("VPN发方生成密钥协商参数失败，code=" + code_to_str(code))
            logger.error("VPN发方生成密钥协商参数失败，code=" + code_to_str(code))

    def SKF_GenAgreementDataAndKeyWithECC_VPN(self):
        try:
            ulAlgId = SGD_SMS4_ECB
            SkeyLen = 16
            pSponsorECCPubKeyBlob = ECCPUBLICKEYBLOB()
            SessionKeyLen = c_ulong()
            SessionKey = c_ubyte()
            A = Arr132(0x00, 0x00, 0x10, 0x00,
                       0xea, 0x84, 0x2e, 0x90, 0x93, 0xaf, 0xbb, 0x20, 0xa3, 0xf8, 0x98, 0x26, 0x14, 0xe4, 0x70, 0x28,
                       0x06, 0x6f, 0x71, 0x07, 0xf7, 0xf8, 0xd1, 0xdf, 0xdb, 0x40, 0x51, 0x40, 0xd9, 0xe4, 0xe4, 0xa6,
                       0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                       0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                       0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                       0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26)
            # 发起方固有公钥
            pSponsorECCPubKeyBlob.BitLen = 256
            memmove(pSponsorECCPubKeyBlob.XCoordinate, byref(A, 4), 64)
            memmove(pSponsorECCPubKeyBlob.YCoordinate, byref(A, 68), 64)
            phKeyHandle1 = c_void_p()
            code = gm.SKF_GenAgreementDataAndKeyWithECC_VPN(
                g.phContainer, ulAlgId, SkeyLen, byref(pSponsorECCPubKeyBlob), byref(Agreement_hostTempPubkey),
                byref(Agreement_slaveTempPubkey), Agreement_hostID, 32, Agreement_slaveID, 32, byref(phKeyHandle1),
                byref(SessionKeyLen), byref(SessionKey))
            if code == 0:
                g.textBrowser.append("VPN收方计算会话密钥成功，code=" + code_to_str(code))
                logger.info("VPN收方计算会话密钥成功，code=" + code_to_str(code))
            else:
                g.textBrowser.append("VPN收方计算会话密钥失败，code=" + code_to_str(code))
                logger.error("VPN收方计算会话密钥失败，code=" + code_to_str(code))
        except BaseException as e:
            logger.exception(e)


    def SKF_GenerateKeyWithECC_VPN(self):
        try:
            reponseECCPubKeyBlob = ECCPUBLICKEYBLOB()
            phKeyHandle2 = c_void_p()
            SessionKeyLen = c_ulong()
            SessionKey = c_ubyte()
            B = Arr132(0x00, 0x00, 0x10, 0x00,
                       0xea, 0x84, 0x2e, 0x90, 0x93, 0xaf, 0xbb, 0x20, 0xa3, 0xf8, 0x98, 0x26, 0x14, 0xe4, 0x70, 0x28,
                       0x06, 0x6f, 0x71, 0x07, 0xf7, 0xf8, 0xd1, 0xdf, 0xdb, 0x40, 0x51, 0x40, 0xd9, 0xe4, 0xe4, 0xa6,
                       0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                       0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                       0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                       0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26)
            reponseECCPubKeyBlob.BitLen = 256
            memmove(reponseECCPubKeyBlob.XCoordinate, byref(B, 4), 64)
            memmove(reponseECCPubKeyBlob.YCoordinate, byref(B, 68), 64)
            code = gm.SKF_GenerateKeyWithECC_VPN(phAgreementHandleVPN, byref(reponseECCPubKeyBlob),
                                                   byref(Agreement_slaveTempPubkey), Agreement_slaveID, 32,
                                                   byref(phKeyHandle2),
                                                   byref(SessionKeyLen), byref(SessionKey))
            if code == 0:
                g.textBrowser.append("VPN发方计算会话密钥成功，code=" + code_to_str(code))
                logger.info("VPN发方计算会话密钥成功，code=" + code_to_str(code))
            else:
                g.textBrowser.append("VPN发方计算会话密钥失败，code=" + code_to_str(code))
                logger.error("VPN发方计算会话密钥失败，code=" + code_to_str(code))
        except BaseException as e:
            print(e)

    # SM2签名
    def dmsUK_Hsign(self):
        # identify = input("输入签名者的ID值：")
        identify = b"1234567812345678"
        idLen = len(identify)
        # plainText = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53,
        #                   0x8E,
        #                   0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7,
        #                   0xA6)
        plainText = Arr32(0xd6, 0x63, 0xab, 0x4d, 0xcf, 0x7d, 0xec, 0x9b, 0xc7, 0x1a, 0xe4, 0x7b, 0xb8, 0xc9, 0x9a, 0x3c, 0x6c, 0x3a, 0xa3, 0x97, 0x35, 0xd8, 0x73, 0x46, 0xb5, 0x2f, 0x21, 0x07, 0xed, 0x44, 0x63, 0xf2)
        plainTextLen = 32
        # g.pSignature = Arr128()
        degestAlgorithmId = c_ulong()
        signatureAlgorithmId = c_ulong()
        code = gm.dmsUK_Hsign(g.phDev, g.phContainer, identify, idLen, plainText, plainTextLen, byref(g.pSignature),byref(degestAlgorithmId), byref(signatureAlgorithmId))
        if code == 0:
            g.textBrowser.append("SM2签名成功，code=" + code_to_str(code))
            logger.info("SM2签名成功，code=" + code_to_str(code))
            pSignatureStrR = ""
            pSignatureStrS = ""
            for i in range(len(g.pSignature.r)):
                print("SM2 签名 r = %s"% hex((g.pSignature.r)[i]))
                pSignatureStrR = pSignatureStrR +(hex((g.pSignature.r)[i]))
            print("pSignatureStr R =%s" % (pSignatureStrR))
            for i in range(len(g.pSignature.s)):
                print("SM2 签名 s = %s"% hex((g.pSignature.s)[i]))
                pSignatureStrS = pSignatureStrS +(hex((g.pSignature.s)[i]))
            print("pSignatureStr S =%s"% (pSignatureStrS))
            # print("签名值r =%s"%(list_to_bytes((g.pSignature.r))))

        else:
            g.textBrowser.append("SM2签名失败，code=" + code_to_str(code))
            logger.error("SM2签名失败，code=" + code_to_str(code))

    # SM2验签
    def dmsUK_HEccVerify(self):
        # 导出签名公钥
        PUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = True
        # bSignFlag = False
        code = gm.SKF_ExportPublicKey(g.phContainer, bSignFlag, PUBK, pulBlobLen)
        if code == 0:
            logger.info(Message.EXPORT_SIGN_KEY_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.EXPORT_SIGN_KEY_FAILED + code_to_str(code))
        # 验证签名
        # identify = input("输入签名者的ID值：")
        # identify = "abc123"

        identify = b"1234567812345678"
        idLen = len(identify)
        # plainText = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53,
        #                   0x8E,
        #                   0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7,
        #                   0xA6)
        plainText = Arr32(0xd6, 0x63, 0xab, 0x4d, 0xcf, 0x7d, 0xec, 0x9b, 0xc7, 0x1a, 0xe4, 0x7b, 0xb8, 0xc9, 0x9a, 0x3c, 0x6c, 0x3a, 0xa3, 0x97, 0x35, 0xd8, 0x73, 0x46, 0xb5, 0x2f, 0x21, 0x07, 0xed, 0x44, 0x63, 0xf2)
        plainTextLen = 32
        pBlob = ECCPUBLICKEYBLOB()
        pBlob.BitLen = 256
        memmove(pBlob.XCoordinate, byref(PUBK, 4), 64)
        memmove(pBlob.YCoordinate, byref(PUBK, 68), 64)
        g.pSignature = Arr128(0xb5,0xc6,0xc2,0xfc,0x2f,0x81,0x06,0x11,0xc3,0x85,0x7b,0x8d,0x77,0x58,0x91,0x2b,0x4b,0x46,0x06,0xbe,0xad,0xdc,0xc0,0x6c,0xd0,0x7d,0x7d,0x66,0xc8,0x3d,0x2c,0xd0,\
                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,\
                              0xad,0x67,0x2f,0x2a,0xf9,0x01,0x36,0xff,0xad,0xcb,0x4d,0x9e,0x53,0xda,0xd5,0x61,0x03,0x22,0x97,0x82,0xb7,0x65,0x94,0x2a,0xd3,0x4a,0xa1,0xff,0x4c,0xcd,0x68,0x31,\
                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)

        # Signature = ECCSIGNATUREBLOB()
        # memmove(Signature.r, g.pSignature, 64)
        # memmove(Signature.s, byref(g.pSignature, 64), 64)

        code = gm.dmsUK_HEccVerify(g.phDev, identify, idLen, plainText, plainTextLen, (g.pSignature), byref(pBlob))
        if code == 0:
            g.textBrowser.append("SM2验签成功，code=" + hex(code))
            logger.info("SM2验签成功，code=" + hex(code))
        else:
            g.textBrowser.append("SM2验签失败，code=" + hex(code))
            logger.error("SM2验签失败，code=" + hex(code))



    # 4.1.8.1.	获取公钥矩阵Hash
    def getPkmHash(self):
        g.pkmHash = create_string_buffer(32)
        code = gm.SKF_get_matrix_hash(g.phApplication,byref(g.pkmHash))
        if code ==0:
            g.textBrowser.append("获取公钥矩阵Hash 成功，code= "+hex(code))
            logger.info("获取公钥矩阵Hash成功，code= "+hex(code))
            logger.info("获取公钥矩阵Hash成功，g.pkmHash= %s " % (g.pkmHash.value))
        else:
            g.textBrowser.append("获取公钥矩阵Hash 失败，code= " + hex(code))
            logger.info("获取公钥矩阵Hash 失败，code= " + hex(code))
    #
    # # 4.1.8.2.	计算公钥值（通过两个点相加）根据标识计算标识公钥
    # def CalculateIdentityPubKey(self):
    #
    #

    # 4.1.8.5.	SM2签名
    def signNoCert(self):

        # g.pSignature = Arr128()

        code = gm.dmsUK_UKey_Sign_no_cert(g.phContainer,g.pkmHash,g.Identity,len(g.Identity),g.useSignData,len(g.useSignData),byref(g.pSignature),byref(g.PA))

        if code == 0:
            g.textBrowser.append("SM2 签名 （无证书）成功，code = "+hex(code))
            logger.info("SM2 签名 （无证书）成功，code = "+hex(code))
            pSignatureStr = ""
            for i in range(len(g.pSignature.r)):
                # print("SM2 签名 r = %s"% (g.pSignature.r)[i])
                pSignatureStr = pSignatureStr +str(hex((g.pSignature.r)[i]))

            print("pSignatureStr =%s"% (pSignatureStr))
            print("yyyyyyy")
        else:
            g.textBrowser.append("SM2 签名 （无证书）失败，code = "+hex(code))
            logger.info("SM2 签名 （无证书）失败，code = "+hex(code))


