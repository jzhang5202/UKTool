# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/23:16:07
# 性能测试


# @async_
import time
from concurrent.futures.thread import ThreadPoolExecutor

from ctypes import byref, pointer, c_void_p, memmove, create_string_buffer, c_uint, memset, c_ulong, c_bool, c_char_p, \
    POINTER

from utils.constant import SGD_SM2_1, Arr32, Arr128, Arr132, ECCPUBLICKEYBLOB, ECCSIGNATUREBLOB, ECCCIPHERBLOB, Arr180, \
    SGD_SMS4_ECB, SGD_SM3, gl_Digest_hHash, BLOCKCIPHERPARAM, plainTextXN, cipherTextXN, SGD_ECB, Arr16, Arr1024, \
    szNameList, APP_NAME, NEW_USER_PIN, USER_PIN, USER_TYPE, CONTAINER_NAME
from utils.globals import g
from utils.guomi import gm
from utils.logs import logger
from crypto_service.message import Message, code_to_str
from PyQt5.QtWidgets import QWidget, QInputDialog, QFileDialog

class Performance(QWidget):
    def SKF_GenECCKeyPair_XN(self):
        run_time = 0
        num, ok = QInputDialog.getInt(self, "测试次数", "请输入测试次数")
        if ok:
            for i in range(num):
                start_time = time.time()
                code = gm.SKF_GenECCKeyPair(g.phContainer, SGD_SM2_1, byref(g.pBlob))
                end_time = time.time()
                if 0 == code:
                    run_time += (end_time - start_time)
                else:
                    logger.error(Message.GENERATE_ECC_FAILED + code_to_str(code))
            avr_time = run_time * 1000 / int(num)
            logger.info("单次平均执行时间：%d ms" % avr_time)

            if ( 0 < run_time ):
                result_xn = num / run_time
                logger.info("SKF_GenECCKeyPair性能测试结果：%d 次/秒" % result_xn)

    # @async_
    def SKF_ECCSignData_XN(self, *args):
        pSignData = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53,
                          0x8E,
                          0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7,
                          0xA6)
        ulSignDataLen = 32
        g.pSignature = Arr128()
        run_time = 0
        num, ok = QInputDialog.getInt(self, "测试次数", "请输入测试次数")
        if ok:
            for i in range(num):
                start_time = time.time()
                code = gm.SKF_ECCSignData(g.phContainer, byref(pSignData), ulSignDataLen, g.pSignature)
                end_time = time.time()
                if 0 == code:
                    run_time += (end_time - start_time)
                else:
                    logger.error(Message.ECC_SING_DATA_FAILED + code_to_str(code))
            signle_time = (run_time * 1000) / num
            logger.info("单次平均执行时间：%d ms" % signle_time)
            if ( 0 < run_time ):
                result_xn = num / (run_time)
                logger.info("SKF_ECCSignData性能测试结果：%d 次/秒" % result_xn)


    def SKF_ECCVerify_XN(self):
        # 导出签名公钥
        PUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = True
        code = gm.SKF_ExportPublicKey(g.phContainer, bSignFlag, PUBK, pulBlobLen)
        if code == 0:
            logger.info(Message.EXPORT_SIGN_KEY_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.EXPORT_SIGN_KEY_FAILED + code_to_str(code))
            return
        # 验证签名
        HASH = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53, 0x8E,
                     0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7, 0xA6)
        pBlob = ECCPUBLICKEYBLOB()
        pBlob.BitLen = 256
        memmove(pBlob.XCoordinate, byref(PUBK, 4), 64)
        memmove(pBlob.YCoordinate, byref(PUBK, 68), 64)
        Signature = ECCSIGNATUREBLOB()
        memmove(Signature.r, g.pSignature, 64)
        memmove(Signature.s, byref(g.pSignature, 64), 64)
        run_time = 0
        num, ok = QInputDialog.getInt(self, "测试次数", "请输入测试次数")
        if ok:
            for i in range(num):
                start_time = time.time_ns()
                code = gm.SKF_ECCVerify(g.phDev, byref(pBlob), HASH, 32, Signature)
                end_time = time.time_ns()
                if 0 == code:
                    run_time += (end_time - start_time)
                else:
                    logger.error(Message.ECC_VERIFY_FAILED + code_to_str(code))
            signle_time = (run_time / 10 ** 6) / num
            print('===')
            logger.info("单次平均执行时间：%d ms" % signle_time)
            if ( 0 < run_time ):
                result_xn = num / (run_time / 10 ** 9)
                logger.info("SKF_ECCVerify性能测试结果：%d 次/秒" % result_xn)


    def SKF_ExtECCEncrypt_XN(self):
        run_time = 0
        num, ok = QInputDialog.getInt(self, "测试次数", "请输入测试次数")
        if ok:
            try:
                X = Arr32(0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
                          0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a)
                Y = Arr32(0x1a, 0x37, 0xa2, 0xc4, 0x5b, 0xfd, 0x14, 0xa4, 0x43, 0x84, 0x10, 0xe3, 0x48, 0xae, 0x54, 0x3f,
                          0x60, 0xb0, 0x47, 0xb8, 0x7f, 0x75, 0xc8, 0xbd, 0xab, 0xc4, 0xbf, 0x77, 0xca, 0xbb, 0x95, 0x3a)
                ECCPubKeyBlob = ECCPUBLICKEYBLOB()
                ECCPubKeyBlob.BitLen = 256
                memmove(ECCPubKeyBlob.XCoordinate, X, 32)
                memmove(ECCPubKeyBlob.YCoordinate, Y, 32)
                pbPlainText = Arr32(0x1a, 0x37, 0xa2, 0xc4, 0x5b, 0xfd, 0x14, 0xa4, 0x43, 0x84, 0x10, 0xe3, 0x48, 0xae,
                                    0x54,
                                    0x3f, 0x60, 0xb0, 0x47, 0xb8, 0x7f, 0x75, 0xc8, 0xbd, 0xab, 0xc4, 0xbf, 0x77, 0xca,
                                    0xbb,
                                    0x95, 0x3a)
                ulPlainTextLen = 32
                pCipherText = ECCCIPHERBLOB()

                for i in range(num):
                    start_time = time.time()
                    code = gm.SKF_ExtECCEncrypt(g.phDev, byref(ECCPubKeyBlob), pbPlainText, ulPlainTextLen, pCipherText)
                    end_time = time.time()
                    if 0 == code:
                        run_time += (end_time - start_time)
                    else:
                        logger.error(Message.EXT_PUBKEY_ENCRYPT_FAILED + code_to_str(code))
            except BaseException as e:
                print(e)
            signle_time = run_time * 1000 / num
            logger.info("单次平均执行时间：%d ms" % signle_time)
            if (0 < run_time):
                result_xn = num / (run_time)
                logger.info("SKF_ExtECCEncrypt性能测试结果：%d 次/秒" % result_xn)


    def SKF_ImportSessionKey_XN(self):
        # 导出加密公钥公钥
        encPUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = False
        code = gm.SKF_ExportPublicKey(g.phContainer, bSignFlag, encPUBK, pulBlobLen)
        if code == 0:
            logger.info(Message.EXPORT_ENCRYPT_KEY_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.EXPORT_ENCRYPT_KEY_FAILED + code_to_str(code))
        # 生成并导出会话密钥
        pSessionKeyData = Arr180()
        code = gm.SKF_ECCExportSessionKey(g.phContainer, SGD_SMS4_ECB, byref(encPUBK), pSessionKeyData,
                                            byref(g.SessionKey))
        if code == 0:
            logger.info(Message.ECC_EXPORT_SESSION_KEY_SUCCESS + code_to_str(code))

        else:
            logger.error(Message.ECC_EXPORT_SESSION_KEY_FAILED + code_to_str(code))
        # 销毁会话密钥
        code = gm.SKF_DestroySessionKey(g.SessionKey)
        if code == 0:
            logger.info(Message.DESTROY_SESSION_KEY_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.DESTROY_SESSION_KEY_FAILED + code_to_str(code))
        # 导入会话密钥
        ulAlgId = SGD_SMS4_ECB
        phKey = c_void_p()
        run_time = 0
        num, ok = QInputDialog.getInt(self, "测试次数", "请输入测试次数")
        if ok:
            for i in range(num):
                start_time = time.time_ns()
                code = gm.SKF_ImportSessionKey(g.phContainer, ulAlgId, pSessionKeyData, 180, byref(phKey))
                end_time = time.time_ns()
                if 0 == code:
                    run_time += (end_time - start_time)
                else:
                    logger.error(Message.IMPORT_SESSION_KEY_FAILED + code_to_str(code))
                code = gm.SKF_DestroySessionKey(phKey)
                if code != 0:
                    logger.error(Message.DESTROY_SESSION_KEY_FAILED + code_to_str(code))
            signle_time = (run_time / 10 ** 6) / num
            logger.info("单次平均执行时间：%d ms" % signle_time)
            if (0 < run_time):
                result_xn = num / (run_time / 10 ** 9)
                logger.info("SKF_ImportSessionKey性能测试结果：%d 次/秒" % result_xn)


    def SKF_Hash_XN(self):
        # 杂凑初始化
        """
        pInput = input("输入：")
        pPubKey = ECCPUBLICKEYBLOB()
        pInputLen = 0  # 表示进行标准的杂凑
        """
        start_time = time.time_ns()
        code = gm.SKF_DigestInit(g.phDev, SGD_SM3, None, None, 0, byref(gl_Digest_hHash))
        if code == 0:
            logger.info(Message.DIGEST_INIT_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.DIGEST_INIT_FAILED + code_to_str(code))
            return

        # 多组数据杂凑
        path, filetype = QFileDialog.getOpenFileName(self, "选取文件", './', "All Files (*)")
        with open(path, 'rb+') as f:
            str = f.read()
        phData = create_string_buffer(str, len(str))
        ulDataLen = len(str)
        code = gm.SKF_DigestUpdate(gl_Digest_hHash, phData, ulDataLen)
        if code == 0:
            logger.info(Message.DIGEST_UPDATE_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.DIGEST_UPDATE_FAILED + code_to_str(code))
            return
        # 结束杂凑
        pbHashData = Arr32()
        ulHashLen = c_uint()
        code = gm.SKF_DigestFinal(gl_Digest_hHash, pbHashData, byref(ulHashLen))
        if code == 0:
            logger.info(Message.DIGEST_FINAL_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.DIGEST_FINAL_FAILED + code_to_str(code))
            return
        end_time = time.time_ns()
        run_time = (end_time - start_time) / (10 ** 6)
        logger.info("file Hash time：%d ms" % run_time)
        speed = 1000 * ulDataLen / (1024 * run_time)
        logger.info("Hash speed：%f KB/s" % speed)


    def SKF_Encrypt_XN(self):
        # *****************加密初始化********************
        EncryptParam = BLOCKCIPHERPARAM()
        EncryptParam.IVLen = 16
        SGD_ECB = 0x00000001
        memset(EncryptParam.IV, 0X00, 32)
        EncryptParam.PaddingType = SGD_ECB
        start_time = time.time()
        code = gm.SKF_EncryptInit(g.SessionKey, EncryptParam)
        if code == 0:
            logger.info(Message.ENCRYPT_INIT_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.ENCRYPT_INIT_FAILED + code_to_str(code))
        # ****************多组数据加密********************
        plainTextLen = 65536
        cipherLen = c_ulong()
        code = gm.SKF_EncryptUpdate(g.SessionKey, plainTextXN, plainTextLen, cipherTextXN, byref(cipherLen))
        if code == 0:
            logger.info(Message.ENCRYPT_UPDATE_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.ENCRYPT_UPDATE_FAILED + code_to_str(code))
        # ******************结束加密************************
        code = gm.SKF_EncryptFinal(g.SessionKey, cipherTextXN, byref(cipherLen))
        if code == 0:
            logger.info(Message.ENCRYPT_FINAL_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.ENCRYPT_FINAL_FAILED + code_to_str(code))
        end_time = time.time()
        # total_time = (end_time - start_time) / 10 ** 6
        total_time = (end_time - start_time)
        # logger.info()("Encrypt time：%s ms" % total_time)
        # speed = 1000 * plainTextLen / (1024 * total_time)
        print('====')
        # logger.info()("Encrypt speed：%s KB/s" % speed)


    def SKF_Decrypt_XN(self):
        # **********解密初始化**********************
        DecryptParam = BLOCKCIPHERPARAM()
        DecryptParam.IVLen = 16
        memset(DecryptParam.IV, 0X00, 32)
        DecryptParam.PaddingType = SGD_ECB

        start_time = time.time_ns()
        code = gm.SKF_DecryptInit(g.SessionKey, DecryptParam)
        if code == 0:
            logger.info(Message.DECRYPT_INIT_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.DECRYPT_INIT_FAILED + code_to_str(code))
        # *************多组数据解密******************
        cipherLen = 65536
        plainTextLen = c_ulong()
        code = gm.SKF_DecryptUpdate(g.SessionKey, cipherTextXN, cipherLen, plainTextXN, byref(plainTextLen))
        if code == 0:
            logger.info(Message.DECRYPT_UPDATE_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.DECRYPT_UPDATE_FAILED + code_to_str(code))
        # ****************结束解密********************
        pbDecryptedData = Arr16()
        ulDecryptedDataLen = c_ulong()
        code = gm.SKF_DecryptFinal(g.SessionKey, pbDecryptedData, byref(ulDecryptedDataLen))
        if code == 0:
            logger.info(Message.DECRYPT_FINA_SUCCESS + code_to_str(code))
        else:
            logger.error(Message.DECRYPT_FINA_FAILED + code_to_str(code))
        end_time = time.time_ns()
        run_time = (end_time - start_time) / 10 ** 6
        print(run_time)
        # logger.info()("Decrypt time：%d ms" % run_time)
        speed = 1024 * cipherLen
        print(speed)
        # logger.info()("Decrypt speed：%f KB/s" % speed)


    def write_file_XN(self):
        Indata = Arr128(0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF)
        szFileName, ok = QInputDialog.getText(self, "文件名输入", "请输入文件名：")
        if ok:
            start_time = time.time_ns()
            for i in range(0, 20480, 128):
                code = gm.SKF_WriteFile(g.phApplication, szFileName.encode(), i, Indata, 128)
                if code != 0:
                    logger.error(Message.WRITE_FILE_FAILED + code_to_str(code))
                    return
            end_time = time.time_ns()
            start_time = (end_time - start_time) / (10 ** 6)
            logger.info("SKF_WriteFile time：%d ms" % start_time)
            speed = 1000 * (128 * 160) / (1024 * start_time)
            logger.info("SKF_WriteFile speed：%f KB/s" % speed)

    def read_file_XN(self):
        pbOutData = Arr1024()
        pulOutLen = c_uint()
        szFileName, ok = QInputDialog.getText(self, "文件名输入", "请输入文件名：")
        if ok:
            start_time = time.time_ns()
            for i in range(0, 20480, 128):
                code = gm.SKF_ReadFile(g.phApplication, szFileName.encode(), i, 128, pbOutData, byref(pulOutLen))
                if code != 0:
                    logger.error(Message.READ_FILE_FAILED + code_to_str(code))
                    return
            end_time = time.time_ns()
            start_time = (end_time - start_time) / (10 ** 6)
            logger.info("SKF_ReadFile time：%d ms" % start_time)
            speed = 1000 * (128 * 160) / (1024 * start_time)
            logger.info("SKF_ReadFile speed：%f KB/s" % speed)



    def signNoCert_XN(self):

        g.pSignature = Arr128()
        run_time = 0
        w = 0
        num, ok = QInputDialog.getInt(self, "测试次数", "请输入测试次数")
        if ok:
            for i in range(num):
                start_time = time.time()
                code = gm.dmsUK_UKey_Sign_no_cert(g.phContainer, g.pkmHash, g.Identity, len(g.Identity), g.useSignData,len(g.useSignData), byref(g.pSignature), byref(g.PA))
                end_time = time.time()
                if 0 == code:
                    run_time += (end_time - start_time)
                else:
                    logger.error("signNoCert_XN error:" + code_to_str(code))
                    w = w + 1
            signle_time = (run_time * 1000) / num
            logger.info("执行 %s 次，成功 %s 次，单次平均执行时间：%d ms" % (num,num-w,signle_time))
            if ( 0 < run_time ):
                result_xn = num / (run_time)
                logger.info("dmsUK_UKey_Sign_no_cert 性能测试结果：%d 次/秒" % result_xn)


    def verifyNoCert_XN(self):
        run_time = 0
        w = 0

        code = gm.dmsUK_UKey_Sign_no_cert(g.phContainer, g.pkmHash, g.Identity, len(g.Identity), g.useSignData,len(g.useSignData), byref(g.pSignature), byref(g.PA))
        if code == 0:
            g.textBrowser.append("SM2 签名 （无证书）成功，code = "+hex(code))
            logger.info("SM2 签名 （无证书）成功，code = "+hex(code))
        else:
            g.textBrowser.append("SM2 签名 （无证书）失败，code = "+hex(code))
            logger.info("SM2 签名 （无证书）失败，code = "+hex(code))
        num, ok = QInputDialog.getInt(self, "测试次数", "请输入测试次数")

        if ok:
            for i in range(num):
                start_time = time.time()
                code = gm.dmsUK_UKey_verify_no_cert(g.phApplication, g.pkmHash, g.Identity, len(g.Identity), g.useSignData,len(g.useSignData), g.PA, g.pSignature)
                end_time = time.time()
                if code == 0:
                    # print("SM2验签 ok")
                    run_time += (end_time - start_time)
                else:
                    print("SM2验签 error !! %s" % hex(code))
                    w = w + 1
            signle_time = (run_time * 1000) / num
            logger.info("执行 %s 次，成功 %s 次，单次平均执行时间：%d ms" % (num,num-w,signle_time))
            if ( 0 < run_time ):
                result_xn = num / (run_time)
                logger.info("dmsUK_UKey_verify_no_cert 性能测试结果：%d 次/秒" % result_xn)



