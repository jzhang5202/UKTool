# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:13:38

from ui_file.testUI import Ui_UkeyTestTool # 增加文本显示器
from crypto_service.iki import *
from crypto_service.util import open_log_file

from crypto_service.crypto import Crypto


class Test(Ui_UkeyTestTool, Crypto):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        g.textBrowser = self.textBrowser

        # 设备管理
        self.pushButton1.clicked.connect(self.SKF_EnumDev)
        self.pushButton2.clicked.connect(self.SKF_ConnectDev)
        self.pushButton3.clicked.connect(self.SKF_DisConnectDev)
        self.pushButton4.clicked.connect(self.SKF_SetLabel)
        self.pushButton5.clicked.connect(self.SKF_GetDevState)
        self.pushButton6.clicked.connect(self.SKF_GetDevInfo)
        self.pushButton7.clicked.connect(self.SKF_LockDev)
        self.pushButton8.clicked.connect(self.SKF_UnlockDev)
        self.pushButton9.clicked.connect(self.SKF_WaitForDevEvent)
        self.pushButton10.clicked.connect(self.SKF_CancelWaitForDevEvent)

        # 访问控制
        self.pushButton11.clicked.connect(self.SKF_ChangeDevAuthKey)
        self.pushButton12.clicked.connect(self.SKF_DevAuth)
        self.pushButton13.clicked.connect(self.SKF_VerifyUserPIN)
        self.pushButton14.clicked.connect(self.SKF_ChangeUserPIN)
        self.pushButton15.clicked.connect(self.SKF_VerifyAdminPIN)
        self.pushButton16.clicked.connect(self.SKF_ChangeAdminPIN)
        self.pushButton17.clicked.connect(self.SKF_GetPINInfo)
        self.pushButton18.clicked.connect(self.SKF_UnblockPIN)
        self.pushButton19.clicked.connect(self.SKF_ClearSecureState)
        # 应用管理
        self.pushButton20.clicked.connect(self.SKF_CreateApplication)
        self.pushButton21.clicked.connect(self.SKF_EnumApplication)
        self.pushButton22.clicked.connect(self.SKF_OpenApplication)
        self.pushButton23.clicked.connect(self.SKF_CloseApplication)
        self.pushButton24.clicked.connect(self.SKF_DeleteApplication)
        # 文件管理
        self.pushButton25.clicked.connect(self.SKF_CreateFile)
        self.pushButton26.clicked.connect(self.SKF_DeleteFile)
        self.pushButton27.clicked.connect(self.SKF_EnumFiles)
        self.pushButton28.clicked.connect(self.SKF_GetFileInfo)
        self.pushButton29.clicked.connect(self.SKF_WriteFile)
        self.pushButton30.clicked.connect(self.SKF_ReadFile)
        # 容器管理
        self.pushButton31.clicked.connect(self.SKF_CreateContainer)
        self.pushButton32.clicked.connect(self.SKF_DeleteContainer)
        self.pushButton33.clicked.connect(self.SKF_OpenContainer)
        self.pushButton34.clicked.connect(self.SKF_CloseContainer)
        self.pushButton35.clicked.connect(self.SKF_EnumContainer)
        self.pushButton36.clicked.connect(self.SKF_GetContainerType)
        self.pushButton37.clicked.connect(self.SKF_ImportCertificate)
        self.pushButton38.clicked.connect(self.SKF_ExportCertificate)
        # 密钥服务
        self.pushButton39.clicked.connect(self.SKF_GenRandom)
        self.pushButton40.clicked.connect(self.SKF_GenECCKeyPairH)
        self.pushButton41.clicked.connect(self.SKF_GenECCKeyPair)
        self.pushButton42.clicked.connect(self.SKF_ImportECCKeyPair)
        self.pushButton43.clicked.connect(self.SKF_ECCSignData)
        self.pushButton44.clicked.connect(self.SKF_ECCVerify)
        self.pushButton45.clicked.connect(self.SKF_ECCExportSessionKey)
        self.pushButton46.clicked.connect(self.SKF_ImportSessionKey)
        self.pushButton47.clicked.connect(self.SKF_ExportSignPublicKey)
        self.pushButton48.clicked.connect(self.SKF_ExportEncrypPublicKey)
        self.pushButton49.clicked.connect(self.SKF_ExportPublicKeyH)
        self.pushButton50.clicked.connect(self.SKF_ExtECCEncrypt)
        self.pushButton51.clicked.connect(self.SKF_GenerateAgreementDataWithECC)
        self.pushButton52.clicked.connect(self.SKF_GenerateAgreementDataAndKeyWithECC)
        self.pushButton53.clicked.connect(self.SKF_GenerateKeyWithECC)
        self.pushButton54.clicked.connect(self.SKF_EncryptInit)
        self.pushButton55.clicked.connect(self.SKF_EncryptUpdate)
        self.pushButton56.clicked.connect(self.SKF_EncryptFinal)
        self.pushButton57.clicked.connect(self.SKF_DecryptInit)
        self.pushButton58.clicked.connect(self.SKF_DecryptUpdate)
        self.pushButton59.clicked.connect(self.SKF_DecryptFinal)
        self.pushButton60.clicked.connect(self.SKF_DigestInit)
        self.pushButton61.clicked.connect(self.SKF_Digest)
        self.pushButton62.clicked.connect(self.SKF_DigestUpdate)
        self.pushButton63.clicked.connect(self.SKF_DigestFinal)
        self.pushButton64.clicked.connect(self.SKF_MacInit)
        self.pushButton65.clicked.connect(self.SKF_Mac)
        self.pushButton66.clicked.connect(self.SKF_MacUpdate)
        self.pushButton67.clicked.connect(self.SKF_MacFinal)
        # IKI自主服务接口
        self.pushButton68.clicked.connect(self.SKF_ImportIdentify)
        self.pushButton69.clicked.connect(self.SKF_ExportIdentify)
        self.pushButton70.clicked.connect(self.SKF_ImportPubMatrix)
        self.pushButton71.clicked.connect(self.SKF_ExportPubMatrix)
        self.pushButton72.clicked.connect(self.SKF_DeletePubMatrix)
        self.pushButton73.clicked.connect(self.SKF_CalculatePubKey)
        self.pushButton74.clicked.connect(self.SKF_CalculatePubKeyAddField)
        self.pushButton75.clicked.connect(self.SKF_ECCExportSessionKeyEx)
        self.pushButton76.clicked.connect(self.SKF_GenerateKDFSessionKey)
        self.pushButton77.clicked.connect(self.SKF_DestroySessionKey)
        self.pushButton78.clicked.connect(self.SKF_ImportPublicKeyRPK)
        self.pushButton79.clicked.connect(self.SKF_ExportPublicKeyRPK)
        self.pushButton80.clicked.connect(self.SKF_UkeyRandomTest)
        self.pushButton81.clicked.connect(self.SKF_RandomSingleTest)
        self.pushButton82.clicked.connect(self.SKF_HashInitFast)
        self.pushButton83.clicked.connect(self.SKF_HashUpdateFast)
        self.pushButton84.clicked.connect(self.SKF_HashFinalFast)
        self.pushButton85.clicked.connect(self.SKF_GenerateAgreementDataWithECC_VPN)
        self.pushButton86.clicked.connect(self.SKF_GenAgreementDataAndKeyWithECC_VPN)
        self.pushButton87.clicked.connect(self.SKF_GenerateKeyWithECC_VPN)
        self.pushButton88.clicked.connect(self.dmsUK_Hsign)
        self.pushButton89.clicked.connect(self.dmsUK_HEccVerify)

        # 性能测试
        self.pushButton91.clicked.connect(self.SKF_GenECCKeyPair_XN)
        self.pushButton92.clicked.connect(self.SKF_ECCSignData_XN)
        self.pushButton93.clicked.connect(self.SKF_ECCVerify_XN)
        self.pushButton94.clicked.connect(self.SKF_ExtECCEncrypt_XN)
        self.pushButton95.clicked.connect(self.SKF_ImportSessionKey_XN)
        self.pushButton96.clicked.connect(self.SKF_Hash_XN)
        self.pushButton97.clicked.connect(self.SKF_Encrypt_XN)
        self.pushButton98.clicked.connect(self.SKF_Decrypt_XN)
        self.pushButton99.clicked.connect(self.write_file_XN)
        self.pushButton100.clicked.connect(self.read_file_XN)

        self.pushButton_89.clicked.connect(open_log_file)
        self.pushButton_2.clicked.connect(self.device_reset)

        self.pushButton1_2.clicked.connect(self.getPkmHash)
        self.pushButton1_3.clicked.connect(self.signNoCert)

