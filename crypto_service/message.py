# -*- coding:utf8 -*-
# @author：X.
# @time：2020/11/18:11:14


class ErrorCode:
    _0XA000001 = "失败"
    _0XA000002 = "异常错误"
    _0XA000003 = "不支持的服务"
    _0XA000004 = "文件操作错误"
    _0XA000005 = "无效的句柄"
    _0XA000006 = "无效的参数"
    _0XA000007 = "读文件错误"
    _0XA000008 = "写文件错误"
    _0XA000009 = "名称长度错误"
    _0XA00000A = "密钥用途错误"
    _0XA00000B = "模的长度错误"
    _0XA00000C = "未初始化"
    _0XA00000D = "对象错误"
    _0XA00000E = "内存错误"
    _0XA00000F = "超时"
    _0XA000010 = "输入数据长度错误"
    _0XA000011 = "输入数据错误"
    _0XA000012 = "生成随机数错误"
    _0XA000013 = "HASH对象错"
    _0XA000014 = "HASH运算错误"
    _0XA000015 = "产生RSA密钥错（预留）"
    _0XA000016 = "RSA密钥模长错误（预留）"
    _0XA000017 = "CSP服务导入公钥错误（预留）"
    _0XA000018 = "RSA加密错误（非对称算法加密错误）"
    _0XA000019 = "RSA解密错误（非对称算法解密错误）"
    _0XA00001A = "HASH值不相等"
    _0XA00001B = "密钥未发现"
    _0XA00001C = "用户标识未发现"
    _0XA00001D = "对象未导出"
    _0XA00001E = "解密时做补丁错误"
    _0XA00001F = "MAC长度错误"
    _0XA000020 = "缓冲区不足"
    _0XA000021 = "密钥类型错误"
    _0XA000022 = "无事件错误"
    _0XA000023 = "设备已移除"
    _0XA000024 = "PIN不正确"
    _0XA000025 = "PIN被锁死"
    _0XA000026 = "PIN无效"
    _0XA000027 = "PIN长度错误"
    _0XA000028 = "用户已经登录"
    _0XA000029 = "没有初始化用户口令"
    _0XA00002A = "PIN类型错误"
    _0XA00002B = "应用名称无效"
    _0XA00002C = "应用已经存在"
    _0XA00002D = "用户没有登录"
    _0XA00002E = "应用不存在"
    _0XA00002F = "文件已经存在"
    _0XA000030 = "空间不足"
    _0XA000031 = "文件不存在"
    _0XA000032 = "已达到最大可管理容器数"
    _0XA000033 = "数据长度错误"
    _0XA000034 = "操作权限不足"
    _0XA000035 = "发送数据错误"
    _0XA000036 = "认证方法锁定"
    _0XA000037 = "引用数据无效"
    _0XA000038 = "认证失败"
    _0XA000039 = "已有打开的应用，当前设备不支持同时打开多个应用"
    _0XA000040 = "引用的容器不存在"
    _0XA000041 = "容器中不存在对应的密钥对"
    _0XA000042 = "验证签名失败"
    _0XA000043 = "签名失败"
    _0XA000044 = "设备已连接"
    _0XA000045 = "设备连接失败"
    _0XA000046 = "随机数检测失败"
    _0XA000047 = "随机数发生器失效"


errCode = ErrorCode()


class Message:
    ENUMERATE_DEV_SUCCESS = "枚举设备成功,message:"
    CONNECT_DEV_SUCCESS = "设备连接成功,message:"
    DISCONNECT_DEV_SUCCESS = "设备成功断开,message:"
    DEV_STATUS_TRUE = "设备已连接,message:"
    DEV_STATUS_FALSE = "设备已断开,message:"
    SET_DEV_LABEL_SUCCESS = "标签设置成功,message:"
    GET_DEV_INFO_SUCCESS = "获取设备信息成功,message:"
    LOCK_DEV_SUCCESS = "设备锁定,message:"
    UNLOCK_DEV_SUCCESS = "解锁设备成功,message:"
    WAITING_DEV_ACTION = "等待设备插拔,message:"
    DEV_INSERT = "设备插入,message:"
    DEV_PULLOUT = "设备拔出,message:"
    CANCEL_WAITING_DEV_ACTION = "取消设备等待事件,message:"

    DEV_AUTH_SUCCESS = "设备认证成功,message:"
    CHANGE_AUTH_PIN_SUCCESS = "修改设备认证密钥成功,message:"
    CHANGE_ADMIN_PIN_SUCCESS = "修改管理员PIN成功,message:"
    CHANGE_USER_PIN_SUCCESS = "修改用户PIN成功,message:"
    GET_ADMIN_PIN_INFO_SUCCESS = "获取管理员PIN信息成功,message:"
    GET_USER_PIN_INFO_SUCCESS = "获取用户PIN信息成功,message:"
    VERIFY_ADMIN_PIN_SUCCESS = "校验管理员PIN成功,message:"
    VERIFY_USER_PIN_SUCCESS = "校验用户PIN成功,message:"
    UNLOCK_PIN_SUCCESS = "解锁用户PIN成功,message:"
    CLEAR_SECURE_STATE_SUCCESS = "成功清除应用安全状态,message:"

    CREATE_APP_SUCCESS = "应用创建成功,message:"
    DEL_APP_SUCCESS = "删除应用成功,message:"
    ENUM_APP_SUCCESS = "枚举应用成功,message:"
    OPEN_APP_SUCCESS = "打开应用成功,message:"
    CLOSE_APP_SUCCESS = "关闭应用成功,message:"

    CREATE_FILE_SUCCESS = "文件创建成功,message:"
    DEL_FILE_SUCCESS = "文件删除成功,message:"
    ENUM_FILE_SUCCESS = "枚举文件成功,message:"
    GET_FILE_INFO_SUCCESS = "获取文件信息成功,message:"
    READ_FILE_SUCCESS = "读取文件成功,message:"
    WRITE_FILE_SUCCESS = "写文件成功,message:"

    CREATE_CONTAINER_SUCCESS = "容器创建成功,message:"
    DEL_CONTAINER_SUCCESS = "容器删除成功,message:"
    OPEN_CONTAINER_SUCCESS = "打开容器成功,message:"
    CLOSE_CONTAINER_SUCCESS = "关闭容器成功,message:"
    GET_CONTAINER_TYPE_SUCCESS = "成功获取容器类型,message:"
    ENUM_CONTAINER_SUCCESS = "枚举容器成功,message:"
    IMPORT_CERT_SUCCESS = "导入证书成功,message:"
    EXPORT_CERT_SUCCESS = "导出证书成功,message:"

    GENERATE_RANDOM_SUCCESS = "生成随机数成功,message:"
    GENERATE_ECC_SUCCESS = "生成ecc签名钥对成功,message:"
    GENERATE_PROTECT_SUCCESS = "生成保护密钥对成功,message:"
    IMPORT_ECC_SUCCESS = "导入Ecc加密密钥成功,message:"
    ECC_SING_DATA_SUCCESS = "Ecc签名成功,message:"
    ECC_VERIFY_SUCCESS = "ECC验签成功,message:"
    ECC_EXPORT_SESSION_KEY_SUCCESS = "生成并导出会话密钥成功,message:"
    RSA_SING_DATA_SUCCESS = "RSA签名成功,message:"
    RSA_VERIFY_SUCCESS = "RSA验签成功,message:"
    EXT_PUBKEY_ENCRYPT_SUCCESS = "ECC外来公钥加密成功,message:"
    GENERATE_AGREEMENT_ECC_SUCCESS = "发方生成密钥协商参数并输出成功,message:"
    GENERATE_AGREEMENT_DATA_SUCCESS = "收方产生协商参数并计算会话密钥成功,message:"
    GENERATE_KEY_WITH_ECC_SUCCESS = "发方计算会话密钥成功,message:"
    EXPORT_SIGN_KEY_SUCCESS = "导出签名公钥成功,message:"
    EXPORT_ENCRYPT_KEY_SUCCESS = "导出加密公钥成功,message:"
    IMPORT_SESSION_KEY_SUCCESS = "导入会话密钥成功,message:"
    EXPORT_PUBLIC_KEY_SUCCESS = "导出临时公钥成功,message:"

    ENCRYPT_INIT_SUCCESS = "加密初始化成功,message:"
    ENCRYPT_SUCCESS = "数据加密成功,message:"
    ENCRYPT_UPDATE_SUCCESS = "多组数据加密成功,message:"
    ENCRYPT_FINAL_SUCCESS = "结束加密"
    DECRYPT_INIT_SUCCESS = "解密初始化成功,message:"
    DECRYPT_SUCCESS = "数据解密成功,message:"
    DECRYPT_UPDATE_SUCCESS = "多组数据解密成功,message:"
    DECRYPT_FINA_SUCCESS = "结束解密成功,message:"
    DIGEST_INIT_SUCCESS = "密码杂凑初始化成功,message:"
    DIGEST_SUCCESS = "数据加密杂凑成功,message:"
    DIGEST_UPDATE_SUCCESS = "多组数据加密杂凑成功,message:"
    DIGEST_FINAL_SUCCESS = "结束密码杂凑"
    MAC_INIT_SUCCESS = "消息鉴别码运算初始化成功,message:"
    MAC_SUCCESS = "单组数据鉴别计算成功,message:"
    MAC_UPDATE_SUCCESS = "多组数据消息鉴别计算成功,message:"
    MAC_FINAL_SUCCESS = "结束消息鉴别运算,message:"

    DESTROY_SESSION_KEY_SUCCESS = "销毁会话密钥成功，message："

    ENUMERATE_DEV_FAILED = "枚举设备失败，message："
    CONNECT_DEV_FAILED = "设备连接失败，message："
    DISCONNECT_DEV_FAILED = "设备断开失败，message："
    GET_DEV_STATUS_FAILED = "获取设备状态失败"
    SET_DEV_LABEL_FAILED = "标签设置失败，message："
    GET_DEV_INFO_FAILED = "获取设备信息失败，message："
    LOCK_DEV_FAILED = "设备锁定失败，message："
    UNLOCK_DEV_FAILED = "解锁设备失败，message："
    WAITING_DEV_FAILED = "等待设备错误："
    CANCEL_WAITING_DEV_FAILED = "取消等待设备错误："

    DEV_AUTH_FAILED = "设备认证失败，message："
    CHANGE_AUTH_PIN_FAILED = "修改设备认证密钥失败，message："
    CHANGE_ADMIN_PIN_FAILED = "修改管理员PIN失败，message："
    CHANGE_USER_PIN_FAILED = "修改用户PIN失败，message："
    GET_ADMIN_PIN_INFO_FAILED = "获取管理员PIN信息失败，message："
    GET_USER_PIN_INFO_FAILED = "获取用户PIN信息失败，message："
    VERIFY_ADMIN_PIN_FAILED = "校验管理员PIN失败，message："
    VERIFY_USER_PIN_FAILED = "校验用户PIN失败，message："
    UNLOCK_PIN_FAILED = "解锁用户PIN失败,剩余重试次数："
    CLEAR_SECURE_STATE_FAILED = "清除应用安全状态失败，message："

    CREATE_APP_FAILED = "应用创建失败，message："
    DEL_APP_FAILED = "删除应用失败，message："
    ENUM_APP_FAILED = "枚举应用失败，message："
    OPEN_APP_FAILED = "打开应用失败，message："
    CLOSE_APP_FAILED = "关闭应用失败，message："

    CREATE_FILE_FAILED = "文件创建失败，message："
    DEL_FILE_FAILED = "文件删除失败，message："
    ENUM_FILE_FAILED = "枚举文件失败，message："
    GET_FILE_INFO_FAILED = "获取文件信息失败，message："
    READ_FILE_FAILED = "读取文件失败，message："
    WRITE_FILE_FAILED = "写文件失败，message："

    CREATE_CONTAINER_FAILED = "容器创建失败，message："
    DEL_CONTAINER_FAILED = "容器删除失败，message："
    OPEN_CONTAINER_FAILED = "打开容器失败，message："
    CLOSE_CONTAINER_FAILED = "关闭容器失败，message："
    GET_CONTAINER_TYPE_FAILED = "获取容器类型失败，message："
    ENUM_CONTAINER_FAILED = "枚举容器失败，message："
    IMPORT_CERT_FAILED = "导入证书失败"
    EXPORT_CERT_FAILED = "导出证书失败"

    GENERATE_RANDOM_FAILED = "生成随机数失败，message："
    GENERATE_ECC_FAILED = "生成ecc签名钥对失败，message："
    GENERATE_PROTECT_FAILED = "生成保护密钥对失败,message:"
    IMPORT_ECC_FAILED = "导入Ecc加密密钥失败，message："
    ECC_SING_DATA_FAILED = "Ecc签名失败，message："
    ECC_VERIFY_FAILED = "ECC数据验签失败，message："
    ECC_EXPORT_SESSION_KEY_FAILED = "生成导出会话密钥失败，message："
    RSA_SING_DATA_FAILED = "RSA 签名失败，message："
    RSA_VERIFY_FAILED = "RSA 数据验签失败，message："
    EXT_PUBKEY_ENCRYPT_FAILED = "ECC外来公钥加密失败，message："
    GENERATE_AGREEMENT_ECC_FAILED = "发方生成密钥协商参数并输出失败，message："
    GENERATE_AGREEMENT_DATA_FAILED = "收方产生协商参数并计算会话密钥失败，message："
    GENERATE_KEY_WITH_ECC_FAILED = "发方计算会话密钥失败，message："
    EXPORT_SIGN_KEY_FAILED = "导出签名公钥失败,message:"
    EXPORT_ENCRYPT_KEY_FAILED = "导出加密公钥失败,message:"
    EXPORT_PUBLIC_KEY_FAILED = "导出临时公钥失败,message:"
    IMPORT_SESSION_KEY_FAILED = "导入会话密钥失败，message："
    ENCRYPT_INIT_FAILED = "加密初始化失败，message："
    ENCRYPT_FAILED = "数据加密失败，message："
    ENCRYPT_UPDATE_FAILED = "多组数据加密失败，message："
    ENCRYPT_FINAL_FAILED = "结束加密，message:"
    DECRYPT_INIT_FAILED = "解密初始化失败，message："
    DECRYPT_FAILED = "数据解密失败，message："
    DECRYPT_UPDATE_FAILED = "多组数据解密失败，message："
    DECRYPT_FINA_FAILED = "结束解密失败，message："
    DIGEST_INIT_FAILED = "密码杂凑初始化失败，message："
    DIGEST_FAILED = "数据加密杂凑失败，message："
    DIGEST_UPDATE_FAILED = "多组数据加密杂凑失败，message："
    DIGEST_FINAL_FAILED = "结束密码杂凑"
    MAC_INIT_FAILED = "消息鉴别码运算初始化失败，message："
    MAC_FAILED = "单组数据鉴别计算失败，message："
    MAC_UPDATE_FAILED = "多组数据消息鉴别计算失败，message："
    MAC_FINAL_FAILED = "结束消息鉴别运算失败，message："

    DESTROY_SESSION_KEY_FAILED = "销毁会话密钥失败，message："


def code_to_str(code):
    code_ = '_' + str(hex(code)).upper()
    return getattr(errCode, code_) if hasattr(errCode, code_) else str(code)
