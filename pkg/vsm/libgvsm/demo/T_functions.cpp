#include <iostream>
#include <cstdio>
#include <cstring>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstdlib>
#include "SDF.h"
#include "TassAPI4GHVSM.h"

using namespace std;
#ifdef _WIN32
#pragma warning(disable:4996)
#include <WinSock2.h>
#endif

#define THREADNUMS 5000
#define BUFLITTLE  32
#define BUFSMALL   128
#define BUF        1024

#define CC_TO_UC(ptr) \
    reinterpret_cast<unsigned char*>(const_cast<char*>(ptr))


#define CHECK_RT(func, rt)\
	if (rt)\
	{\
		printf("Function[%s] run failed %d | 0x%08x\n", #func, rt, rt);\
		return;\
	}\
	else{\
		printf("Function[%s] run success\n", #func);\
	}

#define PRINT_NUM(num)\
do{\
	printf("\t%s = %d | 0x%08X\n", #num, num, num);\
}while(0)

#define PRINT_BIN(buf, len)\
do{\
	printf("\t%s[%s = %d]: %s\n", #buf, #len, len, Bin2String(buf, len, true).c_str());\
}while(0)

#define PRINT_STR(buf, len)\
do{\
	printf("\t%s[%s = %d]: %s\n", #buf, #len, len, buf);\
}while(0)
static void* g_hDev = NULL, * g_hSess = NULL, * g_hKey = NULL;

static unsigned char pwd[] = "a1234567";
//static unsigned char pwd[] = "12345678";
static int pwdLen = 8;
static unsigned int g_keyAsymIndex = 100;
static unsigned int g_keySymIndex = 50;
static unsigned int g_keyAsymIndexRsa = 600;
static unsigned int g_keySymIndexRsa = 601;

static unsigned char* g_Data = NULL;
static unsigned int g_DataLen = 0;
static unsigned char* g_DataOut = NULL;
static unsigned int g_DataOutLen = 0;

string pkcs5_pad(string data) {
	int m = 16 - data.length() % 16;
	string padded_data = data + string(m,m);
	return padded_data;
}

string pkcs5_unpad(string padded_data)
{
	unsigned char m = padded_data.at(padded_data.length() - 1);
	string unPadded_data = padded_data.substr(0, padded_data.length() - (unsigned int)m);
	return unPadded_data;
}

string pad_80(string data)
{
	int m = 16 - data.length() % 16;
	string padded_data = data + string(m, 0x80);
	return padded_data;
}

string unpad_80(string padded_data)
{
	int pad_length = 0;

	for (int i = padded_data.length() - 1; i >= 0; --i) {
		if (padded_data[i] == 0x80)
			pad_length++;
		else
			break;
	}

	if (pad_length == 0)
		return padded_data;

	string unpadded_data = padded_data.substr(0, padded_data.length() - pad_length);
	return unpadded_data;
}

#define TaMalloc(memory, type, size)    if( memory==NULL ){                     \
											memory = (type *)malloc(size);		\
										}										\
										else {                                  \
											free(memory);                       \
											memory = (type *)malloc(size);		\
										}

#define TaFree(Memory)                  if(Memory != NULL){                     \
											free(Memory);                       \
											Memory = NULL;                      \
										}

#define TaZero(buf, length)				memset(buf, 0, length)

#define INIT()												\
		void* hDev = NULL, * hSess = NULL;					\
		int rt = SDF_OpenDevice(&hDev);					\
		if (rt)												\
		{													\
			printf("SDF_OpenDevice failed 0x%08x\n", rt);	\
			return;											\
		}													\
		rt = SDF_OpenSession(hDev, &hSess);					\
		if (rt)												\
		{													\
			printf("SDF_OpenSession failed 0x%08x\n", rt);	\
			SDF_CloseDevice(hDev);							\
			return;											\
		}													\

#define UNINIT()											\
		SDF_CloseSession(hSess);							\
		SDF_CloseDevice(hDev);								\

static string Bin2String(const unsigned char* bin, const unsigned int len, const bool upper = false);
static string Bin2String(const string& bBin, const bool upper = false);
static int String2Bin(const string& str, unsigned char* bin, unsigned int* size);
static string String2Bin(const string& str);

static void printHex(const char* title, unsigned char* buf, int len)
{
	int i;
	printf("%s[length = %d]:\n\t", title == NULL ? "" : title, len);
	for (i = 0; i < len; ++i)
		printf("%02X", buf[i]);
	printf("\n");
}

string  Bin2String(const unsigned char* bin, const unsigned int len, const bool upper)
{
	if (bin == NULL || len == 0)
		return "";
	std::stringstream ss;
	for (int i = 0; i < (int)len; ++i) {
		if (upper)
			ss.setf(std::ios::uppercase);
		ss << std::hex << std::setw(2) << std::setfill('0') << (bin[i] & 0xff);
	}
	return ss.str();
}

string Bin2String(const string& bBin, bool upper)
{
	return Bin2String((unsigned char*)bBin.data(), (unsigned int)bBin.length(), upper);
}

string String2Bin(const string& str)
{
	string bRt = "";
	for (int i = 0; i < (int)str.length() / 2 * 2; i += 2) {
		std::stringstream ss(str.substr(i, 2));
		int tmp = -1;
		ss >> std::hex >> tmp;
		bRt.append(1, (char)(tmp & 0xFF));
	}
	return bRt;
}

int String2Bin(const string& str, unsigned char* bin, unsigned int* size)
{
	if (bin == NULL)
		return -1;
	if (size == NULL)
		return (int)str.length() / 2;
	if (*size < str.length() / 2)
		return (int)str.length() / 2;
	string bBin = String2Bin(str);
	*size = (int)bBin.length();
	memcpy(bin, bBin.data(), *size);
	return *size;
}

char algStr[BUFSMALL] = { 0 };
char* GetAlgStr(unsigned int algID)
{
	switch (algID)
	{
	case SGD_SM1_ECB: sprintf(algStr, "SGD_SM1_ECB"); break;
	case SGD_SM1_CBC: sprintf(algStr, "SGD_SM1_CBC"); break;
	case SGD_SM1_CFB: sprintf(algStr, "SGD_SM1_CFB"); break;
	case SGD_SM1_OFB: sprintf(algStr, "SGD_SM1_OFB"); break;
	case SGD_SM1_MAC: sprintf(algStr, "SGD_SM1_MAC"); break;

	case SGD_SSF33_ECB: sprintf(algStr, "SGD_SSF33_ECB"); break;
	case SGD_SSF33_CBC:	sprintf(algStr, "SGD_SSF33_CBC"); break;
	case SGD_SSF33_CFB:	sprintf(algStr, "SGD_SSF33_CFB"); break;
	case SGD_SSF33_OFB:	sprintf(algStr, "SGD_SSF33_OFB"); break;
	case SGD_SSF33_MAC:	sprintf(algStr, "SGD_SSF33_MAC"); break;

	case SGD_SM4_ECB: sprintf(algStr, "SGD_SM4_ECB"); break;
	case SGD_SM4_CBC: sprintf(algStr, "SGD_SM4_CBC"); break;
	case SGD_SM4_CFB: sprintf(algStr, "SGD_SM4_CFB"); break;
	case SGD_SM4_OFB: sprintf(algStr, "SGD_SM4_OFB"); break;
	case SGD_SM4_MAC: sprintf(algStr, "SGD_SM4_MAC"); break;

	case SGD_ZUC_EEA3: sprintf(algStr, "SGD_ZUC_EEA3"); break;
	case SGD_ZUC_EIA3: sprintf(algStr, "SGD_ZUC_EIA3"); break;

	case SGD_RSA: sprintf(algStr, "SGD_RSA"); break;
	case SGD_SM2: sprintf(algStr, "SGD_SM2"); break;
	case SGD_SM2_1:	sprintf(algStr, "SGD_SM2_1"); break;
	case SGD_SM2_2:	sprintf(algStr, "SGD_SM2_2"); break;
	case SGD_SM2_3:	sprintf(algStr, "SGD_SM2_3"); break;

	case SGD_SM3: sprintf(algStr, "SGD_SM3"); break;
	case 2: sprintf(algStr, "SGD_SHA1"); break;
	case SGD_SHA256: sprintf(algStr, "SGD_SHA256"); break;

	default:
		sprintf(algStr, "0x%08x", algID);
		break;
	}
	return algStr;
}

//string GetAlgStr(unsigned int algID)
//{
//	stringstream ss;
//	switch (algID)
//	{
//	case SGD_SM1_ECB: ss << "SGD_SM1_ECB"; break;
//	case SGD_SM1_CBC: ss << "SGD_SM1_CBC"; break;
//	case SGD_SM1_CFB: ss << "SGD_SM1_CFB"; break;
//	case SGD_SM1_OFB: ss << "SGD_SM1_OFB"; break;
//	case SGD_SM1_MAC: ss <<  "SGD_SM1_MAC"; break;
//
//	case SGD_SSF33_ECB: ss << "SGD_SSF33_ECB"; break;
//	case SGD_SSF33_CBC:	ss << "SGD_SSF33_CBC"; break;
//	case SGD_SSF33_CFB:	ss << "SGD_SSF33_CFB"; break;
//	case SGD_SSF33_OFB:	ss << "SGD_SSF33_OFB"; break;
//	case SGD_SSF33_MAC:	ss << "SGD_SSF33_MAC"; break;
//
//	case SGD_SM4_ECB: ss << "SGD_SM4_ECB"; break;
//	case SGD_SM4_CBC: ss << "SGD_SM4_CBC"; break;
//	case SGD_SM4_CFB: ss << "SGD_SM4_CFB"; break;
//	case SGD_SM4_OFB: ss << "SGD_SM4_OFB"; break;
//	case SGD_SM4_MAC: ss << "SGD_SM4_MAC"; break;
//
//	case SGD_ZUC_EEA3: ss << "SGD_ZUC_EEA3"; break;
//	case SGD_ZUC_EIA3: ss << "SGD_ZUC_EIA3"; break;
//
//	case SGD_RSA: ss << "SGD_RSA"; break;
//	case SGD_SM2: ss << "SGD_SM2"; break;
//	case SGD_SM2_1:	ss << "SGD_SM2_1"; break;
//	case SGD_SM2_2:	ss << "SGD_SM2_2"; break;
//	case SGD_SM2_3:	ss << "SGD_SM2_3"; break;
//
//	case SGD_SM3: ss << "SGD_SM3"; break;
//	case SGD_SHA1: ss << "SGD_SHA1"; break;
//	case SGD_SHA256: ss << "SGD_SHA256"; break;
//
//	default:
//		ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << algID;
//		break;
//	}
//	return ss.str();
//}

/************************************************************************/
/*                              功能测试                                */
/************************************************************************/

/*---------------------------设备管理类函数测试-------------------------*/

void T_SDF_GetDeviceInfo()
{
	DEVICEINFO devInfo = { 0 };
	int rt = SDF_GetDeviceInfo(g_hSess, &devInfo);
	if (rt)
	{
		printf("\nSDF_GetDeviceInfo failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GetDeviceInfo success \n");
		printf("IssuerName: %s\n", devInfo.IssuerName);
		printf("DeviceName: %s\n", devInfo.DeviceName);
		printf("DeviceSerial: %s\n", devInfo.DeviceSerial);
		printf("DeviceVersion: 0x%08x\n", devInfo.DeviceVersion);
		printf("StandardVersion: 0x%08x\n", devInfo.StandardVersion);
		printf("AsymAlgAbility[0]: 0x%08x\n", devInfo.AsymAlgAbility[0]);
		printf("AsymAlgAbility[1]: 0x%08x\n", devInfo.AsymAlgAbility[1]);
		printf("SymAlgAbility: 0x%08x\n", devInfo.SymAlgAbility);
		printf("HashAlgAbility:0x%08x\n", devInfo.HashAlgAbility);
		printf("BufferSize: 0x%08x\n", devInfo.BufferSize);
	}
}

void T_SDF_GenerateRandom()
{
	unsigned char random[BUFLITTLE + 1] = { 0 };
	int rt = SDF_GenerateRandom(g_hSess, 32, random);
	if (rt)
	{
		printf("\nSDF_GenerateRandom failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateRandom success\n");
		printHex("random", random, 32);
	}
}

/*---------------------------密钥管理类函数测试-------------------------*/
void T_SDF_ExportPublicKey_RSA()
{
	RSArefPublicKey rsaSignPubKey = { 0 };
	RSArefPublicKey rsaEncPubKey = { 0 };

	RSArefPublicKey rsaPubKey = { 0 };
	RSArefPrivateKey rsaPriKey = { 0 };
	rsaPubKey.bits = g_keyAsymIndexRsa;
	rsaPriKey.bits = g_keyAsymIndexRsa;

	//存储签名、加密，密钥对
	int rt = SDF_GenerateKeyPair_RSA(g_hSess, 2048, &rsaPubKey, &rsaPriKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_RSA success\n");
		printf("PubKey.bits: %d\n", rsaPubKey.bits);
		printf("PubKey.m: %s\n", Bin2String(rsaPubKey.m, sizeof(rsaPubKey.m), true).data());
		printf("PubKey.e: %s\n", Bin2String(rsaPubKey.e, sizeof(rsaPubKey.e), true).data());
	}
	rt = SDF_ExportSignPublicKey_RSA(g_hSess, g_keyAsymIndexRsa, &rsaSignPubKey);
	if (rt)
	{
		printf("\nSDF_ExportSignPublicKey_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExportSignPublicKey_RSA success\n");
		printf("SignPubKey.bits: %d\n", rsaSignPubKey.bits);
		printf("SignPubKey.m: %s\n", Bin2String(rsaSignPubKey.m, sizeof(rsaSignPubKey.m), true).data());
		printf("SignPubKey.e: %s\n", Bin2String(rsaSignPubKey.e, sizeof(rsaSignPubKey.e), true).data());
	}

	rt = SDF_ExportEncPublicKey_RSA(g_hSess, g_keyAsymIndexRsa, &rsaEncPubKey);
	if (rt)
	{
		printf("\nSDF_ExportEncPublicKey_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExportEncPublicKey_RSA success\n");
		printf("EncPubKey.bits: %d\n", rsaEncPubKey.bits);
		printf("EncPubKey.m: %s\n", Bin2String(rsaEncPubKey.m, sizeof(rsaEncPubKey.m), true).data());
		printf("EncPubKey.e: %s\n", Bin2String(rsaEncPubKey.e, sizeof(rsaEncPubKey.e), true).data());
	}
}

void T_SDF_GenerateKeyPair_RSA()
{
	RSArefPublicKey rsaPubKey = { 0 };
	RSArefPrivateKey rsaPriKey = { 0 };

	int rt = SDF_GenerateKeyPair_RSA(g_hSess, 2048, &rsaPubKey, &rsaPriKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_RSA success\n");
		printf("PubKey.bits: %d\n", rsaPubKey.bits);
		printf("PubKey.m: %s\n", Bin2String(rsaPubKey.m, sizeof(rsaPubKey.m), true).data());
		printf("PubKey.e: %s\n", Bin2String(rsaPubKey.e, sizeof(rsaPubKey.e), true).data());
		printf("PriKey.bits: %d\n", rsaPriKey.bits);
		printf("PriKey.m: %s\n", Bin2String(rsaPriKey.m, sizeof(rsaPriKey.m), true).data());
		printf("PriKey.e: %s\n", Bin2String(rsaPriKey.e, sizeof(rsaPriKey.e), true).data());
		printf("PriKey.d: %s\n", Bin2String(rsaPriKey.d, sizeof(rsaPriKey.d), true).data());
		printf("PriKey.prime[0]: %s\n", Bin2String(rsaPriKey.prime[0], sizeof(rsaPriKey.prime[0]), true).data());
		printf("PriKey.prime[1]: %s\n", Bin2String(rsaPriKey.prime[1], sizeof(rsaPriKey.prime[1]), true).data());
		printf("PriKey.pexp[0]: %s\n", Bin2String(rsaPriKey.pexp[0], sizeof(rsaPriKey.pexp[0]), true).data());
		printf("PriKey.pexp[1]: %s\n", Bin2String(rsaPriKey.pexp[1], sizeof(rsaPriKey.pexp[1]), true).data());
		printf("PriKey.coef: %s\n", Bin2String(rsaPriKey.coef, sizeof(rsaPriKey.coef), true).data());
	}

	TaZero(&rsaPubKey, sizeof(rsaPubKey));
	TaZero(&rsaPriKey, sizeof(rsaPriKey));
	rsaPubKey.bits = g_keyAsymIndexRsa;
	rsaPriKey.bits = g_keyAsymIndexRsa;

	//存储签名、加密，密钥对
	rt = SDF_GenerateKeyPair_RSA(g_hSess, 2048, &rsaPubKey, &rsaPriKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_RSA success\n");
		printf("PubKey.bits: %d\n", rsaPubKey.bits);
		printf("PubKey.m: %s\n", Bin2String(rsaPubKey.m, sizeof(rsaPubKey.m), true).data());
		printf("PubKey.e: %s\n", Bin2String(rsaPubKey.e, sizeof(rsaPubKey.e), true).data());
	}
}

unsigned int g_keyBits[3] = { 128, 192, 256 };

void T_SDF_GenerateKey_And_Import_RSA()
{
	unsigned char encKey[BUF + 1] = { 0 };
	unsigned int encKeyLen = sizeof(encKey);
	RSArefPublicKey rsaPubKey = { 0 };
	RSArefPrivateKey rsaPriKey = { 0 };
	void* hKeyHdl = NULL;

	for (int i = 0; i < 3; ++i)
	{
		//获取公钥
		rsaPubKey.bits = g_keyAsymIndexRsa;
		rsaPriKey.bits = g_keyAsymIndexRsa;
		int rt = SDF_GenerateKeyPair_RSA(g_hSess, 2048, &rsaPubKey, &rsaPriKey);
		if (rt)
		{
			printf("\nSDF_GenerateKeyPair_RSA failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyPair_RSA success\n");
			printf("PubKey.bits: %d\n", rsaPubKey.bits);
			printf("PubKey.m: %s\n", Bin2String(rsaPubKey.m, sizeof(rsaPubKey.m), true).data());
			printf("PubKey.e: %s\n", Bin2String(rsaPubKey.e, sizeof(rsaPubKey.e), true).data());
		}

		//生成会话密钥 外部公钥加密输出
		rt = SDF_GenerateKeyWithEPK_RSA(g_hSess, g_keyBits[i], &rsaPubKey, encKey, &encKeyLen, &hKeyHdl);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithEPK_RSA failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithEPK_RSA success\n");
			printf("key 1: %s\n", Bin2String(encKey, encKeyLen, true).data());

			rt = SDF_DestroyKey(g_hSess, hKeyHdl);
			if (rt)
			{
				printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
				return;
			}
			printf("\nSDF_DestroyKey success\n");
			hKeyHdl = NULL;
		}

		TaZero(encKey, sizeof(encKey));

		//生成会话密钥 内部公钥加密输出
		rt = SDF_GenerateKeyWithIPK_RSA(g_hSess, g_keyAsymIndexRsa, g_keyBits[i], encKey, &encKeyLen, &hKeyHdl);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithIPK_RSA failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithIPK_RSA success\n");
			printf("key 2: %s\n", Bin2String(encKey, encKeyLen, true).data());

			rt = SDF_DestroyKey(g_hSess, hKeyHdl);
			if (rt)
			{
				printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
				return;
			}
			printf("\nSDF_DestroyKey success\n");
			hKeyHdl = NULL;
		}

		rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa, pwd, pwdLen);
		if (rt)
		{
			printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
			printf("\nSDF_GetPrivateKeyAccessRight success\n");

		//导入会话密钥 内部私钥解密
		rt = SDF_ImportKeyWithISK_RSA(g_hSess, g_keyAsymIndexRsa, encKey, encKeyLen, &hKeyHdl);
		if (rt)
		{
			printf("\nSDF_ImportKeyWithISK_RSA failed %d | 0x%08x\n", rt, rt);
			SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa);
			return;
		}
		else
		{
			printf("\nSDF_ImportKeyWithISK_RSA success\n");

			SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa);

			rt = SDF_DestroyKey(g_hSess, hKeyHdl);
			if (rt)
			{
				printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
				return;
			}
			printf("\nSDF_DestroyKey success\n");
			hKeyHdl = NULL;
		}

		/**********以下逻辑，为上面接口密钥存储到加密机的调用方式**********/

		TaZero(encKey, sizeof(encKey));
		int idx = g_keySymIndexRsa;
		void* pIdx = &idx;

		SDF_DestroyKey(g_hSess, &idx);

		//生成会话密钥 外部公钥加密输出，并存储到加密机内部
		rt = SDF_GenerateKeyWithEPK_RSA(g_hSess, g_keyBits[i], &rsaPubKey, encKey, &encKeyLen, &pIdx);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithEPK_RSA failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithEPK_RSA success\n");
			printf("key 1: %s\n", Bin2String(encKey, encKeyLen, true).data());
		}

		TaZero(encKey, sizeof(encKey));

		SDF_DestroyKey(g_hSess, &idx);
		//生成会话密钥 内部公钥加密输出，并存储到加密机内部
		rt = SDF_GenerateKeyWithIPK_RSA(g_hSess, g_keyAsymIndexRsa, g_keyBits[i], encKey, &encKeyLen, &pIdx);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithIPK_RSA failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithIPK_RSA success\n");
			printf("key 2: %s\n", Bin2String(encKey, encKeyLen, true).data());
		}

		rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa, pwd, pwdLen);
		if (rt)
		{
			printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
			printf("\nSDF_GetPrivateKeyAccessRight success\n");

		SDF_DestroyKey(g_hSess, &idx);
		//导入会话密钥 内部私钥解密，并存储到加密机内部
		rt = SDF_ImportKeyWithISK_RSA(g_hSess, g_keyAsymIndexRsa, encKey, encKeyLen, &pIdx);
		if (rt)
		{
			printf("\nSDF_ImportKeyWithISK_RSA %d | 0x%08x\n", rt, rt);
			SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa);
			return;
		}
		else
		{
			printf("\nSDF_ImportKeyWithISK_RSA success\n");
			SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa);
		}
	}
}

void T_SDF_ExchangeDigitEnvelopeBaseOnRSA()
{
	//获取公钥
	RSArefPublicKey rsaEncPubKey = { 0 };
	int rt = SDF_ExportEncPublicKey_RSA(g_hSess, g_keyAsymIndexRsa, &rsaEncPubKey);
	if (rt)
	{
		printf("\nSDF_ExportEncPublicKey_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExportEncPublicKey_RSA success\n");
		printf("EncPubKey.bits: %d\n", rsaEncPubKey.bits);
		printf("EncPubKey.m: %s\n", Bin2String(rsaEncPubKey.m, sizeof(rsaEncPubKey.m), true).data());
		printf("EncPubKey.e: %s\n", Bin2String(rsaEncPubKey.e, sizeof(rsaEncPubKey.e), true).data());
	}

	//生成会话密钥 内部公钥加密输出
	unsigned char encKey[BUF + 1] = { 0 };
	unsigned int encKeyLen = sizeof(encKey);
	void* hKeyHdl = NULL;
	rt = SDF_GenerateKeyWithIPK_RSA(g_hSess, g_keyAsymIndexRsa, 128, encKey, &encKeyLen, &hKeyHdl);
	if (rt)
	{
		printf("\nSDF_GenerateKeyWithIPK_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyWithIPK_RSA success\n");
		printf("key 2: %s\n", Bin2String(encKey, encKeyLen, true).data());

		rt = SDF_DestroyKey(g_hSess, hKeyHdl);
		if (rt) {
			printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
			return;
		}
		printf("\nSDF_DestroyKey success\n");
		hKeyHdl = NULL;
	}

	rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa, pwd, pwdLen);
	if (rt)
	{
		printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_GetPrivateKeyAccessRight success\n");

	unsigned char cipherByPubKey[BUF] = { 0 };
	unsigned int cipherByPubKeyLen = sizeof(cipherByPubKey);
	rt = SDF_ExchangeDigitEnvelopeBaseOnRSA(g_hSess, g_keyAsymIndexRsa, &rsaEncPubKey, encKey, encKeyLen, cipherByPubKey, &cipherByPubKeyLen);
	if (rt)
	{
		printf("\nSDF_ExchangeDigitEnvelopeBaseOnRSA %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa);
		return;
	}
	else
	{
		printf("\nSDF_ExchangeDigitEnvelopeBaseOnRSA success\n");
		printf("cipherByPubKey: %s\n", Bin2String(cipherByPubKey, cipherByPubKeyLen, true).data());
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa);
	}
}

void T_SDF_ExportPublicKey_ECC()
{
	ECCrefPublicKey signPubKey = { 0 };
	ECCrefPublicKey encPubKey = { 0 };

	ECCrefPublicKey pubKey = { 0 };
	ECCrefPrivateKey priKey = { 0 };
	pubKey.bits = g_keyAsymIndex;
	priKey.bits = g_keyAsymIndex;

	unsigned int algID = SGD_SM2;
	//存储签名、加密，密钥对
	int rt = SDF_GenerateKeyPair_ECC(g_hSess, algID, 256, &pubKey, &priKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_ECC success\n");
		printf("PubKey.bits: %d\n", pubKey.bits);
		printf("PubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
		printf("PubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
	}

	rt = SDF_ExportSignPublicKey_ECC(g_hSess, g_keyAsymIndex, &signPubKey);
	if (rt)
	{
		printf("\nSDF_ExportSignPublicKey_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExportSignPublicKey_ECC success\n");
		printf("SignPubKey.bits: %d\n", signPubKey.bits);
		printf("SignPubKey.x: %s\n", Bin2String(signPubKey.x, sizeof(signPubKey.x), true).data());
		printf("SignPubKey.y: %s\n", Bin2String(signPubKey.y, sizeof(signPubKey.y), true).data());
	}

	rt = SDF_ExportEncPublicKey_ECC(g_hSess, g_keyAsymIndex, &encPubKey);
	if (rt)
	{
		printf("\nSDF_ExportSignPublicKey_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExportSignPublicKey_ECC success\n");
		printf("EncPubKey.bits: %d\n", encPubKey.bits);
		printf("EncPubKey.x: %s\n", Bin2String(encPubKey.x, sizeof(encPubKey.x), true).data());
		printf("EncPubKey.y: %s\n", Bin2String(encPubKey.y, sizeof(encPubKey.y), true).data());
	}
}

void T_SDF_GenerateKeyPair_ECC()
{
	ECCrefPublicKey pubKey = { 0 };
	ECCrefPrivateKey priKey = { 0 };
	unsigned int algID = SGD_SM2;

	int rt = SDF_GenerateKeyPair_ECC(g_hSess, algID, 256, &pubKey, &priKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_ECC success\n");
		printf("PubKey.bits: %d\n", pubKey.bits);
		printf("PubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
		printf("PubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
		printf("PriKey.bits: %d\n", priKey.bits);
		printf("PriKey.K: %s\n", Bin2String(priKey.K, sizeof(priKey.K), true).data());
	}

	TaZero(&pubKey, sizeof(pubKey));
	TaZero(&priKey, sizeof(priKey));
	pubKey.bits = g_keyAsymIndex;
	priKey.bits = g_keyAsymIndex;

	//存储签名、加密，密钥对
	rt = SDF_GenerateKeyPair_ECC(g_hSess, algID, 256, &pubKey, &priKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_ECC success\n");
		printf("PubKey.bits: %d\n", pubKey.bits);
		printf("PubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
		printf("PubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
	}
}

void T_SDF_GenerateKey_And_Import_ECC()
{
	ECCCipher cipherKey = { 0 };
	ECCrefPublicKey pubKey = { 0 };
	ECCrefPrivateKey priKey = { 0 };
	void* hKeyHdl = NULL;
	unsigned int algID = SGD_SM2;

	for (int i = 0; i < 3; ++i)
	{
		//生成非对称密钥
		pubKey.bits = g_keyAsymIndex;
		priKey.bits = g_keyAsymIndex;
		int rt = SDF_GenerateKeyPair_ECC(g_hSess, algID, 256, &pubKey, &priKey);
		if (rt)
		{
			printf("\nSDF_GenerateKeyPair_ECC failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyPair_ECC success\n");
			printf("PubKey.bits: %d\n", pubKey.bits);
			printf("PubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
			printf("PubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
			printf("PriKey.bits: %d\n", priKey.bits);
			printf("PriKey.K: %s\n", Bin2String(priKey.K, sizeof(priKey.K), true).data());
		}

		//生成会话密钥 外部公钥加密输出
		rt = SDF_GenerateKeyWithEPK_ECC(g_hSess, g_keyBits[i], algID, &pubKey, &cipherKey, &hKeyHdl);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithEPK_ECCfailed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithEPK_ECC success\n");
			printf("cipherKey.x: %s\n", Bin2String(cipherKey.x, sizeof(cipherKey.x), true).data());
			printf("cipherKey.y: %s\n", Bin2String(cipherKey.y, sizeof(cipherKey.y), true).data());
			printf("cipherKey.M: %s\n", Bin2String(cipherKey.M, sizeof(cipherKey.M), true).data());
			printf("cipherKey.L: %d\n", cipherKey.L);
			printf("cipherKey.C: %s\n", Bin2String(cipherKey.C, cipherKey.L, true).data());

			rt = SDF_DestroyKey(g_hSess, hKeyHdl);
			if (rt) {
				printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
				return;
			}
			printf("\nSDF_DestroyKey success\n");
			hKeyHdl = NULL;
		}

		TaZero(&cipherKey, sizeof(cipherKey));

		//生成会话密钥 内部公钥加密输出
		rt = SDF_GenerateKeyWithIPK_ECC(g_hSess, g_keyAsymIndex, g_keyBits[i], &cipherKey, &hKeyHdl);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithIPK_ECC failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithIPK_ECC success\n");
			printf("cipherKey.x: %s\n", Bin2String(cipherKey.x, sizeof(cipherKey.x), true).data());
			printf("cipherKey.y: %s\n", Bin2String(cipherKey.y, sizeof(cipherKey.y), true).data());
			printf("cipherKey.M: %s\n", Bin2String(cipherKey.M, sizeof(cipherKey.M), true).data());
			printf("cipherKey.L: %d\n", cipherKey.L);
			printf("cipherKey.C: %s\n", Bin2String(cipherKey.C, cipherKey.L, true).data());

			rt = SDF_DestroyKey(g_hSess, hKeyHdl);
			if (rt) {
				printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
				return;
			}
			printf("\nSDF_DestroyKey success\n");
			hKeyHdl = NULL;
		}

		rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndex, pwd, pwdLen);
		if (rt)
		{
			printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
			printf("\nSDF_GetPrivateKeyAccessRight success\n");

		//导入会话密钥 内部私钥解密
		rt = SDF_ImportKeyWithISK_ECC(g_hSess, g_keyAsymIndex, &cipherKey, &hKeyHdl);
		if (rt)
		{
			printf("\nSDF_ImportKeyWithISK_ECC failed %d | 0x%08x\n", rt, rt);
			SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
			return;
		}
		else
		{
			printf("\nSDF_ImportKeyWithISK_ECC success\n");

			SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);

			rt = SDF_DestroyKey(g_hSess, hKeyHdl);
			if (rt) {
				printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
				return;
			}
			printf("\nSDF_DestroyKey success\n");
			hKeyHdl = NULL;
		}

		/**********以下逻辑，为上面接口密钥存储到加密机的调用方式**********/

		TaZero(&cipherKey, sizeof(cipherKey));
		int idx = g_keySymIndex;
		void* pIdx = &idx;

		SDF_DestroyKey(g_hSess, &idx);
		//生成会话密钥 外部公钥加密输出，并存储到加密机内部
		rt = SDF_GenerateKeyWithEPK_ECC(g_hSess, g_keyBits[i], algID, &pubKey, &cipherKey, &pIdx);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithIPK_ECC failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithIPK_ECC success\n");
			printf("cipherKey.x: %s\n", Bin2String(cipherKey.x, sizeof(cipherKey.x), true).data());
			printf("cipherKey.y: %s\n", Bin2String(cipherKey.y, sizeof(cipherKey.y), true).data());
			printf("cipherKey.M: %s\n", Bin2String(cipherKey.M, sizeof(cipherKey.M), true).data());
			printf("cipherKey.L: %d\n", cipherKey.L);
			printf("cipherKey.C: %s\n", Bin2String(cipherKey.C, cipherKey.L, true).data());
		}

		TaZero(&cipherKey, sizeof(cipherKey));

		SDF_DestroyKey(g_hSess, &idx);
		//生成会话密钥 内部公钥加密输出，并存储到加密机内部
		rt = SDF_GenerateKeyWithIPK_ECC(g_hSess, g_keyAsymIndex, g_keyBits[i], &cipherKey, &pIdx);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithIPK_ECC failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithIPK_ECC success\n");
			printf("cipherKey.x: %s\n", Bin2String(cipherKey.x, sizeof(cipherKey.x), true).data());
			printf("cipherKey.y: %s\n", Bin2String(cipherKey.y, sizeof(cipherKey.y), true).data());
			printf("cipherKey.M: %s\n", Bin2String(cipherKey.M, sizeof(cipherKey.M), true).data());
			printf("cipherKey.L: %d\n", cipherKey.L);
			printf("cipherKey.C: %s\n", Bin2String(cipherKey.C, cipherKey.L, true).data());
		}

		rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndex, pwd, pwdLen);
		if (rt)
		{
			printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
			printf("\nSDF_GetPrivateKeyAccessRight success\n");

		SDF_DestroyKey(g_hSess, &idx);
		//导入会话密钥 内部私钥解密，并存储到加密机内部
		rt = SDF_ImportKeyWithISK_ECC(g_hSess, g_keyAsymIndex, &cipherKey, &pIdx);
		if (rt)
		{
			printf("\nSDF_ImportKeyWithISK_ECC failed %d | 0x%08x\n", rt, rt);
			SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
			return;
		}
		else
		{
			printf("\nSDF_ImportKeyWithISK_ECC success\n");
			SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		}
	}
}

void T_SDF_Agreement_And_GenerateKey_WithECC()
{
	void* hAgreeHdl = NULL;
	void* hKeyHdl = NULL;
	ECCrefPublicKey reqPubKey = { 0 };
	ECCrefPublicKey reqTmpPubKey = { 0 };
	ECCrefPublicKey rspPubKey = { 0 };
	ECCrefPublicKey rspTmpPubKey = { 0 };
	unsigned char reqID[] = "111111";
	unsigned char rspID[] = "222222";

	//获取私钥授权
	int rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndex, pwd, pwdLen);
	if (rt)
	{
		printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_GetPrivateKeyAccessRight success\n");

	rt = SDF_GenerateAgreementDataWithECC(g_hSess, g_keyAsymIndex, 128, reqID, strlen((char*)reqID), &reqPubKey, &reqTmpPubKey, &hAgreeHdl);
	if (rt)
	{
		printf("\nSDF_GenerateAgreementDataWithECC failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("\nSDF_GenerateAgreementDataWithECC success\n");
		printf("ReqPubKey.bits: %d\n", reqPubKey.bits);
		printf("ReqPubKey.x: %s\n", Bin2String(reqPubKey.x, sizeof(reqPubKey.x), true).data());
		printf("ReqPubKey.y: %s\n", Bin2String(reqPubKey.y, sizeof(reqPubKey.y), true).data());
		printf("ReqTmpPubKey.bits: %d\n", reqTmpPubKey.bits);
		printf("ReqTmpPubKey.x: %s\n", Bin2String(reqTmpPubKey.x, sizeof(reqTmpPubKey.x), true).data());
		printf("ReqTmpPubKey.y: %s\n", Bin2String(reqTmpPubKey.y, sizeof(reqTmpPubKey.y), true).data());
	}

	rt = SDF_GenerateAgreementDataAndKeyWithECC(g_hSess, g_keyAsymIndex, 128, rspID, strlen((char*)rspID), reqID, strlen((char*)reqID),
		&reqPubKey, &reqTmpPubKey, &rspPubKey, &rspTmpPubKey, &hKeyHdl);
	if (rt)
	{
		printf("\nSDF_GenerateAgreementDataAndKeyWithECC failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("\nSDF_GenerateAgreementDataAndKeyWithECC success\n");
		printf("RspPubKey.bits: %d\n", rspPubKey.bits);
		printf("RspPubKey.x: %s\n", Bin2String(rspPubKey.x, sizeof(rspPubKey.x), true).data());
		printf("RspPubKey.y: %s\n", Bin2String(rspPubKey.y, sizeof(rspPubKey.y), true).data());
		printf("RspTmpPubKey.bits: %d\n", rspTmpPubKey.bits);
		printf("RspTmpPubKey.x: %s\n", Bin2String(rspTmpPubKey.x, sizeof(rspTmpPubKey.x), true).data());
		printf("RspTmpPubKey.y: %s\n", Bin2String(rspTmpPubKey.y, sizeof(rspTmpPubKey.y), true).data());

		rt = SDF_DestroyKey(g_hSess, hKeyHdl);
		if (rt)
		{
			printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
			return;
		}
		printf("\nSDF_DestroyKey success\n");
		hKeyHdl = NULL;
	}

	rt = SDF_GenerateKeyWithECC(g_hSess, rspID, strlen((char*)rspID), &rspPubKey, &rspTmpPubKey, hAgreeHdl, &hKeyHdl);
	if (rt)
	{
		printf("\nSDF_GenerateKeyWithECC failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("SDF_GenerateKeyWithECC success\n");
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
	}

	//使用会话密钥句柄做一些操作......

	rt = SDF_DestroyKey(g_hSess, hKeyHdl);
	if (rt)
	{
		printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
		return;
	}
	printf("\nSDF_DestroyKey success\n");
	hKeyHdl = NULL;


	/**********以下逻辑，为上面接口密钥存储到加密机的调用方式**********/

	TaZero(&reqPubKey, sizeof(reqPubKey));
	TaZero(&reqTmpPubKey, sizeof(reqTmpPubKey));
	TaZero(&rspPubKey, sizeof(rspPubKey));
	TaZero(&rspTmpPubKey, sizeof(rspTmpPubKey));
	int idx = g_keySymIndex;
	void* pIdx = &idx;

	//获取私钥授权
	rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndex, pwd, pwdLen);
	if (rt)
	{
		printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_GetPrivateKeyAccessRight success\n");

	rt = SDF_GenerateAgreementDataWithECC(g_hSess, g_keyAsymIndex, 128, reqID, strlen((char*)reqID), &reqPubKey, &reqTmpPubKey, &hAgreeHdl);
	if (rt)
	{
		printf("\nSDF_GenerateAgreementDataWithECC failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("\nSDF_GenerateAgreementDataWithECC success\n");
		printf("ReqPubKey.bits: %d\n", reqPubKey.bits);
		printf("ReqPubKey.x: %s\n", Bin2String(reqPubKey.x, sizeof(reqPubKey.x), true).data());
		printf("ReqPubKey.y: %s\n", Bin2String(reqPubKey.y, sizeof(reqPubKey.y), true).data());
		printf("ReqTmpPubKey.bits: %d\n", reqTmpPubKey.bits);
		printf("ReqTmpPubKey.x: %s\n", Bin2String(reqTmpPubKey.x, sizeof(reqTmpPubKey.x), true).data());
		printf("ReqTmpPubKey.y: %s\n", Bin2String(reqTmpPubKey.y, sizeof(reqTmpPubKey.y), true).data());
	}

	rt = SDF_GenerateAgreementDataAndKeyWithECC(g_hSess, g_keyAsymIndex, 128, rspID, strlen((char*)rspID), reqID, strlen((char*)reqID),
		&reqPubKey, &reqTmpPubKey, &rspPubKey, &rspTmpPubKey, &pIdx);
	if (rt)
	{
		printf("\nSDF_GenerateAgreementDataAndKeyWithECC failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("\nSDF_GenerateAgreementDataAndKeyWithECC success\n");
		printf("RspPubKey.bits: %d\n", rspPubKey.bits);
		printf("RspPubKey.x: %s\n", Bin2String(rspPubKey.x, sizeof(rspPubKey.x), true).data());
		printf("RspPubKey.y: %s\n", Bin2String(rspPubKey.y, sizeof(rspPubKey.y), true).data());
		printf("RspTmpPubKey.bits: %d\n", rspTmpPubKey.bits);
		printf("RspTmpPubKey.x: %s\n", Bin2String(rspTmpPubKey.x, sizeof(rspTmpPubKey.x), true).data());
		printf("RspTmpPubKey.y: %s\n", Bin2String(rspTmpPubKey.y, sizeof(rspTmpPubKey.y), true).data());
	}

	rt = SDF_GenerateKeyWithECC(g_hSess, rspID, strlen((char*)rspID), &rspPubKey, &rspTmpPubKey, hAgreeHdl, &pIdx);
	if (rt)
	{
		printf("\nSDF_GenerateKeyWithECC failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("SDF_GenerateKeyWithECC success\n");
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
	}
}

void T_SDF_ExchangeDigitEnvelopeBaseOnECC()
{
	ECCrefPublicKey encPubKey = { 0 };
	ECCCipher cipherByOutPubKey = { 0 };
	ECCCipher cipherByInPubKey = { 0 };
	void* hKeyHdl = NULL;
	unsigned int algID = SGD_SM2;

	//获取公钥
	RSArefPublicKey rsaEncPubKey = { 0 };
	int rt = SDF_ExportEncPublicKey_ECC(g_hSess, g_keyAsymIndex, &encPubKey);
	if (rt)
	{
		printf("\nSDF_ExportEncPublicKey_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExportEncPublicKey_ECC success\n");
		printf("EncPubKey.bits: %d\n", encPubKey.bits);
		printf("EncPubKey.x: %s\n", Bin2String(encPubKey.x, sizeof(encPubKey.x), true).data());
		printf("EncPubKey.y: %s\n", Bin2String(encPubKey.y, sizeof(encPubKey.y), true).data());
	}

	//生成会话密钥 内部公钥加密输出
	rt = SDF_GenerateKeyWithIPK_ECC(g_hSess, g_keyAsymIndex, 128, &cipherByInPubKey, &hKeyHdl);
	if (rt)
	{
		printf("\nSDF_GenerateKeyWithIPK_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyWithIPK_ECC success\n");
		printf("cipherByInPubKey.x: %s\n", Bin2String(cipherByInPubKey.x, sizeof(cipherByInPubKey.x), true).data());
		printf("cipherByInPubKey.y: %s\n", Bin2String(cipherByInPubKey.y, sizeof(cipherByInPubKey.y), true).data());
		printf("cipherByInPubKey.M: %s\n", Bin2String(cipherByInPubKey.M, sizeof(cipherByInPubKey.M), true).data());
		printf("cipherByInPubKey.L: %d\n", cipherByInPubKey.L);
		printf("cipherByInPubKey.C: %s\n", Bin2String(cipherByInPubKey.C, cipherByInPubKey.L, true).data());

		rt = SDF_DestroyKey(g_hSess, hKeyHdl);
		if (rt)
		{
			printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
			return;
		}
		printf("\nSDF_DestroyKey success\n");
		hKeyHdl = NULL;
	}

	//获取私钥授权
	rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndex, pwd, pwdLen);
	if (rt)
	{
		printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_GetPrivateKeyAccessRight success\n");

	rt = SDF_ExchangeDigitEnvelopeBaseOnECC(g_hSess, g_keyAsymIndex, algID, &encPubKey, &cipherByInPubKey, &cipherByOutPubKey);
	if (rt)
	{
		printf("\nSDF_ExchangeDigitEnvelopeBaseOnECC %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("\nSDF_ExchangeDigitEnvelopeBaseOnECC success\n");
		printf("cipherByOutPubKey.x: %s\n", Bin2String(cipherByOutPubKey.x, sizeof(cipherByOutPubKey.x), true).data());
		printf("cipherByOutPubKey.y: %s\n", Bin2String(cipherByOutPubKey.y, sizeof(cipherByOutPubKey.y), true).data());
		printf("cipherByOutPubKey.M: %s\n", Bin2String(cipherByOutPubKey.M, sizeof(cipherByOutPubKey.M), true).data());
		printf("cipherByOutPubKey.L: %d\n", cipherByOutPubKey.L);
		printf("cipherByOutPubKey.C: %s\n", Bin2String(cipherByOutPubKey.C, cipherByOutPubKey.L, true).data());

		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
	}
}

void Impl_SDF_GenerateKey_And_Import_KEK(unsigned int algID)
{
	void* hKeyHdl = NULL;
	unsigned char encKey[BUF] = { 0 };
	unsigned int encKeyLen = sizeof(encKey);

	//for (int i = 0; i < 3; i++)
	{
		int i = 0;
		TaZero(encKey, sizeof(encKey));
		encKeyLen = sizeof(encKey);
		//生成会话密钥 加密输出 
		//int rt = SDF_GenerateKeyWithKEK(g_hSess, g_keyBits[i], algID, g_keySymIndex, encKey, &encKeyLen, &hKeyHdl);
		//if (rt)
		//{
		//	printf("\n[algID = %s] SDF_GenerateKeyWithKEK failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
		//	return;
		//}
		//else
		//{
		//	printf("\n[algID = %s] SDF_GenerateKeyWithKEK success\n", GetAlgStr(algID));
		//	printf("encKey: %s\n", Bin2String(encKey, encKeyLen, true).data());

		//	//使用会话密钥句柄做一些操作......

		//	rt = SDF_DestroyKey(g_hSess, hKeyHdl);
		//	if (rt)
		//	{
		//		printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
		//		return;
		//	}
		//	printf("\nSDF_DestroyKey success\n");
		//	hKeyHdl = NULL;
		//}

		//rt = SDF_ImportKeyWithKEK(g_hSess, algID, g_keySymIndex, encKey, encKeyLen, &hKeyHdl);
		//if (rt)
		//{
		//	printf("\n[algID = %s] SDF_ImportKeyWithKEK failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
		//	return;
		//}
		//else
		//{
		//	printf("\n[algID = %s] SDF_ImportKeyWithKEK success\n", GetAlgStr(algID));

		//	//使用会话密钥句柄做一些操作......

		//	rt = SDF_DestroyKey(g_hSess, hKeyHdl);
		//	if (rt)
		//	{
		//		printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
		//		return;
		//	}
		//	printf("\nSDF_DestroyKey success\n");
		//	hKeyHdl = NULL;
		//}

		//导入明文密钥测试
		unsigned char random[BUFLITTLE + 1] = { 0 };
		int randomLen = 16;
		int rt = SDF_GenerateRandom(g_hSess, randomLen, random);
		if (rt)
		{
			printf("\nSDF_GenerateRandom failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateRandom success\n");
			printHex("random", random, randomLen);
		}

		rt = SDF_ImportKey(g_hSess, random, randomLen, &hKeyHdl);
		if (rt)
		{
			printf("\n SDF_ImportKey failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_ImportKey success\n");

			//使用会话密钥句柄做一些操作......

			rt = SDF_DestroyKey(g_hSess, hKeyHdl);
			if (rt)
			{
				printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
				return;
			}
			printf("\nSDF_DestroyKey success\n");
			hKeyHdl = NULL;
		}
		//SDF_DestroyKey(g_hSess, &idx1);
		/**********以下逻辑，为上面接口密钥存储到加密机的调用方式**********/
#if 0
		TaZero(encKey, sizeof(encKey));
		encKeyLen = sizeof(encKey);
		int idx = g_keySymIndex + 1;
		void* pIdx = &idx;

		SDF_DestroyKey(g_hSess, &idx);
		//生成会话密钥 加密输出，并存储到加密机内部
		rt = SDF_GenerateKeyWithKEK(g_hSess, g_keyBits[i], algID, g_keySymIndex, encKey, &encKeyLen, &pIdx);
		if (rt)
		{
			printf("\n[algID = %s] SDF_GenerateKeyWithKEK failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
			return;
		}
		else
		{
			printf("\n[algID = %s] SDF_GenerateKeyWithKEK success\n", GetAlgStr(algID));
			printf("encKey: %s\n", Bin2String(encKey, encKeyLen, true).data());
		}

		SDF_DestroyKey(g_hSess, &idx);
		//导入会话密钥 内部解密，并存储到加密机内部
		rt = SDF_ImportKeyWithKEK(g_hSess, algID, g_keySymIndex, encKey, encKeyLen, &pIdx);
		if (rt)
		{
			printf("\n[algID = %s] SDF_ImportKeyWithKEK failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
			return;
		}
		else
		{
			printf("\n[algID = %s] SDF_ImportKeyWithKEK success\n", GetAlgStr(algID));
		}

		//导入明文密钥测试
		int idx1 = g_keySymIndex + 3;
		void* pIdx1 = &idx1;

		unsigned char random1[BUFLITTLE + 1] = { 0 };
		int randomLen1 = 16;
		rt = SDF_GenerateRandom(g_hSess, randomLen1, random1);
		if (rt)
		{
			printf("\nSDF_GenerateRandom failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateRandom success\n");
			printHex("random", random1, randomLen1);
		}

		SDF_DestroyKey(g_hSess, &idx1);

		rt = SDF_ImportKey(g_hSess, random1, randomLen1, &pIdx1);
		if (rt)
		{
			printf("\n SDF_ImportKey failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_ImportKey success\n");
		}
#endif
	}
}

void T_SDF_GenerateKey_And_Import_KEK()
{
	Impl_SDF_GenerateKey_And_Import_KEK(SGD_SM4_ECB);
	Impl_SDF_GenerateKey_And_Import_KEK(SGD_SM1_ECB);
	Impl_SDF_GenerateKey_And_Import_KEK(SGD_SSF33_ECB);
	Impl_SDF_GenerateKey_And_Import_KEK(SGD_AES_ECB);
	//Impl_SDF_GenerateKey_And_Import_KEK(SGD_ZUC_EEA3);//暂不支持
}

void T_KeyManagementFunctions()
{
	int n = 0;
	while (1)
	{
		printf("\n");
		printf("------------T_KeyManagementFunctions-----------\n");
		printf("3.[1] T_SDF_ExportPublicKey_RSA\n");
		printf("3.[2] T_SDF_GenerateKeyPair_RSA\n");
		printf("3.[3] T_SDF_GenerateKey_And_Import_RSA\n");
		printf("3.[4] T_SDF_ExchangeDigitEnvelopeBaseOnRSA\n");
		printf("3.[5] T_SDF_ExportPublicKey_ECC\n");
		printf("3.[6] T_SDF_GenerateKeyPair_ECC\n");
		printf("3.[7] T_SDF_GenerateKey_And_Import_ECC\n");
		printf("3.[8] T_SDF_Agreement_And_GenerateKey_WithECC\n");
		printf("3.[9] T_SDF_ExchangeDigitEnvelopeBaseOnECC\n");
		printf("3.[10] T_SDF_GenerateKey_And_Import_KEK\n");
		printf("3.[0] quit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		switch (idx) {
		case 1: T_SDF_ExportPublicKey_RSA(); break;
		case 2: T_SDF_GenerateKeyPair_RSA(); break;
		case 3: T_SDF_GenerateKey_And_Import_RSA(); break;
		case 4: T_SDF_ExchangeDigitEnvelopeBaseOnRSA(); break;
		case 5: T_SDF_ExportPublicKey_ECC(); break;
		case 6: T_SDF_GenerateKeyPair_ECC(); break;
		case 7: T_SDF_GenerateKey_And_Import_ECC(); break;
		case 8: T_SDF_Agreement_And_GenerateKey_WithECC(); break;
		case 9: T_SDF_ExchangeDigitEnvelopeBaseOnECC(); break;
		case 10: T_SDF_GenerateKey_And_Import_KEK(); break;
		case 0: return;
		default: printf("Invalid input\n"); break;
		}
	}
}

/*---------------------------非对称算法运算类函数测试-------------------------*/

void T_SDF_KeyOperation_RSA()
{
	void* hKeyHdl = NULL;
	RSArefPublicKey rsaPubKey = { 0 };
	RSArefPrivateKey rsaPriKey = { 0 };
	unsigned char dataPlain[BUF] = { 0 };
	unsigned int dataPlainLen = RSAref_MAX_LEN;
	unsigned char dataEnc[BUF] = { 0 };
	unsigned int dataEncLen = sizeof(dataEnc);
	unsigned char dataOut[BUF] = { 0 };
	unsigned int dataOutLen = sizeof(dataOut);

	for (int i = 0; i < dataPlainLen; i++)
		dataPlain[i] = 'a';

	//获取公钥
	rsaPubKey.bits = g_keyAsymIndexRsa;
	rsaPriKey.bits = g_keyAsymIndexRsa;
	int rt = SDF_GenerateKeyPair_RSA(g_hSess, RSAref_MAX_BITS, &rsaPubKey, &rsaPriKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_RSA success\n");
		printf("PubKey.bits: %d\n", rsaPubKey.bits);
		printf("PubKey.m: %s\n", Bin2String(rsaPubKey.m, sizeof(rsaPubKey.m), true).data());
		printf("PubKey.e: %s\n", Bin2String(rsaPubKey.e, sizeof(rsaPubKey.e), true).data());
	}

	rt = SDF_ExternalPublicKeyOperation_RSA(g_hSess, &rsaPubKey, dataPlain, dataPlainLen, dataEnc, &dataEncLen);
	if (rt)
	{
		printf("\nSDF_ExternalPublicKeyOperation_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExternalPublicKeyOperation_RSA success\n");
		printf("dataEnc: %s\n", Bin2String(dataEnc, dataEncLen, true).data());
	}

	TaZero(dataEnc, sizeof(dataEnc));
	dataEncLen = sizeof(dataEnc);

	rt = SDF_InternalPublicKeyOperation_RSA(g_hSess, g_keyAsymIndexRsa, dataPlain, dataPlainLen, dataEnc, &dataEncLen);
	if (rt)
	{
		printf("\nSDF_InternalPublicKeyOperation_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_InternalPublicKeyOperation_RSA success\n");
		printf("dataEnc: %s\n", Bin2String(dataEnc, dataEncLen, true).data());
	}

	//获取私钥授权
	rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa, pwd, pwdLen);
	if (rt)
	{
		printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_GetPrivateKeyAccessRight success\n");

	rt = SDF_InternalPrivateKeyOperation_RSA(g_hSess, g_keyAsymIndexRsa, dataEnc, dataEncLen, dataOut, &dataOutLen);
	if (rt)
	{
		printf("\nSDF_InternalPrivateKeyOperation_RSA failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa);
		return;
	}
	else
	{
		printf("\nSDF_InternalPrivateKeyOperation_RSA success\n");
		printf("dataOut  : %s\n", dataOut);
		printf("dataPlain: %s\n", dataPlain);

		if (memcmp(dataPlain, dataOut, dataOutLen) != 0)
		{
			printf("RSA Key Operation failed. \n");
		}
	}

	rt = SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndexRsa);
	if (rt)
	{
		printf("\nSDF_ReleasePrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_ReleasePrivateKeyAccessRight success\n");
}

void HashOperationData(unsigned char* data, unsigned int dataLen, unsigned char* hash, unsigned int* hashLen)
{
	ECCrefPublicKey pubKey = { 0 };
	unsigned char ID[BUF] = { 0 };
	unsigned int IDLen = 0;
	unsigned int len = *hashLen;
	unsigned int algID = SGD_SM3;

	int rt = SDF_HashInit(g_hSess, algID, NULL, ID, IDLen);
	if (rt)
	{
		printf("\n[algID = %s] SDF_HashInit failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
		return;
	}
	else
		printf("\n[algID = %s] SDF_HashInit success\n", GetAlgStr(algID));

	rt = SDF_HashUpdate(g_hSess, data, dataLen);
	if (rt)
	{
		printf("\n[algID = %s] SDF_HashUpdate failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
		return;
	}
	else
		printf("\n[algID = %s] SDF_HashUpdate success\n", GetAlgStr(algID));

	rt = SDF_HashFinal(g_hSess, hash, &len);
	if (rt)
	{
		printf("\n[algID = %s] SDF_HashFinal failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
		return;
	}
	else
	{
		printf("\n[algID = %s] SDF_HashFinal success\n", GetAlgStr(algID));
		printf("\nhash: %s\n", Bin2String(hash, len, true).data());
	}
	*hashLen = len;
}

void T_SDF_Sign_And_Verify_ECC()
{
	ECCSignature sign = { 0 };
	ECCrefPublicKey pubKey = { 0 };
	ECCrefPrivateKey priKey = { 0 };
	unsigned char data[] = "12345678123456781234567812345678";
	unsigned int dataLen = strlen((char*)data);
	unsigned char hash[128] = { 0 };
	unsigned int hashLen = sizeof(hash);
	unsigned int algID = SGD_SM2_1;

	//生成非对称密钥并保存到密码机
	pubKey.bits = g_keyAsymIndex;
	priKey.bits = g_keyAsymIndex;
	int rt = SDF_GenerateKeyPair_ECC(g_hSess, algID, 256, &pubKey, &priKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_ECC success\n");
		printf("PubKey.bits: %d\n", pubKey.bits);
		printf("PubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
		printf("PubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
	}

	//对原文数据做hash
	HashOperationData(data, dataLen, hash, &hashLen);

	//获取私钥授权
	rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndex, pwd, pwdLen);
	if (rt)
	{
		printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_GetPrivateKeyAccessRight success\n");

	//内部索引签名、验签
	rt = SDF_InternalSign_ECC(g_hSess, g_keyAsymIndex, hash, hashLen, &sign);
	if (rt)
	{
		printf("\nSDF_InternalSign_ECC failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("\nSDF_InternalSign_ECC success\n");
		printf("sign.r: %s\n", Bin2String(sign.r, sizeof(sign.r), true).data());
		printf("sign.s: %s\n", Bin2String(sign.s, sizeof(sign.s), true).data());
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
	}

	rt = SDF_InternalVerify_ECC(g_hSess, g_keyAsymIndex, hash, hashLen, &sign);
	if (rt)
	{
		printf("\nSDF_InternalVerify_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_InternalVerify_ECC success\n");

	memset(&pubKey, 0, sizeof(ECCrefPublicKey));
	memset(&priKey, 0, sizeof(ECCrefPrivateKey));
	memset(&sign, 0, sizeof(ECCSignature));

	rt = SDF_GenerateKeyPair_ECC(g_hSess, algID, 256, &pubKey, &priKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_ECC success\n");
		printf("PubKey.bits: %d\n", pubKey.bits);
		printf("PubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
		printf("PubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
		printf("PriKey.bits: %d\n", priKey.bits);
		printf("PriKey.K: %s\n", Bin2String(priKey.K, sizeof(priKey.K), true).data());
	}

	////外部密钥签名、验签
	rt = SDF_ExternalSign_ECC(g_hSess, algID, &priKey, hash, hashLen, &sign);
	if (rt)
	{
		printf("\nSDF_ExternalSign_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExternalSign_ECC success\n");
		printf("sign.r: %s\n", Bin2String(sign.r, sizeof(sign.r), true).data());
		printf("sign.s: %s\n", Bin2String(sign.s, sizeof(sign.s), true).data());
	}

	rt = SDF_ExternalVerify_ECC(g_hSess, algID, &pubKey, hash, hashLen, &sign);
	if (rt)
	{
		printf("\nSDF_ExternalVerify_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_ExternalVerify_ECC success\n");
}

void T_SDF_Encrypt_And_Decrypt_Internal_ECC()
{
	ECCCipher encData = { 0 };
	ECCrefPublicKey pubKey = { 0 };
	ECCrefPrivateKey priKey = { 0 };
	unsigned char dataPlain[] = "12345678123456781234567812345678";
	unsigned int dataPlainLen = strlen((char*)dataPlain);
	unsigned char dataOut[BUF] = { 0 };
	unsigned int dataOutLen = sizeof(dataOut);
	//unsigned int algID = SGD_SM2_3;

	//生成非对称密钥,保存到加密机（接口的扩展功能）
	/*pubKey.bits = g_keyAsymIndex;
	priKey.bits = g_keyAsymIndex;
	int rt = SDF_GenerateKeyPair_ECC(g_hSess, algID, 256, &pubKey, &priKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_ECC success\n");
		printf("PubKey.bits: %d\n", pubKey.bits);
		printf("PubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
		printf("PubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
	}*/

	//使用内部ECC公钥 加密运算
	int rt = SDF_InternalEncrypt_ECC(g_hSess, g_keyAsymIndex, dataPlain, dataPlainLen, &encData);
	if (rt)
	{
		printf("\nSDF_InternalEncrypt_ECC failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("\nSDF_InternalEncrypt_ECC success\n");
		printf("encData.x: %s\n", Bin2String(encData.x, sizeof(encData.x), true).data());
		printf("encData.y: %s\n", Bin2String(encData.y, sizeof(encData.y), true).data());
		printf("encData.M: %s\n", Bin2String(encData.M, sizeof(encData.M), true).data());
		printf("encData.L: %d\n", encData.L);
		printf("encData.C: %s\n", Bin2String(encData.C, encData.L, true).data());
	}

	//获取私钥授权
	rt = SDF_GetPrivateKeyAccessRight(g_hSess, g_keyAsymIndex, pwd, pwdLen);
	if (rt)
	{
		printf("\nSDF_GetPrivateKeyAccessRight failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
		printf("\nSDF_GetPrivateKeyAccessRight success\n");

	//使用内部ECC私钥 解密运算
	rt = SDF_InternalDecrypt_ECC(g_hSess, g_keyAsymIndex, &encData, dataOut, &dataOutLen);
	if (rt)
	{
		printf("\nSDF_InternalDecrypt_ECC failed %d | 0x%08x\n", rt, rt);
		SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
		return;
	}
	else
	{
		printf("\nSDF_InternalDecrypt_ECC success\n");
		printf("dataOut  : %s\n", dataOut);
		printf("dataPlain: %s\n", dataPlain);
	}
	SDF_ReleasePrivateKeyAccessRight(g_hSess, g_keyAsymIndex);
}

void T_SDF_Encrypt_And_Decrypt_External_ECC()
{
	ECCCipher encData = { 0 };
	ECCrefPublicKey pubKey = { 0 };
	ECCrefPrivateKey priKey = { 0 };
	unsigned char dataPlain[] = "12345678123456781234567812345678";
	unsigned int dataPlainLen = strlen((char*)dataPlain);
	unsigned int algID = SGD_SM2_3;


	
	//生成非对称密钥
	int rt = SDF_GenerateKeyPair_ECC(g_hSess, algID, 256, &pubKey, &priKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_ECC success\n");
		printf("PubKey.bits: %d\n", pubKey.bits);
		printf("PubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
		printf("PubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
	}

	rt = SDF_ExternalEncrypt_ECC(g_hSess, algID, &pubKey, dataPlain, dataPlainLen, &encData);
	if (rt)
	{
		printf("\nSDF_ExternalEncrypt_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExternalEncrypt_ECC success\n");
		printf("encData.x: %s\n", Bin2String(encData.x, sizeof(encData.x), true).data());
		printf("encData.y: %s\n", Bin2String(encData.y, sizeof(encData.y), true).data());
		printf("encData.M: %s\n", Bin2String(encData.M, sizeof(encData.M), true).data());
		printf("encData.L: %d\n", encData.L);
		printf("encData.C: %s\n", Bin2String(encData.C, encData.L, true).data());
	}

	unsigned char dataOut1[BUF] = { 0 };
	unsigned int dataOutLen1 = sizeof(dataOut1);
	rt = SDF_ExternalDecrypt_ECC(g_hSess, algID, &priKey, &encData, dataOut1, &dataOutLen1);
	if (rt)
	{
		printf("\nSDF_ExternalDecrypt_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExternalDecrypt_ECC success\n");
		printf("dataOut  : %s\n", Bin2String(dataOut1, dataOutLen1, true).data());
		printf("dataPlain: %s\n", Bin2String(dataPlain, dataPlainLen, true).data());
	}
}

void T_SDF_ExternalKeyOperation_RSA()
{
	RSArefPublicKey rsaPubKey = { 0 };
	RSArefPrivateKey rsaPriKey = { 0 };
	unsigned char dataPlain[BUF] = { 0 };
	unsigned int dataPlainLen = RSAref_MAX_LEN;
	//unsigned int dataPlainLen = 256;
	unsigned char dataEnc[BUF] = { 0 };
	unsigned int dataEncLen = sizeof(dataEnc);
	unsigned char dataOut[BUF] = { 0 };
	unsigned int dataOutLen = sizeof(dataOut);

	for (int i = 0; i < dataPlainLen; i++)
		dataPlain[i] = 'a';

	//获取公钥
	int rt = SDF_GenerateKeyPair_RSA(g_hSess, 2048, &rsaPubKey, &rsaPriKey);
	if (rt)
	{
		printf("\nSDF_GenerateKeyPair_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateKeyPair_RSA success\n");
		printf("PubKey.bits: %d\n", rsaPubKey.bits);
		printf("PubKey.m: %s\n", Bin2String(rsaPubKey.m, sizeof(rsaPubKey.m), true).data());
		printf("PubKey.e: %s\n\n\n", Bin2String(rsaPubKey.e, sizeof(rsaPubKey.e), true).data());

		printf("PriKey.bits: %d\n", rsaPriKey.bits);
		printf("PriKey.m: %s\n", Bin2String(rsaPriKey.m, sizeof(rsaPriKey.m), true).data());
		printf("PriKey.e: %s\n", Bin2String(rsaPriKey.e, sizeof(rsaPriKey.e), true).data());
		printf("PriKey.d: %s\n", Bin2String(rsaPriKey.d, sizeof(rsaPriKey.d), true).data());
		printf("PriKey.prime[0]: %s\n", Bin2String(rsaPriKey.prime[0], sizeof(rsaPriKey.prime[0]), true).data());
		printf("PriKey.prime[1]: %s\n", Bin2String(rsaPriKey.prime[1], sizeof(rsaPriKey.prime[1]), true).data());
		printf("PriKey.pexp[0]: %s\n", Bin2String(rsaPriKey.pexp[0], sizeof(rsaPriKey.pexp[0]), true).data());
		printf("PriKey.pexp[1]: %s\n", Bin2String(rsaPriKey.pexp[1], sizeof(rsaPriKey.pexp[1]), true).data());
		printf("PriKey.coef: %s\n", Bin2String(rsaPriKey.coef, sizeof(rsaPriKey.coef), true).data());
	}

	rt = SDF_ExternalPublicKeyOperation_RSA(g_hSess, &rsaPubKey, dataPlain, dataPlainLen, dataEnc, &dataEncLen);
	if (rt)
	{
		printf("\nSDF_ExternalPublicKeyOperation_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExternalPublicKeyOperation_RSA success\n");
		printf("dataEnc: %s\n", Bin2String(dataEnc, dataEncLen, true).data());
	}

	rt = SDF_ExternalPrivateKeyOperation_RSA(g_hSess,
		&rsaPriKey,
		dataEnc, dataEncLen,
		dataOut, &dataOutLen);
	if (rt)
	{
		printf("\nSDF_ExternalPrivateKeyOperation_RSA failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExternalPrivateKeyOperation_RSA success\n");
		printf("dataOut  : %s\n", dataOut);
		printf("dataPlain: %s\n", dataPlain);
		if (memcmp(dataPlain, dataOut, dataOutLen) != 0)
		{
			printf("RSA Key Operation failed. \n");
		}
	}
}

void T_AsymOperationFunctions()
{
	int n = 0;
	while (1)
	{
		printf("\n");
		printf("------------T_AsymOperationFunctions-----------\n");
		printf("4.[1] T_SDF_KeyOperation_RSA\n");
		printf("4.[2] T_SDF_Sign_And_Verify_ECC\n");
		printf("4.[3] T_SDF_Encrypt_And_Decrypt_External_ECC\n");
		printf("4.[4] T_SDF_Encrypt_And_Decrypt_Internal_ECC\n");
		printf("4.[5] T_SDF_ExternalKeyOperation_RSA\n");
		printf("4.[0] quit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		switch (idx) {
		case 1: T_SDF_KeyOperation_RSA(); break;
		case 2: T_SDF_Sign_And_Verify_ECC(); break;
		case 3: T_SDF_Encrypt_And_Decrypt_External_ECC(); break;
		case 4: T_SDF_Encrypt_And_Decrypt_Internal_ECC(); break;
		case 5: T_SDF_ExternalKeyOperation_RSA(); break;
		case 0: return;
		default: printf("Invalid input\n"); break;
		}
	}
}

/*---------------------------对称算法运算类函数测试-------------------------*/

void Impl_SDF_Encrypt_And_Decrypt(unsigned int algIDKey, unsigned int algID)
{
	int rt = 0;
	void* hKeyHdl = NULL;
	unsigned char iv[] = "1122334455667788";
	unsigned char dataPlain[BUF * 10 + 1] = { 0 };
	unsigned int dataPlainLen = sizeof(dataPlain) - 1;
	unsigned char dataEnc[BUF * 10 + 1] = { 0 };
	unsigned int dataEncLen = sizeof(dataEnc);
	unsigned char encKey[BUF] = { 0 };
	unsigned int encKeyLen = sizeof(encKey);
	unsigned char dataOut[BUF * 10 + 1] = { 0 };
	unsigned int dataOutLen = sizeof(dataOut);

	for (int i = 0; i < dataPlainLen; i++)
		dataPlain[i] = 'a';

	//导入明文密钥测试
	unsigned char random[BUFLITTLE + 1] = { 0 };
	int randomLen = 16;
	rt = SDF_GenerateRandom(g_hSess, randomLen, random);
	if (rt)
	{
		printf("\nSDF_GenerateRandom failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateRandom success\n");
		printHex("random", random, randomLen);
	}

	rt = SDF_ImportKey(g_hSess, random, randomLen, &hKeyHdl);
	if (rt)
	{
		printf("\n SDF_ImportKey failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\n SDF_ImportKey success\n");
		printf("encKey: %s\n", Bin2String(random, randomLen, true).data());
	}

	//对称加密
	rt = SDF_Encrypt(g_hSess, hKeyHdl, algID, iv, dataPlain, dataPlainLen, dataEnc, &dataEncLen);
	if (rt)
	{
		printf("\n[algID = %s] SDF_Encrypt failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
		return;
	}
	else
	{
		printf("\n[algID = %s] SDF_Encrypt success\n", GetAlgStr(algID));
		//printf("encData: %s\n", Bin2String(dataEnc, dataEncLen, true).data());
	}

	memcpy(iv, "1122334455667788", sizeof("1122334455667788"));

	//对称解密
	rt = SDF_Decrypt(g_hSess, hKeyHdl, algID, iv, dataEnc, dataEncLen, dataOut, &dataOutLen);
	if (rt)
	{
		printf("\n[algID = %s] SDF_Decrypt failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
		return;
	}
	else
	{
		printf("\n[algID = %s] SDF_Decrypt success\n", GetAlgStr(algID));
		//printf("dataOut: %s\n", Bin2String(dataOut, dataOutLen, true).data());
		//printf("dataPlain: %s\n", Bin2String(dataOut, dataOutLen, true).data());
		printf("dataOut: %s\n", dataOut);
		printf("dataPlain: %s\n", dataPlain);
	}
	SDF_DestroyKey(g_hSess, hKeyHdl);
}

void T_SDF_Encrypt_And_Decrypt()
{
	Impl_SDF_Encrypt_And_Decrypt(SGD_SM4_ECB, SGD_SM4_ECB);
	Impl_SDF_Encrypt_And_Decrypt(SGD_SM4_ECB, SGD_SM4_CBC);
	Impl_SDF_Encrypt_And_Decrypt(SGD_SM1_ECB, SGD_SM1_ECB);
	Impl_SDF_Encrypt_And_Decrypt(SGD_SM1_ECB, SGD_SM1_CBC);
	Impl_SDF_Encrypt_And_Decrypt(SGD_AES_ECB, SGD_AES_CBC);
	Impl_SDF_Encrypt_And_Decrypt(SGD_DES_ECB, SGD_DES_CBC);

	//Impl_SDF_Encrypt_And_Decrypt(SGD_SM7_ECB, SGD_SM7_ECB);
	//Impl_SDF_Encrypt_And_Decrypt(SGD_SM7_CBC, SGD_SM7_CBC);
}

void Impl_SDF_CalculateMAC(unsigned int algIDKey, unsigned int algMacID)
{
	int rt = 0;
	void* hKeyHdl = NULL;
	unsigned char iv[] = "1122334455667788";
	unsigned char dataPlain[1024 * 100] = { 0 };
	unsigned int dataPlainLen = 1024 * 50;
	unsigned char mac[BUFSMALL] = { 0 };
	unsigned int macLen = sizeof(mac);
	unsigned char encKey[BUF] = { 0 };
	unsigned int encKeyLen = sizeof(encKey);

	for (int i = 0; i < dataPlainLen; i++)
		dataPlain[i] = 'a';

	//SGD_SM4_MAC
	//获取会话密钥句柄
	/*int rt = SDF_GenerateKeyWithKEK(g_hSess, 128, algIDKey, g_keySymIndex, encKey, &encKeyLen, &hKeyHdl);
	if (rt)
	{
		printf("\n[algIDKey = %s] SDF_GenerateKeyWithKEK failed %d | 0x%08x\n", GetAlgStr(algIDKey), rt, rt);
		return;
	}
	else
	{
		printf("\n[algIDKey = %s] SDF_GenerateKeyWithKEK success\n", GetAlgStr(algIDKey));
		printf("encKey: %s\n", Bin2String(encKey, encKeyLen, true).data());
	}*/

	unsigned char random[BUFLITTLE + 1] = { 0 };
	int randomLen = 16;
	rt = SDF_GenerateRandom(g_hSess, randomLen, random);
	if (rt)
	{
		printf("\nSDF_GenerateRandom failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_GenerateRandom success\n");
		printHex("random", random, randomLen);
	}

	rt = SDF_ImportKey(g_hSess, random, randomLen, &hKeyHdl);
	if (rt)
	{
		printf("\n SDF_ImportKey failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\n SDF_ImportKey success\n");
		printf("encKey: %s\n", Bin2String(random, randomLen, true).data());
	}

	rt = SDF_CalculateMAC(g_hSess, hKeyHdl, algMacID, iv, dataPlain, dataPlainLen, mac, &macLen);
	if (rt)
	{
		printf("\n[algMacID = %s] SDF_CalculateMAC failed %d | 0x%08x\n", GetAlgStr(algMacID), rt, rt);

		rt = SDF_DestroyKey(g_hSess, hKeyHdl);
		if (rt)
		{
			printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
			return;
		}
		printf("\nSDF_DestroyKey success\n");
		hKeyHdl = NULL;

		return;
	}
	else
	{
		printf("\n[algMacID = %s] SDF_CalculateMAC success\n", GetAlgStr(algMacID));
		printf("mac: %s\n", Bin2String(mac, macLen, true).data());

		rt = SDF_DestroyKey(g_hSess, hKeyHdl);
		if (rt)
		{
			printf("\nSDF_DestroyKey failed %d | 0x%08x\n", rt, rt);
			return;
		}
		printf("\nSDF_DestroyKey success\n");
		hKeyHdl = NULL;
	}
}

void T_SDF_CalculateMAC()
{
	Impl_SDF_CalculateMAC(SGD_SM1_ECB, SGD_SM1_MAC);
	Impl_SDF_CalculateMAC(SGD_SM4_ECB, SGD_SM4_MAC);
	Impl_SDF_CalculateMAC(SGD_SM7_ECB, SGD_SM7_MAC);
}

void T_SymOperationFunctions()
{
	int n = 0;
	while (1)
	{
		printf("\n");
		printf("------------T_SymOperationFunctions-----------\n");
		printf("5.[1] T_SDF_Encrypt_And_Decrypt\n");
		printf("5.[2] T_SDF_CalculateMAC\n");
		printf("5.[0] quit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		switch (idx) {
		case 1: T_SDF_Encrypt_And_Decrypt(); break;
		case 2: T_SDF_CalculateMAC(); break;
		case 0: return;
		default: printf("Invalid input\n"); break;
		}
	}
}

/*---------------------------杂凑运算类函数测试-------------------------*/
void Impl_HashOperationFunctions(unsigned int algID)
{
	ECCrefPublicKey pubKey = { 0 };
	unsigned char ID[BUF] = { 0 };
	unsigned int IDLen = 0;
	unsigned char data[BUF] = { 0 };
	unsigned int dataLen = sizeof(data) - 1;
	unsigned char hash[BUF] = { 0 };
	unsigned int hashLen = sizeof(hash);

	for (int i = 0; i < dataLen; i++)
		data[i] = 'a';

	unsigned char pucID[128] = "\x11\x22\x33\x44\x55\x66\x77\x88\x11\x22\x33\x44\x55\x66\x77\x88";
	unsigned int uiIDLength = 16;
	int rt = SDF_ExportEncPublicKey_ECC(g_hSess, g_keyAsymIndex, &pubKey);
	if (rt)
	{
		printf("\nSDF_ExportEncPublicKey_ECC failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nSDF_ExportEncPublicKey_ECC success\n");
		printf("EncPubKey.bits: %d\n", pubKey.bits);
		printf("EncPubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
		printf("EncPubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
	}

	rt = SDF_HashInit(g_hSess, algID, &pubKey, pucID, uiIDLength);
	if (rt)
	{
		printf("\n[algID = %s] SDF_HashInit failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
		return;
	}
	else
		printf("\n[algID = %s] SDF_HashInit success\n", GetAlgStr(algID));
	for (int i = 0; i < 3; i++)
	{
		rt = SDF_HashUpdate(g_hSess, data, dataLen);
		if (rt)
		{
			printf("\n[algID = %s] SDF_HashUpdate failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
			return;
		}
		else
			printf("\n[algID = %s] SDF_HashUpdate success\n", GetAlgStr(algID));
	}
	rt = SDF_HashFinal(g_hSess, hash, &hashLen);
	if (rt)
	{
		printf("\n[algID = %s] SDF_HashFinal failed %d | 0x%08x\n", GetAlgStr(algID), rt, rt);
		return;
	}
	else
	{
		printf("\n[algID = %s] SDF_HashFinal success\n", GetAlgStr(algID));
		printf("\nhash: %s\n", Bin2String(hash, hashLen, true).data());
	}
}

void T_HashOperationFunctions()
{
	Impl_HashOperationFunctions(SGD_SM3);
	//Impl_HashOperationFunctions(2);
	//Impl_HashOperationFunctions(SGD_SHA256);
}

/*--------------------------用户文件操作类函数测试----------------------*/
void T_FileOperationFunctions()
{
	unsigned char fileName[] = "test1507";
	unsigned int fileNameLen = strlen((char*)fileName);
	unsigned int fileSize = 8192;
	unsigned char data[BUF * 4 + 1] = { 0 };
	unsigned int dataLen = sizeof(data) - 1;
	unsigned char dataOut[BUF * 8 + 1] = { 0 };
	unsigned int dataOutLen = 0;

	for (int i = 0; i < dataLen; i++)
		data[i] = 'a';

	//test 尝试删除一次 
	int rt = SDF_DeleteFile(g_hSess, fileName, fileNameLen);
	//test end

	rt = SDF_CreateFile(g_hSess, fileName, fileNameLen, fileSize);
	if (rt)
	{
		printf("\n[fileSize = %d] SDF_CreateFile failed %d | 0x%08x\n", fileSize, rt, rt);
		return;
	}
	else
		printf("\n[fileSize = %d] SDF_CreateFile success\n", fileSize);

	//写文件 1
	rt = SDF_WriteFile(g_hSess, fileName, fileNameLen, 0, dataLen, data);
	if (rt)
	{
		printf("\n[dataLen = %d] SDF_WriteFile failed %d | 0x%08x\n", dataLen, rt, rt);
		return;
	}
	else
		printf("\n[dataLen = %d] SDF_WriteFile success\n", dataLen);


	////写文件 2
	//rt = SDF_WriteFile(g_hSess, fileName, fileNameLen, dataLen, dataLen, data);
	//if (rt)
	//{
	//	printf("\n[dataLen = %d] SDF_WriteFile failed %d | 0x%08x\n", dataLen, rt, rt);
	//	return;
	//}
	//else
	//	printf("\n[dataLen = %d] SDF_WriteFile success\n", dataLen);
	//
	//dataLen *= 2;

	//读文件
	rt = SDF_ReadFile(g_hSess, fileName, fileNameLen, 0, &dataLen, dataOut);
	if (rt)
	{
		printf("\n[dataLen = %d] SDF_WriteFile failed %d | 0x%08x\n", dataLen, rt, rt);
		return;
	}
	else
	{
		printf("\n[dataLen = %d] SDF_ReadFile success\n", dataLen);
		printf("\n[dataLen = %d] dataOut : %s\n", dataLen, dataOut);
	}

	rt = SDF_DeleteFile(g_hSess, fileName, fileNameLen);
	if (rt)
		printf("SDF_DeleteFile %s failed %d | 0x%08x\n", fileName, rt, rt);
	else
		printf("SDF_DeleteFile %s success\n", fileName);
}

/*----------------------------全功能自动测试----------------------------*/
void T_SelfTest()
{
	T_SDF_GetDeviceInfo();
	T_SDF_GenerateRandom();

	T_SDF_ExportPublicKey_RSA();
	T_SDF_GenerateKeyPair_RSA();
	T_SDF_GenerateKey_And_Import_RSA();
	T_SDF_ExchangeDigitEnvelopeBaseOnRSA();
	T_SDF_ExportPublicKey_ECC();
	T_SDF_GenerateKeyPair_ECC();
	T_SDF_GenerateKey_And_Import_ECC();
	T_SDF_Agreement_And_GenerateKey_WithECC();
	T_SDF_ExchangeDigitEnvelopeBaseOnECC();
	T_SDF_GenerateKey_And_Import_KEK();

	T_SDF_KeyOperation_RSA();
	T_SDF_Sign_And_Verify_ECC();
	T_SDF_Encrypt_And_Decrypt_External_ECC();
	T_SDF_Encrypt_And_Decrypt_Internal_ECC();
	T_SDF_Encrypt_And_Decrypt();
	T_SDF_CalculateMAC();

	T_HashOperationFunctions();
	T_FileOperationFunctions();
}
void T_signtest()
{
	
	int rt = SDF_GetPrivateKeyAccessRight(g_hSess,300,(unsigned char*)"a1234567a",9);
	CHECK_RT(SDF_GetPrivateKeyAccessRight, rt);
	unsigned char hash[32] = { 0 };
	unsigned int hashLen = 32;
	//for (int i = 0;i < 200;i++)
	{
		ECCSignature sign = { 0 };
		//memset(hash, i, 32);
		//rt = SDF_InternalSign_ECC(g_hSess,300, NULL, 0, &sign);
		//CHECK_RT(SDF_InternalSign_ECC, rt);
		//printf("count =%d\n\n", i);

	}
	for (int j = 0;j < 100;j++)
	{
		unsigned char ID[BUF] = { 0 };
		unsigned int IDLen = 0;
		rt = SDF_HashInit(g_hSess, SGD_SM3, NULL, ID, IDLen);
		CHECK_RT(SDF_HashInit, rt);
		unsigned char data[32] = { 0 };
		unsigned int dataLen = 32;

		char datastr[] = "hfwgyVbui1EwIe8mrP3yPjvorrOymuz0oIAGrvpVKls=";
		for (int i = 0;i < 3;i++)
		{
			rt = SDF_HashUpdate(g_hSess, (unsigned char*)datastr, strlen(datastr));
			CHECK_RT(SDF_HashUpdate, rt);
		}
		rt = SDF_HashFinal(g_hSess, hash, &hashLen);
		CHECK_RT(SDF_HashFinal, rt);
		unsigned int len = strlen((char*)hash);
		printf("len=%d\n", len);
		PRINT_BIN(hash, hashLen);
	}
	
}





#define PRINT_NUM(num)\
do{\
	printf("\t%s = %d | 0x%08X\n", #num, num, num);\
}while(0)

#define PRINT_BIN(buf, len)\
do{\
	printf("\t%s[%s = %d]: %s\n", #buf, #len, len, Bin2String(buf, len, true).c_str());\
}while(0)

#define PRINT_STR(buf, len)\
do{\
	printf("\t%s[%s = %d]: %s\n", #buf, #len, len, buf);\
}while(0)


#define DefineStrLen(buf, size)\
 char buf[size] = { 0 };\
 unsigned int buf##Len = sizeof(buf);\


int SDFFunctionsTest(int argc, char* argv[])
{

	int rt = SDF_OpenDevice(&g_hDev);
	if (rt) {
		printf("SDF_OpenDevice failed %#08x\n", rt);
		getchar();
		return -1;
	}
	rt = SDF_OpenSession(g_hDev, &g_hSess);
	if (rt) {
		printf("SDF_OpenSession failed %#08x\n", rt);
		SDF_CloseDevice(g_hDev);
		getchar();
		return -1;
	}
	while (1) {
		printf("\n");
		printf("---------------------------SDF Functions Test-------------------------\n");
		printf("[1] T_SDF_GetDeviceInfo\n");
		printf("[2] T_SDF_GenerateRandom\n");
		printf("[3] T_KeyManagementFunction\n");
		printf("[4] T_AsymOperationFunctions\n");
		printf("[5] T_SymOperationFunctions\n");
		printf("[6] T_HashOperationFunctions\n");
		printf("[7] T_FileOperationFunctions\n");
		printf("[8] T_SelfTest\n");
		printf("[0] Exit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		switch (idx) {
		case 1: T_SDF_GetDeviceInfo(); break;
		case 2: T_SDF_GenerateRandom(); break;
		case 3: T_KeyManagementFunctions(); break;
		case 4: T_AsymOperationFunctions(); break;
		case 5: T_SymOperationFunctions(); break;
		case 6: T_HashOperationFunctions(); break;
		case 7: T_FileOperationFunctions(); break;
		case 8: T_SelfTest(); break;
		case 0:
			SDF_CloseSession(g_hSess);
			SDF_CloseDevice(g_hDev);
			return 0;
		default: printf("Invalid input\n"); break;
		}
	}
	return 0;
}



#define DefineBufLen(buf, size)\
 unsigned char buf[size] = { 0 };\
 unsigned int buf##Len = sizeof(buf);\

#define ParamBufPLen(buf)\
	buf, &buf##Len

#define ParamBufLen(buf)\
	buf, buf##Len

#define PrintBufLen(buf)\
	printHex(#buf, buf, buf##Len)

#define CheckFunctionRT(func, rt)\
	if (rt)\
	{\
		printf("Function[%s] run failed %d | 0x%08x\n", #func, rt, rt);\
		return;\
	}\
	else{\
		printf("Function[%s] run success\n", #func);\
	}

#define Str(str) #str

#define RSA_INDEX_1	30
#define RSA_INDEX_2	31
#define RSA_INDEX_3	32

#define ECC_INDEX_1	30
#define ECC_INDEX_2	31
#define ECC_INDEX_3	32

#define SYMM_INDEX_1	80
#define SYMM_INDEX_2	81
#define SYMM_INDEX_3	82

void T_Tass_GeneratePlainRSA_ECCKeyPair(void* hSess)
{
	{//RSA
		DefineBufLen(pubKeyN, 4096 / 8);
		DefineBufLen(pubKeyE, 4096 / 8);
		DefineBufLen(priKeyD, 4096 / 8);
		DefineBufLen(priKeyP, 4096 / 8 / 2);
		DefineBufLen(priKeyQ, 4096 / 8 / 2);
		DefineBufLen(priKeyDP, 4096 / 8 / 2);
		DefineBufLen(priKeyDQ, 4096 / 8 / 2);
		DefineBufLen(priKeyQINV, 4096 / 8 / 2);

		int rt = Tass_GeneratePlainRSAKeyPair(hSess,
			4096, TA_3,
			ParamBufPLen(pubKeyN),
			ParamBufPLen(pubKeyE),
			ParamBufPLen(priKeyD),
			ParamBufPLen(priKeyP),
			ParamBufPLen(priKeyQ),
			ParamBufPLen(priKeyDP),
			ParamBufPLen(priKeyDQ),
			ParamBufPLen(priKeyQINV));

		CheckFunctionRT(Tass_GeneratePlainRSAKeyPair, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(pubKeyN);
			PrintBufLen(pubKeyE);
			PrintBufLen(priKeyD);
			PrintBufLen(priKeyP);
			PrintBufLen(priKeyQ);
			PrintBufLen(priKeyDP);
			PrintBufLen(priKeyDQ);
			PrintBufLen(priKeyQINV);
		}
	}
	{//ECC
		DefineBufLen(pubKeyX, 512 / 8);
		DefineBufLen(pubKeyY, 512 / 8);
		DefineBufLen(priKeyD, 512 / 8);

		int rt = Tass_GeneratePlainECCKeyPair(hSess,
			TA_SM2,
			ParamBufPLen(pubKeyX),
			ParamBufPLen(pubKeyY),
			ParamBufPLen(priKeyD));

		CheckFunctionRT(Tass_GeneratePlainECCKeyPair, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(pubKeyX);
			PrintBufLen(pubKeyY);
			PrintBufLen(priKeyD);
		}
	}
}

void T_Tass_GenerateAsymmKeyWithLMK(void* hSess)
{
	{//生成RSA密钥
		DefineBufLen(pubKeyN_X, 2048 / 8);
		DefineBufLen(pubKeyE_Y, 2048 / 8);
		DefineBufLen(priKey, 2048/ 8 * 6);

		int rt = Tass_GenerateAsymmKeyWithLMK(hSess,
			TA_RSA, 2048, TA_3,
			TA_SM2,
			ParamBufPLen(pubKeyN_X),
			ParamBufPLen(pubKeyE_Y),
			ParamBufPLen(priKey));

		CheckFunctionRT(Tass_GenerateAsymmKeyWithLMK, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(pubKeyN_X);
			PrintBufLen(pubKeyE_Y);
			PrintBufLen(priKey);
		}
	}
	{//生成ECC密钥
		TA_ECC_CURVE curves[] = {
			TA_SM2,
			TA_NID_NISTP256,
			TA_NID_SECP256K1,
			//TA_NID_SECP384R1,
			//TA_NID_BRAINPOOLP192R1,
			TA_NID_BRAINPOOLP256R1,
			TA_NID_FRP256V1 };
		const char* curveName[] = {
			Str(TA_SM2),
			Str(TA_NID_NISTP256),
			Str(TA_NID_SECP256K1),
			//Str(TA_NID_SECP384R1),
			//Str(TA_NID_BRAINPOOLP192R1),
			Str(TA_NID_BRAINPOOLP256R1),
			Str(TA_NID_FRP256V1) };
		for (int i = 0; i < sizeof(curves) / sizeof(TA_ECC_CURVE); ++i)
		{
			DefineBufLen(pubKeyN_X, 4096 / 8);
			DefineBufLen(pubKeyE_Y, 4096 / 8);
			DefineBufLen(priKey, 4096 / 8 * 6);

			printf("Curves: %s\n", curveName[i]);
			int rt = Tass_GenerateAsymmKeyWithLMK(hSess,
				TA_ECC, 4096, TA_3,
				curves[i],
				ParamBufPLen(pubKeyN_X),
				ParamBufPLen(pubKeyE_Y),
				ParamBufPLen(priKey));

			CheckFunctionRT(Tass_GenerateAsymmKeyWithLMK, rt);

			if (rt == SDR_OK)
			{
				PrintBufLen(pubKeyN_X);
				PrintBufLen(pubKeyE_Y);
				PrintBufLen(priKey);
			}
		}
	}
}

void T_Tass_GenerateSymmKeyWithLMK(void* hSess)
{
	TA_SYMM_ALG symmAlgs[] = {
		TA_DES128,
		TA_DES192,
		TA_AES128,
		TA_AES192,
		TA_AES256,
		TA_SM1,
		TA_SM4,
		TA_SSF33,
		TA_RC4,
		TA_ZUC };
	const char* symmAlgNames[] = {
		Str(TA_DES128),
		Str(TA_DES192),
		Str(TA_AES128),
		Str(TA_AES192),
		Str(TA_AES256),
		Str(TA_SM1),
		Str(TA_SM4),
		Str(TA_SSF33),
		Str(TA_RC4),
		Str(TA_ZUC) };
	for (int i = 0; i < sizeof(symmAlgs) / sizeof(TA_SYMM_ALG); ++i)
	{
		DefineBufLen(keyCipherByLmk, 128);
		DefineBufLen(kcv, 32);

		printf("SymmAlg: %s\n", symmAlgNames[i]);
		int rt = Tass_GenerateSymmKeyWithLMK(hSess,
			symmAlgs[i],
			ParamBufPLen(keyCipherByLmk),
			ParamBufPLen(kcv));

		CheckFunctionRT(Tass_GenerateKeyWithLMK, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(keyCipherByLmk);
			PrintBufLen(kcv);
		}
	}
}

#define GenRSAOnIndex(idx)\
DefineBufLen(pubKeyN, 4096 / 8);\
DefineBufLen(pubKeyE, 4096 / 8);\
DefineBufLen(priKey, 4096 / 8 * 6);\
int rt = Tass_GenerateAsymmKeyWithLMK(hSess,\
	TA_RSA, 4096, TA_3,\
	TA_SM2,\
	ParamBufPLen(pubKeyN),\
	ParamBufPLen(pubKeyE),\
	ParamBufPLen(priKey));\
CheckFunctionRT(Tass_GenerateAsymmKeyWithLMK, rt);\
if (rt == SDR_OK)\
{\
	PrintBufLen(pubKeyN);\
	PrintBufLen(pubKeyE);\
	PrintBufLen(priKey);\
}\
rt = Tass_ImportKeyCipherByLMK(hSess,\
	idx, TA_RSA, TA_SM2, TA_DES128,\
	TA_CIPHER,\
	ParamBufLen(pubKeyN),\
	ParamBufLen(pubKeyE),\
	ParamBufLen(priKey),\
	NULL, 1);\
CheckFunctionRT(Tass_ImportKeyCipherByLMK, rt);\
rt = Tass_ImportKeyCipherByLMK(hSess,\
	idx, TA_RSA, TA_SM2, TA_DES128,\
	TA_SIGN,\
	ParamBufLen(pubKeyN),\
	ParamBufLen(pubKeyE),\
	ParamBufLen(priKey),\
	NULL, 1);\
CheckFunctionRT(Tass_ImportKeyCipherByLMK, rt);

DefineBufLen(pubKeyX, 128);
DefineBufLen(pubKeyY, 128);
DefineBufLen(priKey, 128);

#define GenECCOnIndex(idx, curve)\
int rt = Tass_GenerateAsymmKeyWithLMK(hSess,\
	TA_ECC, 0, TA_3,\
	curve,\
	ParamBufPLen(pubKeyX),\
	ParamBufPLen(pubKeyY),\
	ParamBufPLen(priKey));\
CheckFunctionRT(Tass_GenerateAsymmKeyWithLMK, rt);\
if (rt == SDR_OK)\
{\
	PrintBufLen(pubKeyX);\
	PrintBufLen(pubKeyY);\
	PrintBufLen(priKey);\
}\
rt = Tass_ImportKeyCipherByLMK(hSess, \
	idx, TA_ECC, curve, TA_DES128, \
	TA_CIPHER, \
	ParamBufLen(pubKeyX), \
	ParamBufLen(pubKeyY), \
	ParamBufLen(priKey), \
	NULL, 1); \
CheckFunctionRT(Tass_ImportKeyCipherByLMK, rt);\
rt = Tass_ImportKeyCipherByLMK(hSess, \
	idx, TA_ECC, curve, TA_DES128, \
	TA_SIGN, \
	ParamBufLen(pubKeyX), \
	ParamBufLen(pubKeyY), \
	ParamBufLen(priKey), \
	NULL, 1); \
CheckFunctionRT(Tass_ImportKeyCipherByLMK, rt);

DefineBufLen(keyCipherByLmk, 128);
DefineBufLen(keyCv, 128);

#define GenSymmOnIndex(idx, alg)\
int rt = Tass_GenerateSymmKeyWithLMK(hSess,\
	alg,\
	ParamBufPLen(keyCipherByLmk),\
	ParamBufPLen(keyCv));\
CheckFunctionRT(Tass_GenerateSymmKeyWithLMK, rt);\
if (rt == SDR_OK)\
{\
	PrintBufLen(keyCipherByLmk);\
	PrintBufLen(keyCv);\
}\
rt = Tass_ImportKeyCipherByLMK(hSess,\
	idx, TA_SYMM, TA_SM2, alg,\
	TA_CIPHER,\
	NULL, 0, NULL, 0,\
	ParamBufLen(keyCipherByLmk),\
	keyCv, 1);\
CheckFunctionRT(Tass_ImportKeyCipherByLMK, rt);

void T_Tass_Generate_ImportSymmKeyWithRSA(void* hSess)
{

	GenRSAOnIndex(RSA_INDEX_1);
	unsigned int keySize[3] = { 16, 24, 32 };
	for (int i = 0; i < 3; ++i)
	{
		{//外部RSA密钥加密
			DefineBufLen(keyCipehrByPubKey, 4096 / 8);
			DefineBufLen(keyCipehrByLmk, 64);
			rt = Tass_GenerateSymmKeyWithRSA(hSess,
				0,
				ParamBufLen(pubKeyN),
				ParamBufLen(pubKeyE),
				keySize[i],
				ParamBufPLen(keyCipehrByPubKey),
				ParamBufPLen(keyCipehrByLmk));

			CheckFunctionRT(Tass_GenerateSymmKeyWithRSA, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByPubKey);
				PrintBufLen(keyCipehrByLmk);
			}

			SDF_GetPrivateKeyAccessRight(hSess, RSA_INDEX_1, (unsigned char*)"a1234567", strlen("a1234567"));

			rt = Tass_ImportSymmKeyCipherByInternalRSA(hSess,
				RSA_INDEX_1,
				ParamBufLen(keyCipehrByPubKey),
				ParamBufPLen(keyCipehrByLmk));

			SDF_ReleasePrivateKeyAccessRight(hSess, RSA_INDEX_1);

			CheckFunctionRT(Tass_ImportSymmKeyCipherByInternalRSA, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByLmk);
			}
		}
		{//内部RSA密钥加密
			DefineBufLen(keyCipehrByPubKey, 4096 / 8);
			DefineBufLen(keyCipehrByLmk, 64);
			rt = Tass_GenerateSymmKeyWithRSA(hSess,
				RSA_INDEX_1,
				NULL, 0, NULL, 0,
				keySize[i],
				ParamBufPLen(keyCipehrByPubKey),
				ParamBufPLen(keyCipehrByLmk));

			CheckFunctionRT(Tass_GenerateSymmKeyWithRSA, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByPubKey);
				PrintBufLen(keyCipehrByLmk);
			}

			SDF_GetPrivateKeyAccessRight(hSess, RSA_INDEX_1, (unsigned char*)"a1234567", strlen("a1234567"));

			rt = Tass_ImportSymmKeyCipherByInternalRSA(hSess,
				RSA_INDEX_1,
				ParamBufLen(keyCipehrByPubKey),
				ParamBufPLen(keyCipehrByLmk));

			SDF_ReleasePrivateKeyAccessRight(hSess, RSA_INDEX_1);

			CheckFunctionRT(Tass_ImportSymmKeyCipherByInternalRSA, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByLmk);
			}
		}
	}
	//删除写入的密钥，恢复现场
	Tass_DestroyKey(hSess, TA_RSA, RSA_INDEX_1);
}

void T_Tass_Generate_ImportSymmKeyWithECC(void* hSess)
{
	GenECCOnIndex(ECC_INDEX_1, TA_SM2);
	unsigned int keySize[3] = { 16, 24, 32 };
	for (int i = 0; i < 3; ++i)
	{
		{//外部ECC密钥加密
			DefineBufLen(keyCipehrByPubKey, 256);
			DefineBufLen(keyCipehrByLmk, 64);
			rt = Tass_GenerateSymmKeyWithECC(hSess,
				0,
				TA_SM2,
				ParamBufLen(pubKeyX),
				ParamBufLen(pubKeyY),
				keySize[i],
				ParamBufPLen(keyCipehrByPubKey),
				ParamBufPLen(keyCipehrByLmk));

			CheckFunctionRT(Tass_GenerateSymmKeyWithECC, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByPubKey);
				PrintBufLen(keyCipehrByLmk);
			}

			SDF_GetPrivateKeyAccessRight(hSess, ECC_INDEX_1, (unsigned char*)"a1234567", strlen("a1234567"));

			rt = Tass_ImportSymmKeyCipherByInternalECC(hSess,
				ECC_INDEX_1,
				ParamBufLen(keyCipehrByPubKey),
				ParamBufPLen(keyCipehrByLmk));

			SDF_ReleasePrivateKeyAccessRight(hSess, ECC_INDEX_1);

			CheckFunctionRT(Tass_ImportSymmKeyCipherByInternalRSA, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByLmk);
			}
		}
		{//内部ECC密钥加密
			DefineBufLen(keyCipehrByPubKey, 256);
			DefineBufLen(keyCipehrByLmk, 64);
			rt = Tass_GenerateSymmKeyWithECC(hSess,
				ECC_INDEX_1,
				TA_SM2,
				NULL, 0, NULL, 0,
				keySize[i],
				ParamBufPLen(keyCipehrByPubKey),
				ParamBufPLen(keyCipehrByLmk));

			CheckFunctionRT(Tass_GenerateSymmKeyWithECC, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByPubKey);
				PrintBufLen(keyCipehrByLmk);
			}

			SDF_GetPrivateKeyAccessRight(hSess, ECC_INDEX_1, (unsigned char*)"a1234567", strlen("a1234567"));

			rt = Tass_ImportSymmKeyCipherByInternalECC(hSess,
				ECC_INDEX_1,
				ParamBufLen(keyCipehrByPubKey),
				ParamBufPLen(keyCipehrByLmk));

			SDF_ReleasePrivateKeyAccessRight(hSess, ECC_INDEX_1);

			CheckFunctionRT(Tass_ImportSymmKeyCipherByInternalECC, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByLmk);
			}
		}
	}
	//删除写入的密钥，恢复现场
	Tass_DestroyKey(hSess, TA_ECC, RSA_INDEX_1);
}

void T_Tass_Generate_ImportSymmKeyWithKEK(void* hSess)
{
	GenSymmOnIndex(SYMM_INDEX_1, TA_DES128);
	unsigned int keySize[3] = { 16, 24, 32 };
	for (int i = 0; i < 3; ++i)
	{
		{//内部KEK密钥加密
			DefineBufLen(keyCipehrByKek, 128);
			DefineBufLen(keyCipehrByLmk, 64);
			rt = Tass_GenerateSymmKeyWithInternalKEK(hSess,
				SYMM_INDEX_1,
				keySize[i],
				ParamBufPLen(keyCipehrByKek),
				ParamBufPLen(keyCipehrByLmk));

			CheckFunctionRT(Tass_GenerateSymmKeyWithInternalKEK, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByKek);
				PrintBufLen(keyCipehrByLmk);
			}

			rt = Tass_ImportSymmKeyCipherByInternalKEK(hSess,
				SYMM_INDEX_1,
				ParamBufLen(keyCipehrByKek),
				ParamBufPLen(keyCipehrByLmk));

			CheckFunctionRT(Tass_ImportSymmKeyCipherByInternalKEK, rt);
			if (rt == SDR_OK)
			{
				PrintBufLen(keyCipehrByLmk);
			}
		}
	}
	//删除写入的密钥，恢复现场
	Tass_DestroyKey(hSess, TA_SYMM, SYMM_INDEX_1);
}

void T_Tass_ConvertSymmKeyCipherByLMK_KEKToKEK_LMK(void* hSess)
{
	GenSymmOnIndex(SYMM_INDEX_1, TA_DES128);

	{//内部KEK密钥加密
		DefineBufLen(keyCipherByKek, 128);

		rt = Tass_ConvertSymmKeyCipherByLMKToKEK(hSess,
			ParamBufLen(keyCipherByLmk),
			SYMM_INDEX_1,
			NULL, 0,
			TA_DES128, TA_ECB,
			ParamBufPLen(keyCipherByKek));

		CheckFunctionRT(Tass_ConvertSymmKeyCipherByLMKToKEK, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(keyCipherByKek);
		}

		rt = Tass_ConvertSymmKeyCipherByKEKToLMK(hSess,
			ParamBufLen(keyCipherByKek),
			SYMM_INDEX_1,
			NULL, 0,
			TA_DES128,
			TA_ECB,
			ParamBufPLen(keyCipherByLmk));

		CheckFunctionRT(Tass_ConvertSymmKeyCipherByKEKToLMK, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(keyCipherByLmk);
		}
	}

	{//外部KEK密钥加密
		DefineBufLen(keyCipherByKek, 128);

		rt = Tass_ConvertSymmKeyCipherByLMKToKEK(hSess,
			ParamBufLen(keyCipherByLmk),
			0,
			ParamBufLen(keyCipherByLmk),
			TA_DES128, TA_ECB,
			ParamBufPLen(keyCipherByKek));

		CheckFunctionRT(Tass_ConvertSymmKeyCipherByLMKToKEK, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(keyCipherByKek);
		}

		rt = Tass_ConvertSymmKeyCipherByKEKToLMK(hSess,
			ParamBufLen(keyCipherByKek),
			0,
			ParamBufLen(keyCipherByLmk),
			TA_DES128,
			TA_ECB,
			ParamBufPLen(keyCipherByLmk));

		CheckFunctionRT(Tass_ConvertSymmKeyCipherByKEKToLMK, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(keyCipherByLmk);
		}
	}

	//删除写入的密钥，恢复现场
	Tass_DestroyKey(hSess, TA_SYMM, SYMM_INDEX_1);
}

void T_Tass_GetInternalKeyCipherByLMK_ImportKeyCipherByLMK(void* hSess)
{
	{//对称密钥
		GenSymmOnIndex(SYMM_INDEX_1, TA_DES128);

		TA_SYMM_ALG alg;
		rt = Tass_GetInternalKeyCipherByLMK(hSess,
			SYMM_INDEX_1, TA_SYMM, TA_SIGN,
			NULL, NULL, NULL, NULL,
			ParamBufPLen(keyCipherByLmk),
			keyCv,
			&alg,
			NULL);

		CheckFunctionRT(Tass_GetInternalKeyCipherByLMK, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(keyCipherByLmk);
			printHex("alg", (unsigned char*)&alg, sizeof(alg));
		}

		//删除写入的密钥，恢复现场
		Tass_DestroyKey(hSess, TA_SYMM, SYMM_INDEX_1);
	}
	{//RSA密钥
		GenRSAOnIndex(RSA_INDEX_1);

		SDF_GetPrivateKeyAccessRight(hSess, RSA_INDEX_1, (unsigned char*)"a1234567", 8);

		rt = Tass_GetInternalKeyCipherByLMK(hSess,
			RSA_INDEX_1, TA_RSA,
			TA_CIPHER,
			ParamBufPLen(pubKeyN),
			ParamBufPLen(pubKeyE),
			ParamBufPLen(priKey),
			NULL, NULL, NULL);

		SDF_ReleasePrivateKeyAccessRight(hSess, RSA_INDEX_1);

		CheckFunctionRT(Tass_GetInternalKeyCipherByLMK, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(pubKeyN);
			PrintBufLen(pubKeyE);
			PrintBufLen(priKey);
		}

		//删除写入的密钥，恢复现场
		Tass_DestroyKey(hSess, TA_RSA, RSA_INDEX_1);
	}
	{//ECC
		GenECCOnIndex(ECC_INDEX_1, TA_SM2);

		SDF_GetPrivateKeyAccessRight(hSess, ECC_INDEX_1, (unsigned char*)"a1234567", 8);

		TA_ECC_CURVE curve;
		rt = Tass_GetInternalKeyCipherByLMK(hSess,
			ECC_INDEX_1, TA_ECC,
			TA_CIPHER,
			ParamBufPLen(pubKeyX),
			ParamBufPLen(pubKeyY),
			ParamBufPLen(priKey),
			NULL, NULL,
			&curve);

		SDF_ReleasePrivateKeyAccessRight(hSess, ECC_INDEX_1);

		CheckFunctionRT(Tass_GetInternalKeyCipherByLMK, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(pubKeyX);
			PrintBufLen(pubKeyY);
			PrintBufLen(priKey);
			printHex("curve", (unsigned char*)&curve, sizeof(curve));
		}

		//删除写入的密钥，恢复现场
		Tass_DestroyKey(hSess, TA_ECC, ECC_INDEX_1);
	}
}

void T_Tass_GetInternalRSA_ECCPublicKey(void* hSess)
{
	{//RSA密钥
		GenRSAOnIndex(RSA_INDEX_1);

		DefineBufLen(label, 128);
		rt = Tass_GetInternalRSAPublicKey(hSess,
			RSA_INDEX_1, TA_CIPHER,
			ParamBufPLen(pubKeyN),
			ParamBufPLen(pubKeyE),
			ParamBufPLen(label));

		CheckFunctionRT(Tass_GetInternalRSAPublicKey, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(pubKeyN);
			PrintBufLen(pubKeyE);
			PrintBufLen(label);
		}

		//删除写入的密钥，恢复现场
		Tass_DestroyKey(hSess, TA_RSA, RSA_INDEX_1);
	}
	{//ECC
		GenECCOnIndex(ECC_INDEX_1, TA_SM2);

		TA_ECC_CURVE curve;
		rt = Tass_GetInternalECCPublicKey(hSess,
			ECC_INDEX_1, TA_CIPHER,
			&curve,
			ParamBufPLen(pubKeyX),
			ParamBufPLen(pubKeyY));

		CheckFunctionRT(Tass_GetInternalECCPublicKey, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(pubKeyX);
			PrintBufLen(pubKeyY);
			printHex("curve", (unsigned char*)&curve, sizeof(curve));
		}

		//删除写入的密钥，恢复现场
		Tass_DestroyKey(hSess, TA_ECC, ECC_INDEX_1);
	}
}

void T_Tass_GetIndexInfo_Get_SetKeyLabel_GetKeyIndex_GetSymmKeyInfo_GetSymmKCV_DestroyKey(void* hSess)
{
	{//对称密钥
		unsigned int tmp = 0;
		int rttttt = Tass_GetKeyIndex(hSess, TA_SYMM, "test", strlen("test"), &tmp);

		rttttt = Tass_GetKeyIndex(hSess, TA_RSA, "test", strlen("test"), &tmp);
		rttttt = Tass_GetKeyIndex(hSess, TA_ECC, "test", strlen("test"), &tmp);

		GenSymmOnIndex(SYMM_INDEX_1, TA_DES128);

		rttttt = Tass_SetKeyLabel(hSess, TA_SYMM, SYMM_INDEX_1, "", 0);

		DefineBufLen(info, 2048);
		rt = Tass_GetIndexInfo(hSess, TA_SYMM,
			ParamBufPLen(info));

		CheckFunctionRT(Tass_GetIndexInfo, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(info);
		}

		DefineBufLen(label, 128);
		char* pLabel = (char*)label;
		rt = Tass_GetKeyLabel(hSess, TA_SYMM, SYMM_INDEX_1,
			pLabel, &labelLen);

		CheckFunctionRT(Tass_GetKeyLabel, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(label);
		}

		rt = Tass_SetKeyLabel(hSess, TA_SYMM, SYMM_INDEX_1,
			"TEST_LABEL", strlen("TEST_LABEL"));

		CheckFunctionRT(Tass_SetKeyLabel, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(label);
		}

		unsigned int index;

		rt = Tass_GetKeyIndex(hSess, TA_SYMM,
			"TEST_LABEL", strlen("TEST_LABEL"),
			&index);

		CheckFunctionRT(Tass_GetKeyIndex, rt);

		if (rt == SDR_OK)
		{
			printf("Index: %d\n", index);
		}

		rt = Tass_GetKeyLabel(hSess, TA_SYMM, SYMM_INDEX_1,
			pLabel, &labelLen);

		CheckFunctionRT(Tass_GetKeyLabel, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(label);
		}
		TA_SYMM_ALG alg;
		unsigned char kcv[8] = { 0 };

		rt = Tass_GetSymmKeyInfo(hSess,
			SYMM_INDEX_1,
			&alg,
			pLabel, &labelLen,
			kcv);

		CheckFunctionRT(Tass_GetSymmKeyInfo, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(label);
			printHex("kcv", kcv, sizeof(kcv));
		}

		rt = Tass_GetSymmKCV(hSess,
			0,
			ParamBufLen(keyCipherByLmk), alg,
			kcv);

		CheckFunctionRT(Tass_GetSymmKCV, rt);
		if (rt == SDR_OK)
		{
			printHex("kcv", kcv, sizeof(kcv));
		}

		rt = Tass_GetSymmKCV(hSess,
			SYMM_INDEX_1,
			NULL, 0, alg,
			kcv);
		CheckFunctionRT(Tass_GetSymmKCV, rt);
		if (rt == SDR_OK)
		{
			printHex("kcv", kcv, sizeof(kcv));
		}

		Tass_DestroyKey(hSess, TA_SYMM, SYMM_INDEX_1);

		rt = Tass_GetIndexInfo(hSess, TA_SYMM,
			ParamBufPLen(info));

		CheckFunctionRT(Tass_GetIndexInfo, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(info);
		}
	}
}

int TassManagementFunctionsTest(void* hSess)
{
	while (1) {
		int i = 0;
		printf("\n");
		printf("---------------------------Tass Management Functions Test-------------------------\n");
		printf("[%d] T_Tass_GeneratePlainRSA_ECCKeyPair\n", ++i);
		printf("[%d] T_Tass_GenerateAsymmKeyWithLMK\n", ++i);
		printf("[%d] T_Tass_GenerateSymmKeyWithLMK\n", ++i);
		printf("[%d] T_Tass_Generate_ImportSymmKeyWithRSA\n", ++i);
		printf("[%d] T_Tass_Generate_ImportSymmKeyWithECC\n", ++i);
		printf("[%d] T_Tass_Generate_ImportSymmKeyWithKEK\n", ++i);
		printf("[%d] T_Tass_ConvertSymmKeyCipherByLMK_KEKToKEK_LMK\n", ++i);
		printf("[%d] T_Tass_GetInternalKeyCipherByLMK_ImportKeyCipherByLMK\n", ++i);
		printf("[%d] T_Tass_GetInternalRSA_ECCPublicKey\n", ++i);
		printf("[%d] T_Tass_GetIndexInfo_Get_SetKeyLabel_GetKeyIndex_GetSymmKeyInfo_GetSymmKCV_DestroyKey\n", ++i);
		printf("[0] Exit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		switch (idx) {
		case 1: T_Tass_GeneratePlainRSA_ECCKeyPair(hSess); break;
		case 2: T_Tass_GenerateAsymmKeyWithLMK(hSess); break;
		case 3: T_Tass_GenerateSymmKeyWithLMK(hSess); break;
		case 4: T_Tass_Generate_ImportSymmKeyWithRSA(hSess); break;
		case 5: T_Tass_Generate_ImportSymmKeyWithECC(hSess); break;
		case 6: T_Tass_Generate_ImportSymmKeyWithKEK(hSess); break;
		case 7: T_Tass_ConvertSymmKeyCipherByLMK_KEKToKEK_LMK(hSess); break;
		case 8: T_Tass_GetInternalKeyCipherByLMK_ImportKeyCipherByLMK(hSess); break;
		case 9: T_Tass_GetInternalRSA_ECCPublicKey(hSess); break;
		case 10: T_Tass_GetIndexInfo_Get_SetKeyLabel_GetKeyIndex_GetSymmKeyInfo_GetSymmKCV_DestroyKey(hSess); break;
		case 0: return 0;
		default: printf("Invalid input\n"); continue;
		}
	}
}

void T_Tass_ExchangeDataEnvelopeRSA(void* hSess)
{
	GenRSAOnIndex(RSA_INDEX_1);

	DefineBufLen(keyCipherByPubKey, 4096 / 8);
	DefineBufLen(keyCipherByLmk, 128);

	rt = Tass_GenerateSymmKeyWithRSA(hSess,
		RSA_INDEX_1,
		NULL, 0, NULL, 0,
		16,
		ParamBufPLen(keyCipherByPubKey),
		ParamBufPLen(keyCipherByLmk));

	CheckFunctionRT(Tass_GenerateSymmKeyWithRSA, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(keyCipherByPubKey);
		PrintBufLen(keyCipherByLmk);
	}

	SDF_GetPrivateKeyAccessRight(hSess, RSA_INDEX_1, (unsigned char*)"a1234567", 8);

	rt = Tass_ExchangeDataEnvelopeRSA(hSess,
		RSA_INDEX_1,
		ParamBufLen(pubKeyN),
		ParamBufLen(pubKeyE),
		ParamBufLen(keyCipherByPubKey),
		ParamBufPLen(keyCipherByPubKey));

	SDF_ReleasePrivateKeyAccessRight(hSess, RSA_INDEX_1);

	CheckFunctionRT(Tass_ExchangeDataEnvelopeRSA, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(keyCipherByPubKey);
	}

	SDF_GetPrivateKeyAccessRight(hSess, RSA_INDEX_1, (unsigned char*)"a1234567", 8);

	rt = Tass_ImportSymmKeyCipherByInternalRSA(hSess,
		RSA_INDEX_1,
		ParamBufLen(keyCipherByPubKey),
		ParamBufPLen(keyCipherByLmk));

	SDF_ReleasePrivateKeyAccessRight(hSess, RSA_INDEX_1);


	CheckFunctionRT(Tass_ImportSymmKeyCipherByInternalRSA, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(keyCipherByLmk);
	}

	Tass_DestroyKey(hSess, TA_RSA, RSA_INDEX_1);
}

void T_Tass_RSAEncrypt_Decrypt(void* hSess)
{
	GenRSAOnIndex(RSA_INDEX_1);

	for (int i = 0; i < 2; ++i)
	{
		TA_RSA_PAD pads[] = {
			TA_NOPAD,
			TA_PKCS1_5,
			TA_OAEP };
		const char* padNames[] = {
			Str(TA_NOPAD),
			Str(TA_PKCS1_5),
			Str(TA_OAEP) };
		for (int j = 0; j < sizeof(pads) / sizeof(TA_RSA_PAD); ++j)
		{

			printf("%s %s\n", i == 0 ? "Internal Key" : "External Key", padNames[j]);

			DefineBufLen(data, 4096 / 8);
			memset(data, 01, dataLen);

			rt = Tass_RSAEncrypt(hSess,
				i == 0 ? RSA_INDEX_1 : 0,
				ParamBufLen(pubKeyN),
				ParamBufLen(pubKeyE),
				pads[j], TA_SHA512, (unsigned char*)"1234", 4,
				data,
				j == TA_NOPAD ? dataLen : 128,
				ParamBufPLen(data));

			CheckFunctionRT(Tass_RSAEncrypt, rt);

			if (rt == SDR_OK)
			{
				PrintBufLen(data);
			}

			if (i == 0)
				SDF_GetPrivateKeyAccessRight(hSess, RSA_INDEX_1, (unsigned char*)"a1234567", strlen("a1234567"));


			rt = Tass_RSADecrypt(hSess,
				i == 0 ? RSA_INDEX_1 : 0,
				ParamBufLen(priKey),
				pads[j], TA_SHA512, (unsigned char*)"1234", 4,
				ParamBufLen(data),
				ParamBufPLen(data));

			if (i == 0)
				SDF_ReleasePrivateKeyAccessRight(hSess, RSA_INDEX_1);


			CheckFunctionRT(Tass_RSADecrypt, rt);

			if (rt == SDR_OK)
			{
				PrintBufLen(data);
			}
		}
	}
	Tass_DestroyKey(hSess, TA_RSA, RSA_INDEX_1);
}

void T_Tass_RSASign_Verify_ExternalHash_Pad(void* hSess)
{
	unsigned int index = 88;
	unsigned char ctx[512] = { 0 };
	unsigned int ctxLen = sizeof(ctx);
	unsigned char outCtx[512] = { 0 };
	unsigned int outCtxLen = sizeof(outCtx);
	unsigned char hash[512] = { 0 };
	unsigned int hashLen = sizeof(hash);
	unsigned char sig[1024] = { 0 };
	unsigned int sigLen = sizeof(sig);

	string srcData = "12345678123456781234567812345678";
	unsigned char shaType[8][128] = { "", "", "", "",
									  "302D300d06096086480165030402040500041C", // sha224
									  "3031300d060960864801650304020105000420", // sha256
									  "3041300d060960864801650304020205000430", // sha384
									  "3051300d060960864801650304020305000440"  // sha512
	};

	DefineBufLen(pubKeyN_X, 4096 / 8);
	DefineBufLen(pubKeyE_Y, 4096 / 8);
	DefineBufLen(priKey, 4096 / 8 * 6);

	int rt = Tass_GenerateAsymmKeyWithLMK(hSess,
		TA_RSA, 4096, TA_65537,
		TA_SM2,
		ParamBufPLen(pubKeyN_X),
		ParamBufPLen(pubKeyE_Y),
		ParamBufPLen(priKey));
	if (rt == SDR_OK)
		printf("Tass_GenerateAsymmKeyWithLMK is success!\n");
	else
	{
		printf("Tass_GenerateAsymmKeyWithLMK is failed! rt = %d\n", rt);
		return;
	}

	for (int i = TA_SHA224; i <= TA_SHA512; i++)
	{
		memset(sig, 0, sizeof(sig));
		memset(ctx, 0, sizeof(ctx));
		memset(hash, 0, sizeof(hash));
		memset(outCtx, 0, sizeof(outCtx));
		ctxLen = sizeof(ctx);
		outCtxLen = sizeof(outCtx);
		hashLen = sizeof(hash);
		sigLen = sizeof(sig);

		printf("\nhashType = %d\n", i);
		int rv = Tass_HashInit(hSess,
			(TA_HASH_ALG)i,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			ctx, &ctxLen);
		if (rv == SDR_OK)
		{
			PrintBufLen(ctx);
		}

		rv = Tass_HashUpdate(hSess,
			ctx, ctxLen,
			(unsigned char*)srcData.c_str(), srcData.size(),
			outCtx, &outCtxLen);
		if (rv == SDR_OK)
		{
			PrintBufLen(ctx);
		}

		rv = Tass_HashFinal(hSess,
			outCtx, outCtxLen,
			hash, &hashLen);
		if (rv == SDR_OK)
		{
			PrintBufLen(hash);
		}

		string shaTypeStr = (char*)shaType[i - 1];
		string hashStr = Bin2String(hash, hashLen, true);

		string inData = shaTypeStr + hashStr;
		string dataBin = String2Bin(inData);

		/* 以下通过内部索引签名验签 */
		//填充模式: TA_PKCS1_5
		rv = SDF_GetPrivateKeyAccessRight(hSess, index, pwd, strlen((char*)pwd));

		rv = Tass_RSASign(hSess, index,
			NULL, 0,
			TA_PKCS1_5, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			(unsigned char*)dataBin.c_str(), dataBin.size(),
			sig, &sigLen);
		if (rv == SDR_OK)
		{
			printf("\npad = TA_PKCS1_5 Tass_RSASign is success!\n");
			PrintBufLen(sig);
		}
		else
		{
			printf("pad = TA_PKCS1_5 Tass_RSASign is failed! rt = %d\n", rv);
			return;
		}

		SDF_ReleasePrivateKeyAccessRight(hSess, index);

		rv = Tass_RSAVerify(hSess, index,
			NULL, 0,
			NULL, 0,
			TA_PKCS1_5, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			(unsigned char*)dataBin.c_str(), dataBin.size(),
			sig, sigLen);
		if (rv == SDR_OK)
			printf("pad = TA_PKCS1_5 Tass_RSAVerify is success!\n");
		else
		{
			printf("pad = TA_PKCS1_5 Tass_RSAVerify is failed! rt = %d\n", rv);
			return;
		}

		//填充模式: TA_PSS
		memset(sig, 0, sizeof(sig));
		sigLen = sizeof(sig);
		rv = SDF_GetPrivateKeyAccessRight(hSess, index, pwd, strlen((char*)pwd));

		rv = Tass_RSASign(hSess, index,
			NULL, 0,
			TA_PSS, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, &sigLen);
		if (rv == SDR_OK)
		{
			printf("\npad = TA_PSS Tass_RSASign is success!\n");
			PrintBufLen(sig);
		}
		else
		{
			printf("pad = TA_PSS Tass_RSASign is failed! rt = %d\n", rv);
			return;
		}

		SDF_ReleasePrivateKeyAccessRight(hSess, index);

		rv = Tass_RSAVerify(hSess, index,
			NULL, 0,
			NULL, 0,
			TA_PSS, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, sigLen);
		if (rv == SDR_OK)
			printf("pad = TA_PSS Tass_RSAVerify is success!\n");
		else
		{
			printf("pad = TA_PSS Tass_RSAVerify is failed! rt = %d\n", rv);
			return;
		}


		/* 以下通过外送密钥签名验签 */
		//填充模式: TA_PKCS1_5
		memset(sig, 0, sizeof(sig));
		sigLen = sizeof(sig);
		rv = Tass_RSASign(hSess, 0,
			priKey, priKeyLen,
			TA_PKCS1_5, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			(unsigned char*)dataBin.c_str(), dataBin.size(),
			sig, &sigLen);
		if (rv == SDR_OK)
		{
			printf("\npad = TA_PKCS1_5 Tass_RSASign is success!\n");
			PrintBufLen(sig);
		}
		else
		{
			printf("pad = TA_PKCS1_5 Tass_RSASign is failed! rt = %d\n", rv);
			return;
		}

		rv = Tass_RSAVerify(hSess, 0,
			pubKeyN_X, pubKeyN_XLen,
			pubKeyE_Y, pubKeyE_YLen,
			TA_PKCS1_5, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			(unsigned char*)dataBin.c_str(), dataBin.size(),
			sig, sigLen);
		if (rv == SDR_OK)
		{
			printf("pad = TA_PKCS1_5 Tass_RSAVerify is success!\n");
			PrintBufLen(sig);
		}
		else
		{
			printf("pad = TA_PKCS1_5 Tass_RSAVerify is failed! rt = %d\n", rv);
			return;
		}

		//填充模式: TA_PSS
		memset(sig, 0, sizeof(sig));
		sigLen = sizeof(sig);

		rv = Tass_RSASign(hSess, 0,
			priKey, priKeyLen,
			TA_PSS, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, &sigLen);
		if (rv == SDR_OK)
		{
			printf("\npad = TA_PSS Tass_RSASign is success!\n");
			PrintBufLen(sig);
		}
		else
		{
			printf("pad = TA_PSS Tass_RSASign is failed! rt = %d\n", rv);
			return;
		}

		rv = Tass_RSAVerify(hSess, 0,
			pubKeyN_X, pubKeyN_XLen,
			pubKeyE_Y, pubKeyE_YLen,
			TA_PSS, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, sigLen);
		if (rv == SDR_OK)
			printf("pad = TA_PSS Tass_RSAVerify is success!\n");
		else
		{
			printf("pad = TA_PSS Tass_RSAVerify is failed! rt = %d\n", rv);
			return;
		}
	}
}

void T_Tass_RSASign_Verify_ExternalHash_NotPad(void* hSess)
{
	unsigned int index = 88;
	unsigned char ctx[512] = { 0 };
	unsigned int ctxLen = sizeof(ctx);
	unsigned char outCtx[512] = { 0 };
	unsigned int outCtxLen = sizeof(outCtx);
	unsigned char hash[512] = { 0 };
	unsigned int hashLen = sizeof(hash);
	unsigned char sig[1024] = { 0 };
	unsigned int sigLen = sizeof(sig);

	string srcData = "12345678123456781234567812345678";

	/* TA_NOPAD, TA_NOHASH */
	int dataLen = 512;
	unsigned char data[BUF * 5] = { 0 };
	memset(data, 'a', dataLen);

	int rv = SDF_GetPrivateKeyAccessRight(hSess, index, pwd, strlen((char*)pwd));

	rv = Tass_RSASign(hSess, index,
		NULL, 0,
		TA_NOPAD, TA_NOHASH,
		TA_NOHASH, TA_NOHASH,
		data, dataLen,
		sig, &sigLen);
	if (rv == SDR_OK)
	{
		printf("TA_NOPAD, TA_NOHASH: Tass_RSASign is success!\n");
		PrintBufLen(sig);
	}
	else
	{
		printf("TA_NOPAD, TA_NOHASH: Tass_RSASign is failed! rt = %d\n", rv);
		return;
	}

	SDF_ReleasePrivateKeyAccessRight(hSess, index);

	rv = Tass_RSAVerify(hSess, index,
		NULL, 0,
		NULL, 0,
		TA_NOPAD, TA_NOHASH,
		TA_NOHASH, TA_NOHASH,
		data, dataLen,
		sig, sigLen);
	if (rv == SDR_OK)
		printf("TA_NOPAD, TA_NOHASH: Tass_RSAVerify is success!\n");
	else
	{
		printf("TA_NOPAD, TA_NOHASH: Tass_RSAVerify is failed! rt = %d\n", rv);
		return;
	}

	DefineBufLen(pubKeyN_X, 4096 / 8);
	DefineBufLen(pubKeyE_Y, 4096 / 8);
	DefineBufLen(priKey, 4096 / 8 * 6);

	int rt = Tass_GenerateAsymmKeyWithLMK(hSess,
		TA_RSA, 4096, TA_65537,
		TA_SM2,
		ParamBufPLen(pubKeyN_X),
		ParamBufPLen(pubKeyE_Y),
		ParamBufPLen(priKey));
	if (rt == SDR_OK)
		printf("Tass_GenerateAsymmKeyWithLMK is success!\n");
	else
	{
		printf("Tass_GenerateAsymmKeyWithLMK is failed! rt = %d\n", rt);
		return;
	}

	for (int i = TA_SHA224; i <= TA_SHA512; i++)
	{
		memset(sig, 0, sizeof(sig));
		memset(ctx, 0, sizeof(ctx));
		memset(hash, 0, sizeof(hash));
		memset(outCtx, 0, sizeof(outCtx));
		ctxLen = sizeof(ctx);
		outCtxLen = sizeof(outCtx);
		hashLen = sizeof(hash);
		sigLen = sizeof(sig);

		printf("\nhashType = %d\n", i);
		int rv = Tass_HashInit(hSess,
			(TA_HASH_ALG)i,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			ctx, &ctxLen);
		if (rv == SDR_OK)
		{
			PrintBufLen(ctx);
		}

		rv = Tass_HashUpdate(hSess,
			ctx, ctxLen,
			(unsigned char*)srcData.c_str(), srcData.size(),
			outCtx, &outCtxLen);
		if (rv == SDR_OK)
		{
			PrintBufLen(ctx);
		}

		rv = Tass_HashFinal(hSess,
			outCtx, outCtxLen,
			hash, &hashLen);
		if (rv == SDR_OK)
		{
			PrintBufLen(hash);
		}

		/* 以下通过内部索引签名验签 */
		//填充模式: TA_PKCS1_5
		rv = SDF_GetPrivateKeyAccessRight(hSess, index, pwd, strlen((char*)pwd));

		rv = Tass_RSASign(hSess, index,
			NULL, 0,
			TA_PKCS1_5, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, &sigLen);
		if (rv == SDR_OK)
		{
			printf("\npad = TA_PKCS1_5 Tass_RSASign is success!\n");
			PrintBufLen(sig);
		}
		else
		{
			printf("pad = TA_PKCS1_5 Tass_RSASign is failed! rt = %d\n", rv);
			return;
		}

		SDF_ReleasePrivateKeyAccessRight(hSess, index);

		rv = Tass_RSAVerify(hSess, index,
			NULL, 0,
			NULL, 0,
			TA_PKCS1_5, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, sigLen);
		if (rv == SDR_OK)
			printf("pad = TA_PKCS1_5 Tass_RSAVerify is success!\n");
		else
		{
			printf("pad = TA_PKCS1_5 Tass_RSAVerify is failed! rt = %d\n", rv);
			return;
		}

		//填充模式: TA_PSS
		memset(sig, 0, sizeof(sig));
		sigLen = sizeof(sig);
		rv = SDF_GetPrivateKeyAccessRight(hSess, index, pwd, strlen((char*)pwd));

		rv = Tass_RSASign(hSess, index,
			NULL, 0,
			TA_PSS, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, &sigLen);
		if (rv == SDR_OK)
		{
			printf("\npad = TA_PSS Tass_RSASign is success!\n");
			PrintBufLen(sig);
		}
		else
		{
			printf("pad = TA_PSS Tass_RSASign is failed! rt = %d\n", rv);
			return;
		}

		SDF_ReleasePrivateKeyAccessRight(hSess, index);

		rv = Tass_RSAVerify(hSess, index,
			NULL, 0,
			NULL, 0,
			TA_PSS, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, sigLen);
		if (rv == SDR_OK)
			printf("pad = TA_PSS Tass_RSAVerify is success!\n");
		else
		{
			printf("pad = TA_PSS Tass_RSAVerify is failed! rt = %d\n", rv);
			return;
		}


		/* 以下通过外送密钥签名验签 */
		//填充模式: TA_PKCS1_5
		memset(sig, 0, sizeof(sig));
		sigLen = sizeof(sig);
		rv = Tass_RSASign(hSess, 0,
			priKey, priKeyLen,
			TA_PKCS1_5, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, &sigLen);
		if (rv == SDR_OK)
		{
			printf("\npad = TA_PKCS1_5 Tass_RSASign is success!\n");
			PrintBufLen(sig);
		}
		else
		{
			printf("pad = TA_PKCS1_5 Tass_RSASign is failed! rt = %d\n", rv);
			return;
		}

		rv = Tass_RSAVerify(hSess, 0,
			pubKeyN_X, pubKeyN_XLen,
			pubKeyE_Y, pubKeyE_YLen,
			TA_PKCS1_5, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, sigLen);
		if (rv == SDR_OK)
			printf("pad = TA_PKCS1_5 Tass_RSAVerify is success!\n");
		else
		{
			printf("pad = TA_PKCS1_5 Tass_RSAVerify is failed! rt = %d\n", rv);
			return;
		}

		//填充模式: TA_PSS
		memset(sig, 0, sizeof(sig));
		sigLen = sizeof(sig);

		rv = Tass_RSASign(hSess, 0,
			priKey, priKeyLen,
			TA_PSS, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, &sigLen);
		if (rv == SDR_OK)
		{
			printf("\npad = TA_PSS Tass_RSASign is success!\n");
			PrintBufLen(sig);
		}
		else
		{
			printf("pad = TA_PSS Tass_RSASign is failed! rt = %d\n", rv);
			return;
		}

		rv = Tass_RSAVerify(hSess, 0,
			pubKeyN_X, pubKeyN_XLen,
			pubKeyE_Y, pubKeyE_YLen,
			TA_PSS, TA_NOHASH,
			(TA_HASH_ALG)i, (TA_HASH_ALG)i,
			hash, hashLen,
			sig, sigLen);
		if (rv == SDR_OK)
			printf("pad = TA_PSS Tass_RSAVerify is success!\n");
		else
		{
			printf("pad = TA_PSS Tass_RSAVerify is failed! rt = %d\n", rv);
			return;
		}
	}
}

void T_Tass_RSASign_Verify_ExternalHash(void* hSess)
{
	/*外部对hash值填充*/
	printf("\n\n\nT_Tass_RSASign_Verify_ExternalHash_Pad:\n");
	T_Tass_RSASign_Verify_ExternalHash_Pad(hSess);

	/*外部对hash值不填充*/
	printf("\n\n\nT_Tass_RSASign_Verify_ExternalHash_NotPad:\n");
	T_Tass_RSASign_Verify_ExternalHash_NotPad(hSess);
}

void T_Tass_MultiHash(void* hSess)
{
	int rt = 0;

	unsigned int dataCnt = 5;

	DefineBufLen(data0, 16);
	DefineBufLen(data1, 24);
	DefineBufLen(data2, 32);
	DefineBufLen(data3, 48);
	DefineBufLen(data4, 64);
	const unsigned char* datas[] = { data0, data1, data2, data3, data4 };
	unsigned int dataLens[5] = { 16, 24, 32, 48, 64 };

	DefineBufLen(hash0, 64);
	DefineBufLen(hash1, 64);
	DefineBufLen(hash2, 64);
	DefineBufLen(hash3, 64);
	DefineBufLen(hash4, 64);
	unsigned char* hashs[] = { hash0, hash1, hash2, hash3, hash4 };
	unsigned int hashLen = 64;
	TA_HASH_ALG algs[] = { TA_SHA224, TA_SHA256, TA_SHA384, TA_SHA512, TA_SM3 };

	for (int i = 0; i < sizeof(algs) / sizeof(TA_HASH_ALG); ++i) {
		TA_HASH_ALG alg = algs[i];
		int rt = Tass_MultiHash(hSess,
			alg, NULL, 0, NULL, 0, NULL, 0,
			dataCnt,
			datas, dataLens,
			hashs, &hashLen);
		if (rt == SDR_OK)
			printf("Tass_MultiHash is success!\n");
		else
		{
			printf("Tass_MultiHash is failed! rt = %d\n", rt);
			return;
		}

		for (int j = 0; j < dataCnt; ++j) {
			char title[16] = { 0 };
			sprintf(title, "hashs[%d]", j);
			printHex(title, hashs[j], hashLen);
		}
	}
}

void T_Tass_RSASign_Verify_SignPublicKeyOperation(void* hSess)
{
	GenRSAOnIndex(RSA_INDEX_1);

	for (int i = 0; i < 2; ++i)
	{
		TA_RSA_PAD pads[] = {
			TA_NOPAD,
			TA_PKCS1_5,
			TA_PSS };
		const char* padNames[] = {
			Str(TA_NOPAD),
			Str(TA_PKCS1_5),
			Str(TA_PSS) };
		for (int j = 0; j < sizeof(pads) / sizeof(TA_RSA_PAD); ++j)
		{
			printf("%s %s\n", i == 0 ? "Internal Key" : "External Key", padNames[j]);

			DefineBufLen(data, 4096 / 8);
			memset(data, 01, dataLen);

			DefineBufLen(sig, 4096 / 8);
			memset(sig, 01, sigLen);

			if (i == 0)
				SDF_GetPrivateKeyAccessRight(hSess, RSA_INDEX_1, (unsigned char*)"a1234567", strlen("a1234567"));

			rt = Tass_RSASign(hSess,
				i == 0 ? RSA_INDEX_1 : 0,
				ParamBufLen(priKey),
				pads[j], TA_SHA512, TA_SHA512, 4,
				data,
				j == TA_NOPAD ? dataLen : 128,
				ParamBufPLen(sig));

			if (i == 0)
				SDF_ReleasePrivateKeyAccessRight(hSess, RSA_INDEX_1);

			CheckFunctionRT(Tass_RSASign, rt);

			if (rt == SDR_OK)
			{
				PrintBufLen(sig);
			}

			rt = Tass_RSAVerify(hSess,
				i == 0 ? RSA_INDEX_1 : 0,
				ParamBufLen(pubKeyN),
				ParamBufLen(pubKeyE),
				pads[j], TA_SHA512, TA_SHA512, 4,
				data,
				j == TA_NOPAD ? dataLen : 128,
				ParamBufLen(sig));

			CheckFunctionRT(Tass_RSAVerify, rt);

			rt = Tass_RSASignPublicKeyOperation(hSess,
				i == 0 ? RSA_INDEX_1 : 0,
				ParamBufLen(pubKeyN),
				ParamBufLen(pubKeyE),
				ParamBufLen(sig),
				ParamBufPLen(data));

			CheckFunctionRT(Tass_RSASignPublicKeyOperation, rt);

			if (rt == SDR_OK)
			{
				PrintBufLen(data);
			}
		}
	}
	Tass_DestroyKey(hSess, TA_RSA, RSA_INDEX_1);
}

void T_Tass_ExchangeDataEnvelopeECC(void* hSess)
{
	GenECCOnIndex(ECC_INDEX_1, TA_SM2);

	DefineBufLen(keyCipherByPubKey, 4096 / 8);
	DefineBufLen(keyCipherByLmk, 128);

	rt = Tass_GenerateSymmKeyWithECC(hSess,
		ECC_INDEX_1,
		TA_SM2,
		NULL, 0, NULL, 0,
		16,
		ParamBufPLen(keyCipherByPubKey),
		ParamBufPLen(keyCipherByLmk));

	CheckFunctionRT(Tass_GenerateSymmKeyWithECC, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(keyCipherByPubKey);
		PrintBufLen(keyCipherByLmk);
	}

	SDF_GetPrivateKeyAccessRight(hSess, ECC_INDEX_1, (unsigned char*)"a1234567", 8);

	rt = Tass_ExchangeDataEnvelopeECC(hSess,
		ECC_INDEX_1,
		TA_SM2,
		ParamBufLen(pubKeyX),
		ParamBufLen(pubKeyY),
		ParamBufLen(keyCipherByPubKey),
		ParamBufPLen(keyCipherByPubKey));

	SDF_ReleasePrivateKeyAccessRight(hSess, ECC_INDEX_1);

	CheckFunctionRT(Tass_ExchangeDataEnvelopeECC, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(keyCipherByPubKey);
	}

	SDF_GetPrivateKeyAccessRight(hSess, ECC_INDEX_1, (unsigned char*)"a1234567", 8);

	rt = Tass_ImportSymmKeyCipherByInternalECC(hSess,
		ECC_INDEX_1,
		ParamBufLen(keyCipherByPubKey),
		ParamBufPLen(keyCipherByLmk));

	SDF_ReleasePrivateKeyAccessRight(hSess, ECC_INDEX_1);


	CheckFunctionRT(Tass_ImportSymmKeyCipherByInternalECC, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(keyCipherByLmk);
	}

	Tass_DestroyKey(hSess, TA_ECC, ECC_INDEX_1);
}

void T_Tass_InternalECCSign_Decrypt_VerifyHash_Encrypt(void* hSess)
{
	GenECCOnIndex(ECC_INDEX_1, TA_SM2);

	DefineBufLen(hash, 32);
	DefineBufLen(sig, 128);

	SDF_GetPrivateKeyAccessRight(hSess, ECC_INDEX_1, (unsigned char*)"a1234567", 8);

	rt = Tass_InternalECCSignHash(hSess,
		TA_SM2,
		ECC_INDEX_1,
		ParamBufLen(hash),
		ParamBufPLen(sig));

	SDF_ReleasePrivateKeyAccessRight(hSess, ECC_INDEX_1);

	CheckFunctionRT(Tass_InternalECCSignHash, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(sig);
	}

	rt = Tass_ECCVerifyHash(hSess,
		TA_SM2,
		ECC_INDEX_1,
		ParamBufLen(pubKeyX),
		ParamBufLen(pubKeyY),
		ParamBufLen(hash),
		ParamBufLen(sig));

	CheckFunctionRT(Tass_ECCVerifyHash, rt);

	rt = Tass_ECCVerifyHash(hSess,
		TA_SM2,
		0,
		ParamBufLen(pubKeyX),
		ParamBufLen(pubKeyY),
		ParamBufLen(hash),
		ParamBufLen(sig));

	CheckFunctionRT(Tass_ECCVerifyHash, rt);

	DefineBufLen(cipher, 512);
	rt = Tass_ECCEncrypt(hSess,
		TA_SM2,
		ECC_INDEX_1,
		ParamBufLen(pubKeyX),
		ParamBufLen(pubKeyY),
		ParamBufLen(hash),
		ParamBufPLen(cipher));

	CheckFunctionRT(Tass_ECCEncrypt, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(cipher);
	}
	SDF_GetPrivateKeyAccessRight(hSess, ECC_INDEX_1, (unsigned char*)"a1234567", 8);

	rt = Tass_InternalECCDecrypt(hSess,
		TA_SM2,
		ECC_INDEX_1,
		ParamBufLen(cipher),
		ParamBufPLen(hash));

	SDF_ReleasePrivateKeyAccessRight(hSess, ECC_INDEX_1);

	CheckFunctionRT(Tass_InternalECCDecrypt, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(hash);
	}

	rt = Tass_ECCEncrypt(hSess,
		TA_SM2,
		0,
		ParamBufLen(pubKeyX),
		ParamBufLen(pubKeyY),
		ParamBufLen(hash),
		ParamBufPLen(cipher));

	CheckFunctionRT(Tass_ECCEncrypt, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(cipher);
	}

	SDF_GetPrivateKeyAccessRight(hSess, ECC_INDEX_1, (unsigned char*)"a1234567", 8);

	rt = Tass_InternalECCDecrypt(hSess,
		TA_SM2,
		ECC_INDEX_1,
		ParamBufLen(cipher),
		ParamBufPLen(hash));

	SDF_ReleasePrivateKeyAccessRight(hSess, ECC_INDEX_1);

	CheckFunctionRT(Tass_InternalECCDecrypt, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(hash);
	}
	Tass_DestroyKey(hSess, TA_ECC, ECC_INDEX_1);
}

void T_Tass_PrivateKeyCipherByLMKOperation(void* hSess)
{
	{//RSA
		GenRSAOnIndex(RSA_INDEX_1);

		DefineBufLen(inData, 512);
		DefineBufLen(outData, 512);

		rt = Tass_PrivateKeyCipherByLMKOperation(hSess,
			TA_RSA, TA_SM2, TA_SIGN,
			ParamBufLen(priKey),
			ParamBufLen(inData),
			ParamBufPLen(outData));


		CheckFunctionRT(Tass_PrivateKeyCipherByLMKOperation, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(outData);
		}

		rt = Tass_RSAVerify(hSess,
			0,
			ParamBufLen(pubKeyN),
			ParamBufLen(pubKeyE),
			TA_NOPAD, TA_NOHASH, TA_NOHASH, 0,
			ParamBufLen(inData),
			ParamBufLen(outData));

		CheckFunctionRT(Tass_RSAVerify, rt);

		Tass_DestroyKey(hSess, TA_RSA, RSA_INDEX_1);
	}
	{//ECC-SM2
		GenECCOnIndex(ECC_INDEX_1, TA_SM2);

		DefineBufLen(inData, 32);
		DefineBufLen(outData, 256);

		rt = Tass_PrivateKeyCipherByLMKOperation(hSess,
			TA_ECC, TA_SM2, TA_SIGN,
			ParamBufLen(priKey),
			ParamBufLen(inData),
			ParamBufPLen(outData));


		CheckFunctionRT(Tass_PrivateKeyCipherByLMKOperation, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(outData);
		}

		rt = Tass_ECCVerifyHash(hSess,
			TA_SM2,
			0,
			ParamBufLen(pubKeyX),
			ParamBufLen(pubKeyY),
			ParamBufLen(inData),
			ParamBufLen(outData));

		CheckFunctionRT(Tass_ECCVerifyHash, rt);

		outDataLen = sizeof(outData);

		rt = Tass_ECCEncrypt(hSess,
			TA_SM2,
			ECC_INDEX_1,
			NULL, 0, NULL, 0,
			ParamBufLen(inData),
			ParamBufPLen(outData));

		CheckFunctionRT(Tass_ECCEncrypt, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(outData);
		}

		rt = Tass_PrivateKeyCipherByLMKOperation(hSess,
			TA_ECC, TA_SM2, TA_CIPHER,
			ParamBufLen(priKey),
			ParamBufLen(outData),
			ParamBufPLen(inData));

		CheckFunctionRT(Tass_PrivateKeyCipherByLMKOperation, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(inData);
		}

		Tass_DestroyKey(hSess, TA_ECC, ECC_INDEX_1);
	}
}

void T_Tass_SymmKeyOperation_CalculateMAC(void* hSess)
{
	GenSymmOnIndex(SYMM_INDEX_1, TA_DES128);

	for (int i = 0; i < 2; ++i)
	{
		TA_SYMM_MODE symmMode[] = { TA_ECB,TA_CBC,	TA_CFB,	TA_OFB, };
		const char* symmModeName[] = { Str(TA_ECB),Str(TA_CBC),Str(TA_CFB),Str(TA_OFB) };
		unsigned char iv[16] = { 0 };

		DefineBufLen(data, 512);

		for (int j = 0; j < sizeof(symmMode) / sizeof(TA_SYMM_MODE); ++j)
		{
			printf("%s Key [%s] Operation\n", 0 == i ? "Internal" : "External", symmModeName[j]);

			TaZero(data, dataLen);
			TaZero(iv, sizeof(iv));

			rt = Tass_SymmKeyOperation(hSess,
				TA_ENC, symmMode[j],
				iv,
				i == 0 ? SYMM_INDEX_1 : 0,
				ParamBufLen(keyCipherByLmk),
				TA_DES128,
				ParamBufLen(data),
				data, iv);

			CheckFunctionRT(Tass_SymmKeyOperation, rt);

			if (rt == SDR_OK)
			{
				PrintBufLen(data);
			}

			TaZero(iv, sizeof(iv));

			rt = Tass_SymmKeyOperation(hSess,
				TA_DEC, symmMode[j],
				iv,
				i == 0 ? SYMM_INDEX_1 : 0,
				ParamBufLen(keyCipherByLmk),
				TA_DES128,
				ParamBufLen(data),
				data, iv);

			CheckFunctionRT(Tass_SymmKeyOperation, rt);

			if (rt == SDR_OK)
			{
				PrintBufLen(data);
			}
		}

		DefineBufLen(mac, 16);

		rt = Tass_CalculateMAC(hSess,
			i == 0 ? TA_ISO9797_1_CBC : TA_ISO9797_3_LRL,
			iv,
			i == 0 ? SYMM_INDEX_1 : 0,
			ParamBufLen(keyCipherByLmk),
			TA_DES128,
			ParamBufLen(data),
			ParamBufPLen(mac));

		CheckFunctionRT(Tass_CalculateMAC, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(mac);
		}
	}
	Tass_DestroyKey(hSess, TA_SYMM, SYMM_INDEX_1);
}

void T_Tass_SymmKeyGCMOperation(void* hSess)
{
	GenSymmOnIndex(SYMM_INDEX_1, TA_SM4);

	for (int i = 0; i < 2; ++i)
	{
		DefineBufLen(inData, 16);
		DefineBufLen(outData, 16);
		DefineBufLen(iv, 16);
		DefineBufLen(tags, 16);

		int rt = Tass_SymmKeyGCMOperation(hSess,
			TA_ENC,
			i == 0 ? SYMM_INDEX_1 : 0,
			TA_FALSE,
			ParamBufLen(keyCipherByLmk),
			TA_SM4,
			ParamBufLen(inData),
			ParamBufLen(iv),
			ParamBufLen(iv),
			ParamBufPLen(tags),
			ParamBufPLen(outData));

		CheckFunctionRT(Tass_SymmKeyGCMOperation, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(outData);
			PrintBufLen(tags);
		}

		rt = Tass_SymmKeyGCMOperation(hSess,
			TA_DEC,
			i == 0 ? SYMM_INDEX_1 : 0,
			TA_FALSE,
			ParamBufLen(keyCipherByLmk),
			TA_SM4,
			ParamBufLen(outData),
			ParamBufLen(iv),
			ParamBufLen(iv),
			ParamBufPLen(tags),
			ParamBufPLen(inData));

		CheckFunctionRT(Tass_SymmKeyGCMOperation, rt);

		if (rt == SDR_OK)
			PrintBufLen(inData);

		for (int j = 0; j < 2; ++j) {//加解密
			DefineBufLen(ctx, 1024);
			rt = Tass_SymmKeyGCMOperationInit(hSess,
				j == 0 ? TA_ENC : TA_DEC,
				i == 0 ? SYMM_INDEX_1 : 0,
				TA_FALSE,
				ParamBufLen(keyCipherByLmk),
				TA_SM4,
				ParamBufLen(iv),
				ParamBufLen(iv),
				ParamBufPLen(ctx));
			CheckFunctionRT(Tass_SymmKeyGCMOperationInit, rt);
			if (rt == SDR_OK)
				PrintBufLen(ctx);

			rt = Tass_SymmKeyGCMOperationUpdate(hSess,
				j == 0 ? TA_ENC : TA_DEC,
				TA_SM4,
				ParamBufLen(inData),
				ParamBufLen(ctx),
				ParamBufPLen(outData),
				ParamBufPLen(ctx));
			CheckFunctionRT(Tass_SymmKeyGCMOperationUpdate, rt);
			if (rt == SDR_OK) {
				PrintBufLen(outData);
				PrintBufLen(ctx);
			}
			rt = Tass_SymmKeyGCMOperationFinal(hSess,
				j == 0 ? TA_ENC : TA_DEC,
				TA_SM4,
				ParamBufLen(ctx),
				ParamBufPLen(tags));
			CheckFunctionRT(Tass_SymmKeyGCMOperationFinal, rt);
			if (rt == SDR_OK) {
				PrintBufLen(tags);
			}
			memcpy(inData, outData, outDataLen);
		}
	}
	Tass_DestroyKey(hSess, TA_SYMM, SYMM_INDEX_1);
}

void T_Tass_SymmKeyCCMOperation_Init_Update_Final(void* hSess)
{
	GenSymmOnIndex(SYMM_INDEX_1, TA_AES128);

	for (int i = 0; i < 2; ++i)
	{
		DefineBufLen(inData, 16);
		DefineBufLen(outData, 16);
		DefineBufLen(nonce, 10);
		DefineBufLen(authData, 16);
		DefineBufLen(tags, 16);

		DefineBufLen(ctx, 512);

		int rt = Tass_SymmKeyCCMOperation(hSess,
			TA_ENC,
			i == 0 ? SYMM_INDEX_1 : 0,
			TA_FALSE,
			ParamBufLen(keyCipherByLmk),
			TA_AES128,
			ParamBufLen(inData),
			ParamBufLen(nonce),
			ParamBufLen(authData),
			ParamBufLen(tags),
			ParamBufPLen(outData));

		CheckFunctionRT(Tass_SymmKeyCCMOperation, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(outData);
			PrintBufLen(tags);
		}

		rt = Tass_SymmKeyCCMOperationInit(hSess,
			TA_DEC,
			i == 0 ? SYMM_INDEX_1 : 0,
			TA_FALSE,
			ParamBufLen(keyCipherByLmk),
			TA_AES128,
			ParamBufLen(nonce),
			ParamBufLen(authData),
			tagsLen,
			inDataLen,
			ParamBufPLen(ctx));

		CheckFunctionRT(Tass_SymmKeyCCMOperationInit, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(ctx);
		}

		rt = Tass_SymmKeyCCMOperationUpdate(hSess,
			TA_DEC,
			ParamBufLen(ctx),
			ParamBufLen(outData),
			ParamBufPLen(ctx),
			ParamBufPLen(inData));

		CheckFunctionRT(Tass_SymmKeyCCMOperationUpdate, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(ctx);
			PrintBufLen(inData);
		}

		rt = Tass_SymmKeyCCMOperationFinal(hSess,
			TA_DEC,
			ParamBufLen(ctx),
			ParamBufPLen(tags));

		CheckFunctionRT(Tass_SymmKeyCCMOperationFinal, rt);

		rt = Tass_SymmKeyCCMOperationInit(hSess,
			TA_ENC,
			i == 0 ? SYMM_INDEX_1 : 0,
			TA_FALSE,
			ParamBufLen(keyCipherByLmk),
			TA_AES128,
			ParamBufLen(nonce),
			ParamBufLen(authData),
			tagsLen,
			inDataLen,
			ParamBufPLen(ctx));

		CheckFunctionRT(Tass_SymmKeyCCMOperationInit, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(ctx);
		}

		rt = Tass_SymmKeyCCMOperationUpdate(hSess,
			TA_ENC,
			ParamBufLen(ctx),
			ParamBufLen(inData),
			ParamBufPLen(ctx),
			ParamBufPLen(outData));

		CheckFunctionRT(Tass_SymmKeyCCMOperationUpdate, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(ctx);
			PrintBufLen(outData);
		}

		rt = Tass_SymmKeyCCMOperationFinal(hSess,
			TA_ENC,
			ParamBufLen(ctx),
			ParamBufPLen(tags));

		CheckFunctionRT(Tass_SymmKeyCCMOperationFinal, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(tags);
		}

		rt = Tass_SymmKeyCCMOperation(hSess,
			TA_DEC,
			i == 0 ? SYMM_INDEX_1 : 0,
			TA_FALSE,
			ParamBufLen(keyCipherByLmk),
			TA_AES128,
			ParamBufLen(outData),
			ParamBufLen(nonce),
			ParamBufLen(authData),
			ParamBufLen(tags),
			ParamBufPLen(inData));

		CheckFunctionRT(Tass_SymmKeyCCMOperation, rt);

		if (rt == SDR_OK)
		{
			PrintBufLen(inData);
		}
	}
	Tass_DestroyKey(hSess, TA_SYMM, SYMM_INDEX_1);
}

void T_Tass_HashInit_Update_Final(void* hSess)
{
	GenECCOnIndex(ECC_INDEX_1, TA_SM2);

	DefineBufLen(ctx, 512);

	rt = Tass_HashInit(hSess,
		TA_SM3,
		ParamBufLen(pubKeyX),
		ParamBufLen(pubKeyY),
		NULL, 0,
		ParamBufPLen(ctx));

	CheckFunctionRT(Tass_HashInit, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(ctx);
	}

	rt = Tass_HashUpdate(hSess,
		ParamBufLen(ctx),
		(unsigned char*)"12345678", 8,
		ParamBufPLen(ctx));

	CheckFunctionRT(Tass_HashUpdate, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(ctx);
	}

	DefineBufLen(hash, 512 / 8);

	rt = Tass_HashFinal(hSess,
		ParamBufLen(ctx),
		ParamBufPLen(hash));

	CheckFunctionRT(Tass_HashFinal, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(hash);
	}

	hashLen = sizeof(hash);

	rt = Tass_HashInit(hSess,
		TA_SM3,
		NULL, 0, NULL, 0,
		NULL, 0,
		ParamBufPLen(ctx));
	CheckFunctionRT(Tass_HashInit, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(ctx);
	}

	rt = Tass_HashUpdate(hSess,
		ParamBufLen(ctx),
		(unsigned char*)"12345678", 8,
		ParamBufPLen(ctx));

	CheckFunctionRT(Tass_HashUpdate, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(ctx);
	}

	rt = Tass_HashFinal(hSess,
		ParamBufLen(ctx),
		ParamBufPLen(hash));

	CheckFunctionRT(Tass_HashFinal, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(hash);
	}
}

void T_Tass_Create_Read_Write_DeleteFile(void* hSess)
{
	int rt = Tass_CreateFile(hSess,
		(unsigned char*)"TestFile", 8,
		1024);

	CheckFunctionRT(Tass_CreateFile, rt);

	DefineBufLen(data, 1024);

	rt = Tass_ReadFile(hSess,
		(unsigned char*)"TestFile", 8,
		0, 1024,
		ParamBufPLen(data));

	CheckFunctionRT(Tass_ReadFile, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(data);
	}

	for (int i = 0; i < sizeof(data); ++i)
		data[i] = (unsigned char)i;

	rt = Tass_WriteFile(hSess,
		(unsigned char*)"TestFile", 8, 0,
		ParamBufLen(data));

	CheckFunctionRT(Tass_WriteFile, rt);

	rt = Tass_ReadFile(hSess,
		(unsigned char*)"TestFile", 8,
		0, 1024,
		ParamBufPLen(data));

	CheckFunctionRT(Tass_ReadFile, rt);

	if (rt == SDR_OK)
	{
		PrintBufLen(data);
	}

	rt = Tass_DeleteFile(hSess,
		(unsigned char*)"TestFile", 8);

	CheckFunctionRT(Tass_DeleteFile, rt);
}


void T_Tass_ProKeyDiversifyOperation(void* hSess)
{
	int rt = 0;
	DefineBufLen(proKey, 256);
	DefineBufLen(proKcv, 16);
	rt = Tass_GenerateSymmKeyWithLMK(hSess,TA_SM4, proKey,&proKeyLen, proKcv,&proKcvLen);
	CheckFunctionRT(Tass_GenerateSymmKeyWithLMK, rt);
	PrintBufLen(proKey);//保护密钥
	PrintBufLen(proKcv);

	DefineBufLen(iv, 16);
	memset(iv, 0x11, ivLen);
	DefineBufLen(sessKeyPlain, 32);
	memset(sessKeyPlain + 16, 0x10, 16);//给明文sessKey做PKCS7填充处理
	DefineBufLen(sessKey, 32);

	rt = Tass_SymmKeyOperation(hSess,TA_ENC,TA_CBC,iv,0,proKey,proKeyLen,TA_SM4, sessKeyPlain, sessKeyPlainLen, sessKey, NULL);
	CheckFunctionRT(Tass_SymmKeyOperation, rt);
	PrintBufLen(sessKey);//保护密钥加密CBC加密的会话密钥密文

	DefineBufLen(sessKeyMac, 16);
	memcpy(sessKeyMac, sessKey + sessKeyLen - 16, 16);//取最后16字节做sessKey的mac
	PrintBufLen(sessKeyMac);

	DefineBufLen(data, 32);
	DefineBufLen(cipher, 256);
	DefineBufLen(plain, 256);
	rt = Tass_ProKeyDiversifyOperation(hSess, 0, TA_SM4, proKey, proKeyLen, proKcv, TA_PAD_PKCS_7, sessKey, sessKeyLen, iv, 
		sessKeyMac, sessKeyMacLen, TA_CBC, iv, ivLen, NULL, 0, NULL, 0,TA_SM4, 0, 0, NULL,0, TA_SM4, TA_ENC, TA_ECB, 
		data, dataLen, TA_PAD_PKCS_7, NULL, 0, NULL, 0, NULL,0,cipher,&cipherLen,NULL,0);
	CheckFunctionRT(Tass_ProKeyDiversifyOperation, rt);
	PrintBufLen(cipher);

	rt = Tass_ProKeyDiversifyOperation(hSess, 0, TA_SM4, proKey, proKeyLen, proKcv, TA_PAD_PKCS_7, sessKey, sessKeyLen, iv,
		sessKeyMac, sessKeyMacLen, TA_CBC, iv, ivLen, NULL, 0, NULL, 0, TA_SM4, 0, 0, NULL,0, TA_SM4, TA_DEC, TA_ECB,
		cipher, cipherLen, TA_PAD_PKCS_7, NULL, 0, NULL, 0, NULL, 0, plain, &plainLen, NULL, 0);
	CheckFunctionRT(Tass_ProKeyDiversifyOperation, rt);
	PrintBufLen(plain);


}

int TassCryptoOperationFunctionsTest(void* hSess)
{
	while (1) {
		int i = 0;
		printf("\n");
		printf("---------------------------Tass Management Functions Test-------------------------\n");
		printf("[%d] T_Tass_ExchangeDataEnvelopeRSA\n", ++i);
		printf("[%d] T_Tass_RSAEncrypt_Decrypt\n", ++i);
		printf("[%d] T_Tass_RSASign_Verify_SignPublicKeyOperation\n", ++i);
		printf("[%d] T_Tass_ExchangeDataEnvelopeECC\n", ++i);
		printf("[%d] T_Tass_InternalECCSign_VerifyHash_Encrypt_InternalECCDecrypt\n", ++i);
		printf("[%d] T_Tass_PrivateKeyCipherByLMKOperation\n", ++i);
		printf("[%d] T_Tass_SymmKeyOperation_CalculateMAC\n", ++i);
		printf("[%d] T_Tass_SymmKeyGCMOperation\n", ++i);
		printf("[%d] T_Tass_SymmKeyCCMOperation_Init_Update_Final\n", ++i);
		printf("[%d] T_Tass_HashInit_Update_Final\n", ++i);
		printf("[%d] T_Tass_Create_Read_Write_DeleteFile\n", ++i);
		printf("[%d] T_Tass_RSASign_Verify_ExternalHash\n", ++i);
		printf("[%d] T_Tass_MultiHash\n", ++i);
		printf("[%d] T_Tass_ProKeyDiversifyOperation\n", ++i);
		printf("[0] Exit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		switch (idx) {
		case 1: T_Tass_ExchangeDataEnvelopeRSA(hSess); break;
		case 2: T_Tass_RSAEncrypt_Decrypt(hSess); break;
		case 3: T_Tass_RSASign_Verify_SignPublicKeyOperation(hSess); break;
		case 4: T_Tass_ExchangeDataEnvelopeECC(hSess); break;
		case 5: T_Tass_InternalECCSign_Decrypt_VerifyHash_Encrypt(hSess); break;
		case 6: T_Tass_PrivateKeyCipherByLMKOperation(hSess); break;
		case 7: T_Tass_SymmKeyOperation_CalculateMAC(hSess); break;
		case 8: T_Tass_SymmKeyGCMOperation(hSess); break;
		case 9: T_Tass_SymmKeyCCMOperation_Init_Update_Final(hSess); break;
		case 10: T_Tass_HashInit_Update_Final(hSess); break;
		case 11: T_Tass_Create_Read_Write_DeleteFile(hSess); break;
		case 12: T_Tass_RSASign_Verify_ExternalHash(hSess); break;
		case 13: T_Tass_MultiHash(hSess); break;
		case 14: T_Tass_ProKeyDiversifyOperation(hSess); break;
		case 0: return 0;
		default: printf("Invalid input\n"); continue;
		}
	}
}

void T_Tass_GenerateRandom(void* hSess)
{
	DefineBufLen(random, 1024);
	int rt = Tass_GenerateRandom(hSess,
		1024,
		random);

	if (rt == SDR_OK)
	{
		PrintBufLen(random);
	}
}

void T_Tass_GetDeviceInfo(void* hSess)
{
	DefineBufLen(issuerName, 64);
	DefineBufLen(deviceName, 64);
	DefineBufLen(deviceSrn, 64);
	unsigned char deviceVersion[4];
	unsigned char standardVersion[4];
	unsigned char asymAlgAbility[8];
	unsigned char symAlgAbility[4];
	unsigned char fileStoreSize[4];
	unsigned char dmkcv[8];

	int rt = Tass_GetDeviceInfo(hSess,
		ParamBufPLen(issuerName),
		ParamBufPLen(deviceName),
		ParamBufPLen(deviceSrn),
		deviceVersion,
		standardVersion,
		asymAlgAbility,
		symAlgAbility,
		fileStoreSize,
		dmkcv);

	if (rt == SDR_OK)
	{
		PrintBufLen(issuerName);
		PrintBufLen(deviceName);
		PrintBufLen(deviceSrn);
		printHex("deviceVersion", deviceVersion, sizeof(deviceVersion));
		printHex("standardVersion", standardVersion, sizeof(standardVersion));
		printHex("asymAlgAbility", asymAlgAbility, sizeof(asymAlgAbility));
		printHex("symAlgAbility", symAlgAbility, sizeof(symAlgAbility));
		printHex("fileStoreSize", fileStoreSize, sizeof(fileStoreSize));
		printHex("dmkcv", dmkcv, sizeof(dmkcv));
	}
}

void T_Tass_Export_ImportCovertKeyBySymmKey(void* hSess)
{
	unsigned char cipherKey[1024] = { 0 };
	unsigned int cipherKeyLen = sizeof(cipherKey);
	unsigned char label[128] = { 0 };
	unsigned int labelLen = sizeof(label);
	unsigned char iv[] = "1122334455667788";

	unsigned int keyAlg = 0;
	int index = 30;
	int coverIndex = 30;

	int rt = Tass_ExportCovertKeyBySymmKey(hSess,
		TA_SM4, TA_CBC,
		iv, index,
		TA_ECC,
		coverIndex, &keyAlg,
		cipherKey, &cipherKeyLen,
		label, &labelLen);
	if (rt == SDR_OK)
		PrintBufLen(cipherKey);
	else
		printf("Tass_ExportCovertKeyBySymmKey is failed! rt = %d\n", rt);

	rt = Tass_ImportCovertKeyBySymmKey(hSess,
		TA_SM4, TA_CBC,
		iv, index,
		TA_ECC, TA_NID_SECP384R1,
		123,
		cipherKey, cipherKeyLen);
	if (rt == SDR_OK)
		printf("Tass_ImportCovertKeyBySymmKey is success!\n");
	else
		printf("Tass_ImportCovertKeyBySymmKey is failed! rt = %d\n", rt);
}

void T_Tass_Export_ImportCovertKeyByAsymmKey(void* hSess)
{
	unsigned int index = 1;
	unsigned int keyAlg = 0;

	unsigned char covertKey[1024] = { 0 };
	unsigned int covertKeyLen = sizeof(covertKey);
	unsigned char label[128] = { 0 };
	unsigned int labelLen = sizeof(label);

	int covertIndex = 30;

	int rt = Tass_ExportCovertKeyByAsymmKey(hSess,
		index, TA_ECC,
		covertIndex, &keyAlg,
		covertKey, &covertKeyLen,
		label, &labelLen);
	if (rt == SDR_OK)
		PrintBufLen(covertKey);
	else
		printf("Tass_ExportCovertKeyByAsymmKey is failed! rt = %d\n", rt);

	rt = Tass_ImportCovertKeyByAsymmKey(hSess,
		index, TA_ECC,
		keyAlg, covertIndex,
		covertKey, covertKeyLen);
	if (rt == SDR_OK)
		printf("Tass_ImportCovertKeyByAsymmKey is success!\n");
	else
		printf("Tass_ImportCovertKeyByAsymmKey is failed! rt = %d\n", rt);
}


void T_Tass_KeyEncryptByLMKToOhter_And_OhterToLMK_Test(void* hSess)
{
	int rt = 0;
	int index = 100;
	int covertKeyIndex = 50;
	unsigned char keyByCovertKey[1024 * 5] = { 0 };
	unsigned int keyByCovertKeyLen = sizeof(keyByCovertKey);
	unsigned char mac[128] = { 0 };
	unsigned int macLen = sizeof(mac);
	unsigned char tags[128] = { 0 };
	unsigned int tagsLen = sizeof(tags);
	unsigned char keyCV[128] = { 0 };
	string iv = "1122334455667788";
	string aad = "1122334455667788";

	string ivBin = String2Bin(iv);
	string addBin = String2Bin(aad);

	unsigned char pubKeyN_X[2048] = { 0 };
	unsigned int pubKeyN_XLen = sizeof(pubKeyN_X);
	unsigned char pubKeyE_Y[2048] = { 0 };
	unsigned int pubKeyE_YLen = sizeof(pubKeyE_Y);
	unsigned char priKeyCipherByLmk[2048] = { 0 };
	unsigned int priKeyCipherByLmkLen = sizeof(priKeyCipherByLmk);

	//产生LMK加密的随机非对称密钥
	//rt = Tass_GenerateAsymmKeyWithLMK(hSess,
	//	TA_ECC, 0, (TA_RSA_E)0,
	//	TA_NID_NISTP256,		// ECC: TA_SM2/TA_NID_NISTP256/TA_NID_SECP256K1
	//	ParamBufPLen(pubKeyN_X),
	//	ParamBufPLen(pubKeyE_Y),
	//	ParamBufPLen(priKeyCipherByLmk));
	if (rt == SDR_OK)
	{
		printf("\nTass_GenerateAsymmKeyWithLMK is success!\n");
		PrintBufLen(pubKeyN_X);
		PrintBufLen(pubKeyE_Y);
		PrintBufLen(priKeyCipherByLmk);
	}
	else
	{
		printf("Tass_GenerateAsymmKeyWithLMK is failed! rt = %d\n", rt);
		return;
	}

	//LMK加密的密钥转其它密钥加密
	//rt = Tass_KeyEncryptByLMKToOhter(hSess,
	//	TA_RSA,		//TA_SYMM / TA_RSA / TA_ECC
	//	TA_SM4,
	//	TA_GCM,
	//	(unsigned char*)ivBin.c_str(),
	//	(unsigned char*)ivBin.c_str(),
	//	ivBin.size(),
	//	(unsigned char*)addBin.c_str(),
	//	addBin.size(),
	//	index,	//index
	//	TA_SIGN,
	//	NULL,
	//	0,
	//	NULL,
	//	0,
	//	NULL,
	//	0,
	//	TA_PAD_PKCS1_5,
	//	TA_SHA224,
	//	TA_SHA224,
	//	NULL,
	//	0,
	//	TA_ECC_KEY_P8,		//被保护密钥为非对称/对称，0、1、2、12、20、21、22 || 0、2、12 || 0、1、2、12
	//	1,				//被保护密钥为内/外部密钥
	//	TA_SIGN,
	//	covertKeyIndex,
	//	TA_NID_SECP256K1,				//ECC时：TA_SM2 / TA_NID_NISTP256 / TA_NID_SECP256K1
	//	priKeyCipherByLmk,
	//	priKeyCipherByLmkLen,
	//	NULL,
	//	keyByCovertKey,
	//	&keyByCovertKeyLen,
	//	mac, &macLen,
	//	tags, &tagsLen,
	//	keyCV);
	if (rt == SDR_OK)
	{
		printf("\nTass_KeyEncryptByLMKToOhter is success!\n");
		printf("保护密钥索引：%d\n", index);
		printf("被保护密钥索引：%d\n", covertKeyIndex);
		PrintBufLen(keyByCovertKey);
		PrintBufLen(tags);
		printf("keyCV = %s\n", Bin2String(keyCV, 8, true).c_str());
	}
	else
	{
		printf("Tass_KeyEncryptByLMKToOhter is failed! rt = %d\n", rt);
		return;
	}

	unsigned char keyCipherByLmk[1024 * 5] = { 0 };
	unsigned int keyCipherByLmkLen = sizeof(keyCipherByLmk);
	unsigned char keyCV1[128] = { 0 };

	string skPlain = "E33A6C5744D3D147E5ABD180891B8AE86BAB348365C5C4B13A372405B543EDF1";
	string skPlainBin = String2Bin(skPlain);

	unsigned char out[64] = { 0 };
	unsigned char sk[32] = { 0 };
	memset(sk, 0x0, 32);
	//memcpy(sk + 32, skPlainBin.data(), skPlainBin.size());
	unsigned char outData[256] = { 0 };
	unsigned char outIv[128] = { 0 };

	rt = Tass_SymmKeyOperation(hSess,
		TA_ENC,
		TA_ECB,
		NULL,
		index,
		NULL, 0,
		TA_AES256,
		sk, 32,
		outData,
		outIv);

	memcpy(out, outData, 32);

	unsigned char outData1[256] = { 0 };
	unsigned char outIv1[128] = { 0 };
	rt = Tass_SymmKeyOperation(hSess,
		TA_ENC,
		TA_ECB,
		NULL,
		index,
		NULL, 0,
		TA_AES256,
		(unsigned char*)skPlainBin.data(), skPlainBin.size(),
		outData1,
		outIv1);

	memcpy(out + 32, outData1, 32);

	string skCipher = "8061AEEF9B94EA659897718E4F1B866DB8EE8A7C6845AE5CE5353D9604954AC6";
	string skBin = String2Bin(skCipher);

	//其它密钥加密转 LMK 加密的密钥
	rt = Tass_KeyEncryptByOhterToLMK(hSess,
		TA_SYMM,		//TA_SYMM / TA_RSA / TA_ECC
		TA_AES256,
		TA_ECB,
		NULL,
		NULL,
		0,
		NULL,
		0,
		NULL,
		0,
		index,
		TA_SIGN,
		NULL,
		0,
		NULL,
		0,
		NULL,
		0,
		TA_NO_PAD,
		TA_SHA224,	//仅当“保护密钥加密填充方式”取值为06（OAEP）时有效
		TA_SHA224,	//仅当“保护密钥加密填充方式”取值为06（OAEP）时有效
		NULL,		//仅当“保护密钥加密填充方式”取值为06（OAEP）时有效
		0,			//仅当“保护密钥加密填充方式”取值为06（OAEP）时有效
		TA_ECC_SPECIAL_KEY,	//被保护密钥为非对称/对称，0、1、2、12、20、21、22 || 0、2、12 || 0、1、2、12
		TA_SM2, // ECC: TA_SM2/TA_NID_NISTP256/TA_NID_SECP256K1, 对称：TA_AES128/TA_AES192/TA_AES256/TA_SM4，
		out,
		64,
		NULL,
		NULL,
		0,
		keyCipherByLmk,
		&keyCipherByLmkLen,
		keyCV1);
	if (rt == SDR_OK)
	{
		printf("\nTass_KeyEncryptByOhterToLMK is success!\n");
		printf("保护密钥索引：%d\n", index);
		PrintBufLen(keyCipherByLmk);
		printf("keyCV1 = %s\n", Bin2String(keyCV1, 8, true).c_str());
	}
	else
	{
		printf("Tass_KeyEncryptByOhterToLMK is failed! rt = %d\n", rt);
		return;
	}

}

void T_Tass_KeyEncryptByLMKToOhter_And_OhterToLMK(void* hSess)
{
	T_Tass_KeyEncryptByLMKToOhter_And_OhterToLMK_Test(hSess);
}

void T_Tass_EciesEncrypt_EciesDecrypt(void* hSess)
{
	unsigned int index = 111;
	unsigned int sharedInfoSeque = 0;

	string iv;
	string iv1 = "1234567812345678";
	string iv2 = "12345678123456781234567812345678";
	string iv8 = String2Bin(iv1);
	string iv16 = String2Bin(iv2);

	string sharedInfoS1 = "789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF";
	string S1 = String2Bin(sharedInfoS1);
	string sharedInfoS2 = "4ED5301E2613A1626B1A197C5C950C898DF4E68F7ABCE16688388AB32ADF8654C13F5A3D308E41A284BF8F5A9C48BEB083098B";
	string S2 = String2Bin(sharedInfoS2);

	int curve[6] = { TA_NID_NISTP256, TA_NID_SECP256K1, TA_NID_SECP384R1, TA_NID_BRAINPOOLP192R1, TA_NID_BRAINPOOLP256R1, TA_NID_FRP256V1 };
	int kdf[3] = { TA_ISO_18033_2_KDF1, TA_ISO_18033_2_KDF2, TA_X9_63KDF };
	int hashAndHmacAlg[4] = { TA_SHA224, TA_SHA256, TA_SHA384, TA_SHA512 };
	int encAlg[9] = { TA_DES128, TA_DES192, TA_AES128, TA_AES192, TA_AES256, TA_SM1, TA_SM4, TA_SSF33, /*TA_SM7,*/ TA_XOR };
	int encMode[5] = { TA_ECB, TA_CBC, TA_CFB, TA_OFB, TA_CTR };
	int pad[6] = { TA_NOFORCE_PAD_80, TA_FORCE_PAD_80, TA_NOFORCE_PAD_00, TA_PAD_PKCS1_5, TA_PAD_PKCS_7, TA_NO_PAD };

	int num = 0;

	for (int i = 0; i < sizeof(curve) / sizeof(int); i++)
	{
		for (int kdfNum = 0; kdfNum < sizeof(kdf) / sizeof(int); kdfNum++)
		{
			for (int j = 0; j < sizeof(hashAndHmacAlg) / sizeof(int); j++)
			{
				for (int n = 0; n < sizeof(encAlg) / sizeof(int); n++)
				{
					for (int modeNum = 0; modeNum < sizeof(encMode) / sizeof(int); modeNum++)
					{
						for (int padNum = 0; padNum < sizeof(pad) / sizeof(int); padNum++)
						{
							if (encAlg[n] == TA_DES128 || encAlg[n] == TA_DES192 || encAlg[n] == TA_SM7)
								iv = iv8;
							else
								iv = iv16;
							unsigned int hmacFlag = 1;
							unsigned char plain[1024] = { 0 };
							unsigned int plainLen = 512;
							memset(plain, 'a', plainLen);

							unsigned char ephemeralPubKeyR[1024] = { 0 };
							unsigned int ephemeralPubKeyRLen = sizeof(ephemeralPubKeyR);
							unsigned char cipher[1024] = { 0 };
							unsigned int cipherLen = sizeof(cipher);
							unsigned char hmac[1024] = { 0 };
							unsigned int hmacLen = sizeof(hmac);
							int privateKeyType = 0;

							int rt = Tass_EciesEncrypt(hSess,
								(TA_ECC_CURVE)curve[i],
								(TA_KDF)kdf[kdfNum],
								(TA_HASH_ALG)hashAndHmacAlg[j],
								(TA_SYMM_ALG)encAlg[n],
								(TA_SYMM_MODE)encMode[modeNum],
								index + i,
								NULL,
								0,
								privateKeyType = 0,
								(unsigned char*)iv.data(),
								iv.size(),
								sharedInfoSeque,
								(unsigned char*)S1.data(),
								S1.size(),
								hmacFlag = 1,
								(TA_HMAC_ALG)hashAndHmacAlg[j],
								(unsigned char*)S2.data(),
								S2.size(),
								(TA_PAD)pad[padNum],
								plain,
								plainLen,
								ephemeralPubKeyR,
								&ephemeralPubKeyRLen,
								cipher,
								&cipherLen,
								hmac,
								&hmacLen);
							if (rt == SDR_OK)
							{
								printf("\nTass_EciesEncrypt is success!\n");
								printf("ECC公钥索引号：%d\n", index + i);
								printf("ephemeralPubKeyRLen = %d, ephemeralPubKeyR: %s\n", ephemeralPubKeyRLen, Bin2String(ephemeralPubKeyR, ephemeralPubKeyRLen, true).data());
								printf("cipherLen = %d, cipher: %s\n", cipherLen, Bin2String(cipher, cipherLen, true).data());
								printf("hmacLen = %d, hmac: %s\n", hmacLen, Bin2String(hmac, hmacLen, true).data());
							}
							else
							{
								printf("Tass_EciesEncrypt is failed! %d | 0x%08x\n", rt, rt);
								return;
							}

							unsigned int publicKeyIndex = 0;
							unsigned int privateKeyIndex = index;
							unsigned int privateKeyFlag = 0;
							unsigned char out[1024] = { 0 };
							unsigned int outLen = sizeof(out);

							rt = Tass_EciesDecrypt(hSess,
								(TA_ECC_CURVE)curve[i],
								(TA_KDF)kdf[kdfNum],
								(TA_HASH_ALG)hashAndHmacAlg[j],
								(TA_SYMM_ALG)encAlg[n],
								(TA_SYMM_MODE)encMode[modeNum],
								publicKeyIndex = 0,
								ephemeralPubKeyR,
								ephemeralPubKeyRLen,
								privateKeyIndex + i,
								privateKeyFlag = 2,
								NULL,
								0,
								(unsigned char*)iv.data(),
								iv.size(),
								sharedInfoSeque,
								(unsigned char*)S1.data(),
								S1.size(),
								hmacFlag = 1,
								(TA_HMAC_ALG)hashAndHmacAlg[j],
								(unsigned char*)S2.data(),
								S2.size(),
								hmac,
								hmacLen,
								(TA_PAD)pad[padNum],
								cipher,
								cipherLen,
								out,
								&outLen);
							if (rt == SDR_OK)
							{
								printf("\nTass_EciesEncrypt is success!\n");
								printf("outLen = %d, out: %s\n", outLen, out);
							}
							else
							{
								printf("Tass_EciesDecrypt is failed! %d | 0x%08x\n", rt, rt);
								return;
							}
							printf("num = %d\n", ++num);
						}
					}
				}
			}
		}
	}
}

void T_Tass_BatchEncrypt_BatchDecrypt(void* hSess)
{
	int rt = 0;
	unsigned int index = 0;
	unsigned char key[256] = { 0 };
	unsigned int keyLen = sizeof(key);
	char iv[32] = "1122334455667788";

	//string keyStr = "1B7A6EE096174F4703B8C397CD9CF159";
	string keyStr = "72C9C6CB8C580E8672C9C6CB8C580E86";
	string binKey = String2Bin(keyStr);

	printf("Tass_BatchEncrypt:\n");

	unsigned int num = 5;
	UserInfo info[1024] = { 0 };
	unsigned char names[64] = "abcd";
	unsigned char phones[64] = "1234567890";
	unsigned char ids[64] = "1122";

	for (int i = 0; i < 4; i++)
	{
		info[i].name = names;
		info[i].nameLen = strlen((char*)names);

		info[i].phone = phones;
		info[i].phoneLen = strlen((char*)phones);

		info[i].id = ids;
		info[i].idLen = strlen((char*)ids);
	}
	info[4].name = names;
	info[4].nameLen = strlen((char*)names);

	info[4].phone = names;
	info[4].phoneLen = strlen((char*)names);

	info[4].id = ids;
	info[4].idLen = strlen((char*)ids);

	unsigned int uiAlgID = SGD_SM4_ECB;
	{
		UserInfo cipherInfo[1024] = { 0 };
		unsigned char name[1024][64] = { 0 };
		unsigned char phone[1024][64] = { 0 };
		unsigned char id[1024][64] = { 0 };
		for (int i = 0; i < num; i++)
		{
			cipherInfo[i].name = name[i];
			cipherInfo[i].nameLen = 128;

			cipherInfo[i].phone = phone[i];
			cipherInfo[i].phoneLen = 128;

			cipherInfo[i].id = id[i];
			cipherInfo[i].idLen = 128;
		}

		rt = Tass_BatchEncrypt(hSess,
			index,
			(unsigned char*)binKey.data(),
			binKey.size(),
			uiAlgID,
			(unsigned char*)iv,
			num,
			info,
			cipherInfo);
		if (rt == 0)
		{
			printf("Tass_BatchEncrypt success\n");
			for (int i = 0; i < num; i++)
			{
				printf("nameLen = %d, name = %s\n", cipherInfo[i].nameLen, cipherInfo[i].name);
				printf("phoneLen = %d, phone: %s\n", cipherInfo[i].phoneLen, cipherInfo[i].phone);
				printf("idLen = %d, id: %s\n\n", cipherInfo[i].idLen, cipherInfo[i].id);
			}
		}
		else
			printf("Tass_BatchEncrypt failed! %d | 0x%08x\n", rt, rt);

		memset(iv, 0, sizeof(iv));
		memcpy(iv, "1122334455667788", sizeof("1122334455667788"));
		UserInfo plainInfo[1024] = { 0 };
		unsigned char name1[1024][64] = { 0 };
		unsigned char phone1[1024][64] = { 0 };
		unsigned char id1[1024][64] = { 0 };
		for (int i = 0; i < num; i++)
		{
			plainInfo[i].name = name1[i];
			plainInfo[i].nameLen = 64;

			plainInfo[i].phone = phone1[i];
			plainInfo[i].phoneLen = 64;

			plainInfo[i].id = id1[i];
			plainInfo[i].idLen = 64;
		}

		cipherInfo[2].phoneLen = 0;
		rt = Tass_BatchDecrypt(hSess,
			index,
			(unsigned char*)binKey.data(),
			binKey.size(),
			uiAlgID,
			(unsigned char*)iv,
			num,
			cipherInfo,
			plainInfo);
		if (rt == 0)
		{
			printf("Tass_BatchDecrypt success\n");
			for (int i = 0; i < num; i++)
			{
				printf("outInfos[%d].nameLen = %d, name = %s\n", i, plainInfo[i].nameLen, plainInfo[i].name);
				printf("outInfos[%d].phoneLen = %d, phone = %s\n", i, plainInfo[i].phoneLen, plainInfo[i].phone);
				printf("outInfos[%d].idLen = %d, id = %s\n", i, plainInfo[i].idLen, plainInfo[i].id);
			}
		}
		else
			printf("Tass_BatchDecrypt failed! %d | 0x%08x\n", rt, rt);
	}
	return;
}

void T_Tass_MultiDataEncrypt_Decrypt(void* hSess)
{
	while (1)
	{
		TassData plainData[4 * 7] = { 0 };
		TassData cipherData[4 * 7] = { 0 };

		//此处演示只有name/phone/id/addr 4个字段的情况，如添加其他字段可参考此处处理
		for (int i = 0; i < sizeof(plainData) / sizeof(TassData);) {
			plainData[i].data = (unsigned char*)calloc(32, sizeof(char));
			plainData[i].dataLen = sprintf((char*)plainData[i].data, (char*)"name_%05d", i);
			//printf("plainData[%d].data: %s\n", i, plainData[i].data);
			++i;

			plainData[i].data = (unsigned char*)calloc(32, sizeof(char));
			plainData[i].dataLen = sprintf((char*)plainData[i].data, (char*)"phone_%05d", i);
			//printf("plainData[%d].data: %s\n", i, plainData[i].data);
			++i;

			plainData[i].data = (unsigned char*)calloc(32, sizeof(char));
			plainData[i].dataLen = sprintf((char*)plainData[i].data, (char*)"id_%05d", i);
			//printf("plainData[%d].data: %s\n", i, plainData[i].data);
			++i;

			plainData[i].data = (unsigned char*)calloc(32, sizeof(char));
			plainData[i].dataLen = sprintf((char*)plainData[i].data, "addr_%05d", i);
			//printf("plainData[%d].data: %s\n", i, plainData[i].data);
			++i;
		}

		for (int i = 0; i < sizeof(cipherData) / sizeof(TassData); ++i) {
			cipherData[i].data = (unsigned char*)calloc(64, sizeof(char));
			cipherData[i].dataLen = 64;
		}

		//string keyStr = "1B7A6EE096174F4703B8C397CD9CF159";
		string keyStr = "72C9C6CB8C580E8672C9C6CB8C580E86";
		string binKey = String2Bin(keyStr);
		int cnt = sizeof(plainData) / sizeof(TassData);
		int rt = Tass_MultiDataEncrypt(hSess,
			1, NULL, 0,
			SGD_SM4_ECB,
			cnt,
			plainData,
			cipherData);
		if (rt == 0)
		{
			printf("Tass_BatchEncrypt success\n");
			for (int i = 0; i < sizeof(plainData) / sizeof(TassData); i++)
			{
				printf("cipherData[%d].dataLen = %d, cipherData[%d].data = %s\n", i, cipherData[i].dataLen, i, cipherData[i].data);
			}
		}
		else
			printf("Tass_BatchEncrypt failed! %d | 0x%08x\n", rt, rt);

		rt = Tass_MultiDataDecrypt(hSess,
			1, NULL, 0,
			SGD_SM4_ECB,
			cnt,
			cipherData,
			plainData);
		if (rt == 0)
		{
			printf("Tass_BatchDecrypt success\n");
			for (int i = 0; i < sizeof(cipherData) / sizeof(TassData); i++)
			{
				printf("plainData[%d].dataLen = %d, plainData[%d].data = %s\n", i, plainData[i].dataLen, i, plainData[i].data);
			}
		}
		else
			printf("Tass_BatchDecrypt failed! %d | 0x%08x\n", rt, rt);

		//释放内存防止内存泄漏
		for (int i = 0; i < sizeof(plainData) / sizeof(TassData); ++i) {
			free(plainData[i].data);
			free(cipherData[i].data);
		}
	}
}

void T_Tass_CalculateHmac(void* hSess)
{
	unsigned int index = 0;
	unsigned int keyType = 2;
	unsigned char data[1024 * 8] = { 0 };
	unsigned int dataLen = 1024 * 8;
	memset(data, 'a', dataLen);

	string sm4Key = "58D9B7B59B276326475EE6A7DA5601E1";
	string key = String2Bin(sm4Key);

	int hmacAlg[4] = { TA_HMAC_SHA224, TA_HMAC_SHA256, TA_HMAC_SHA384, TA_HMAC_SHA512 };

	for (int i = 0; i < 4; i++)
	{
		unsigned char hmac[1024] = { 0 };
		unsigned int hmacLen = sizeof(hmac);

		int rt = Tass_CalculateHmac(hSess,
			(TA_HMAC_ALG)hmacAlg[i],
			index,
			(unsigned char*)key.data(),
			key.size(),
			data, dataLen,
			hmac, &hmacLen);
		if (rt == SDR_OK)
		{
			printf("\nTass_CalculateHmac is success!\n");
			PrintBufLen(hmac);
		}
		else
		{
			printf("Tass_CalculateHmac is failed! %d | 0x%08x\n", rt, rt);
			return;
		}
	}
}

void T_Tass_GetKeyInfo(void* hSess)
{
	int keyType[3] = { TA_SYMM, TA_RSA, TA_ECC };
	for (int i = 0; i < sizeof(keyType) / sizeof(int); i++)
	{
		unsigned int index = 5;
		unsigned int signBits_Curve = 0;
		TA_RSA_E signE;
		unsigned int encBits_Curve = 0;
		TA_RSA_E encE;
		unsigned int priKeyPwdFlag = 0;
		unsigned char label[128] = { 0 };
		unsigned int labelLen = 0;
		unsigned char kcv[8] = { 0 };
		unsigned char updateTime[128] = { 0 };

		int rt = Tass_GetKeyInfo(hSess,
			(TA_KEY_TYPE)keyType[i],
			index,
			&signBits_Curve,
			&signE,
			&encBits_Curve,
			&encE,
			&priKeyPwdFlag,
			label,
			&labelLen,
			kcv,
			updateTime);
		if (rt == 0)
		{
			printf("Tass_GetKeyInfo success.\n");
			printf("signBits_Curve = %d\n", signBits_Curve);
			printf("signE = %d\n", signE);
			printf("encBits_Curve = %d\n", encBits_Curve);
			printf("encE = %d\n", encE);
			printf("labelLen = %d, label: %s\n", labelLen, label);
			printf("kcv: %s\n", Bin2String(kcv, 8, true).data());
			printf("updateTime: %s\n\n", updateTime);
		}
		else
		{
			printf("Tass_GetKeyInfo is failed! %d | 0x%08x\n", rt, rt);
			return;
		}
	}
}

void T_GetPublicKeyByPrivateKey_ECC(void* hSess, unsigned int keyStatus)
{
	int rt = 0;
	ECCrefPublicKey pubKey = { 0 };
	ECCrefPrivateKey priKey = { 0 };
	unsigned char skCipher[64] = { 0 };
	unsigned int skCipherLen = 0;
	unsigned char skPlain[32] = { 0 };
	unsigned int skPlainLen = 0;

	if (keyStatus == 1)
	{
		unsigned int algID = SGD_SM2;
		rt = SDF_GenerateKeyPair_ECC(g_hSess, algID, 256, &pubKey, &priKey);
		if (rt)
		{
			printf("\nSDF_GenerateKeyPair_ECC failed %d | 0x%08x\n", rt, rt);
			return;
		}
		else
		{
			printf("\nSDF_GenerateKeyPair_ECC success\n");
			printf("PubKey.bits: %d\n", pubKey.bits);
			printf("PubKey.x: %s\n", Bin2String(pubKey.x, sizeof(pubKey.x), true).data());
			printf("PubKey.y: %s\n", Bin2String(pubKey.y, sizeof(pubKey.y), true).data());
		}

		memcpy(skPlain, priKey.K + 32, 32);
		skPlainLen = sizeof(skPlain);
	}
	else
	{
		DefineBufLen(pk_X, 4096 / 8);
		DefineBufLen(pk_Y, 4096 / 8);
		DefineBufLen(sk, 4096 / 8 * 6);

		rt = Tass_GenerateAsymmKeyWithLMK(hSess,
			TA_ECC, 0, TA_65537,
			TA_SM2,
			ParamBufPLen(pk_X),
			ParamBufPLen(pk_Y),
			ParamBufPLen(sk));
		if (rt == SDR_OK)
		{
			printf("Tass_GenerateAsymmKeyWithLMK is success!\n");
			PrintBufLen(pk_X);
			PrintBufLen(pk_Y);
			PrintBufLen(sk);
		}
		else
		{
			printf("Tass_GenerateAsymmKeyWithLMK is failed! rt = %d\n", rt);
			return;
		}

		memcpy(skCipher, sk, skLen);
		skCipherLen = skLen;
	}
	unsigned char pubKeyN_X[32] = { 0 };
	unsigned int pubKeyN_XLen = 0;
	unsigned char pubKeyE_Y[32] = { 0 };
	unsigned int pubKeyE_YLen = 0;

	rt = Tass_GetPublicKeyByPrivateKey(hSess,
		TA_ECC,
		TA_SM2,
		keyStatus,
		keyStatus == 1 ? skPlain : skCipher, keyStatus == 1 ? skPlainLen : skCipherLen,
		0,
		pubKeyN_X,
		&pubKeyN_XLen,
		pubKeyE_Y,
		&pubKeyE_YLen);
	if (rt)
	{
		printf("\nTass_GetPrivateKeyByPublicKey failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_GetPrivateKeyByPublicKey success\n");
		printf("pubKeyN_X: %s\n", Bin2String(pubKeyN_X, pubKeyN_XLen, true).data());
		printf("pubKeyE_Y: %s\n", Bin2String(pubKeyE_Y, pubKeyE_YLen, true).data());
	}
	return;
}

void T_GetPublicKeyByPrivateKey_RSA(void* hSess)
{
	DefineBufLen(pk_N, 4096 / 8);
	DefineBufLen(pk_E, 4096 / 8);
	DefineBufLen(sk, 4096 / 8 * 6);

	int rt = Tass_GenerateAsymmKeyWithLMK(hSess,
		TA_RSA, 4096, TA_65537,
		TA_SM2,
		ParamBufPLen(pk_N),
		ParamBufPLen(pk_E),
		ParamBufPLen(sk));
	if (rt == SDR_OK)
	{
		printf("Tass_GenerateAsymmKeyWithLMK is success!\n");
		PrintBufLen(pk_N);
		PrintBufLen(pk_E);
		PrintBufLen(sk);
	}
	else
	{
		printf("Tass_GenerateAsymmKeyWithLMK is failed! rt = %d\n", rt);
		return;
	}

	unsigned int rsaBits = 0;
	rt = Tass_GetPublicKeyByPrivateKey(hSess,
		TA_RSA,
		TA_SM2,
		2,
		sk, skLen,
		&rsaBits,
		pk_N,
		&pk_NLen,
		pk_E,
		&pk_ELen);
	if (rt)
	{
		printf("\nTass_GetPrivateKeyByPublicKey failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_GetPrivateKeyByPublicKey success\n");
		printf("rsaBits = %d\n", rsaBits);
		printf("pubKey_N: %s\n", Bin2String(pk_N, pk_NLen, true).data());
		printf("pubKey_E: %s\n", Bin2String(pk_E, pk_ELen, true).data());
	}
}

void T_Tass_GetPublicKeyByPrivateKey(void* hSess)
{
	//通过ECC私钥明文获取公钥
	T_GetPublicKeyByPrivateKey_ECC(hSess, 1);
	//通过ECC私钥密文获取公钥
	T_GetPublicKeyByPrivateKey_ECC(hSess, 2);
	//通过RSA私钥密文获取公钥
	T_GetPublicKeyByPrivateKey_RSA(hSess);
}

void T_Tass_GetDevVersionInfo(void* hSess)
{
	unsigned char dmkcv[64] = { 0 };
	unsigned char hostVersion[16] = { 0 };
	unsigned char manageVersion[16] = { 0 };
	unsigned char cryptoModuleVersion[16] = { 0 };
	unsigned char devSn[16] = { 0 };
	unsigned int devSnLen = 0;
	unsigned int runMode = 0;

	int rt = Tass_GetDevVersionInfo(hSess,
		dmkcv,
		hostVersion,
		manageVersion,
		cryptoModuleVersion,
		devSn,
		&devSnLen,
		&runMode);
	if (rt)
	{
		printf("\nTass_GetDevVersionInfo failed %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_GetDevVersionInfo success\n");
		printf("dmkcv = %s\n", dmkcv);
		printf("hostVersion: %s\n", hostVersion);
		printf("manageVersion: %s\n", manageVersion);
		printf("cryptoModuleVersion: %s\n", cryptoModuleVersion);
		printf("devSnLen = %d, devSn: %s\n", devSnLen, devSn);
		printf("runMode = %d\n", runMode);
	}
}

void T_Tass_AgreementDataAndKeyWithECC(void* hSess)
{
	unsigned int index = 0;
	string pubKeyX = "D2EDCB60D515577B3045BFE6EAD90E3E6C8EECB392C06A0D4CB7DE6192ECF69B";
	string pubKeyY = "BD7DF1399BBF5E9CAE50DF560A03A2C8850BF58B1DA6D087B71242DFF6AD4E39";
	string pubX = String2Bin(pubKeyX);
	string pubY = String2Bin(pubKeyY);
	unsigned char sessionKey[256] = { 0 };
	unsigned int sessionKeyLen = 0;

	unsigned char ppubX[128] = { 0 };
	unsigned int ppubXLen = 0;
	unsigned char ppubY[128] = { 0 };
	unsigned int ppubYLen = 0;
	unsigned char priKeyD[128] = { 0 };
	unsigned int priKeyDLen = 0;

	int rt = Tass_GeneratePlainECCKeyPair(hSess,
		TA_SM2,
		ppubX, &ppubXLen,
		ppubY, &ppubYLen,
		priKeyD, &priKeyDLen);
	if (rt)
	{
		printf("\nTass_GeneratePlainECCKeyPair %d | 0x%08x\n", rt, rt);
		return;
	}

	rt = Tass_AgreementDataAndKeyWithECC(hSess,
		TA_SM2,
		TA_NO_AGREE,
		index,
		index == 0 ? priKeyD : NULL, index == 0 ? priKeyDLen : 0,
		(unsigned char*)pubX.data(), pubX.size(),
		(unsigned char*)pubY.data(), pubY.size(),
		sessionKey, &sessionKeyLen);
	if (rt)
	{
		printf("\nTass_AgreementDataAndKeyWithECC %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_AgreementDataAndKeyWithECC success\n");
		printf("sessionKeyLen = %d, sessionKey: %s\n", sessionKeyLen, Bin2String(sessionKey, sessionKeyLen, true).data());
	}
}

void T_Tass_DeriveKeyHKDF(void* hSess)
{
	string salt = "0CCDBDCF05884B4565799F37621191D3";
	unsigned int index = 1;
	unsigned int ikmType = 1;
	string ikmStr = "7301A6947220F92449A912A7C4D8D3FD";
	string info = "0000000000000000";
	unsigned int offset = 0;
	string ikm = String2Bin(ikmStr);
	string inT = "00000000000000000000000000000000";
	unsigned int deriveLen = 16;
	unsigned int nextOffset = 0;
	unsigned char outT[64] = { 0 };
	unsigned int outTLen = 0;
	unsigned char deriveKey[64] = { 0 };
	unsigned int deriveKeyLen = 0;

	int rt = Tass_HKDF(hSess,
		TA_HMAC_HASH_SHA224,
		(unsigned char*)salt.data(), salt.size(),
		index, index == 0 ? TA_TRUE : TA_FALSE,
		(unsigned char*)ikm.data(), ikm.size(),
		(unsigned char*)info.data(), info.size(),
		offset,
		(unsigned char*)inT.data(), inT.size(),
		deriveLen,
		&nextOffset,
		outT, &outTLen,
		deriveKey, &deriveKeyLen);
	if (rt)
	{
		printf("\nTass_DeriveKeyHKDF %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_DeriveKeyHKDF success\n");
		printf("nextOffset = %d\n", nextOffset);
		printf("outTLen = %d, outT: %s\n", outTLen, Bin2String(outT, outTLen, true).data());
		printf("deriveKeyLen = %d, deriveKey: %s\n", deriveKeyLen, Bin2String(deriveKey, deriveKeyLen, true).data());
	}
}


void T_Tass_CMACSingle_CMAC_PRKDF_CMAC(void* hSess)
{
	unsigned char cmac[32] = { 0 };
	unsigned int cmacLen = 32;
	int rt = Tass_CMACSingle(hSess,
		TA_SM4,
		0,
		TA_TRUE,
		(unsigned char*)"123456789ABCDEF0", 16,
		(unsigned char*)"12345", 5,
		cmac, &cmacLen);
	if (rt)
	{
		printf("\nTass_CMACSingle %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_CMACSingle success\n");
		printf("cmacLen = %d, cmac: %s\n", cmacLen, Bin2String(cmac, cmacLen, true).data());
	}

	unsigned char ctx[256] = { 0 };
	unsigned int ctxLen = 256;
	rt = Tass_CMAC(hSess,
		TA_DB_FIRST,
		TA_SM4,
		0,
		TA_TRUE,
		(unsigned char*)"123456789ABCDEF0", 16,
		(unsigned char*)"12", 2,
		ctx, &ctxLen,
		NULL, NULL);
	if (rt)
	{
		printf("\nTass_CMAC %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_CMAC success\n");
		printf("ctxLen = %d, ctx: %s\n", ctxLen, Bin2String(ctx, ctxLen, true).data());
	}
	rt = Tass_CMAC(hSess,
		TA_DB_MID,
		TA_SM4,
		0,
		TA_TRUE,
		(unsigned char*)"123456789ABCDEF0", 16,
		(unsigned char*)"3", 1,
		ctx, &ctxLen,
		NULL, NULL);
	if (rt)
	{
		printf("\nTass_CMAC %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_CMAC success\n");
		printf("ctxLen = %d, ctx: %s\n", ctxLen, Bin2String(ctx, ctxLen, true).data());
	}
	rt = Tass_CMAC(hSess,
		TA_DB_LAST,
		TA_SM4,
		0,
		TA_TRUE,
		(unsigned char*)"123456789ABCDEF0", 16,
		(unsigned char*)"45", 2,
		ctx, &ctxLen,
		cmac, &cmacLen);
	if (rt)
	{
		printf("\nTass_CMAC %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_CMAC success\n");
		printf("cmacLen = %d, cmac: %s\n", cmacLen, Bin2String(cmac, cmacLen, true).data());
	}

	string bKey = String2Bin("0705E60B6D4366ED5189A72AEBCDE3EB");
	unsigned char derKey[32] = { 0 };
	unsigned int derKeyLen = 32;
	rt = Tass_PRKDF_CMAC(hSess,
		TA_AES128,
		0,
		TA_TRUE,
		(unsigned char*)bKey.data(), bKey.size(),
		(unsigned char*)"HELLOWORLD", 10,
		(unsigned char*)"TEST", 4,
		derKey, &derKeyLen);
	if (rt)
	{
		printf("\nTass_PRKDF_CMAC %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_PRKDF_CMAC success\n");
		printf("derKeyLen = %d, derKey: %s\n", derKeyLen, Bin2String(derKey, derKeyLen, true).data());
	}
}

void T_Tass_ExportMultiKeys(void* hSess)
{
	string bCipher = String2Bin(
		"AD0CDE5A24E57F159DFB74BA70FAF4BFF5D62ED7BA5222E74043ACF1DB2D29B1"
		"D07DBC615401E0E1D372A122B2BE56A3AB94E78F739708A746EC852008201E45"
		"F125C12A8EFA47375EA4D86B3D3ECFA1D91FDD539571271B69C1669E717DEA4E"
		"64BE54BBC2877AA9AA1FAB638DF735E6");
	unsigned int expIdxs[] = { 1, 2, 3, 4 };
	unsigned int expAlgs[4] = { 0 };
	unsigned char expKeyCipher[256] = { 0 };
	unsigned int expKeyCipherLen = 256;
	int rt = Tass_ExportMultiKeys(hSess,
		(unsigned char*)bCipher.data(), bCipher.size(),
		TA_ECC, TA_SM2,
		1, NULL, 0,
		TA_SYMM,
		4, expIdxs,
		TA_FORCE_PAD_80,
		TA_AES128,
		TA_ECB, NULL, 0,
		expAlgs,
		expKeyCipher, &expKeyCipherLen);
	if (rt)
	{
		printf("\nTass_ExportMultiKeys %d | 0x%08x\n", rt, rt);
		return;
	}
	else
	{
		printf("\nTass_ExportMultiKeys success\n");
		for (unsigned int i = 0; i < sizeof(expIdxs) / sizeof(unsigned int); ++i) {
			printf("expAlgs[%d] = %d | 0x%08X\n", i, expAlgs[i], expAlgs[i]);
		}
		printf("expKeyCipherLen = %d, expKeyCipher: %s\n", expKeyCipherLen, Bin2String(expKeyCipher, expKeyCipherLen, true).data());
	}
}
void T_Tass_ExportAndImportKey(void* hSess)
{
	unsigned char keyCipherByLmk[64] = { 0 };
	unsigned int keyCipherByLmkLen = sizeof(keyCipherByLmk);

	unsigned char kcv[16] = { 0 };
	unsigned int kcvLen = sizeof(kcv);
	unsigned char iv[32] = { 0 };
	unsigned char symmKcv[12] = { 0 };

	unsigned char pubKeyN_X[128] = { 0 };
	unsigned int pubKeyN_XLen = sizeof(pubKeyN_X);
	unsigned char pubKeyE_Y[128] = { 0 };
	unsigned int pubKeyE_YLen = sizeof(pubKeyE_Y);
	unsigned char priCipherKeyByLmk[256] = { 0 };
	unsigned int priCipherKeyByLmkLen = { 0 };
	//生成保护密钥
	int rt = Tass_GenerateAsymmKeyWithLMK(hSess, TA_ECC, 0, TA_3, TA_SM2, pubKeyN_X, &pubKeyN_XLen, pubKeyE_Y, &pubKeyE_YLen, priCipherKeyByLmk, &priCipherKeyByLmkLen);
	unsigned char sm2PubKey[512] = { 0 };
	memcpy(sm2PubKey, pubKeyN_X, pubKeyN_XLen);
	memcpy(sm2PubKey + pubKeyN_XLen, pubKeyE_Y, pubKeyE_YLen);
	unsigned int sm2PubKeyLen = pubKeyN_XLen+ pubKeyE_YLen;
	if (rt)
	{
		printf("Tass_GenerateAsymmKeyWithLMK|Error|\n");
	}
	else
	{
		
		printf("Tass_GenerateAsymmKeyWithLMK|Susses|\n");
		printHex("sm2PubKey", sm2PubKey, sm2PubKeyLen);
		printHex("priCipherKeyByLmk", priCipherKeyByLmk, priCipherKeyByLmkLen);
	}
	//生成目的密钥
	rt = Tass_GenerateSymmKeyWithLMK(hSess, TA_SM4, keyCipherByLmk, &keyCipherByLmkLen, kcv, &kcvLen);
	if (rt)
	{
		printf("Tass_GenerateSymmKeyWithLMK|Error|\n");
	}
	else
	{
		printf("Tass_GenerateSymmKeyWithLMK|Susses|\n");
		printHex("keyCipherByLmk", keyCipherByLmk, keyCipherByLmkLen);
	}
	//LMK转SM2加密
	unsigned char keyCipherBySm2[512] = { 0 };
	unsigned int keyCipherBySm2Len = sizeof(keyCipherBySm2);
		rt = Tass_ExportKey(hSess, TA_ECC, 
		TA_SM2,
		TA_ECB,
		NULL,
		NULL, 0, 
		NULL, 0,
		0,
		TA_CIPHER, 
		sm2PubKey, sm2PubKeyLen,
		 //保护密钥
		NULL, 
		NULL, 0,
		TA_NO_PAD, TA_NOHASH, TA_NOHASH, 
		NULL, 0,
		TA_SYMM_KEY,
		0, TA_CIPHER,
		TA_SM4, 
		keyCipherByLmk, keyCipherByLmkLen,
		//目的密钥
		NULL, keyCipherBySm2,
		& keyCipherBySm2Len,
		NULL,0, NULL, 0, symmKcv);
	if (rt)
	{
		printf("Tass_ExportKey|Error|\n");
	}
	else
	{
		printf("Tass_ExportKey|Susses|\n");
		printHex("keyCipherBySm2", keyCipherBySm2, keyCipherBySm2Len);
	}
	unsigned char sm4CipherByLmk[512] = { 0 };
	unsigned int sm4KeyCipherByLmkLen = sizeof(sm4CipherByLmk);
	//SM2加密转LMK
	rt = Tass_ImportKey(hSess, TA_ECC,
			TA_SM2,
			TA_ECB,
			NULL,
			NULL, 0, 
			NULL, 0,
		    NULL, 0,
			0,
			TA_CIPHER, 
			priCipherKeyByLmk, priCipherKeyByLmkLen,
		//	 //保护密钥
			NULL, 
			NULL, 0,
			TA_NO_PAD, TA_NOHASH, TA_NOHASH, 
			NULL, 0,
			TA_SYMM_KEY,
			TA_SM4,
		keyCipherBySm2, keyCipherBySm2Len, NULL, NULL,0,sm4CipherByLmk,
		&sm4KeyCipherByLmkLen,
		 symmKcv);
	if (rt)
	{
		printf("Tass_ImportKey|Error|\n");
	}
	else
	{
		printf("Tass_ImportKey|Susses|\n");
		printHex("sm4CipherByLmk", sm4CipherByLmk, sm4KeyCipherByLmkLen);
	}
	


}
int TassOtherFunctionsTest(void* hSess)
{
	while (1) {
		int i = 0;
		printf("\n");
		printf("---------------------------Tass Management Functions Test-------------------------\n");
		printf("[%d] T_Tass_GenerateRandom\n", ++i);
		printf("[%d] T_Tass_GetDeviceInfo\n", ++i);
		printf("[%d] T_Tass_Export_ImportCovertKeyBySymmKey\n", ++i);
		printf("[%d] T_Tass_Export_ImportCovertKeyByAsymmKey\n", ++i);
		printf("[%d] T_Tass_KeyEncryptByLMKToOhter_OhterAnd_ToLMK\n", ++i);
		printf("[%d] T_Tass_EciesEncrypt_EciesDecrypt\n", ++i);
		printf("[%d] T_Tass_BatchEncrypt_BatchDecrypt\n", ++i);
		printf("[%d] T_Tass_MultiDataEncrypt_Decrypt\n", ++i);
		printf("[%d] T_Tass_CalculateHmac\n", ++i);
		printf("[%d] T_Tass_GetKeyInfo\n", ++i);
		printf("[%d] T_Tass_GetPrivateKeyByPublicKey\n", ++i);
		printf("[%d] T_Tass_GetDevVersionInfo\n", ++i);
		printf("[%d] T_Tass_AgreementDataAndKeyWithECC\n", ++i);
		printf("[%d] T_Tass_DeriveKeyHKDF\n", ++i);
		printf("[%d] T_Tass_CMACSingle_CMAC_PRKDF_CMAC\n", ++i);
		printf("[%d] T_Tass_ExportMultiKeys\n", ++i);
		printf("[%d] T_Tass_ExportAndImportKey\n", ++i);
		printf("[0] Exit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		switch (idx) {
		case 1: T_Tass_GenerateRandom(hSess); break;
		case 2: T_Tass_GetDeviceInfo(hSess); break;
		case 3: T_Tass_Export_ImportCovertKeyBySymmKey(hSess); break;
		case 4: T_Tass_Export_ImportCovertKeyByAsymmKey(hSess); break;
		case 5: T_Tass_KeyEncryptByLMKToOhter_And_OhterToLMK(hSess); break;
		case 6: T_Tass_EciesEncrypt_EciesDecrypt(hSess); break;
		case 7: T_Tass_BatchEncrypt_BatchDecrypt(hSess); break;
		case 8: T_Tass_MultiDataEncrypt_Decrypt(hSess); break;
		case 9: T_Tass_CalculateHmac(hSess); break;
		case 10: T_Tass_GetKeyInfo(hSess); break;
		case 11: T_Tass_GetPublicKeyByPrivateKey(hSess); break;
		case 12: T_Tass_GetDevVersionInfo(hSess); break;
		case 13: T_Tass_AgreementDataAndKeyWithECC(hSess); break;
		case 14: T_Tass_DeriveKeyHKDF(hSess); break;
		case 15: T_Tass_CMACSingle_CMAC_PRKDF_CMAC(hSess); break;
		case 16: T_Tass_ExportMultiKeys(hSess); break;
		case 17: T_Tass_ExportAndImportKey(hSess); break;
		case 0: return 0;
		default: printf("Invalid input\n"); continue;
		}
	}
}
#define SYSINDEX 1
#define KGCINDEX 2
#define USERINDEXM1 3
#define USERINDEXM2 4
#define USERINDEXM3 5
#define KGCINDEXM2 6
#define USERINDEXMB 7
#define USERINDEXMF 8





void TassHashSingleTest(void* hSess)
{
	unsigned char pubKeyX[2048] = { 0 };
	unsigned int pubKeyXLen = 2048;
	unsigned char pubKeyY[2048] = { 0 };
	unsigned int pubKeyYLen = 2048;
	unsigned char priKeyD[2048] = { 0 };
	unsigned int priKeyDLen = 2048;
	int rt = Tass_GeneratePlainECCKeyPair(hSess, TA_SM2, pubKeyX,&pubKeyXLen, pubKeyY,&pubKeyYLen, priKeyD,&priKeyDLen);
	CHECK_RT(Tass_GeneratePlainECCKeyPair, rt);
	PRINT_BIN(pubKeyX, pubKeyXLen);
	PRINT_BIN(pubKeyY, pubKeyYLen);
	unsigned char id[1] = { 0x01 };
	unsigned int idLen = 1;
	unsigned char data[512] = { 0 };
	unsigned int detaLen = 512;
	unsigned char hash[2048] = { 0 };
	unsigned int hashLen = 2048;
	TA_HASH_ALG hashAlg[7] = {
	(TA_HASH_ALG)1,(TA_HASH_ALG)2,
	TA_SHA224,
	TA_SHA256,
	TA_SHA384,
	TA_SHA512,
	TA_SM3 ,
	//TA_SHA3_224,
	//TA_SHA3_256,
	//TA_SHA3_384,
	//TA_SHA3_512
	};
	for (int i = 0;i < 7;i++)
	{
		printf("hash alg =%d\n", hashAlg[i]);
		if (hashAlg[i] == TA_SM3)
		{
			rt = Tass_HashSingle(hSess, hashAlg[i], pubKeyX, 0, pubKeyY, 0, id, 0, data, detaLen, hash, &hashLen);
			CHECK_RT(Tass_HashSingle, rt);
			PRINT_BIN(hash, hashLen);
		}

		rt = Tass_HashSingle(hSess, hashAlg[i], pubKeyX, pubKeyXLen, pubKeyY, pubKeyYLen, id, idLen, data, detaLen, hash, &hashLen);
		CHECK_RT(Tass_HashSingle, rt);
		PRINT_BIN(hash, hashLen);

	}
	
}

#if 0
int TassHash(void* hSess)
{

	FILE* p_file = fopen("bigdata.txt", "r");

	long lSize;

	string str_native_json("");
	char* szBuf;
	if (p_file)
	{
		fseek(p_file, 0, SEEK_END);
		lSize = ftell(p_file);
		fseek(p_file, 0, SEEK_SET);
		szBuf = new char[lSize + 1]; 
		fread(szBuf, 1, lSize, p_file);
		fclose(p_file);
		szBuf[lSize] = 0;
		str_native_json = szBuf;
		delete szBuf;

	}
	unsigned char ctx[1024] = { 0 };
	unsigned  int ctxLen = 1024;
	int rt = Tass_HashInit(hSess, TA_SHA224,NULL,0,NULL,0,NULL,0, ctx,&ctxLen);
	CHECK_RT(Tass_HashInit, rt);

	unsigned int aaa = lSize / 8192;
	for (int i = 0;i < aaa;i++)
	{
		string bbb = str_native_json.substr(aaa * 0, 8192);
		unsigned char ccc[8192] = { 0 };
		unsigned int cccLen = 8192;
		String2Bin(bbb, ccc, &cccLen);
		int rt = Tass_HashUpdate(hSess, ctx, ctxLen, ccc, cccLen,);
	}
	int rt = Tass_HashUpdate(hSess);
	int rt = Tass_HashFinal(hSess);
}
#endif



void TassGetKeyInfoTest(void* hSess)
{
	unsigned int signBits_Curve = 0;
	TA_RSA_E signE = (TA_RSA_E)0;
	unsigned int encBits_Curve = 0;
	TA_RSA_E encE= (TA_RSA_E)0;
	unsigned int priKeyPwdFlag = 0;
	unsigned char label[1024] = { 0 };
	unsigned int labelLen = 0;
	unsigned char kcv[8] = { 0 };
	unsigned char updateTime[1024] = {0};
	int rt = Tass_GetKeyInfo(hSess, TA_SYMM,1,&signBits_Curve,&signE,&encBits_Curve,&encE ,&priKeyPwdFlag, label,&labelLen,
		kcv, updateTime);
	
	CHECK_RT(Tass_GetKeyInfo, rt);
	PRINT_NUM(signBits_Curve);
	PRINT_NUM(signE);
	PRINT_NUM(encBits_Curve);
	PRINT_NUM(encE);
	PRINT_NUM(priKeyPwdFlag);

	PRINT_STR(label, labelLen);
	PRINT_BIN(kcv, 8);
	PRINT_STR(updateTime, 19);

}
void TassBigFileEncryptDecryptTest(void* hSess)
{
	unsigned char iv[16] = { 0 };
	unsigned int ivLen = 16;
	int rt;
	//while (1)
	{
		rt = Tass_BigFileEncryptDecrypt(hSess, TA_ENC, TA_CBC, TA_AES128, iv, ivLen, 1, NULL, 0, 16, 100, 4096, 20, "in2.txt", "out2.txt");
		if (rt)
		{
			printf("\nEncrypt error\n");
		}
		else
		{
			printf("\nEncrypt success\n");
		}
		rt = Tass_BigFileEncryptDecrypt(hSess, TA_DEC, TA_CBC, TA_AES128, iv, ivLen, 1, NULL, 0, 16, 100, 4096, 20, "out2.txt", "out_in2.txt");
		if (rt)
		{
			printf("\nDecrypt error\n");
		}
		else
		{
			printf("\nDecrypt success\n");
		}
	}
	


}

void TassKeySynchronousTest(void* hSess)
{
	DefineBufLen(sm4key, 256);
	DefineBufLen(kcv, 8);
	int rt = Tass_GenerateSymmKeyWithLMK(hSess, TA_SM4, sm4key, &sm4keyLen, kcv, &kcvLen);
	//CHECK_FUN_RT(Tass_GenerateSymmKeyWithLMK, rt);



	TassCommAllMessage* message = NULL;
	Tass_CommAllMessageNew(&message);

	rt = Tass_ImportKeyCipherByLMKSynchronous(hSess, 999, TA_SYMM, TA_SM2, TA_SM4, TA_SIGN, NULL, 0, NULL, 0, sm4key, sm4keyLen, kcv, 1,
		message);
	printf("rt = %d\n ", rt);
	if (rt)
	{
		printf("[Tass_ImportKeyCipherByLMKForAll] failed %#08x\n", rt);
		PRINT_NUM(message->hostCnt);
		for (int i = 0;i < message->hostCnt;i++) {
			PRINT_STR(message->hostMessage[i].ip,1);
			PRINT_NUM(message->hostMessage[i].code);
		}

	}
	else
	{
		printf("[Tass_ImportKeyCipherByLMKForAll] success \n");
		PRINT_NUM(message->hostCnt);
		for (int i = 0;i < message->hostCnt;i++) {

			PRINT_STR(message->hostMessage[i].ip,1);
			PRINT_NUM(message->hostMessage[i].code);
		}
	}
	Tass_CommAllMessageFree(message);
	unsigned int test = 0;
	printf("destroy key? yes-1 no-2 \n ");
	scanf("%d", &test);
	if (test == 1)
	{
		TassCommAllMessage* message2 = NULL;
		Tass_CommAllMessageNew(&message2);

		rt = Tass_DestroyKeySynchronous(hSess, TA_SYMM, 999, message2);
		printf("rt = %d\n ", rt);
		if (rt)
		{
			printf("[Tass_DestroyKeySynchronous] failed %#08x\n", rt);
			PRINT_NUM(message2->hostCnt);
			for (int i = 0;i < message2->hostCnt;i++) {
				PRINT_STR(message2->hostMessage[i].ip,1);
				PRINT_NUM(message2->hostMessage[i].code);
			}

		}
		else
		{
			printf("[Tass_DestroyKeySynchronous] success \n");
			PRINT_NUM(message2->hostCnt);
			for (int i = 0;i < message2->hostCnt;i++) {

				PRINT_STR(message2->hostMessage[i].ip,1);
				PRINT_NUM(message2->hostMessage[i].code);
			}
		}
		Tass_CommAllMessageFree(message2);
	}
}

#include <fstream>
int TassFileTest(void* hSess)
{
	std::ifstream inputFile("1.pdf", std::ios::binary);
	std::ofstream outputFile("2.pdf", std::ios::binary);
	unsigned char plainText[1024] = { 0 };
	unsigned int plainTextLen = sizeof(plainText);
	unsigned char cipherText[1024+16] = { 0 };
	unsigned int cipherTextLen = sizeof(cipherText)-16;
	int count = 0,i = 0;
	bool flag = false;
	int rt = 0;

	streampos fileSize = inputFile.tellg();
	if (fileSize % 1024 == 0) {
		count = fileSize / 1024;
		flag = true;
	}
	while (inputFile.read(reinterpret_cast<char*>(plainText), plainTextLen)) {
		i++;
		if (i == count - 1)
		{
			string padData = pkcs5_pad(string((char*)plainText, plainTextLen));
			rt = Tass_SymmKeyOperation(hSess,
				TA_ENC, TA_ECB,
				NULL,
				1,
				NULL, 0,
				TA_SM4,
				CC_TO_UC(padData.data()), padData.length(),
				cipherText, NULL);
			if (rt) {
				printf("Tass_ SymmKeyOperation failed at [%d|%08x]", rt, rt);
				return -1;
			}
			outputFile.write(reinterpret_cast<char*>(cipherText), padData.length());
		}
		else
		{
			rt = Tass_SymmKeyOperation(hSess,
				TA_ENC, TA_ECB,
				NULL,
				1,
				NULL, 0,
				TA_SM4,
				ParamBufLen(plainText),
				cipherText, NULL);
			if (rt) {
				printf("Tass_ SymmKeyOperation failed at [%d|%08x]", rt, rt);
				return -1;
			}
			outputFile.write(reinterpret_cast<char*>(cipherText), plainTextLen);
		}
	}
	if (inputFile.gcount() > 0)
	{//填充
		unsigned char tmp[1024] = { 0 };
		int tmpLen = inputFile.gcount();
		memcpy(tmp, plainText, tmpLen);
		string lastData = pkcs5_pad(string((char*)tmp, tmpLen));

		rt = Tass_SymmKeyOperation(hSess,
			TA_ENC, TA_ECB,
			NULL,
			1,
			NULL, 0,
			TA_SM4,
			CC_TO_UC(lastData.data()), lastData.length(),
			cipherText, NULL);
		if (rt)
			printf("Tass_ SymmKeyOperation failed at [%d|%08x]", rt, rt);
		outputFile.write(reinterpret_cast<char*>(cipherText), lastData.length());
	}

	inputFile.close();
	outputFile.close();
	std::ifstream encFile("2.pdf", std::ios::binary);
	std::ofstream decFile("3.pdf", std::ios::binary);
	memset(plainText, 0x00, 1024);
	memset(cipherText, 0x00, 1024+16);
	cipherTextLen = 1024;
	plainTextLen = 1024;
	while (encFile.read(reinterpret_cast<char*>(cipherText), cipherTextLen)) {
		rt = Tass_SymmKeyOperation(hSess,
			TA_DEC, TA_ECB,
			NULL,
			1,
			NULL, 0,
			TA_SM4,
			ParamBufLen(cipherText),
			plainText, NULL);
		if (rt)
			printf("Tass_ SymmKeyOperation failed at [%d|%08x]", rt, rt);
		decFile.write(reinterpret_cast<char*>(plainText), cipherTextLen);
	}
	if (encFile.gcount() > 0)
	{//去填充
		if (!flag)
		{
			int lastLen = encFile.gcount();
			rt = Tass_SymmKeyOperation(hSess,
				TA_DEC, TA_ECB,
				NULL,
				1,
				NULL, 0,
				TA_SM4,
				cipherText, lastLen,
				plainText, NULL);
			if (rt)
				printf("Tass_ SymmKeyOperation failed at [%d|%08x]", rt, rt);
			string lastData = pkcs5_unpad(string((char*)plainText, lastLen));
			decFile.write(reinterpret_cast<char*>(plainText), lastLen);
		}
	}
	encFile.close();
	decFile.close();
}

int  TassOtherFunctionsTest2(void* hSess)
{
	while (1) {
		int i = 0;
		printf("\n");
		printf("---------------------------Tass Management Functions Test-------------------------\n");
		printf("[%d] TassHashSingleTest\n", ++i);
		printf("[%d] TassGetKeyInfoTest\n", ++i);
		printf("[%d] TassBigFileEncryptDecryptTest\n", ++i);
		printf("[%d] TassKeySynchronousTest\n", ++i);
		printf("[0] Exit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		//idx = 1;
		switch (idx) {
		case 1: TassHashSingleTest(g_hSess);break;
		case 2: TassGetKeyInfoTest(g_hSess);break;
		case 3: TassBigFileEncryptDecryptTest(g_hSess);break;
		case 4: TassKeySynchronousTest(g_hSess);break;

		case 0:return 0;

		default: printf("Invalid input\n"); continue;
		}
	}
}
void TassCertReq(void* hSess)
{
	int rt = 0;


	DefineBufLen(x,256);
	DefineBufLen(y, 256);
	DefineBufLen(pri, 256);


	rt = Tass_GenerateAsymmKeyWithLMK(hSess,TA_ECC,0,TA_3,TA_SM2,x,&xLen,y,&yLen,pri,&priLen);
	CheckFunctionRT(Tass_GenerateAsymmKeyWithLMK,rt);
	printHex("x",x, xLen);
	printHex("y",y, yLen);
	printHex("pri",pri, priLen);

	unsigned char dn[] = "CN=N,O=U";
	unsigned int dnLen = sizeof(dn);
	DefineBufLen(cert, 2048);
	rt = Tass_GenerateSignRootCert(hSess,TA_ECC,0,TA_SIGN,TA_SM2,pri,priLen,0,dn,dnLen,TA_SHA1,3650,TA_PEM,cert,&certLen);
	CheckFunctionRT(Tass_GenerateSignRootCert, rt);
	printf("cert:%s\n\n", cert);

	DefineBufLen(reqCert, 2048);
	rt = Tass_GenerateCertReq(g_hSess, TA_ECC, 0, TA_EXKEY, TA_SM2, pri, priLen,0, dn, dnLen, TA_SHA1, TA_PEM, reqCert, &reqCertLen);
	CheckFunctionRT(Tass_GenerateCertReq, rt);
	printf("reqCert:%s\n\n", reqCert);
	
	unsigned char dn2[] = "CN=N,O=XZ";
	unsigned int dn2Len = sizeof(dn2);
	DefineBufLen(cert2, 2048);
	DefineBufLen(pubDer, 2048);
	memcpy(pubDer, "\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08\x2A\x81\x1C\xCF\x55\x01\x82\x2D\x03\x42\x00\x04", 27);
	memcpy(pubDer+27, x, 32);
	memcpy(pubDer + 27+32, y, 32);
	pubDerLen = 27 + 32 + 32;
	rt = Tass_IssueSubordinateCert(g_hSess, TA_ECC, 0, TA_EXKEY, TA_SM2, pri, priLen, 0, dn, dnLen,
		1, TA_PEM, reqCert, reqCertLen, TA_ECC, 0, TA_EXKEY, TA_SM2, pubDer, pubDerLen, 0, dn2, dn2Len,
		TA_SHA1, 3650, TA_PEM, cert2, &cert2Len);
	CheckFunctionRT(Tass_IssueSubordinateCert, rt);
	printf("cert2:%s\n\n", cert2);

	memset(cert, 0, sizeof(cert));
	char nsComment[] = "nsComment";
	unsigned int nsCommentLen = strlen(nsComment);
	char basicConstraints[] = "CA:FALSE";
	unsigned int basicConstraintsLen = strlen(basicConstraints);

	rt = Tass_GenerateSignRootCert_V2(hSess, TA_ECC, 0, TA_SIGN, TA_SM2, pri, priLen, 0, dn, dnLen, TA_SHA1, 3650, TA_PEM,
		3,(unsigned char*)nsComment, nsCommentLen, (unsigned char*)basicConstraints, basicConstraintsLen,cert, &certLen);
	CheckFunctionRT(Tass_GenerateSignRootCert, rt);
	printf("cert:%s\n\n", cert);

	memset(cert2, 0, sizeof(cert2));
	rt = Tass_IssueSubordinateCert_V2(g_hSess, TA_ECC, 0, TA_EXKEY, TA_SM2, pri, priLen, 0, dn, dnLen,
		1, TA_PEM, reqCert, reqCertLen, TA_ECC, 0, TA_EXKEY, TA_SM2, pubDer, pubDerLen, 0, dn2, dn2Len,
		TA_SHA1, 3650, TA_PEM, 
		3, (unsigned char*)nsComment, nsCommentLen, (unsigned char*)basicConstraints, basicConstraintsLen,cert2, &cert2Len);
	CheckFunctionRT(Tass_IssueSubordinateCert, rt);
	printf("cert2:%s\n\n", cert2);




	return;
}
int TassManagementFunctionsTest(int argc, char* argv[])
{
	int rt = SDF_OpenDevice(&g_hDev);
	if (rt) {
		printf("SDF_OpenDevice failed %#08x\n", rt);
		getchar();
		return -1;
	}
	rt = SDF_OpenSession(g_hDev, &g_hSess);
	if (rt) {
		printf("SDF_OpenSession failed %#08x\n", rt);
		SDF_CloseDevice(g_hDev);
		getchar();
		return -1;
	}

	while (1) {
		int i = 0;
		printf("\n");
		printf("---------------------------Tass Functions Test-------------------------\n");
		printf("[%d] TassManagementFunctionsTest\n", ++i);
		printf("[%d] TassCryptoOperationFunctionsTest\n", ++i);
		printf("[%d] TassOtherFunctionsTest\n", ++i);
		printf("[%d] TassOtherFunctionsTest2\n", ++i);
		printf("[%d] TassFileTest\n", ++i);
		printf("[%d] TassCertReq\n", ++i);
		printf("[0] Exit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		switch (idx) {
		case 1: TassManagementFunctionsTest(g_hSess); break;
		case 2: TassCryptoOperationFunctionsTest(g_hSess); break;
		case 3: TassOtherFunctionsTest(g_hSess); break;
		case 4: TassOtherFunctionsTest2(g_hSess);
		case 5: TassFileTest(g_hSess);
		case 6: TassCertReq(g_hSess);
		case 0:
			SDF_CloseSession(g_hSess);
			SDF_CloseDevice(g_hDev);
			return 0;
		default: printf("Invalid input\n"); break;
		}
	}
	return 0;
}

#if defined(_WIN16) || defined(_WIN32) || defined(_WIN64)
#include <winsock.h> 
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <arpa/inet.h>
#endif

#include<iostream>
#include<string>

#define IS_ONE(number, n) ((number >> n)& (0x1))
#define BigtoLittle16(A)  ((((uint8_t)(A) & 0xff00) >> 8) |(((uint8_t)(A) & 0x00ff) << 8))

//int strHex2Dec(char* sHex, int iHexLen, char* sDec, int iDecLen)
//{
//	char sSrc[65];
//	char sForamt[6];
//	unsigned long ulSrc;
//	memset(sSrc, 0, sizeof(sSrc));
//	memcpy(sSrc, sHex, iHexLen);
//	strupr(sSrc);
//	*(sSrc + 0) < 'A' ? ulSrc = *(sSrc + 0) - 0x30 : ulSrc = *(sSrc + 0) - 0x41 + 0x0A;
//	for (int i = 1; i < iHexLen; i++)
//		* (sSrc + i) < 'A' ? ulSrc = ulSrc * 16 + *(sSrc + i) - 0x30 : ulSrc = ulSrc * 16 + *(sSrc + i) - 0x41 + 0x0A;
//	sprintf(sForamt, "%%0%du", iDecLen);
//	snprintf(sDec, iDecLen, sForamt, ulSrc);
//	return ulSrc;
//}

int Test()
{
	int rt = SDF_OpenDevice(&g_hDev);
	if (rt) {
		printf("SDF_OpenDevice failed %#08x\n", rt);
		getchar();
		return -1;
	}
	rt = SDF_OpenSession(g_hDev, &g_hSess);
	if (rt) {
		printf("SDF_OpenSession failed %#08x\n", rt);
		SDF_CloseDevice(g_hDev);
		getchar();
		return -1;
	}
	while (1)
	{
		unsigned char key[32] = { 0 };
		unsigned int keyLen = 32;
		memset(key, 1, 32);

		void* hKeyHdl = NULL;


		//rt = SDF_GetSymmKeyHandle();
#if 0
		void* hKeyHdl = NULL;
		void* hKeyHdl1 = NULL;
		unsigned char iv[] = "1122334455667788";
		unsigned char dataPlain[BUF * 10 + 1] = { 0 };
		unsigned int dataPlainLen = sizeof(dataPlain) - 1;
		unsigned char dataEnc[BUF * 10 + 1] = { 0 };
		unsigned int dataEncLen = sizeof(dataEnc);
		unsigned char encKey[BUF] = { 0 };
		unsigned int encKeyLen = sizeof(encKey);
		unsigned char dataOut[BUF * 10 + 1] = { 0 };
		unsigned int dataOutLen = sizeof(dataOut);

		rt = SDF_GenerateKeyWithKEK(g_hSess, 128, SGD_SM4_ECB, g_keySymIndex, encKey, &encKeyLen, &hKeyHdl);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithKEK failed %d | 0x%08x\n", rt, rt);
			return rt;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithKEK success\n");
			printf("encKey: %s\n", Bin2String(encKey, encKeyLen, true).data());
		}

		rt = SDF_ImportKeyWithKEK(g_hSess, SGD_SM4_ECB, g_keySymIndex, encKey, encKeyLen, &hKeyHdl1);
		if (rt)
		{
			printf("\nSDF_ImportKeyWithKEK failed %d | 0x%08x\n", rt, rt);
			return rt;
		}
		else
			printf("\nSDF_ImportKeyWithKEK success\n");

		//对称加密
		rt = SDF_Encrypt(g_hSess, hKeyHdl1, SGD_SM4_ECB, iv, dataPlain, dataPlainLen, dataEnc, &dataEncLen);
		if (rt)
		{
			printf("\nSDF_Encrypt failed %d | 0x%08x\n", rt, rt);
			return rt;
		}
		else
		{
			printf("\nSDF_Encrypt success\n");
			//printf("encData: %s\n", Bin2String(dataEnc, dataEncLen, true).data());
		}
		SDF_DestroyKey(g_hSess, hKeyHdl);
		hKeyHdl = NULL;

		SDF_DestroyKey(g_hSess, hKeyHdl1);
		hKeyHdl1 = NULL;

		memset(encKey, 0, sizeof(encKey));
		encKeyLen = sizeof(encKey);

		rt = SDF_GenerateKeyWithKEK(g_hSess, 128, SGD_SM4_ECB, g_keySymIndex, encKey, &encKeyLen, &hKeyHdl);
		if (rt)
		{
			printf("\nSDF_GenerateKeyWithKEK failed %d | 0x%08x\n", rt, rt);
			return rt;
		}
		else
		{
			printf("\nSDF_GenerateKeyWithKEK success\n");
			printf("encKey: %s\n", Bin2String(encKey, encKeyLen, true).data());
		}

		rt = SDF_ImportKeyWithKEK(g_hSess, SGD_SM4_ECB, g_keySymIndex, encKey, encKeyLen, &hKeyHdl1);
		if (rt)
		{
			printf("\nSDF_ImportKeyWithKEK failed %d | 0x%08x\n", rt, rt);
			return rt;
		}
		else
			printf("\nSDF_ImportKeyWithKEK success\n");

		memcpy(iv, "1122334455667788", sizeof("1122334455667788"));

		//对称解密
		rt = SDF_Decrypt(g_hSess, hKeyHdl1, SGD_SM4_ECB, iv, dataEnc, dataEncLen, dataOut, &dataOutLen);
		if (rt)
		{
			printf("\nSDF_Decrypt failed %d | 0x%08x\n", rt, rt);
			return rt;
		}
		else
		{
			printf("\nSDF_Decrypt success\n");
			//printf("dataOut: %s\n", Bin2String(dataOut, dataOutLen, true).data());
			//printf("dataPlain: %s\n", Bin2String(dataOut, dataOutLen, true).data());
			//printf("dataOut: %s\n", dataOut);
			//printf("dataPlain: %s\n", dataPlain);
		}
		SDF_DestroyKey(g_hSess, hKeyHdl);
		hKeyHdl = NULL;

		SDF_DestroyKey(g_hSess, hKeyHdl1);
		hKeyHdl1 = NULL;

		SDF_CloseSession(g_hSess);
#endif
	}
	SDF_CloseSession(g_hSess);
	SDF_CloseDevice(g_hDev);
	return 0;
}


int TassFormatTlsPassword(TassTLSHostInfo* info,
	char pwd[128 + 1],
	unsigned char pwdSm2Cipher[32 + 32 + 32 + 128],
	unsigned int* pwdSm2CipherLen)
{
	if (info->host.protocol == 4)
	{
		if (!strcmp(info->host.pfxPath, "./sm2.ClientByWenHuan.sig.pfx")){
			memcpy(pwd, "12345678", 8);
		}
		else {
			memcpy(pwd, "12345678", 8);
		}
		
	}
	else
	{
		return -1;
	}
	return 0;
}

int TassTLsPwdCallBackTest(int argc, char* argv[])
{
	Tass_SetCbTlsPassword(TassFormatTlsPassword);
	int rt = SDF_OpenDevice(&g_hDev);
	if (rt) {
		printf("SDF_OpenDevice failed %#08x\n", rt);
		getchar();
		return -1;
	}
	else{
		printf("SDF_OpenDevice success \n");
	}
	rt = SDF_OpenSession(g_hDev, &g_hSess);
	if (rt) {
		printf("SDF_OpenSession failed %#08x\n", rt);
		SDF_CloseDevice(g_hDev);
		getchar();
		return -1;
	}
	else {
		printf("SDF_OpenSession success \n");
	}
}



int main(int argc, char* argv[])
{
	
	while (1)
	{

		printf("\n");
		printf("---------------------------GHSM/GVSM Functions Test-------------------------\n");
		printf("[1] SDF Functions Test\n");
		printf("[2] Tass Functions Test\n");
		printf("[3] Tass TlsPwdCallBack Test\n");
		printf("[0] Exit\n");
		printf("Test Command Num: ");
		int idx;
		cin >> idx;
		//idx = 2;
		switch (idx) {
		case 1: SDFFunctionsTest(argc, argv); break;
		case 2: TassManagementFunctionsTest(argc, argv); break;
		case 3: TassTLsPwdCallBackTest(argc, argv); break;
		case 0: return 0;
		default: printf("Invalid input\n"); break;
		}
	}
	return 0;
}
