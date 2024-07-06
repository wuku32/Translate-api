"""
-*- coding: utf-8 -*-
@File   : .py
@author : @鲨鱼爱兜兜
@Time   : 2024/06/25 22:23
"""

import time
import json
import base64
import hashlib
import pprint
import string

import requests
import execjs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pandas as pd
from pandas import DataFrame

headers = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded',
    "Cookie": "",
    'Origin': '',
    'Pragma': 'no-cache',
    'Referer': '',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}


def baidu(query: str, f: str = 'en', to: str = 'zh') -> str:
    """

    :param query: query
    :param f: 源语言，可以为`auto`，更多选项参见官方文档`https://ai.baidu.com/ai-doc/MT/4kqryjku9#语种列表`
    :param to: 译文语言，默认翻译为中文`zh`
    :return: str
    """
    with open('baidu.js', 'r', encoding='utf-8') as f1:
        js_code = f1.read()
    params = {
        "from": f,
        "to": to,
        "query": query,
        "simple_means_flag": "3",
        "sign": execjs.compile(js_code).call('T', query),
        "token": "618e4f37cd15de2718962c27a17da2a4",
        "domain": "common",
        "ts": int(time.time() * 1000)  # 单位从`s`精确到`ms`
    }
    headers['Origin'] = 'https://fanyi.baidu.com'
    headers['Referer'] = 'https://fanyi.baidu.com/mtpe-individual/multimodal'
    headers[
        "Cookie"] = "BIDUPSID=529D72F795F09560A9A5CC1A17AE73A7; PSTM=1681276039; BAIDUID=529D72F795F09560D97567446104438A:FG=1; APPGUIDE_10_0_2=1; REALTIME_TRANS_SWITCH=1; FANYI_WORD_SWITCH=1; HISTORY_SWITCH=1; SOUND_SPD_SWITCH=1; SOUND_PREFER_SWITCH=1; H_WISE_SIDS=219946_219561_216852_213349_214806_219942_213028_230174_204917_110085_236308_243706_243873_244726_240590_245412_247148_250889_249892_253427_254294_254473_254734_254689_239150_253212_250882_255938_255981_253685_107315_254075_256083_253990_255660_255476_254076_256500_254831_256739_251971_256229_254317_256589_256996_257080_257290_256096_251059_251133_254299_257482_244253_257543_257656_257663_255177_257936_257167_257903_257823_257586_257403_255231_257790_257791_253900_258235_258257_257995_258344_258511_258373_258372_227146_256859_258724_258728_258305_258938_257303_255910_258982_258958_230288_259034_259047_259050_257016_252256_259186_259190_259193_256223_259200_259413_259285_259316_259430_259517_259569_259606_256998_259558_259409_259645_251786; H_WISE_SIDS_BFESS=219946_219561_216852_213349_214806_219942_213028_230174_204917_110085_236308_243706_243873_244726_240590_245412_247148_250889_249892_253427_254294_254473_254734_254689_239150_253212_250882_255938_255981_253685_107315_254075_256083_253990_255660_255476_254076_256500_254831_256739_251971_256229_254317_256589_256996_257080_257290_256096_251059_251133_254299_257482_244253_257543_257656_257663_255177_257936_257167_257903_257823_257586_257403_255231_257790_257791_253900_258235_258257_257995_258344_258511_258373_258372_227146_256859_258724_258728_258305_258938_257303_255910_258982_258958_230288_259034_259047_259050_257016_252256_259186_259190_259193_256223_259200_259413_259285_259316_259430_259517_259569_259606_256998_259558_259409_259645_251786; BDUSS=h6eG1qcGMyNG9FTkJuVGgwVHVPTXIwWEV-VVdIRW9qODhDM3NSMjhnUkhoY2RrRVFBQUFBJCQAAAAAAQAAAAEAAAAp5g1rRG91RG91QUlTSEFZVQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEf4n2RH-J9kUH; BDUSS_BFESS=h6eG1qcGMyNG9FTkJuVGgwVHVPTXIwWEV-VVdIRW9qODhDM3NSMjhnUkhoY2RrRVFBQUFBJCQAAAAAAQAAAAEAAAAp5g1rRG91RG91QUlTSEFZVQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEf4n2RH-J9kUH; BAIDUID_BFESS=529D72F795F09560D97567446104438A:FG=1; BA_HECTOR=2gah21a4258181ah21010g2m1ib2i9t1o; ZFY=:Bm5JPjPwyZ:A6lDbsF8UsRm1GTqHmNyMKbKywqthif:Bk:C; RT=\"z=1&dm=baidu.com&si=lh9ofaq79e8&ss=lk2ljtmb&sl=0&tt=0&bcn=https%3A%2F%2Ffclog.baidu.com%2Flog%2Fweirwood%3Ftype%3Dperf&ld=2av&ul=2b9cj&hd=2b9cz\"; BDRCVFR[bPTzwF-RsLY]=mk3SLVN4HKm; PSINO=1; delPer=0; Hm_lvt_64ecd82404c51e03dc91cb9e8c025574=1688543894,1688709758,1689345794,1689391036; Hm_lpvt_64ecd82404c51e03dc91cb9e8c025574=1689391036; H_PS_PSSID=36550_38643_38831_39027_39023_38959_38954_39009_38961_38820_38990_39086_38636_26350_39092_39052_39100_38951; BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; ab_sr=1.0.1_ODY4MzdjODliZjBmYjk3MDM0MGE1YTYyODEzZmNiNTFhNDVjNGVlY2Q2YjdhMzdjYmFmYmQ0NjM0NzY3NDk5ZWYzYjJhNjQ3MWY1MjZkOGE3NWQ5ODU4MDUwNDY0ZmE5MTM5NzEyZWUxMTU3MGVkNThlZDE5Mjc0MmI4NTBlZTcxZTNmM2Q2ZWFhZjYyN2ZhMGU2YTU4MDMxN2Q1MWFiYjhlYzQ5NmU5YjJkZWNlNjcwNTk5NGZiMzM0ZWZlZmMy"

    response = requests.post(url="https://fanyi.baidu.com/v2transapi", headers=headers, params=params)
    response.encoding = 'utf-8'

    headers.pop('Origin')
    headers.pop('Referer')
    headers.pop('Cookie')

    # print(response.json())
    return response.json()['trans_result']['data'][0]['dst']


def youdao(query: str, f: str = 'en', to: str = 'zh-CHS') -> str:
    def _decrypt(decrypt_str):
        key = "ydsecret://query/key/B*RGygVywfNBwpmBaZg*WT7SIOUP2T0C9WHMZN39j^DAdaZhAnxvGcCY6VYFwnHl"
        iv = "ydsecret://query/iv/C@lZe2YzHtZ2CYgaXKSVfsb7Y4QWHjITPPZ0nQp87fBeJ!Iv6v^6fvi2WN@bYpJ4"
        key_md5 = hashlib.md5(key.encode('utf-8')).digest()
        iv_md5 = hashlib.md5(iv.encode('utf-8')).digest()
        aes = AES.new(key=key_md5, mode=AES.MODE_CBC, iv=iv_md5)
        code = aes.decrypt(base64.urlsafe_b64decode(decrypt_str))
        return unpad(code, AES.block_size).decode('utf8')

    time_id = int(time.time() * 1000)
    e = f"client=fanyideskweb&mysticTime={time_id}&product=webfanyi&key=fsdsogkndfokasodnaso"
    sign = hashlib.md5(e.encode()).hexdigest()
    cookies = {
        'OUTFOX_SEARCH_USER_ID': '700918787@10.110.96.153',
        'OUTFOX_SEARCH_USER_ID_NCOO': '192754076.3130601',
    }

    data = {
        'i': query,
        'from': f,
        'to': to,
        'dictResult': 'true',
        'keyid': 'webfanyi',
        'sign': sign,
        'client': 'fanyideskweb',
        'product': 'webfanyi',
        'appVersion': '1.0.0',
        'vendor': 'web',
        'pointParam': 'client,mysticTime,product',
        'mysticTime': time_id,
        'keyfrom': 'fanyi.web',
        'mid': '1',
        'screen': '1',
        'model': '1',
        'network': 'wifi',
        'abtest': '0',
        'yduuid': 'abcdefg',
    }

    headers['Origin'] = 'https://fanyi.youdao.com'
    headers['Referer'] = 'https://fanyi.youdao.com'

    response = requests.post('https://dict.youdao.com/webtranslate', cookies=cookies, headers=headers, data=data)
    response.encoding = 'utf-8'

    headers.pop('Origin')
    headers.pop('Referer')

    decrypt = _decrypt(response.text)
    # print(json.loads(decrypt))
    return json.loads(decrypt)['translateResult'][0][0]['tgt']


def aiciba(query: str, f: str = 'en', to: str = 'zh') -> str:
    data = {
        'from': f,
        'to': to,
        'q': query
    }
    s = hashlib.md5(f"6key_web_new_fanyi6dVjYLFyzfkFkk{query}".encode()).hexdigest()[:16].encode()
    encode_key = "L4fBtD5fLC9FQw22".encode()
    decode_key = "aahc3TfyfCEmER33".encode()
    cipher1 = AES.new(encode_key, AES.MODE_ECB)
    padded_data1 = pad(s, AES.block_size)
    encrypted = cipher1.encrypt(padded_data1)
    sign = base64.b64encode(encrypted).decode('utf-8')
    params = {
        'c': 'trans',
        'm': 'fy',
        'client': '6',
        'auth_user': 'key_web_new_fanyi',
        'sign': sign
    }

    headers['origin'] = 'https://www.iciba.com'
    headers['referer'] = 'https://www.iciba.com/'

    response = requests.post('https://ifanyi.iciba.com/index.php', params=params, headers=headers, data=data)
    response.encoding = 'utf-8'

    headers.pop('origin')
    headers.pop('referer')

    cipher2 = AES.new(decode_key, AES.MODE_ECB)
    decrypt = unpad(cipher2.decrypt(base64.b64decode(response.json()['content'])), AES.block_size).decode('utf-8')
    # print(json.loads(decrypt))
    return json.loads(decrypt)['out']


def __360(query: str) -> str:
    """

    :param query: 查询词
    :return:
    """
    cookies = {
        'QiHooGUID': 'CD711E29AF0DDB2AE2AC5174A21A78CB.1700807377894',
        '__guid': '15484592.2679069343796695600.1709564733332.9546',
        'so_huid': '11lieFZAMo62jQiVEFxiNyAWxL87vX%2FIKfjJyM05M%2BElg%3D',
        '__huid': '11lieFZAMo62jQiVEFxiNyAWxL87vX%2FIKfjJyM05M%2BElg%3D',
        'Q_UDID': 'e5653a0c-9642-8871-17d6-0097687f5429',
        'count': '1',
    }

    params = {
        'eng': '1',
        'validate': '',
        'ignore_trans': '0',
        'query': query,
    }

    headers['origin'] = 'https://fanyi.so.com'
    headers['referer'] = 'https://fanyi.so.com/'
    headers['priority'] = 'u=1, i'
    headers['pro'] = 'fanyi'

    response = requests.post('https://fanyi.so.com/index/search', params=params, cookies=cookies, headers=headers)
    response.encoding = 'utf-8'

    headers.pop('origin')
    headers.pop('referer')
    headers.pop('priority')
    headers.pop('pro')

    # print(response.json())
    return response.json()['data']['fanyi']


def youdao_f() -> DataFrame:
    response = requests.get('https://api-overmind.youdao.com/openapi/get/luna/dict/luna-front/prod/langType')

    f_dict = response.json()['data']['value']['textTranslate']
    # pprint.pprint(f_dict)

    # 提取第二层字典的键值对
    items = f_dict['common']
    items.extend(f_dict['specify'])
    # pprint.pprint(items)

    df: DataFrame = pd.DataFrame(items)
    # df.drop_duplicates(inplace=True)
    # print(df)
    return df


def aiciba_f() -> DataFrame:
    ts = int(time.time() * 1000)
    text = f'/index.phptransgetLanguageAAA4270{ts}enc5cecewwheuasfdfc9ef88996fd0d80'.encode('utf-8')
    # 创建md5 hash对象
    md5_hash = hashlib.md5()
    # 更新hash对象，使用utf-8编码的字符串
    md5_hash.update(text)
    # 获取16进制格式的散列值
    md5_digest = md5_hash.hexdigest()
    # print(md5_digest)

    params = {
        'auth_user': "",
        'c': "trans",
        'm': "getLanguage",
        'nonce': "",
        'q': "0",
        'str': "",
        'style': "",
        'timestamp': "",
        'type': "en",
        'signature': md5_digest
    }

    response = requests.get('https://ifanyi.iciba.com/index.php', params=params, headers=headers)

    f_dict = response.json()
    # pprint.pprint(f_dict)

    # 提取第二层字典的键值对
    items = []
    for key in ['common'] + list(string.ascii_uppercase):
        if key in list('IOUV'):
            continue
        for sub_key, value in f_dict[key].items():
            items.append((value, sub_key))

    df: DataFrame = pd.DataFrame(items, columns=['语言', '字母'])
    # df.drop_duplicates(inplace=True)
    # print(df)
    return df


if __name__ == '__main__':
    youdao_f()
