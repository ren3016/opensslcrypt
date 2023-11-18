<?php

/**
 * ---------------------------------
 * Author: dream <ren3016@qq.com>
 * wechat: ren3016
 * createtime: 2023-05-10
 * ---------------------------------
 * OpenSslCrypt： 以openssl_encrypt加密解密数据
 * ---------------------------------
 * 可用于涉密数据存储写传输（如存储帐号密码等敏感数据时使用）
 * 类指定的$key秘钥字符串需要保密，无秘钥用户不能解密成原始数据
 * 同一字符，每次生成的秘钥不同
 * 使用方式：加密：$cry = new OpenSslCrypt();   $aaa = $cry->enc('中国');
 * 解密：$cry = new OpenSslCrypt();   $aaa = $cry->dec('B6_NRUXw_lrElQub4e842rYBxHJDtrEp4Jm6-q0IGIWXZ1WfCu20U46cWKtEvNtT80yOyZiomK-RANp5eV2N2g');
 */

namespace Ren3016\Opensslcrypt;

class OpenSslCrypt
{
    // 类属性 使用 private 修饰
    private $cipher_mode = 'AES-256-CBC'; // 密码方式，AES-128-CBC时长度为16，为AES-256-CBC长度为32
    private $key = 'dream_3016_secret_key'; // 秘钥字符串，加密和解密必须使用相同秘钥，否则不能解密
    private $options = OPENSSL_RAW_DATA; // OPENSSL_RAW_DATA 只是告诉openssl_encrypt()将cipherText作为原始数据返回.默认情况下,它返回Base64编码.

    /**
     * 加密
     * 类方法 使用 public 修饰
     * enc 对传入字符串或数组进行openssl_encrypt加密
     * @param string $text_str 要加密的字符串
     * @return string|false 加密成功返回字符串，失败返回false
     */
    public function enc($text_str)
    {
        // 在openssl_get_cipher_methods()密码方式列表数组中，查找指定的密码方式$this->cipher_mode是否有效，为避免大小写错误，都转为小写。
        if (in_array(strtolower($this->cipher_mode), array_map('strtolower', openssl_get_cipher_methods()))) {
            // openssl_cipher_iv_length获取密码iv长度(16位)，$cipher_mode为AES-128-CBC时长度为16，为AES-256-CBC长度为32
            $ivlen = openssl_cipher_iv_length($this->cipher_mode);
            // openssl_random_pseudo_bytes生成一个伪随机字节串（生成$ivlen长度字节串）
            $iv = openssl_random_pseudo_bytes($ivlen);
            // 如果传入的是数组，先转为json字符串再加密
            if (is_array($text_str) || is_object($text_str)) {
                $text_str = json_encode($text_str);
            }
            // openssl_encrypt加密数据，如果$options=OPENSSL_RAW_DATA返回原始数据（看上去是乱码），$options=0返回Base64编码
            $cipher_text_raw = openssl_encrypt($text_str, $this->cipher_mode, $this->key, $this->options, $iv);
            // 使用HMAC方法生成带有密钥的哈希值， $raw_output为true输出原始二进制数据(32位长度)，为false输出小写16进制字符串(64位长度)。
            $rnd_secret = hash_hmac('sha256', $cipher_text_raw, $this->key, $raw_output = true);
            // 将 1.随机字节串，2.带有密钥的哈希值原始二进制数据，3.加密的原始数据。进行base64编码
            $cipher_text = $this->b64Encode($iv . $rnd_secret . $cipher_text_raw);
            return $cipher_text;
        } else {
            return false; // 密码方式 不在规定的方式中
        }
    }

    /**
     * 解密
     * 类方法 使用 public 修饰
     * dec 解密由enc生成的秘钥
     * @param string $secret_str 经过enc加密的字符串。
     * @param int $chk_expt_dmf 默认为0，并且返回是数组：就验证过期时间及域名，其它不验证
     * @return string|false 解密成功返回原字符串，失败返回false
     */
    public function dec($b64_str, $chk_expt_dmf = 0)
    {
        $chk_expt_dmf = intval($chk_expt_dmf);
        // base64解码后得到：1.随机字节串，2.带有密钥的哈希值原始二进制数据，3.加密的原始数据 三种连接的原始数据
        $secret_str = $this->b64Decode($b64_str);
        // openssl_cipher_iv_length获取密码iv长度(16位)，$cipher_mode为AES-128-CBC时长度为16，为AES-256-CBC长度为32
        $ivlen = openssl_cipher_iv_length($this->cipher_mode);
        // 从原始数据 0 至 $ivlen位 获取：秘钥字节串
        $iv = substr($secret_str, 0, $ivlen);
        // 从原始数据 $ivlen 至 $sha2len位获取：带有密钥的哈希值，加密时hash_hmac($raw_output=true)时$sha2len长度为32，$raw_output=false时$sha2len长度为64
        $old_secret = substr($secret_str, $ivlen, $sha2len = 32);
        // 从原始数据 $ivlen + $sha2len 至 结尾获取：原始加密数据
        $cipher_text_raw = substr($secret_str, $ivlen + $sha2len);
        // 将获取到的原始加密数据$cipher_text_raw，使用HMAC方法生成带有密钥的哈希值
        $new_secret = hash_hmac('sha256', $cipher_text_raw, $this->key, $raw_output = true);
        // 将加密时:带有密钥的哈希值 和 解密后:带有密钥的哈希值进行比较，如果一致，就输出原始文字。hash_equals可防止时序攻击的字符串比较
        if (hash_equals($old_secret, $new_secret)) //PHP 5.6+ timing attack safe comparison
        {
            // 原始加密数据进行解密
            $original_plaintext = @openssl_decrypt($cipher_text_raw, $this->cipher_mode, $this->key, $this->options, $iv);
            // 解密成功，存在字符串 或 Json字符串，就显示解密成功的数据
            if ($original_plaintext) {
                // 看下数据能不能转为数组，如果可以就是数组，如果不行，原始数据就是字符串
                $arr_text = json_decode($original_plaintext, JSON_OBJECT_AS_ARRAY);
                // 如果解密后的数组存在，检查是否过期，域名是否相同
                if ($arr_text) {
                    // 如果chk_expt_dmf=0就要验证过期时间及域名，否则不验证
                    if ($chk_expt_dmf == 0) {
                        // 如果是数组，验证过期时间
                        if (isset($arr_text['expt']) && $arr_text['expt'] < time()) {
                            return false;
                        }
                        // 如果是数组，验证来源和当前域名是否相同
                        if (isset($arr_text['dmf']) && $arr_text['dmf'] != $_SERVER["SERVER_NAME"]) {
                            return false;
                        }
                    }
                    
                    // 数据没有问题，可以显示原始数组
                    $original_plaintext = $arr_text;
                }
                // 返回原始数组 或 原始字符串
                return $original_plaintext;
            } else {
                return false;  // openssl_decrypt解密失败
            }
        } else {
            return false; // 新旧哈希值对比不一致
        }
    }

    /**
     * b64Encode()将数据进行base64编码
     * @param string $input 要编码的数据
     * @return string 编码后的字符串
     */
    private function b64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * b64Decode()将base64编码的数据解码
     * @param string $input 要解码的字符串
     * @return string 解码后的原始数据
     */
    private function b64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

}

