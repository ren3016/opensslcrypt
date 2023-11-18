# opensslcrypt 以openssl_encrypt加密解密数据

## 一、加载方式：

### 1.1 composer 自动加载

include "vendor/autoload.php";

use ren3016\OpenSSLCrypt\OpenSSLCrypt;

### 1.2 引入文件

include_ones "src/opensslcrypt.php"

use ren3016\OpensslCrypt\OpenSSLCrypt;

## 二、实例化类，创建 $crypt 对象

$crypt = new OpenSSLCrypt();

### 2.1 加密

加密字符串或数组，使用类方式 enc

$crypt_str = $crypt->enc("Hello World!");

echo"Hello World! 加密后是： " . $crypt_str . "`<br><br>`\n\n";

### 2.2 解密

把加密字符串 解密为 字符串或数组，使用类方法 dec

echo" 再解密后是： " . $crypt->dec($crypt_str);
