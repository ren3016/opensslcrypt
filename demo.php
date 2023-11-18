<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

include "vendor/autoload.php"; // composer自动加载
// include_once "src/Opensslcrypt.php";  // 直接引用文件

use Ren3016\Opensslcrypt\OpenSslCrypt;

// 实例化类，创建 $crypt 对象
$crypt = new OpenSslCrypt();

// 使用类方法 enc 进行 字符串或数组 加密
$crypt_str = $crypt->enc("Hello World!");
echo "Hello World! 加密后是：" . $crypt_str . "<br><br>\n\n";

// 使用类方法 dec 把加密字符串 解密为 字符串或数组
echo "再解密后是：" . $crypt->dec($crypt_str);


?>