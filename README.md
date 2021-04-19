# 介绍
该项目对Api接口实现安全处理

### 请求参数
```text
nonce       随机字符串
time        请求时间戳
sign        请求参数按字母升序后的md5
```
### 签名
这里以PHP的代码为例
```php
/**
 * 获取签名
 * @param array $params
 * @author Colin
 * @date 2021-04-19 上午11:56
 * @return string
 */
public function getSign($params = []){
    if (isset($params['sign'])){
        unset($params['sign']);
    }
    ksort($params);
    $string = '';
    foreach ($params as $key => $val){
        $string .= $key . '=' . $val . '&';
    }
    $string = substr($string , 0 , -1);
    $string .= $this->appKey;
    return md5($string);
}
```
### 使用
```php
$sign = new ApiSecurity([
	'redis' => [
		'host' => '192.168.0.254' ,
	]
]);
// 设置appKey
$sign->appKey = '607d00d50544a';
$res = $sign->isValid();
var_dump($res);
```
默认开启重放攻击防御
### 关闭重放防御
```php
$sign->replay = false;
```
