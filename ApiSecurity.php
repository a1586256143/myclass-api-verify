<?php

/**
 * Api安全类
 * @author Colin <xiongxinsheng@yikaosheng.com>
 * @date 2021-04-19 下午2:18
 */
class ApiSecurity{
	public $appKey = '';
	// 错误代码
	public $error = [
		-1 => '签名错误' ,
		-2 => '无效的请求' ,
		-3 => '无效的请求'
	];
	/**
	 * 配置
	 * @var array[]
	 */
	public $config = [
		'redis' => [
			'host' => '' ,
			'port' => 6379 ,
			'timeout' => 60 ,
			'select' => 6 ,
			'pass' => '' ,
		] ,
	];
	/**
	 * @var Redis $redis
	 */
	public $redis = '';
	/**
	 * 重放攻击防御 默认开启
	 * @var bool
	 */
	public $replay = true;

	public function __construct($config = []) {
		if ($config){
			$this->config = array_replace_recursive($this->config , $config);
		}
	}

	/**
	 * 获取Redis
	 * @author Colin <xiongxinsheng@yikaosheng.com>
	 * @date 2021-04-19 下午2:29
	 */
	protected function getRedis(){
		if (!$this->redis){
			$redis = new Redis();
			$redisConfig = $this->config['redis'];
			$redis->pconnect($redisConfig['host'] , $redisConfig['port'] , $redisConfig['timeout']);
			if ($redisConfig['pass']){
				$redis->auth($redis['pass']);
			}
			$redis->select($redisConfig['select']);
			$this->redis = $redis;
		}
		return $this->redis;
	}

	/**
	 * 获取签名
	 * @param array $params
	 * @author Colin <xiongxinsheng@yikaosheng.com>
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

	/**
	 * 验证是否有效
	 * @param array $params
	 * @return bool
	 * @author Colin <xiongxinsheng@yikaosheng.com>
	 * @date 2021-04-19 下午12:04
	 */
	public function verify($params = []){
		$sign = $this->getSign($params);
		return $sign == $params['sign'];
	}

	/**
	 * 是否为有效的请求
	 * @return bool|int
	 * @author Colin <xiongxinsheng@yikaosheng.com>
	 * @date 2021-04-19 下午12:09
	 */
	public function isValid(){
		$params = $_GET ? $_GET : $_POST;
		$sign = $this->verify($params);
		if (!$sign){
			return -1; // sign错误
		}

		// 1分钟后这个请求就过期了
		if (($params['time'] + 60) < time()){
			return -2; // 请求的时间已经过期了
		}
		if ($this->replay){
			$this->getRedis();
			// 防止重放攻击
			$nonce = $params['nonce'];
			$key = 'request_replay_attack';
			// 支持1分钟内1500次请求 60 * 1500 = 90000
			if ($this->redis->hLen($key) > 90000){
				$this->redis->del($key);
			}
			if ($this->redis->hExists($key , $nonce)){
				return -3; // 该请求已经处理了
			}
			$this->redis->hSet($key , $nonce , 1);
		}
		return true;
	}

	/**
	 * 获取错误码
	 * @param $code
	 * @return string
	 * @author Colin <xiongxinsheng@yikaosheng.com>
	 * @date 2021-04-19 下午12:11
	 */
	public function getError($code){
		return isset($this->error[$code]) ? $this->error[$code] : '';
	}
}