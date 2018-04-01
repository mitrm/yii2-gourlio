<?php

namespace mitrm\gourlio;

use Yii;
use yii\base\Component;
use yii\base\BaseObject;

class Cryptobox extends BaseObject
{

    public $all_key = [];

    public $cryptobox_version = '2.0';

    public $coinName = ''; // Bitcoin


    public $coinLabel;

    public $webdev_key;
    public $box_id;
    public $amount;
    public $amountUSD = 0;
    public $order_id;
    public $user_id;
    public $language = 'ru';
    public $period;
    public $private_key;
    public $public_key;
    private $userFormat = 'COOKIE'; // Не используется
    private $iframe_id = 'my_iframe'; // Не используется

    public function load($options)
    {
        $cryptobox_private_keys = $this->getCryptoboxPrivateKeys();
        $this->coinName = mb_strtolower($options['coinName']);
        $this->public_key = $this->all_key[$this->coinName]['public_key'];
        $this->private_key = $this->all_key[$this->coinName]['private_key'];

        if (!function_exists('mb_stripos') || !function_exists('mb_strripos')) {
            throw new \BadFunctionCallException('Error. Please enable MBSTRING extension in PHP.');
        }

        foreach ($options as $key => $value) {
            if (in_array($key, array('public_key', 'private_key', 'webdev_key', 'amount', 'period', 'language', 'iframe_id', 'order_id', 'user_id', 'userFormat'))) {
                $this->$key = (is_string($value)) ? trim($value) : $value;
            }
        }


        $this->box_id = $this->left($this->public_key, 'AA');

        if (preg_replace('/[^A-Za-z0-9]/', '', $this->public_key) != $this->public_key || strlen($this->public_key) != 50 || !strpos($this->public_key, 'AA') || !$this->box_id || !is_numeric($this->box_id) || strpos($this->public_key, '77') === false || !strpos($this->public_key, 'PUB')) {
            throw new \BadFunctionCallException('Invalid Cryptocoin Payment Box PUBLIC KEY - ' . ($this->public_key ? $this->public_key : 'cannot be empty'));
        }

        if (preg_replace('/[^A-Za-z0-9]/', '', $this->private_key) != $this->private_key || strlen($this->private_key) != 50 || !strpos($this->private_key, 'AA') || $this->box_id != $this->left($this->private_key, 'AA') || !strpos($this->private_key, 'PRV') || $this->left($this->private_key, 'PRV') != $this->left($this->public_key, 'PUB')) {
            throw new \BadFunctionCallException('Invalid Cryptocoin Payment Box PRIVATE KEY' . ($this->private_key ? '' : ' - cannot be empty'));
        }

        if (!in_array($this->private_key, explode('^', $cryptobox_private_keys))) {
            throw new \BadFunctionCallException('Error. Please add your Cryptobox Private Key');
        }

        $c = substr($this->right($this->left($this->public_key, 'PUB'), 'AA'), 5);
        $this->coinLabel = $this->right($c, '77');
        $this->coinName = $this->left($c, '77');

        if ($this->amount && strpos($this->amount, '.')) {
            $this->amount = rtrim(rtrim($this->amount, '0'), '.');
        }

        if (!$this->amount || $this->amount <= 0) {
            $this->amount = 0;
        }
        if ($this->amount && (!is_numeric($this->amount) || $this->amount < 0.0001 || $this->amount > 500000000)) {
            new \BadFunctionCallException('Invalid Amount - ' . sprintf('%.8f', $this->amount) . $this->coinLabel . ' Allowed range: 0.0001 .. 500,000,000');
        }


        $this->period = trim(strtoupper(str_replace(' ', '', $this->period)));
        if (substr($this->period, -1) == 'S') {
            $this->period = substr($this->period, 0, -1);
        }

        for ($i = 1; $i <= 90; $i++) {
            $arr[] = $i . 'MINUTE';
            $arr[] = $i . 'HOUR';
            $arr[] = $i . 'DAY';
            $arr[] = $i . 'WEEK';
            $arr[] = $i . 'MONTH';
        }

        if ($this->period != 'NOEXPIRY' && !in_array($this->period, $arr)) {
            new \BadFunctionCallException('Invalid Cryptobox Period - ' . $this->period);
        }
        $this->period = str_replace(['MINUTE', 'HOUR', 'DAY', 'WEEK', 'MONTH'], [' MINUTE', ' HOUR', ' DAY', ' WEEK', ' MONTH'], $this->period);

        $this->user_id = trim($this->user_id);
        if ($this->user_id && preg_replace('/[^A-Za-z0-9\.\_\-\@]/', '', $this->user_id) != $this->user_id) {
            new \BadFunctionCallException('Invalid User ID - $this->user_id. Allowed symbols: a..Z0..9_-@.');
        }
        if (strlen($this->user_id) > 50) {
            new \BadFunctionCallException('Invalid User ID - ' . $this->user_id . '. Max: 50 symbols');
        }
        $this->order_id = trim($this->order_id);
        if ($this->order_id && preg_replace('/[^A-Za-z0-9\.\_\-\@]/', '', $this->order_id) != $this->order_id) {
            new \BadFunctionCallException('Invalid Order ID - $this->order_id. Allowed symbols: a..Z0..9_-@.');
        }
        if (!$this->order_id || strlen($this->order_id) > 50) {
            new \BadFunctionCallException('Invalid Order ID - $this->order_id. Max: 50 symbols');
        }
        return $this;
    }

    /**
     * Левая часть строки до символа
     * @param $str
     * @param $findme
     * @param bool $firstpos
     * @return bool|string
     */
    public function left($str, $findme, $firstpos = true)
    {
        $pos = ($firstpos) ? stripos($str, $findme) : strripos($str, $findme);
        if ($pos === false) {
            return $str;
        } else {
            return substr($str, 0, $pos);
        }
    }

    /**
     * Правая часть строки до символа
     * @param $str
     * @param $findme
     * @param bool $firstpos
     * @return bool|string
     */
    public function right($str, $findme, $firstpos = true)
    {
        $pos = ($firstpos) ? stripos($str, $findme) : strripos($str, $findme);
        if ($pos === false) {
            return $str;
        } else {
            return substr($str, $pos + strlen($findme));
        }
    }

    /**
     *
     * @param $str
     * @return float|int
     */
    public function icrc32($str)
    {
        $in = crc32($str);
        $int_max = pow(2, 31) - 1;
        if ($in > $int_max) {
            $out = $in - $int_max * 2 - 2;
        } else {
            $out = $in;
        }
        $out = abs($out);
        return $out;
    }


    /**
     * Если $is_confirmed = true, проверяется была ли подтверждена транзакция от 6 подтверждений
     * @param bool $is_confirmed
     * @return bool
     */
    public function isPaid($is_confirmed = false)
    {
        if ($data = $this->checkPayment()) {
            if (isset($data['status']) && $data['status'] == 'payment_received') {
                if ($is_confirmed && (isset($data['confirmed']) && $data['confirmed'])) {
                    return true;
                } elseif ($is_confirmed) {
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Проверка статуса оплаты
     * @param  $is_confirmed boolean
     * @return mixed
     */
    public function checkPayment()
    {
        $ip = $this->ip_address();
        $private_key_hash = strtolower(hash('sha512', $this->private_key));
        $hash = md5($this->box_id . $private_key_hash . $this->user_id . $this->order_id . $this->language . $this->period . $ip);
        $data = array(
            'g' => $private_key_hash,
            'b' => $this->box_id,
            'o' => $this->order_id,
            'u' => $this->user_id,
            'l' => $this->language,
            'e' => $this->period,
            'i' => $ip,
            'h' => $hash
        );

        $ch = curl_init('https://coins.gourl.io/result.php');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        $res = curl_exec($ch);
        curl_close($ch);

        if ($res) {
            $res = json_decode($res, true);
        }
        if ($res) {
            foreach ($res as $k => $v) {
                if (is_string($v)) {
                    $res[$k] = trim($v);
                }
            }
        }

        if (isset($res['status']) && in_array($res['status'], array('payment_received')) &&
            $res['box'] && is_numeric($res['box']) && $res['box'] > 0 && $res['amount'] && is_numeric($res['amount']) && $res['amount'] > 0 &&
            isset($res['private_key_hash']) && strlen($res['private_key_hash']) == 128 && preg_replace('/[^A-Za-z0-9]/', '', $res['private_key_hash']) == $res['private_key_hash'] && strtolower($res['private_key_hash']) == $private_key_hash) {

            foreach ($res as $k => $v) {
                if ($k == 'datetime') {
                    $mask = '/[^0-9\ \-\:]/';
                } elseif (in_array($k, array('err', 'date'))) {
                    $mask = '/[^A-Za-z0-9\.\_\-\@\ ]/';
                } else {
                    $mask = '/[^A-Za-z0-9\.\_\-\@]/';
                }
                if ($v && preg_replace($mask, '', $v) != $v) {
                    $res[$k] = '';
                }
            }

            if (!$res['amountusd'] || !is_numeric($res['amountusd'])) {
                $res['amountusd'] = 0;
            }
            if (!$res['confirmed'] || !is_numeric($res['confirmed'])) {
                $res['confirmed'] = 0;
            }

            return $res;
        }
        return [];
    }


    /* 3. Function get_json_values()
	 *
	 * Alternatively, you can receive JSON values through php curl on server side and use it in your php/other files without using javascript and jquery/ajax.
	 * Return Array; Examples -
	 * Payment not received - https://coins.gourl.io/b/20/c/Bitcoin/p/20AAvZCcgBitcoin77BTCPUB0xyyeKkxMUmeTJRWj7IZrbJ0oL/a/0/au/2.21/pe/NOEXPIRY/l/en/o/invoice22/u/83412313__3bccb54769/us/COOKIE/j/1/d/ODIuMTEuOTQuMTIx/h/e889b9a07493ee96a479e471a892ae2e
	 * Payment received successfully - https://coins.gourl.io/b/20/c/Bitcoin/p/20AAvZCcgBitcoin77BTCPUB0xyyeKkxMUmeTJRWj7IZrbJ0oL/a/0/au/0.1/pe/NOEXPIRY/l/en/o/invoice1/u/demo/us/MANUAL/j/1/d/ODIuMTEuOTQuMTIx/h/ac7733d264421c8410a218548b2d2a2a
	 *
	 * By default the user sees bitcoin payment box as iframe in html format - function display_cryptobox().
	 * JSON data will allow you to easily customise your bitcoin payment boxes. For example, you can display payment amount and
	 * bitcoin payment address with your own text, you can also accept payments in android/windows and other applications.
	 * You get an array of values - payment amount, bitcoin address, text; and can place them in any position on your webpage/application.
     * @return array
	 */
    public function getPaymentData()
    {
        $arr = [];
        $url = $this->cryptobox_json_url();
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Get_Json_Values PHP Class ' . $this->cryptobox_version);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        $res = curl_exec($ch);
        curl_close($ch);

        // security; validate data sent by gourl.io
        $f = false;
        if ($res) {
            $arr = $arr2 = json_decode($res, true);
            if (isset($arr2['data_hash'])) {
                unset($arr2['data_hash']);
                if (strtolower($arr['data_hash']) == strtolower(hash('sha512', $this->private_key . json_encode($arr2) . $this->private_key))) {
                    $f = true;
                }
            }
        }
        if (!$f) {
            $arr = array();
        }
        return $arr;
    }


    /* 2. Function cryptobox_json_url()
	 *
	 * It generates url with your parameters to gourl.io payment gateway.
	 * Using this url you can get bitcoin/altcoin payment box values in JSON format and use it on html page with Jquery/Ajax.
	 * See instruction https://gourl.io/bitcoin-payment-gateway-api.html#p8
	 *
	 * JSON Values Example -
	 * Payment not received - https://coins.gourl.io/b/20/c/Bitcoin/p/20AAvZCcgBitcoin77BTCPUB0xyyeKkxMUmeTJRWj7IZrbJ0oL/a/0/au/2.21/pe/NOEXPIRY/l/en/o/invoice22/u/83412313__3bccb54769/us/COOKIE/j/1/d/ODIuMTEuOTQuMTIx/h/e889b9a07493ee96a479e471a892ae2e
	 * Payment received successfully - https://coins.gourl.io/b/20/c/Bitcoin/p/20AAvZCcgBitcoin77BTCPUB0xyyeKkxMUmeTJRWj7IZrbJ0oL/a/0/au/0.1/pe/NOEXPIRY/l/en/o/invoice1/u/demo/us/MANUAL/j/1/d/ODIuMTEuOTQuMTIx/h/ac7733d264421c8410a218548b2d2a2a
	 *
	 * Alternatively, you can receive JSON values through php curl on server side - function get_json_values() and use it in your php/other files without using javascript and jquery/ajax.
	 *
	 * By default the user sees bitcoin payment box as iframe in html format - function display_cryptobox().
	 * JSON data will allow you to easily customise your bitcoin payment boxes. For example, you can display payment amount and
	 * bitcoin payment address with your own text, you can also accept payments in android/windows and other applications.
	 * You get an array of values - payment amount, bitcoin address, text; and can place them in any position on your webpage/application.
	 */
    public function cryptobox_json_url()
    {
        $ip = $this->ip_address();
        $hash = $this->cryptobox_hash(true);
        $data = [
            'b' => $this->box_id,
            'c' => $this->coinName,
            'p' => $this->public_key,
            'a' => $this->amount,
            'au' => $this->amountUSD,
            'pe' => str_replace(' ', '_', $this->period),
            'l' => $this->language,
            'o' => $this->order_id,
            'u' => $this->user_id,
            'us' => $this->userFormat,
            'j' => 1, // json
            'd' => base64_encode($ip),
            'h' => $hash
        ];

        if ($this->webdev_key) {
            $data['w'] = $this->webdev_key;
        }
        $data['z'] = rand(0, 10000000);

        $url = 'https://coins.gourl.io';
        foreach ($data as $k => $v) {
            $url .= '/' . $k . '/' . rawurlencode($v);
        }
        return $url;
    }


    /* 4. Function cryptobox_hash($json = false, $width = 0, $height = 0)
	 *
	 * It generates security md5 hash for all values used in payment boxes.
	 * This protects payment box parameters from changes by end user in web browser.
	 * $json = true - generate md5 hash for json payment data output
	 * or generate hash for iframe html box with sizes $width x $height
	 */
    public function cryptobox_hash($json = false, $width = 0, $height = 0)
    {
        if ($json) {
            $hash_str = $this->box_id . '|' . $this->coinName . '|' . $this->public_key . '|' . $this->private_key . '|' . $this->webdev_key . '|' . $this->amount . '|' . $this->amountUSD . '|' . $this->period . '|' . $this->language . '|' . $this->order_id . '|' . $this->user_id . '|' . $this->userFormat . '|' . $this->ip_address();
        } else {
            $hash_str = $this->box_id . '|' . $this->coinName . '|' . $this->public_key . '|' . $this->private_key . '|' . $this->webdev_key . '|' . $this->amount . '|' . $this->amountUSD . '|' . $this->period . '|' . $this->language . '|' . $this->order_id . '|' . $this->user_id . '|' . $this->userFormat . '|' . $this->iframe_id . '|' . $width . '|' . $height;
        }
        $hash = md5($hash_str);
        return $hash;
    }


    /**
     * Получить ip пользователя
     * @return string
     */
    public function ip_address()
    {
        static $ip_address;

        if ($ip_address) {
            return $ip_address;
        }

        $ip_address = '';
        $proxy_ips = (defined('PROXY_IPS')) ? unserialize(PROXY_IPS) : array();  // your server internal proxy ip
        $internal_ips = array('127.0.0.0', '127.0.0.1', '127.0.0.2', '192.0.0.0', '192.0.0.1', '192.168.0.0', '192.168.0.1', '192.168.0.253', '192.168.0.254', '192.168.0.255', '192.168.1.0', '192.168.1.1', '192.168.1.253', '192.168.1.254', '192.168.1.255', '192.168.2.0', '192.168.2.1', '192.168.2.253', '192.168.2.254', '192.168.2.255', '10.0.0.0', '10.0.0.1', '11.0.0.0', '11.0.0.1', '1.0.0.0', '1.0.1.0', '1.1.1.1', '255.0.0.0', '255.0.0.1', '255.255.255.0', '255.255.255.254', '255.255.255.255', '0.0.0.0', '::', '0::', '0:0:0:0:0:0:0:0');

        for ($i = 1; $i <= 2; $i++) {
            if (!$ip_address) {
                foreach (array('HTTP_CLIENT_IP', 'HTTP_X_CLIENT_IP', 'HTTP_X_CLUSTER_CLIENT_IP', 'X-Forwarded-For', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP', 'REMOTE_ADDR') as $header) {
                    if (!$ip_address && isset($_SERVER[$header]) && $_SERVER[$header]) {
                        $ip = trim($_SERVER[$header]);
                        $ip2 = '';
                        if (strpos($ip, ',') !== FALSE) {
                            list($ip, $ip2) = explode(',', $ip, 2);
                            $ip = trim($ip);
                            $ip2 = trim($ip2);
                        }

                        if ($ip && filter_var($ip, FILTER_VALIDATE_IP) && !in_array($ip, $proxy_ips) && ($i == 2 || !in_array($ip, $internal_ips))) {
                            $ip_address = $ip;
                        } elseif ($ip2 && filter_var($ip2, FILTER_VALIDATE_IP) && !in_array($ip2, $proxy_ips) && ($i == 2 || !in_array($ip2, $internal_ips))) {
                            $ip_address = $ip2;
                        }
                    }
                }
            }
        }

        if (!$ip_address || !filter_var($ip_address, FILTER_VALIDATE_IP)) {
            $ip_address = '0.0.0.0';
        }
        return $ip_address;
    }

    /**
     * @return string
     */
    public function getCryptoboxPrivateKeys()
    {
        foreach ($this->all_key as $value) {
            $private_keys[] = $value['private_key'];
        }
        return implode('^', $private_keys);
    }

    /**
     * Проверяет оповещения о поступлении платежа
     * @return array
     */
    public function checkWebhookData()
    {
        $post = Yii::$app->request->post();

        $cryptobox_private_keys = $this->getCryptoboxPrivateKeys();

        $valid_key = false;
        if (isset($post['private_key_hash']) && strlen($post['private_key_hash']) == 128 && preg_replace('/[^A-Za-z0-9]/', '', $post['private_key_hash']) == $post['private_key_hash']) {
            $keyshash = array();
            $arr = explode('^', $cryptobox_private_keys);
            foreach ($arr as $v) $keyshash[] = strtolower(hash('sha512', $v));
            if (in_array(strtolower($post['private_key_hash']), $keyshash)) {
                $valid_key = true;
            }
        }
        if (!$valid_key && isset($post['json']) && $post['json'] == '1') {
            $data_hash = $boxID = '';
            if (isset($post['data_hash']) && strlen($post['data_hash']) == 128 && preg_replace('/[^A-Za-z0-9]/', '', $post['data_hash']) == $post['data_hash']) {
                $data_hash = strtolower($post['data_hash']);
                unset($post['data_hash']);
            }
            if (isset($post['box']) && is_numeric($post['box']) && $post['box'] > 0) $boxID = intval($post['box']);

            if ($data_hash && $boxID) {
                $private_key = '';
                $arr = explode('^', $cryptobox_private_keys);
                foreach ($arr as $v) {
                    if (strpos($v, $boxID . 'AA') === 0) {
                        $private_key = $v;
                    }
                }

                if ($private_key) {
                    $data_hash2 = strtolower(hash('sha512', $private_key . json_encode($post) . $private_key));
                    if ($data_hash == $data_hash2) {
                        $valid_key = true;
                    }
                }
                unset($private_key);
            }

            if (!$valid_key) {
                die('Error! Invalid Json Data sha512 Hash!');
            }

        }

        if ($post) {
            foreach ($post as $k => $v) {
                if (is_string($v)) {
                    $post[$k] = trim($v);
                }
            }
        }

        if (isset($post['plugin_ver']) && !isset($post['status']) && $valid_key) {
            echo 'cryptoboxver_' . 'php_' . $this->cryptobox_version;
            die;
        }

        if (Yii::$app->request->isPost && isset($post['status']) && in_array($post['status'], array('payment_received', 'payment_received_unrecognised')) &&
            $post['box'] && is_numeric($post['box']) && $post['box'] > 0 && $post['amount'] && is_numeric($post['amount']) && $post['amount'] > 0 && $valid_key) {

            foreach ($post as $k => $v) {
                if ($k == 'datetime') {
                    $mask = '/[^0-9\ \-\:]/';
                } elseif (in_array($k, array('err', 'date', 'period'))) {
                    $mask = '/[^A-Za-z0-9\.\_\-\@\ ]/';
                } else {
                    $mask = '/[^A-Za-z0-9\.\_\-\@]/';
                }
                if ($v && preg_replace($mask, '', $v) != $v) {
                    $post[$k] = '';
                }
            }

            if (!$post['amountusd'] || !is_numeric($post['amountusd'])) {
                $post['amountusd'] = 0;
            }
            if (!$post['confirmed'] || !is_numeric($post['confirmed'])) {
                $post['confirmed'] = 0;
            }
            if ($post['confirmed']) {
                $box_status = 'cryptobox_updated';
            } else {
                $box_status = 'cryptobox_nochanges';
            }
        } else {
            $box_status = 'Only POST Data Allowed';
        }
        return ['text_return' => $box_status, 'params' => $post];
    }
}