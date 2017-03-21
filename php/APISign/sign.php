<?php
/**
 * Created by PhpStorm.
 * User: willzhao
 * Date: 17/3/21
 * Time: 17:27
 */

require 'vendor/autoload.php';
use \Firebase\JWT\JWT;

date_time_set('UTC');

class Sign
{
    /*
     * Get time second
     */
    public function getNowSignTime()
    {
        return (new DateTime('now', new DateTimeZone('UTC')))->getTimestamp();
    }

    /*
     * Sign http
     * return
     *   signature string
     * */
    public function signHttp($appId, $path, $time, $key)
    {
        if($time==null)$time = $this->getNowSignTime();
        $dateTime = new DateTime(null, new DateTimeZone('UTC'));
        $dateTime->setTimestamp($time);

        $token = array(
            "appID" => $appId,
            "path" => $path,
            "utctime" => $dateTime->format(Datetime::RFC3339)
        );
        return JWT::encode($token, $key, 'HS256');
    }

    /*
     * Verify http
     * returns
     *   true/false
     * */
    public function verifyHttp($appId, $path, $time, $key, $signature)
    {
        $sign = JWT::decode($signature,$key,array("HS256"));
        $dateTime = new DateTime(null, new DateTimeZone('UTC'));
        $dateTime->setTimestamp($time);
        if($sign->get("appID")==$appId && $sign->get("path")==$path && $sign->get("utctime")==$dateTime->format(DateTime::RFC3339)){
            return true;
        }else{
            return false;
        }

    }

}


?>