<?php
/**
 * Created by PhpStorm.
 * User: willzhao
 * Date: 17/3/21
 * Time: 17:29
 */
//require_once ('Sign.php');
// $test = new Sign();
// $v = $test->sayHello('sss');
// echo $v;


require_once 'sign.php';
$secrt ='Secret';
$appid ='应用ID';
$path = 'Http请求路径';
$t = new Sign();

echo $t->signHttp($appid,$path,null,$secrt);


?>
