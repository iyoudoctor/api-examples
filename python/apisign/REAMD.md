# API签名示例

## 依赖

* pywt
* rfc3339

_安装依赖: pip install -U -r requirements.txt_

## 样例

__生成签名__:

执行`./sign.py signhttp -i {AppID} -p {请求的路径} -k {私钥文件}`会生成使用当前时间戳生成的签名，改签名允许和服务器有一定的时间间隔，到目前为止，这个容许的时间差是正负10s

__验证签名__:

执行`./sign.py verifyhttp -i {AppID} -p {请求的路径} -k {公钥文件} -t {时间戳} -s {签名}`会验证生成的签名是否有效
