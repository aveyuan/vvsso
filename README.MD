## 使用GO编写的SSO签名认证工具
> 在网站管理中，网站越来越多,所以，希望统一登录接口实现，本工具基于签名做认证，默认30秒的有效期，通过传递用户名，用户id,有效期，签名到对端。对端根据相关信息解密比对。

vvsso url sec_token user_name user_id 可以得到最终的链接地址，使用地址可以直接访问

Linux的快速使用方法

```
google-chrome $(vvsso url sec_token user_name user_id)
```

