# sm4_crypt

##环境
python 3.7
##依赖库
gmssl，pillow
```bash
pip install gmssl
pip install pillow
```
##功能描述
sm4分组密码有五种加密形式：ECB、CBC、CFB、OFB、CTR。gmssl库实现了ECB和CBC形式，本项目实现了CFB、OFB、CTR形式。
##测试
对于一张图片，加密像素点信息，将加密后的像素点信息以图片方式还原存储，本项目为了验证加密的正确性，还执行了解密，将解密后的信息也以图片的形式存储。执行结果位于result文件夹中。
