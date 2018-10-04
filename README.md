# cs161-p2
project 2 for cs161



#### userlib提供的API的翻译

RandomBytes: 生成随机数

DatastoreSet: 传进来key和value，用key来索引保存，然后存到datastore数组的对应位置

DatastoreGet: 传进来key，取走保存的内容

DatastoreDelete: 删除对应key的内容

DatastoreClear: 全部删除

KeystoreSet: 用key来索引，用来保存PublicKey，*对于这个怎么用还没想好...到底要加密啥...*

KeystoreClear: 删除所有key

KeystoreGet: 取出PublicKey

DatastoreGetMap: 直接返回datastore，不知道有什么必要...

KeystoreGetMap: 返回keystore，同上

GenerateRSAKey: 用rsa库提供的API得到一对rsakey，返回*PrivateKey，函数这么用

```go
x, b := userlib.GenerateRSAKey()
x1 := &x.PublicKey
```

RSAEncrypt: RSA加密

RSADecrypt: RSA解密

RSASign: 签名

RSAVerify: 给定message和sign，确认签名

HMAC: 传进来key，传回去Mac，根据官方文档，使用的时候：

```go
// CheckMAC reports whether messageMAC is a valid HMAC tag for message.
func CheckMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

```

Equal: trivial的判断相等

NewSHA256: 生成一个用于生成SHA256 hash的一个...我也不知道是啥…种子吗…官方文档：

```go
h := sha256.New()
h.Write([]byte("hello world\n"))
fmt.Printf("%x", h.Sum(nil))
```

Argon2Key(password, salt, keyLen): 一个帮你加盐加密的东西，不需要自己实现对于密码和用户名的hash了

```go
key := argon2.IDKey([]byte("passord"), []byte("aaa"), 1, 64*1024, 4, 32)
fmt.Println(key)
```

CFBEncrypter, CFBDecrypter: CFB模式的加密解密



> TODO: 翻译成英语…回头再说吧

#### 设计文档

首先是有username，password和文件

对于name，由于需要保证不知道名字，需要加一次hash，对于password同样，保存hash，因为保证了password的熵，所以直接用password来加密信息



username, password, file

save the hash of the username in the datastore, also the hash of the password

and use the password to decrypte the file



initUser: 生成userdata structure，生成RSA密钥，在datastore中保存data structure，在keystore中保存key





#### 一些问题

If we have a user and he successfully logged in, does he need to know how many files he have? or only after he inputs the filename can we check if the file name is valid?

> 不需要