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

piazza:
sha := userlib.NewSHA256()
sha.Write([]byte("aaa"))
hash := sha.Sum([]byte("foobar"))
hash2 := sha.Sum([]byte("foobar"))
fmt.Println(hash)
fmt.Println(hash2)
```

Argon2Key(password, salt, keyLen): 一个帮你加盐加密的东西，不需要自己实现对于密码和用户名的hash了

```go
key := argon2.IDKey([]byte("passord"), []byte("aaa"), 1, 64*1024, 4, 32)
fmt.Println(key)
```

CFBEncrypter, CFBDecrypter: CFB模式的加密解密



> TODO: 翻译成英语…回头再说吧

#### 设计文档

datastore的地址是32bytes

总的来看，有四个table，分别为user, userHMAC(用一个key来获得user的bytes的HMAC), file(用来保存用户file的信息), fileHMAC(用一个key来获得file的bytes的HMAC)

user内部明文保存password，明文保存username

然后使用Argon2Key(salt, password)当key，在key = hash("saltforkey"+username)内保存salt，还需要一个IV，这个就直接生成随机数，在key = hash("IVforCFBAES"+username)内保存，防止长度拓展攻击

**这两次hash直接NewSHA256**

文件info的保存就在一个随机地址，同样明文保存随机地址

userHMAC和fileHMAC同样保存在hash("userHMAC"+username), hash("fileHMAC"+username)，同样保证长度扩展攻击

这回RSA private key就可以直接保存了

对于文件，每个用户都有一个保存自己有的文件的info文件，其中保存了文件名，文件地址以及文件解密的key，和验证HMAC的key (KeyForDecrypt和KeyForHMAC)

对于保存的文件，直接是一个json，一个是加密后文件的HMAC，一个是加密后的文件(老师说要encrypt then hmac来确保没有侧信道攻击)

然后如果是append直接把原始地址重新SHA256 hash一遍，获得新地址

当然这里的nonce和key肯定是不能重用的...这里直接hash原始的key和nonce就行（我觉得）

当想要共享的时候，在sharingRecord中保存有public key加密后的key，以及一个用这个key加密后的文件信息（文件地址，文件解密用的key以及验证HMAC用的key）

发送E(m, key), E(key, Bpublic), Sign(m, Aprivate)



问题：

如果一个A给B B已经有的信息怎么办？

> 忽略这个文件

这个我想和nick去确认一下，我们可以直接删除原来的文件，用新的key去加密吗...因为我觉得这个approach太容易想到了。。。





~~其中file的地址用user内的内容来推出，用Argon2Key来做，保存一个salt(SaltForFileAddress), argon2key(salt, password)对应的位置保存file的内容~~

~~file直接保存地址，密码，hash，以及文件名，所以必须直接加密json，使用AES-CFB和SaltForFileInfoKey, 16 bytes~~

~~userHMAC和fileHMAC就直接保存在hash("userHMAC"+username), hash("fileHMAC"+username), 保证长度扩展攻击无效~~

~~对于userHMAC和fileHMAC的计算：用password生成HMAC~~

~~RSA public保存在keystore，private先json，然后用CFB保存，使用SaltForRSAKey, 16bytes, 以及CFB需要的IV(NonceForRSAData), 16bytes~~~~



four table, user, userHMAC(the mac for chunk user, with a generated key from password), file, fileHMAC(the mac for chunk file, with a generated key from password)

for file, we need a key to encrypt the chunk, a typical key



首先是有username，password和文件

对于name，由于需要保证不知道名字，需要加一次hash，对于password同样，保存hash，因为保证了password的熵，所以直接用password来加密信息



username, password, file

save the hash of the username in the datastore, also the hash of the password

and use the password to decrypte the file



initUser: 生成userdata structure，生成RSA密钥，在datastore中保存data structure，在keystore中保存key

1. datastore[hash(username)], hashing save as Username
2. save hash(passsword), here use Argon2Key with a random bytes for salt, and save slat in the data base, length 16bytes, the salt is SaltForPW, the saved encrypted password is UserPasswod
3. save the public key, save AES-CFB(argon2(password, salt2), private key), salt2 saved as SalfForRSAKey, and we need to save the Nonce as NonceForRSAData
4. return the data structure





```go
var newone User
err = json.Unmarshal(marshaluser, &newone)
if err != nil{
    return &userdata, err
}

fmt.Println(newone.Username)
```



1. datastore[hash(username)] = hash(passsword), here use Argon2Key with a random bytes for salt, and save slat in the data base
2. datastore[hash(filename||username)] = hash(json(HMAC(hash(password), passage),CFB-AES(passage))









#### 一些问题

If we have a user and he successfully logged in, does he need to know how many files he have? or only after he inputs the filename can we check if the file name is valid?

> 不需要