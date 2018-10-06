package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"fmt"
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username []byte   // something after hash
	UserPassword []byte    // the saved user password after hashing
	FileInfoAddress []byte
	FileInfoPassword []byte
	PrivateKey *userlib.PrivateKey
	NonceForFileInfoData []byte


	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileInfo struct {
	name []string
	KeyForDecrypt []string
	KeyForHMAC []string
	StoreAddress []string
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	var user_file_info FileInfo

	// first generate the hash for the username for key
	sha := userlib.NewSHA256()
	sha.Write([]byte(username))
	name_hash := sha.Sum([]byte(""))
	// save the username and the password as plain text
	userdata.Username = []byte(username)
	userdata.UserPassword = []byte(password)

	// begin to generate the rsa key pair, first generate the nonce
	var RSAKeyPair *userlib.PrivateKey
	RSAKeyPair, err = userlib.GenerateRSAKey()
	// save the public key into the keystore
	userlib.KeystoreSet(string(name_hash), RSAKeyPair.PublicKey)
	userdata.PrivateKey = RSAKeyPair


	// generate a unique address for user's file information
	userdata.FileInfoAddress = userlib.RandomBytes(32)
	// save the file info
	//fmt.Println(len(user_file_info.hash))
	file_info_marshal, err := json.Marshal(user_file_info)
	if (err != nil){
		return &userdata, err
	}
	// encrypt the file info
	userdata.FileInfoPassword = userlib.RandomBytes(16)
	to_store_file_info_data := make([]byte, len(file_info_marshal))
	userdata.NonceForFileInfoData = userlib.RandomBytes(16)  // generate the nonce
	temp_encryptor := userlib.CFBEncrypter(userdata.FileInfoPassword, userdata.NonceForFileInfoData)
	temp_encryptor.XORKeyStream(to_store_file_info_data, file_info_marshal)

	//store the file info data
	userlib.DatastoreSet(string(userdata.FileInfoAddress), to_store_file_info_data)


	// prepare the IV and the salt for CFB-AES
	sha = userlib.NewSHA256()
	sha.Write([]byte("saltforkey"+username))
	key_salt_address := sha.Sum([]byte(""))
	key_salt := userlib.RandomBytes(16)
	userlib.DatastoreSet(string(key_salt_address), key_salt)
	sha = userlib.NewSHA256()
	sha.Write([]byte("IVforCFBAES"+username))
	key_IV_address := sha.Sum([]byte(""))
	key_IV := userlib.RandomBytes(16)
	userlib.DatastoreSet(string(key_IV_address), key_IV)

	// begin to save and encrypte the data
	user_marshal, err := json.Marshal(userdata)
	if (err != nil){
		return &userdata, err
	}
	user_AES_key := userlib.Argon2Key([]byte(password), key_salt, 16)
	to_store_user_data := make([]byte, len(user_marshal))
	temp_encryptor = userlib.CFBEncrypter(user_AES_key, key_IV)
	temp_encryptor.XORKeyStream(to_store_user_data, user_marshal)
	// save the data in data store
	userlib.DatastoreSet(string(name_hash), to_store_user_data)

	// generate the HMAC for user
	temp_mac := userlib.NewHMAC([]byte(password))
	temp_mac.Write(to_store_user_data)
	user_hmac := temp_mac.Sum(nil)
	sha = userlib.NewSHA256()
	sha.Write([]byte("userHMAC" + username))
	user_hmac_address := sha.Sum([]byte(""))
	userlib.DatastoreSet(string(user_hmac_address), user_hmac)

	// generate the HMAC for the file info
	temp_mac = userlib.NewHMAC([]byte(password))
	temp_mac.Write(to_store_file_info_data)
	file_info_hmac := temp_mac.Sum(nil)
	sha = userlib.NewSHA256()
	sha.Write([]byte("fileinfoHMAC" + username))
	file_info_hmac_address := sha.Sum([]byte(""))
	userlib.DatastoreSet(string(file_info_hmac_address), file_info_hmac)


	// fmt.Println(userdata.FileInfoAddress)
	// fmt.Println(userdata.FileInfoPassword)
	// fmt.Println(userdata.PrivateKey)
	// fmt.Println(userdata.NonceForFileInfoData)

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	sha := userlib.NewSHA256()
	sha.Write([]byte(username))
	name_hash := sha.Sum([]byte(""))
	// first get from the remote datastore
	temp_data, ok := userlib.DatastoreGet(string(name_hash))
	if !ok {
		fmt.Println("It is not a valid user!")
		return nil, errors.New("not a valid user!")
	}


	// check if the HMAC is true

	temp_mac := userlib.NewHMAC([]byte(password))
	temp_mac.Write(temp_data)
	user_hmac := temp_mac.Sum(nil)
	sha = userlib.NewSHA256()
	sha.Write([]byte("userHMAC" + username))
	user_hmac_address := sha.Sum([]byte(""))
	expect_hmac, ok := userlib.DatastoreGet(string(user_hmac_address))
	if !ok {
		//fmt.Println("1wtf happened?????")
		return nil, errors.New("file system corrupted or it is not a valid user!")
	}
	if strings.Compare(string(user_hmac), string(expect_hmac)) != 0 {
		//fmt.Println("2wtf happened?????")
		return nil, errors.New("file system corrupted or it is not a valid user!")
	}

	// first get the IV and the salt for CFB-AES decrypt
	sha = userlib.NewSHA256()
	sha.Write([]byte("saltforkey"+username))
	key_salt_address := sha.Sum([]byte(""))
	key_salt, ok := userlib.DatastoreGet(string(key_salt_address))
	// key_salt not found, file system corrupted
	if !ok {
		return nil, errors.New("file system corrupted!")
	}
	sha = userlib.NewSHA256()
	sha.Write([]byte("IVforCFBAES"+username))
	key_IV_address := sha.Sum([]byte(""))
	key_IV, ok := userlib.DatastoreGet(string(key_IV_address))
	// key_IV not found, file system corrupted
	if !ok {
		return nil, errors.New("file system corrupted!")
	}

	// try to decrypt the data
	decryption_data := make([]byte, len(temp_data))
	user_AES_key := userlib.Argon2Key([]byte(password), key_salt, 16)
	temp_decryptor := userlib.CFBDecrypter(user_AES_key, key_IV)
	temp_decryptor.XORKeyStream(decryption_data, temp_data)

	// then unmarshal to get the data
	err = json.Unmarshal(decryption_data, &userdata)
	if err != nil {
		return nil, err
	}

	// check if the password is valid
	if password != string(userdata.UserPassword) {
		return nil, errors.New("not a valid password!")
	}
	// fmt.Println(userdata.FileInfoAddress)
	// fmt.Println(userdata.FileInfoPassword)
	// fmt.Println(userdata.PrivateKey)
	// fmt.Println(userdata.NonceForFileInfoData)

	return &userdata, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}

