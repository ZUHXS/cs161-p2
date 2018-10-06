package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"crypto/hmac"
	"crypto/sha256"
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
	SaltForPW []byte    // salt for Argon2key
	UserPassword []byte    // the saved user password after hashing
	SaltForRSAKey []byte
	NonceForRSAData []byte
	SaltForFileInfoKey []byte
	NonceForFileInfoData []byte
	RSAPrivateKey []byte
	SaltForFileAddress []byte


	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileInfo struct {
	name []string
	key []string
	hash []string
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

	// first generate the hash for the username
	sha := userlib.NewSHA256()
	sha.Write([]byte(username))
	name_hash := sha.Sum([]byte(""))
	//fmt.Println(len(name_hash))
	//fmt.Println(name_hash)
	userdata.Username = name_hash

	userdata.SaltForPW = userlib.RandomBytes(32)  // to generate 32 length password
	userdata.UserPassword = userlib.Argon2Key([]byte(password), []byte(userdata.SaltForPW), 32)  // length is 32

	// begin to generate the rsa key pair, first generate the nonce
	userdata.SaltForRSAKey = userlib.RandomBytes(16)
	var RSAKeyPair *userlib.PrivateKey
	RSAKeyPair, err = userlib.GenerateRSAKey()
	userlib.KeystoreSet(string(name_hash), RSAKeyPair.PublicKey)
	//generate the bytes by json
	RSAmarshal, err := json.Marshal(RSAKeyPair)
	// generate the key for AES using SaltForRSAKey
	temp_AES_en_key := userlib.Argon2Key([]byte(password), userdata.SaltForRSAKey, 16)  // 16 for AES key
	to_store_RSA_data := make([]byte, len(RSAmarshal))
	userdata.NonceForRSAData = userlib.RandomBytes(16)
	temp_encryptor := userlib.CFBEncrypter(temp_AES_en_key, userdata.NonceForRSAData)
	temp_encryptor.XORKeyStream(to_store_RSA_data, RSAmarshal)
	userdata.RSAPrivateKey = to_store_RSA_data


	// generate a unique address for user's file information
	userdata.SaltForFileAddress = userlib.RandomBytes(32)
	temp_address := userlib.Argon2Key([]byte(password), userdata.SaltForFileAddress, 32)
	// save the file info
	//fmt.Println(len(user_file_info.hash))
	file_info_marshal, err := json.Marshal(user_file_info)
	if (err != nil){
		return &userdata, err
	}
	// encrypt the file info
	userdata.SaltForFileInfoKey = userlib.RandomBytes(16)
	temp_file_info_en_key := userlib.Argon2Key([]byte(password), userdata.SaltForFileInfoKey, 16)
	to_store_file_info_data := make([]byte, len(file_info_marshal))
	userdata.NonceForFileInfoData = userlib.RandomBytes(16)
	temp_encryptor = userlib.CFBEncrypter(temp_file_info_en_key, userdata.NonceForFileInfoData)
	temp_encryptor.XORKeyStream(to_store_file_info_data, file_info_marshal)

	fmt.Println(to_store_file_info_data)
	userlib.DatastoreSet(string(temp_address), to_store_file_info_data)

	// save the user info
	user_marshal, err := json.Marshal(userdata)
	if (err != nil){
		return &userdata, err
	}
	// save the data in data store
	userlib.DatastoreSet(string(userdata.Username), user_marshal)

	// generate the HMAC for user
	temp_mac := hmac.New(sha256.New, []byte(password))
	temp_mac.Write(user_marshal)
	user_hmac := temp_mac.Sum(nil)
	sha = userlib.NewSHA256()
	sha.Write([]byte("userHMAC" + username))
	user_hmac_address := sha.Sum([]byte(""))
	userlib.DatastoreSet(string(user_hmac_address), user_hmac)

	// generate the HMAC for the file info
	temp_mac = hmac.New(sha256.New, []byte(password))
	temp_mac.Write(user_marshal)
	file_info_hmac := temp_mac.Sum(nil)
	sha = userlib.NewSHA256()
	sha.Write([]byte("fileinfoHMAC" + username))
	file_info_hmac_address := sha.Sum([]byte(""))
	userlib.DatastoreSet(string(file_info_hmac_address), file_info_hmac)


	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	sha := userlib.NewSHA256()
	sha.Write([]byte("username"))
	//name_hash := sha.Sum([]byte(username))
	//user_index_key := name_hash





	return
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

