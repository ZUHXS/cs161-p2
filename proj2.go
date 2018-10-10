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
	FileName [][]byte
	KeyForDecrypt [][]byte
	NonceForDecrypt [][]byte
	KeyForHMAC [][]byte
	StoreAddress [][]byte
	NumberAddress [][]byte
}

type FileDataStructure struct {
	HMAC []byte
	EncryptedContent []byte
}

func CalcHMAC(key []byte, data[]byte) (result []byte) {
	temp_mac := userlib.NewHMAC(key)
	temp_mac.Write(data)
	result = temp_mac.Sum(nil)
	return
}

func CalcHash(origin []byte) (result []byte){
	sha := userlib.NewSHA256()
	sha.Write(origin)
	result = sha.Sum([]byte(""))
	return
}


func CalcEncCFBAES(key []byte, nonce []byte, data []byte) ([]byte) {
	result := make([]byte, len(data))
	temp_encryptor := userlib.CFBEncrypter(key, nonce)
	temp_encryptor.XORKeyStream(result, data)
	return result
}

func CalcDecCFBAES(key []byte, nonce []byte, data []byte) ([]byte) {
	result := make([]byte, len(data))
	temp_decryptor := userlib.CFBDecrypter(key, nonce)
	temp_decryptor.XORKeyStream(result, data)
	return result
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
	name_hash := CalcHash([]byte(username))
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
	userdata.NonceForFileInfoData = userlib.RandomBytes(16)  // generate the nonce
	to_store_file_info_data := CalcEncCFBAES(userdata.FileInfoPassword, userdata.NonceForFileInfoData, file_info_marshal)

	//store the file info data
	userlib.DatastoreSet(string(userdata.FileInfoAddress), to_store_file_info_data)


	// prepare the IV and the salt for CFB-AES
	key_salt_address := CalcHash([]byte("saltforkey"+username))
	key_salt := userlib.RandomBytes(16)
	userlib.DatastoreSet(string(key_salt_address), key_salt)
	key_IV_address := CalcHash([]byte("IVforCFBAES"+username))
	key_IV := userlib.RandomBytes(16)
	userlib.DatastoreSet(string(key_IV_address), key_IV)

	// begin to save and encrypte the data
	user_marshal, err := json.Marshal(userdata)
	if (err != nil){
		return &userdata, err
	}
	user_AES_key := userlib.Argon2Key([]byte(password), key_salt, 16)
	to_store_user_data := CalcEncCFBAES(user_AES_key, key_IV, user_marshal)
	// save the data in data store
	userlib.DatastoreSet(string(name_hash), to_store_user_data)

	// generate the HMAC for user
	user_hmac := CalcHMAC([]byte(password), to_store_user_data)
	user_hmac_address := CalcHash([]byte("userHMAC" + username))
	userlib.DatastoreSet(string(user_hmac_address), user_hmac)

	// generate the HMAC for the file info
	file_info_hmac := CalcHMAC([]byte(password), to_store_file_info_data)
	file_info_hmac_address := CalcHash([]byte("fileinfoHMAC" + username))
	userlib.DatastoreSet(string(file_info_hmac_address), file_info_hmac)


	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	name_hash := CalcHash([]byte(username))
	// first get from the remote datastore
	temp_data, ok := userlib.DatastoreGet(string(name_hash))
	if !ok {
		fmt.Println("It is not a valid user!")
		return nil, errors.New("not a valid user!")
	}


	// check if the HMAC is true
	user_hmac := CalcHMAC([]byte(password), temp_data)
	user_hmac_address := CalcHash([]byte("userHMAC" + username))
	expect_hmac, ok := userlib.DatastoreGet(string(user_hmac_address))
	if !ok {
		//fmt.Println("1wtf happened?????")
		return nil, errors.New("IntegrityError")
	}
	if !userlib.Equal(user_hmac, expect_hmac) {    // Does NOT leak timing.
		//fmt.Println("2wtf happened?????")
		return nil, errors.New("IntegrityError")
	}

	// first get the IV and the salt for CFB-AES decrypt
	key_salt_address := CalcHash([]byte("saltforkey"+username))
	key_salt, ok := userlib.DatastoreGet(string(key_salt_address))
	// key_salt not found, file system corrupted
	if !ok {
		return nil, errors.New("IntegrityError")
	}
	key_IV_address := CalcHash([]byte("IVforCFBAES"+username))
	key_IV, ok := userlib.DatastoreGet(string(key_IV_address))
	// key_IV not found, file system corrupted
	if !ok {
		return nil, errors.New("IntegrityError")
	}

	// try to decrypt the data
	user_AES_key := userlib.Argon2Key([]byte(password), key_salt, 16)
	decryption_data := CalcDecCFBAES(user_AES_key, key_IV, temp_data)

	// then unmarshal to get the data
	err = json.Unmarshal(decryption_data, &userdata)
	if err != nil {
		return nil, err
	}

	// check if the password is valid
	if password != string(userdata.UserPassword) {
		return nil, errors.New("not a valid password!")
	}

	return &userdata, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// first get the file info data
	temp_data, ok := userlib.DatastoreGet(string(userdata.FileInfoAddress))
	if !ok {   // we don't have the return value... So nothing happens...
		return
	}
	// check if the HMAC satisfies the file_info
	file_info_hmac_address := CalcHash([]byte("fileinfoHMAC"+string(userdata.Username)))
	expect_file_info_hmac, ok := userlib.DatastoreGet(string(file_info_hmac_address))
	if !ok {
		return
	}
	file_info_hmac := CalcHMAC(userdata.UserPassword, temp_data)
	if !userlib.Equal(expect_file_info_hmac, file_info_hmac) {
		return
	}

	// recover the file info
	recover_data := CalcDecCFBAES(userdata.FileInfoPassword, userdata.NonceForFileInfoData, temp_data)
	// unmarshal the data
	var file_info FileInfo
	err := json.Unmarshal(recover_data, &file_info)
	if err != nil {
		return
	}

	index := len(file_info.StoreAddress)
	var a int
	flag := 0
	for a = 0; a < index; a++ {
		if filename == string(file_info.FileName[a]) {
			flag = 1    // overwrite the data
			break
		}
	}



	if flag == 0 {
		file_info.FileName = append(file_info.FileName, []byte(filename))
		file_info.NumberAddress = append(file_info.NumberAddress, userlib.RandomBytes(32))
		file_info.StoreAddress = append(file_info.StoreAddress, userlib.RandomBytes(32))   // address 32 bytes
		file_info.KeyForDecrypt = append(file_info.KeyForDecrypt, userlib.RandomBytes(16)) // AES 128
		file_info.NonceForDecrypt = append(file_info.NonceForDecrypt, userlib.RandomBytes(16))
		file_info.KeyForHMAC = append(file_info.KeyForHMAC, userlib.RandomBytes(16)) // length of the key for HMAC 16 bytes
	} else { // update the corresponding file info
		index = a
	}

	// generate the number bytes to store
	Number := 1
	Number_byte, err := json.Marshal(Number)
	// reset the Number
	userlib.DatastoreSet(string(file_info.NumberAddress[a]), Number_byte)

	// encrypt the file data
	data_after_encryption := CalcEncCFBAES(file_info.KeyForDecrypt[index], file_info.NonceForDecrypt[index], data)
	// calculate the HMAC for the encrypted data
	data_hmac := CalcHMAC(file_info.KeyForHMAC[index], data_after_encryption)
	var NewFileData FileDataStructure
	NewFileData.EncryptedContent = data_after_encryption
	NewFileData.HMAC = data_hmac
	// marshal the data
	File_data_marshal, err := json.Marshal(NewFileData)
	if err != nil {
		return
	}
	// store the filedata
	userlib.DatastoreSet(string(file_info.StoreAddress[index]), File_data_marshal)
	// restore the file info
	file_info_marshal, err := json.Marshal(file_info)
	if err != nil {
		return
	}

	// encrypt the file info
	to_store_file_info_data := CalcEncCFBAES(userdata.FileInfoPassword, userdata.NonceForFileInfoData, file_info_marshal)
	// store the file info data
	userlib.DatastoreSet(string(userdata.FileInfoAddress), to_store_file_info_data)

	// update the hmac for file info
	new_file_info_hmac := CalcHMAC(userdata.UserPassword, to_store_file_info_data)
	new_file_info_hmac_address := CalcHash([]byte("fileinfoHMAC" + string(userdata.Username)))
	userlib.DatastoreSet(string(new_file_info_hmac_address), new_file_info_hmac)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	temp_data, ok := userlib.DatastoreGet(string(userdata.FileInfoAddress))
	if !ok {
		return errors.New("IntegrityError")
	}
	// check if the HMAC satisfies the file_info
	file_info_hmac_address := CalcHash([]byte("fileinfoHMAC"+string(userdata.Username)))
	expect_file_info_hmac, ok := userlib.DatastoreGet(string(file_info_hmac_address))
	if !ok {
		return errors.New("IntegrityError")
	}
	file_info_hmac := CalcHMAC(userdata.UserPassword, temp_data)
	if !userlib.Equal(expect_file_info_hmac, file_info_hmac) {
		return errors.New("IntegrityError")
	}
	// recover the file info
	recover_data := CalcDecCFBAES(userdata.FileInfoPassword, userdata.NonceForFileInfoData, temp_data)

	// unmarshal the data
	var file_info FileInfo
	err = json.Unmarshal(recover_data, &file_info)
	if err != nil {
		return err
	}
	index := len(file_info.FileName)
	flag := 0
	var a int
	for a = 0; a < index; a++ {
		if string(file_info.FileName[a]) == filename {
			flag = 1
			break
		}
	}
	if flag == 0 {
		return errors.New("File does not exist!")  // the file doesn't exist or the user no longer has access to the file.
	}

	// Find the correct address to place the new data
	temp_file_data_nonce := file_info.NonceForDecrypt[a]
	temp_file_data_key_Dec := file_info.KeyForDecrypt[a]
	temp_file_data_address := file_info.StoreAddress[a]
	//temp_data, ok = userlib.DatastoreGet(string(temp_file_data_address))

	// get the current file number
	NumberByte, ok := userlib.DatastoreGet(string(file_info.NumberAddress[a]))
	if !ok {
		return errors.New("IntegrityError")
	}
	// unmarshal the data
	var Number int
	err = json.Unmarshal(NumberByte, &Number)
	if err != nil {
		return err
	}

	// update the Number and restore into the datastore
	Number += 1
	NewNumberByte, err := json.Marshal(Number)
	userlib.DatastoreSet(string(file_info.NumberAddress[a]), NewNumberByte)


	for count := 1; count < Number; count++ {
		temp_file_data_nonce = CalcHash(temp_file_data_nonce)[:16]
		temp_file_data_key_Dec = CalcHash(temp_file_data_key_Dec)[:16]
		temp_file_data_address = CalcHash(temp_file_data_address)
	}
	// encrypt the data
	data_after_encryption := CalcEncCFBAES(temp_file_data_key_Dec, temp_file_data_nonce, data)
	data_hmac := CalcHMAC(file_info.KeyForHMAC[a], data_after_encryption)
	var NewFileData FileDataStructure
	NewFileData.EncryptedContent = data_after_encryption
	NewFileData.HMAC = data_hmac
	// marshal the data
	file_data_marshal, err := json.Marshal(NewFileData)
	if err != nil {
		return err
	}

	// store the filedata
	userlib.DatastoreSet(string(temp_file_data_address), file_data_marshal)

	// restore the file info
	file_info_marshal, err := json.Marshal(file_info)
	if err != nil {
		return
	}
	// encrypt the file info
	to_store_file_info_data := CalcEncCFBAES(userdata.FileInfoPassword, userdata.NonceForFileInfoData, file_info_marshal)
	// store the file info data
	userlib.DatastoreSet(string(userdata.FileInfoAddress), to_store_file_info_data)

	// update the hmac for file info
	new_file_info_hmac := CalcHMAC(userdata.UserPassword, to_store_file_info_data)
	new_file_info_hmac_address := CalcHash([]byte("fileinfoHMAC" + string(userdata.Username)))
	userlib.DatastoreSet(string(new_file_info_hmac_address), new_file_info_hmac)

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	temp_data, ok := userlib.DatastoreGet(string(userdata.FileInfoAddress))
	if !ok {
		return nil, errors.New("IntegrityError")
	}
	// check if the HMAC satisfies the file_info
	file_info_hmac_address := CalcHash([]byte("fileinfoHMAC"+string(userdata.Username)))
	expect_file_info_hmac, ok := userlib.DatastoreGet(string(file_info_hmac_address))
	if !ok {
		return nil, errors.New("IntegrityError")
	}
	file_info_hmac := CalcHMAC(userdata.UserPassword, temp_data)
	if !userlib.Equal(expect_file_info_hmac, file_info_hmac) {
		return nil, errors.New("IntegrityError")
	}

	// recover the file info
	recover_data := CalcDecCFBAES(userdata.FileInfoPassword, userdata.NonceForFileInfoData, temp_data)

	// unmarshal the data
	var file_info FileInfo
	err = json.Unmarshal(recover_data, &file_info)
	if err != nil {
		return nil, err
	}
	index := len(file_info.FileName)
	flag := 0
	var a int
	for a = 0; a < index; a++ {
		if string(file_info.FileName[a]) == filename {
			flag = 1
			break
		}
	}
	if flag == 0 {
		return nil, nil
	}

	// get the data
	temp_temp_data, ok := userlib.DatastoreGet(string(file_info.StoreAddress[a]))
	if !ok {
		fmt.Println("error loading!")
		return nil, errors.New("IntegrityError")
	}
	// first unmarshal and check if it is valid
	var new_file_data FileDataStructure
	err = json.Unmarshal(temp_temp_data, &new_file_data)
	if err != nil {
		return nil, err
	}
	// calculate the HMAC for the encrypted data
	data_hmac := CalcHMAC(file_info.KeyForHMAC[a], new_file_data.EncryptedContent)
	// check if the HMAC equals
	if !userlib.Equal(new_file_data.HMAC, data_hmac) {
		return nil, errors.New("IntegrityError")
	}

	// equals, begin to decrypt the data
	recover_file_data := CalcDecCFBAES(file_info.KeyForDecrypt[a], file_info.NonceForDecrypt[a], new_file_data.EncryptedContent)


	// get the total number
	NumberBytes, ok := userlib.DatastoreGet(string(file_info.NumberAddress[a]))
	if !ok {
		return nil, errors.New("IntegrityError")
	}
	var Number int
	err = json.Unmarshal(NumberBytes, &Number)
	if err != nil {
		return nil, err
	}

	// check if there are appended data
	temp_file_data_address := file_info.StoreAddress[a]
	temp_file_data_nonce := file_info.NonceForDecrypt[a]
	temp_file_data_key_Dec := file_info.KeyForDecrypt[a]

	var temp_file_data FileDataStructure
	for b := 1; b < Number; b++ {
		temp_file_data_address = CalcHash(temp_file_data_address)
		temp_file_data_nonce = CalcHash(temp_file_data_nonce)[:16]
		temp_file_data_key_Dec = CalcHash(temp_file_data_key_Dec)[:16]
		temp_origin_data, ok := userlib.DatastoreGet(string(temp_file_data_address))
		if !ok {
			return nil, errors.New("1IntegrityError")
		}
		// begin to decrypt, first unmarshal
		err = json.Unmarshal(temp_origin_data, &temp_file_data)
		if err != nil {
			return nil, err
		}
		// then check the HMAC
		data_hmac := CalcHMAC(file_info.KeyForHMAC[a], temp_file_data.EncryptedContent)
		if !userlib.Equal(data_hmac, temp_file_data.HMAC) {
			return nil, errors.New("2IntegrityError")
		}
		// begin to decrypt the data
		temp_recover_file_data := CalcDecCFBAES(temp_file_data_key_Dec, temp_file_data_nonce, temp_file_data.EncryptedContent)
		recover_file_data = []byte(string(recover_file_data) + string(temp_recover_file_data))
	}


	/*
	var temp_file_data FileDataStructure
	for ; ; temp_file_data_address= CalcHash(temp_file_data_address) {
		temp_origin_data, ok = userlib.DatastoreGet(string(temp_file_data_address))
		if !ok {
			break
		}
		temp_file_data_nonce = CalcHash(temp_file_data_nonce)[:16]
		temp_file_data_key_Dec = CalcHash(temp_file_data_key_Dec)[:16]
		// begin to decrypt, first unmarshal
		err = json.Unmarshal(temp_origin_data, &temp_file_data)
		if err != nil {
			return nil, err
		}
		// then check the HMAC
		data_hmac := CalcHMAC(file_info.KeyForHMAC[a], temp_file_data.EncryptedContent)
		if !userlib.Equal(data_hmac, temp_file_data.HMAC) {
			return nil, errors.New("IntegrityError")
		}
		// begin to decrypt the data
		temp_recover_file_data := CalcDecCFBAES(temp_file_data_key_Dec, temp_file_data_nonce, temp_file_data.EncryptedContent)
		recover_file_data = []byte(string(recover_file_data) + string(temp_recover_file_data))
	}
	//fmt.Println(temp_file_data_nonce, temp_file_data_key_Dec)
	// encrypt the data
	*/


	return recover_file_data, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	KeyAfterEncrypt []byte   // RSAEncrypt(public key, key)
	NonceForEncrypt []byte
	DataAfterEncrypt []byte   // E(key, data)
	RSASignOnHashCT []byte   // sign(hash(ciphertext))
}

type sharingData struct {
	KeyForDecrypt []byte
	NonceForDecrypt []byte
	KeyForHMAC []byte
	StoreAddress []byte
	NumberAddress []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	var share_record sharingRecord
	// first get the key and nonce, and use public key to encrypt it
	AES_key := userlib.RandomBytes(16)
	share_record.NonceForEncrypt = userlib.RandomBytes(16)
	// get the public key
	recipient_name_hash := CalcHash([]byte(recipient))
	recipient_public_key, ok := userlib.KeystoreGet(string(recipient_name_hash))
	if !ok {
		return "", errors.New("NotValidUser")
	}
	RSA_encrypted_data, err := userlib.RSAEncrypt(&recipient_public_key, AES_key, nil)
	if err != nil {
		return "", err
	}
	share_record.KeyAfterEncrypt = RSA_encrypted_data

	// encrypt the data
	var share_file_info sharingData
	// get the file info data
	temp_data, ok := userlib.DatastoreGet(string(userdata.FileInfoAddress))
	if !ok {
		return "", errors.New("IntegrityError")
	}
	// check if the HMAC satisfies the file_info
	sha := userlib.NewSHA256()
	sha.Write([]byte("fileinfoHMAC"+string(userdata.Username)))
	file_info_hmac_address := sha.Sum([]byte(""))
	expect_file_info_hmac, ok := userlib.DatastoreGet(string(file_info_hmac_address))
	if !ok {
		return "", errors.New("IntegrityError")
	}
	temp_mac := userlib.NewHMAC([]byte(userdata.UserPassword))
	temp_mac.Write(temp_data)
	file_info_hmac := temp_mac.Sum(nil)
	if string(expect_file_info_hmac) != string(file_info_hmac) {
		return "", errors.New("IntegrityError")
	}

	// recover the file info
	recover_data := make([]byte, len(temp_data))
	temp_decryptor := userlib.CFBDecrypter(userdata.FileInfoPassword, userdata.NonceForFileInfoData)
	temp_decryptor.XORKeyStream(recover_data, temp_data)

	// unmarshal the data
	var file_info FileInfo
	err = json.Unmarshal(recover_data, &file_info)
	if err != nil {
		return "", err
	}

	// find the filename
	index := len(file_info.FileName)
	flag := 0
	var a int
	for a = 0; a < index; a++ {
		if userlib.Equal(file_info.FileName[a], []byte(filename)) {
			flag = 1
			break
		}
	}
	if flag == 0 {
		return "", errors.New("NotValidFilename")
	}

	// get the file info
	share_file_info.KeyForDecrypt = file_info.KeyForDecrypt[a]
	share_file_info.NonceForDecrypt = file_info.NonceForDecrypt[a]
	share_file_info.StoreAddress = file_info.StoreAddress[a]
	share_file_info.KeyForHMAC = file_info.KeyForHMAC[a]
	share_file_info.NumberAddress = file_info.NumberAddress[a]

	// marshal the data
	file_info_data_marshaled, err := json.Marshal(share_file_info)
	if err != nil {
		return "", err
	}

	// use the key to encrypt
	encrypted_file_info_data := CalcEncCFBAES(AES_key, share_record.NonceForEncrypt, file_info_data_marshaled)
	share_record.DataAfterEncrypt = encrypted_file_info_data

	// get the sign on the original data
	file_info_data_marshaled_hashed := CalcHash(file_info_data_marshaled)
	RSA_sig_on_DT, err := userlib.RSASign(userdata.PrivateKey, file_info_data_marshaled_hashed)
	if err != nil {
		return "", err
	}
	share_record.RSASignOnHashCT = RSA_sig_on_DT

	// marshal the message to get the message
	result_data, err := json.Marshal(share_record)
	if err != nil {
		return "", err
	}

	return string(result_data), nil
}

// golang doesn't support function overload
// so I have to do this
// what a f***ing language!

func (userdata *User) StoreFileWithIndex(filename string, new_file_info sharingData) error{
	// first get the file info data
	temp_data, ok := userlib.DatastoreGet(string(userdata.FileInfoAddress))
	if !ok {   // we don't have the return value... So nothing happens...
		return errors.New("IntegrityError")
	}
	// check if the HMAC satisfies the file_info
	file_info_hmac_address := CalcHash([]byte("fileinfoHMAC"+string(userdata.Username)))
	expect_file_info_hmac, ok := userlib.DatastoreGet(string(file_info_hmac_address))
	if !ok {
		return errors.New("IntegrityError")
	}
	file_info_hmac := CalcHMAC(userdata.UserPassword, temp_data)
	if !userlib.Equal(expect_file_info_hmac, file_info_hmac) {
		return errors.New("IntegrityError")
	}

	// recover the file info
	recover_data := CalcDecCFBAES(userdata.FileInfoPassword, userdata.NonceForFileInfoData, temp_data)
	// unmarshal the data
	var file_info FileInfo
	err := json.Unmarshal(recover_data, &file_info)
	if err != nil {
		return errors.New("IntegrityError")
	}

	// find the filename
	index := len(file_info.StoreAddress)
	var a int
	flag := 0
	for a = 0; a < index; a++ {
		if filename == string(file_info.FileName[a]) {
			flag = 1    // overwrite the data
			break
		}
	}

	if flag == 0 {
		file_info.FileName = append(file_info.FileName, []byte(filename))
		file_info.NumberAddress = append(file_info.NumberAddress, new_file_info.NumberAddress)
		file_info.StoreAddress = append(file_info.StoreAddress, new_file_info.StoreAddress)   // address 32 bytes
		file_info.KeyForDecrypt = append(file_info.KeyForDecrypt, new_file_info.KeyForDecrypt) // AES 128
		file_info.NonceForDecrypt = append(file_info.NonceForDecrypt, new_file_info.NonceForDecrypt)
		file_info.KeyForHMAC = append(file_info.KeyForHMAC, new_file_info.KeyForHMAC) // length of the key for HMAC 16 bytes
	} else {     // update the corresponding file info
		return errors.New("RepeatedFileName!")     // according to Nick's answer on Piazza, "It is up to you what you do"
	}

	// restore the file info
	file_info_marshal, err := json.Marshal(file_info)
	if err != nil {
		return errors.New("IntegrityError")
	}
	// encrypt the file info
	to_store_file_info_data := CalcEncCFBAES(userdata.FileInfoPassword, userdata.NonceForFileInfoData, file_info_marshal)
	// store the file info data
	userlib.DatastoreSet(string(userdata.FileInfoAddress), to_store_file_info_data)

	// update the hmac for file info
	new_file_info_hmac := CalcHMAC(userdata.UserPassword, to_store_file_info_data)
	new_file_info_hmac_address := CalcHash([]byte("fileinfoHMAC" + string(userdata.Username)))
	userlib.DatastoreSet(string(new_file_info_hmac_address), new_file_info_hmac)
	return nil
}



// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	// first unmarshal the data, get the key
	var share_record sharingRecord
	err := json.Unmarshal([]byte(msgid), &share_record)
	if err != nil {
		return err
	}
	Data_key, err := userlib.RSADecrypt(userdata.PrivateKey, share_record.KeyAfterEncrypt, nil)
	if err != nil {
		return err
	}

	// use the Data_key to decrypte the file record
	marshaled_file_info := CalcDecCFBAES(Data_key, share_record.NonceForEncrypt, share_record.DataAfterEncrypt)

	// unmarshal the record
	var file_info sharingData
	err = json.Unmarshal(marshaled_file_info, &file_info)
	if err != nil {
		return err
	}

	// TODO: check if there are MITM

	// store the data in the user's datastore
	err = userdata.StoreFileWithIndex(filename, file_info)
	if err != nil {
		return err
	}


	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}

