package models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/ShebinSp/Dencryptor/pkg/utils"
	"gorm.io/gorm"
)

type ImageData struct {
	Id       uint `gorm:"primarykey;unique"`
	UserId   uint
	FileName string
	Format   string
	//	Data     []byte
	AecKey []byte
	Hash   string
}

type ImageFileList struct {
	Id       uint `gorm:"primarykey;unique"`
	UserId   uint
	FileName string
	Hash     string
}

// newly created for mongodb
// type Data struct {
// 	Id uint `gorm:"primarykey;unique"`
// 	ImgId uint
// 	File []byte
// }

func (i *ImageData) EncryptAES(plainData []byte) ([]byte, error) {

	// Generate AES key
	aesKey, err := utils.GenerateRandomKey()
	if err != nil {
		return nil, err
	}
	i.AecKey = aesKey

	// Hashing the aesKey
	_ = i.HashKey()

	// Initialize AES cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nounce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nounce)
	if err != nil {
		return nil, err
	}

	cipherData := gcm.Seal(nounce, nounce, plainData, nil)

	// as an update the file will no longer saved in server db but mail to client.
	//	i.Data = cipherData // add the  cipherData to the model and to database

	return cipherData, nil
}

func (i *ImageData) DecryptAES(ciphertext []byte) ([]byte, error) {

	// Initialize AES cipher
	block, err := aes.NewCipher(i.AecKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nounceSize := gcm.NonceSize()
	// nounce, cipherText := i.Data[:nounceSize], i.Data[nounceSize:]
	nounce, cipherText := ciphertext[:nounceSize], ciphertext[nounceSize:]

	plainData, err := gcm.Open(nil, nounce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainData, nil
}

func (i *ImageData) HashKey() string {
	hash := sha256.Sum256(i.AecKey)

	keyHash := hex.EncodeToString(hash[:])
	// id := strconv.Itoa(int(i.Id))
	// keyHash += id

	i.Hash = keyHash

	return keyHash
}

// <--- ImageHashList Operations---> \\

func (i *ImageData) SaveHashToList(id uint, hash string, db *gorm.DB) error {
	var imgHashList ImageFileList

	imgHashList.FileName = i.FileName
	imgHashList.UserId = id
	imgHashList.Hash = hash

	res := db.Create(&imgHashList)
	if res.Error != nil {
		return res.Error
	}
	return nil
}

func (i *ImageData) GenerateFile() {

}
