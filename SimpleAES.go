package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// 兼容C#的SimpleAES https://github.com/jonjomckay/dotnet-simpleaes

const (
	saltSize = 16 // Salt 长度
	keySize  = 32 // 密钥长度
)

func GenerateKey(password, salt []byte) ([]byte, error) {
	return pbkdf2.Key(password, salt, 10000, keySize, sha1.New), nil
}

func Decrypt(ciphertext string, password []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	salt := data[:saltSize]
	key, err := GenerateKey(password, salt)
	if err != nil {
		return nil, err
	}

	encryptedData := data[saltSize:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 将 IV 从密文中提取出来
	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedData, encryptedData)

	// 去除 PKCS#7 填充
	paddingSize := int(encryptedData[len(encryptedData)-1])
	encryptedData = encryptedData[:len(encryptedData)-paddingSize]

	return encryptedData, nil
}

func Encrypt(data []byte, password []byte) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key, err := GenerateKey(password, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 使用 PKCS#7 填充方式对明文进行填充
	paddingSize := aes.BlockSize - len(data)%aes.BlockSize
	padding := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	data = append(data, padding...)

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(data, data)

	// 将 Salt、IV 和加密后的数据拼接起来，并进行 base64 编码
	ciphertext := append(salt, iv...)
	ciphertext = append(ciphertext, data...)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
