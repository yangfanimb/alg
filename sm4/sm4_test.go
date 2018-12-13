package sm4

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"internal/utils"
	"testing"
)

type sm4CbcTestData struct {
	key []byte
	iv  []byte
	in  []byte
	out []byte
}

var testData = []sm4CbcTestData{
	{
		key: []byte{0x7b, 0xea, 0x0a, 0xa5, 0x45, 0x8e, 0xd1, 0xa3, 0x7d, 0xb1, 0x65, 0x2e, 0xfb, 0xc5, 0x95, 0x05},
		iv:  []byte{0x70, 0xb6, 0xe0, 0x8d, 0x46, 0xee, 0x82, 0x24, 0x45, 0x60, 0x0b, 0x25, 0xc4, 0x71, 0xfa, 0xba},
		in:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		out: []byte{0xca, 0x55, 0xc5, 0x15, 0x0b, 0xf7, 0xf4, 0x6f, 0xc9, 0x89, 0x2a, 0xce, 0x49, 0x78, 0x93, 0x03},
	},
	{
		key: []byte{0x7b, 0xea, 0x0a, 0xa5, 0x45, 0x8e, 0xd1, 0xa3, 0x7d, 0xb1, 0x65, 0x2e, 0xfb, 0xc5, 0x95, 0x05},
		iv:  []byte{0x70, 0xb6, 0xe0, 0x8d, 0x46, 0xee, 0x82, 0x24, 0x45, 0x60, 0x0b, 0x25, 0xc4, 0x71, 0xfa, 0xba},
		in:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		out: []byte{0x95, 0xe1, 0xec, 0x3b, 0x56, 0x4a, 0x46, 0x71, 0xe7, 0xd6, 0xb1, 0x10, 0xe9, 0x09, 0x0b, 0x1b, 0xb7, 0xb5, 0x9e, 0x8d, 0x74, 0x47, 0x1e, 0x70, 0x86, 0x04, 0x6b, 0xe8, 0x78, 0x00, 0x45, 0x32},
	},
}

func TestECB(t *testing.T) {
	fmt.Println("ECB begin")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	block, err := NewCipher(data)
	if err != nil {
		t.Error(err.Error())
		return
	}

	src := utils.PKCS5Padding(data, block.BlockSize())
	blockMode := NewECBEncrypter(block)
	result := make([]byte, len(src))
	blockMode.CryptBlocks(result, src)
	fmt.Printf("encrypt result:%s\n", hex.EncodeToString(result))

	blockMode = NewECBDecrypter(block)
	plain := make([]byte, len(result))
	blockMode.CryptBlocks(plain, result)
	fmt.Printf("decrypt result:%s\n", hex.EncodeToString(plain))
	plain = utils.PKCS5UnPadding(plain)
	fmt.Printf("unpack result:%x\n", plain)

	fmt.Println("ECB end")
}

func TestCBC(t *testing.T) {
	fmt.Println("CBC begin")
	for _, data := range testData {
		block, err := NewCipher(data.key)
		if err != nil {
			t.Error(err.Error())
			return
		}

		blockMode := cipher.NewCBCEncrypter(block, data.iv)
		result := make([]byte, len(data.out))
		blockMode.CryptBlocks(result, utils.PKCS5Padding(data.in, block.BlockSize()))
		fmt.Printf("encrypt result:%s\n", hex.EncodeToString(result))
		if !bytes.Equal(result, data.out) {
			t.Error("encrypt result not equal expected")
			return
		}

		blockMode = cipher.NewCBCDecrypter(block, data.iv)
		plain := make([]byte, len(result))
		blockMode.CryptBlocks(plain, result)
		fmt.Printf("decrypt result:%s\n", hex.EncodeToString(plain))
		plain = utils.PKCS5UnPadding(plain)
		fmt.Printf("unpack result:%x\n", plain)
		if !bytes.Equal(plain, data.in) {
			t.Error("decrypt result not equal expected")
			return
		}
	}
	fmt.Println("CBC end")
}

func TestOFB(t *testing.T) {
	fmt.Println("OFB begin")
	block, err := NewCipher(testData[0].key)
	if err != nil {
		t.Error(err.Error())
		return
	}

	stream := cipher.NewOFB(block, testData[0].iv)
	result := make([]byte, len(testData[0].in))
	stream.XORKeyStream(result, testData[0].in)
	fmt.Printf("encrypt result:%s\n", hex.EncodeToString(result))

	plain := make([]byte, len(result))
	stream = cipher.NewOFB(block, testData[0].iv)
	stream.XORKeyStream(plain, result)
	fmt.Printf("decrypt result:%s\n", hex.EncodeToString(plain))
	fmt.Println("OFB end")
}
