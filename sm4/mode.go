package sm4

import "crypto/cipher"

// cbcEncAble is implemented by cipher.Blocks that can provide an optimized
// implementation of CBC encryption through the cipher.BlockMode interface.
// See crypto/cipher/cbc.go.
type cbcEncAble interface {
	NewCBCEncrypter(iv []byte) cipher.BlockMode
}

// cbcDecAble is implemented by cipher.Blocks that can provide an optimized
// implementation of CBC decryption through the cipher.BlockMode interface.
// See crypto/cipher/cbc.go.
type cbcDecAble interface {
	NewCBCDecrypter(iv []byte) cipher.BlockMode
}
