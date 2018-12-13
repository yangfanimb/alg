// +build amd64 arm64

package sm4

import (
	"crypto/cipher"
	"internal/subtlex"
)

type sm4CipherAsm struct {
	sm4Cipher
}

var supportsSM4 = false

func newCipher(key []byte) (cipher.Block, error) {
	if !supportsSM4 {
		return newCipherGeneric(key)
	}

	n := len(key)
	c := sm4CipherAsm{sm4Cipher{make([]uint32, n), make([]uint32, n)}}

	return &c, nil
}

func (c *sm4CipherAsm) BlockSize() int { return BlockSize }

func (c *sm4CipherAsm) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/sm4: output not full block")
	}
	if subtlex.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/sm4: invalid buffer overlap")
	}
	c.Encrypt(dst, src)
	//encryptBlockAsm(len(c.enc)/4-1, &c.enc[0], &dst[0], &src[0])
}

func (c *sm4CipherAsm) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/sm4: output not full block")
	}
	if subtlex.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/sm4: invalid buffer overlap")
	}

	c.Decrypt(dst, src)
	//decryptBlockAsm(len(c.dec)/4-1, &c.dec[0], &dst[0], &src[0])
}
