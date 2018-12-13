package sm4

import (
	"crypto/cipher"
	"strconv"

	"github.com/yangfanimb/alg/internal/subtlex"
)

const (
	// BlockSize in bytes.
	BlockSize = 16
	// KeySize in bytes.
	KeySize = 16
)

// A cipher is an instance of SM4 encryption using a particular key.
type sm4Cipher struct {
	enc []uint32
	dec []uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/sm4: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the SM4 key
// 16*8=128
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	if k != KeySize {
		return nil, KeySizeError(k)
	}

	return newCipher(key)
}

// newCipherGeneric creates and returns a new cipher.Block
// implemented in pure Go.
func newCipherGeneric(key []byte) (cipher.Block, error) {
	n := len(key) + 16
	c := sm4Cipher{make([]uint32, n), make([]uint32, n)}
	expandKeyGo(key, c.enc, c.dec)
	return &c, nil
}

func (c *sm4Cipher) BlockSize() int { return BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/sm4: output not full block")
	}
	if subtlex.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/sm4: invalid buffer overlap")
	}

	processBlock(c.enc, src, dst)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/sm4: output not full block")
	}
	if subtlex.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("crypto/sm4: invalid buffer overlap")
	}

	processBlock(c.dec, src, dst)
}
