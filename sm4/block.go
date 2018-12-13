package sm4

import (
	"encoding/binary"
	"math/bits"
)

func expandKeyGo(key []byte, enc, dec []uint32) {
	var mK [4]uint32
	var x [5]uint32
	mK[0] = binary.BigEndian.Uint32(key[0:4])
	mK[1] = binary.BigEndian.Uint32(key[4:8])
	mK[2] = binary.BigEndian.Uint32(key[8:12])
	mK[3] = binary.BigEndian.Uint32(key[12:16])

	x[0] = mK[0] ^ fK[0]
	x[1] = mK[1] ^ fK[1]
	x[2] = mK[2] ^ fK[2]
	x[3] = mK[3] ^ fK[3]
	for i := 0; i < 32; i++ {
		x[(i+4)%5] = encRound(x[i%5], x[(i+1)%5], x[(i+2)%5], x[(i+3)%5], x[(i+4)%5], enc[:], i)
	}

	x[0] = mK[0] ^ fK[0]
	x[1] = mK[1] ^ fK[1]
	x[2] = mK[2] ^ fK[2]
	x[3] = mK[3] ^ fK[3]
	for i := 0; i < 32; i++ {
		x[(i+4)%5] = decRound(x[i%5], x[(i+1)%5], x[(i+2)%5], x[(i+3)%5], x[(i+4)%5], dec[:], i)
	}

	return
}

func encRound(x0 uint32, x1 uint32, x2 uint32, x3 uint32, x4 uint32, rk []uint32, i int) uint32 {
	x4 = x0 ^ tAp(x1^x2^x3^cK[i])
	rk[i] = x4
	return x4
}

func decRound(x0 uint32, x1 uint32, x2 uint32, x3 uint32, x4 uint32, rk []uint32, i int) uint32 {
	x4 = x0 ^ tAp(x1^x2^x3^cK[i])
	rk[31-i] = x4
	return x4
}

func lAp(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 13) ^ bits.RotateLeft32(b, 23)
}

func tAp(z uint32) uint32 {
	return lAp(tau(z))
}

func tau(a uint32) uint32 {
	var aArr [4]byte
	var bArr [4]byte
	binary.BigEndian.PutUint32(aArr[:], a)
	bArr[0] = sBox[aArr[0]]
	bArr[1] = sBox[aArr[1]]
	bArr[2] = sBox[aArr[2]]
	bArr[3] = sBox[aArr[3]]
	return binary.BigEndian.Uint32(bArr[:])
}

func processBlock(rk []uint32, in []byte, out []byte) {
	var x [BlockSize / 4]uint32
	x[0] = binary.BigEndian.Uint32(in[0:4])
	x[1] = binary.BigEndian.Uint32(in[4:8])
	x[2] = binary.BigEndian.Uint32(in[8:12])
	x[3] = binary.BigEndian.Uint32(in[12:16])

	for i := 0; i < 32; i += 4 {
		x[0] = f0(x[:], rk[i])
		x[1] = f1(x[:], rk[i+1])
		x[2] = f2(x[:], rk[i+2])
		x[3] = f3(x[:], rk[i+3])
	}
	r(x[:])

	binary.BigEndian.PutUint32(out[0:4], x[0])
	binary.BigEndian.PutUint32(out[4:8], x[1])
	binary.BigEndian.PutUint32(out[8:12], x[2])
	binary.BigEndian.PutUint32(out[12:16], x[3])
}

func l(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^
		bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
}

func t(z uint32) uint32 {
	return l(tau(z))
}

func r(a []uint32) {
	a[0] = a[0] ^ a[3]
	a[3] = a[0] ^ a[3]
	a[0] = a[0] ^ a[3]
	a[1] = a[1] ^ a[2]
	a[2] = a[1] ^ a[2]
	a[1] = a[1] ^ a[2]
}

func f0(x []uint32, rk uint32) uint32 {
	return x[0] ^ t(x[1]^x[2]^x[3]^rk)
}

func f1(x []uint32, rk uint32) uint32 {
	return x[1] ^ t(x[2]^x[3]^x[0]^rk)
}

func f2(x []uint32, rk uint32) uint32 {
	return x[2] ^ t(x[3]^x[0]^x[1]^rk)
}

func f3(x []uint32, rk uint32) uint32 {
	return x[3] ^ t(x[0]^x[1]^x[2]^rk)
}
