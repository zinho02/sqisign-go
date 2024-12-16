package sqisign

import (
	"encoding/hex"
	"unsafe"
)

//#include <stdlib.h>
import "C"

func main() {
	pk, sk, _ := GenerateKey()
	defer C.free(unsafe.Pointer(sk.CSecretKey))
	defer C.free(unsafe.Pointer(pk.CPublicKey))
	println("=================SECRET KEY===================")
	PrintHex(sk.CSecretKey, C_CRYPTO_SECRETKEYBYTES)
	println("=================PUBLIC KEY===================")
	PrintHex(pk.CPublicKey, C_CRYPTO_PUBLICKEYBYTES)
	sig, _ := sk.Sign(nil, []byte("oioi"), nil)
	println("=================SIGNATURE===================")
	println(hex.EncodeToString(sig))
	msg, _ := pk.Verify(4, sig)
	println("=================VERIFY===================")
	println(hex.EncodeToString(msg))
	println("=================PUBLIC===================")
	PrintHex(sk.Public().CPublicKey, C_CRYPTO_PUBLICKEYBYTES)
}
