package main

import (
	"fmt"
	"github.com/vhxs/cryptography/rsa"
)

func main() {
	// key gen
	pub_key, prv_key, _ := rsa.Generate_key_pair(7, 19, 5)

	// encrypt
	ciphertext := rsa.Encrypt("I'm a plaintext", pub_key)

	// print encrypted
	fmt.Println(ciphertext)

	// decrypt
	plaintext, _ := rsa.Decrypt(ciphertext, prv_key)

	// print decrypted (hopefully it's the same string back)
	fmt.Println(plaintext)
}
