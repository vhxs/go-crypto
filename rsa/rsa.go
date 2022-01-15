package rsa

import (
	"errors"
	"fmt"
)

type public_key struct {
	prime_product int64
	exp_enc       int64
}

type private_key struct {
	prime_product int64
	exp_dec       int64
}

func gcd(x int64, y int64) int64 {
	if y == 0 {
		return x
	} else {
		return gcd(y, x%y)
	}
}

// See definition and relationship with Euler's totient function here:
//  https://en.wikipedia.org/wiki/Carmichael_function
func carmichael(p int64, q int64) int64 {
	product := (p - 1) * (q - 1)
	return product / gcd(p-1, q-1)
}

func generate_public_key(p int64, q int64, e int64) *public_key {
	var n = p * q
	new_public_key := public_key{prime_product: n, exp_enc: e}
	return &new_public_key
}

// Multiplicative inverse of e, in the group \mathbb{Z}_lambda
//  find pseudocode here: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
func multiplicative_inverse(e int64, lambda int64) (int64, error) {
	var t int64 = 0
	var r = lambda

	var new_t int64 = 1
	var new_r = e

	var quotient int64
	for new_r != 0 {
		quotient = r / new_r
		t, new_t = new_t, t-quotient*new_t
		r, new_r = new_r, r-quotient*new_r
	}

	if r > 1 {
		return -1, errors.New("Not invertible")
	}
	if t < 0 {
		t += lambda
	}
	return t, nil
}

func generate_private_key(p int64, q int64, e int64) (*private_key, error) {
	var n = p * q
	var lambda = carmichael(p, q)
	if d, err := multiplicative_inverse(e, lambda); err != nil {
		return nil, errors.New("Invalid choice of e")
	} else {
		new_private_key := private_key{prime_product: n, exp_dec: d}
		return &new_private_key, nil
	}
}

func Generate_key_pair(p int64, q int64, e int64) (*public_key, *private_key, error) {
	new_public_key := generate_public_key(p, q, e)
	if new_private_key, err := generate_private_key(p, q, e); err != nil {
		return nil, nil, err
	} else {
		return new_public_key, new_private_key, nil
	}
}

func encode(plaintext string) []byte {
	return []byte(plaintext)
}

func decode(encoded []byte) string {
	return string(encoded)
}

// math.Pow expects floats
func intPowMod(a, b, n int64) int64 {
    if b == 0 {
        return 1
    }
    result := a
    for i := int64(2); i <= b; i++ {
        result *= a
		result = result % n
    }
    return result
}

func Encrypt(plaintext string, pub_key *public_key) []int64 {
	encoded_text := encode(plaintext)
	text_length := len(encoded_text)
	ciphertext := make([]int64, text_length)

	n := pub_key.prime_product
	e := pub_key.exp_enc
	for i := 0; i < text_length; i++ {
		ciphertext[i] = intPowMod(int64(encoded_text[i]), e, n)
	}

	return ciphertext
}

func Decrypt(ciphertext []int64, prv_key *private_key) (string, error) {
	text_length := len(ciphertext)
	plaintext_bytes := make([]byte, text_length)

	n := prv_key.prime_product
	d := prv_key.exp_dec
	for i := 0; i < text_length; i++ {
		plaintext_int := intPowMod(ciphertext[i], d, n)
		if plaintext_int > 255 {
			fmt.Println(plaintext_int)
			return "", errors.New("invalid cipher text, not ascii")
		}
		plaintext_bytes[i] = byte(plaintext_int)
	}

	return decode(plaintext_bytes), nil
}