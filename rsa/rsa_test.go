package rsa

import (
	"math/rand"
	"testing"
)

func TestGcd(t *testing.T) {
	want := int64(3)
	if got := gcd(21, 15); got != want {
		t.Errorf("gcd(%d, %d) = %d, want %d", 21, 15, got, want)
	}
}

func TestMultiplicativeInverse(t *testing.T) {
	want := int64(3)
	if got, err := multiplicative_inverse(3, 8); got != want || err != nil {
		t.Errorf("inv %d mod %d is %d, want %d", 3, 8, got, want)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	p := int64(61)
	q := int64(53)
	e := int64(17)

	expected_product := int64(3233)
	expected_exp_enc := int64(17)
	expected_exp_dec := int64(413)

	new_public_key, new_private_key, err := Generate_key_pair(p, q, e)

	if new_public_key.prime_product != expected_product {
		t.Errorf("Expected product %d, got %d", expected_product, new_public_key.prime_product)
	} else if new_private_key.prime_product != expected_product {
		t.Errorf("Expected product %d, got %d", expected_product, new_private_key.prime_product)
	} else if new_public_key.exp_enc != expected_exp_enc {
		t.Errorf("Expected encryption exponent %d, got %d", expected_exp_enc, new_public_key.exp_enc)
	} else if new_private_key.exp_dec != expected_exp_dec {
		t.Errorf("Expected decryption exponent %d, got %d", expected_exp_dec, new_private_key.exp_dec)
	} else if err != nil {
		t.Error(err.Error())
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate key pair
	pub_key, prv_key, err := Generate_key_pair(7, 19, 5)
	if err != nil {
		t.Error(err.Error())
	}

	// try out random plaintexts, check whether dec(enc(text)) == text
	for i := 0; i < 100; i++ {
		rand_string := randStringBytes(20)
		ciphertext := Encrypt(rand_string, pub_key)
		decrypted, err := Decrypt(ciphertext, prv_key)

		if err != nil {
			t.Error(err.Error())
		}

		if rand_string != decrypted {
			t.Errorf("Encrypt and Decrypt are not inverses on input string %s", rand_string)
		}
	}
}

func randStringBytes(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    b := make([]byte, n)
    for i := range b {
        b[i] = letterBytes[rand.Intn(len(letterBytes))]
    }
    return string(b)
}