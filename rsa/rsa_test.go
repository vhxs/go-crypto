package rsa

import "testing"

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

// adding comment here to push some change