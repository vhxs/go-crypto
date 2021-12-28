package crypto

import (
	"errors"
)

type public_key struct {
	prime_product int
	exp_enc       int
}

type private_key struct {
	prime_product int
	exp_dec       int
}

func gcd(x int, y int) int {
	if y == 0 {
		return x
	} else {
		return gcd(y, x%y)
	}
}

// See definition and relationship with Euler's totient function here:
//  https://en.wikipedia.org/wiki/Carmichael_function
func carmichael(p int, q int) int {
	product := (p - 1) * (q - 1)
	return product / gcd(p-1, q-1)
}

func generate_public_key(p int, q int, e int) *public_key {
	var n = p * q
	new_public_key := public_key{prime_product: n, exp_enc: e}
	return &new_public_key
}

// Multiplicative inverse of e, in the group \mathbb{Z}_lambda
//  find pseudocode here: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
func multiplicative_inverse(e int, lambda int) (int, error) {
	var t = 0
	var r = lambda

	var new_t = 1
	var new_r = e

	var quotient int
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

func generate_private_key(p int, q int, e int) (*private_key, error) {
	var n = p * q
	var lambda = carmichael(p, q)
	if d, err := multiplicative_inverse(e, lambda); err != nil {
		return nil, errors.New("Invalid choice of e")
	} else {
		new_private_key := private_key{prime_product: n, exp_dec: d}
		return &new_private_key, nil
	}
}

func generate_key_pair(p int, q int, e int) (*public_key, *private_key, error) {
	new_public_key := generate_public_key(p, q, e)
	if new_private_key, err := generate_private_key(p, q, e); err != nil {
		return nil, nil, err
	} else {
		return new_public_key, new_private_key, nil
	}
}
