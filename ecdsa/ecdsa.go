// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in FIPS 186-3.
//
// This implementation derives the nonce from an AES-CTR CSPRNG keyed by:
//
// SHA2-512(priv.D || entropy || hash)[:32]
//
// The CSPRNG key is indifferentiable from a random oracle as shown in
// [Coron], the AES-CTR stream is indifferentiable from a random oracle
// under standard cryptographic assumptions (see [Larsson] for examples).
//
// References:
//   [Coron]
//     https://cs.nyu.edu/~dodis/ps/merkle.pdf
//   [Larsson]
//     https://www.nada.kth.se/kurser/kth/2D1441/semteo03/lecturenotes/assump.pdf
package ecdsa

// Further references:
//   [NSA]: Suite B implementer's guide to FIPS 186-3
//     https://apps.nsa.gov/iaarchive/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/suite-b-implementers-guide-to-fips-186-3-ecdsa.cfm
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf

import (
	"crypto"
	"crypto/elliptic"
	"github.com/tjfoc/gmsm/sm2"
	"io"
	"math/big"
)

type PublicKey struct {
	sm2.PublicKey
}

//// PublicKey represents an ECDSA public key.
//type PublicKey struct {
//	elliptic.Curve
//	X, Y *big.Int
//}

// Any methods implemented on PublicKey might need to also be implemented on
// PrivateKey, as the latter embeds the former and will expose its methods.

// Equal reports whether pub and x have the same value.
//
// Two keys are only considered to have the same value if they have the same Curve value.
// Note that for example elliptic.P256() and elliptic.P256().Params() are different
// values, as the latter is a generic not constant time implementation.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.X.Cmp(xx.X) == 0 && pub.Y.Cmp(xx.Y) == 0 &&
		// Standard library Curve implementations are singletons, so this check
		// will work for those. Other Curves might be equivalent even if not
		// singletons, but there is no definitive way to check for that, and
		// better to err on the side of safety.
		pub.Curve == xx.Curve
}

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	sm2.PrivateKey
}
//type PrivateKey struct {
//	PublicKey
//	D *big.Int
//}

// Public returns the public key corresponding to priv.
//func (priv *PrivateKey) Public() crypto.PublicKey {
//	return &priv.PublicKey
//}

// Equal reports whether priv and x have the same value.
//
// See PublicKey.Equal for details on how Curve is compared.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}

	return priv.PublicKey.X.Cmp(xx.X) == 0 && priv.PublicKey.Y.Cmp(xx.Y) == 0 &&
		// Standard library Curve implementations are singletons, so this check
		// will work for those. Other Curves might be equivalent even if not
		// singletons, but there is no definitive way to check for that, and
		// better to err on the side of safety.
		priv.PublicKey.Curve == xx.Curve

}

//Sign signs digest with priv, reading randomness from rand. The opts argument
//is not currently used but, in keeping with the crypto.Signer interface,
//should be the hash function used to digest the message.
//
//This method implements crypto.Signer, which is an interface to support keys
//where the private part is kept in, for example, a hardware module. Common
//uses should use the Sign function in this package directly.
//func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
//	r, s, err := Sign(rand, priv, digest)
//	if err != nil {
//		return nil, err
//	}
//
//	var b cryptobyte.Builder
//	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
//		b.AddASN1BigInt(r)
//		b.AddASN1BigInt(s)
//	})
//	return b.Bytes()
//}


// GenerateKey generates a public and private key pair.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	priv, err := sm2.GenerateKey(rand)
	return &PrivateKey{*priv}, err

	//k, err := randFieldElement(c, rand)
	//if err != nil {
	//	return nil, err
	//}
	//
	//priv := new(PrivateKey)
	//priv.PublicKey.Curve = c
	//priv.D = k
	//priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	//return priv, nil
}



// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	return sm2.Sm2Sign(&priv.PrivateKey, hash, nil, rand)
	//randutil.MaybeReadByte(rand)
	//
	//// Get min(log2(q) / 2, 256) bits of entropy from rand.
	//entropylen := (priv.Curve.Params().BitSize + 7) / 16
	//if entropylen > 32 {
	//	entropylen = 32
	//}
	//entropy := make([]byte, entropylen)
	//_, err = io.ReadFull(rand, entropy)
	//if err != nil {
	//	return
	//}
	//
	//// Initialize an SHA-512 hash context; digest ...
	//md := sha512.New()
	//md.Write(priv.D.Bytes()) // the private key,
	//md.Write(entropy)        // the entropy,
	//md.Write(hash)           // and the input hash;
	//key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	//// which is an indifferentiable MAC.
	//
	//// Create an AES-CTR instance to use as a CSPRNG.
	//block, err := aes.NewCipher(key)
	//if err != nil {
	//	return nil, nil, err
	//}
	//
	//// Create a CSPRNG that xors a stream of zeros with
	//// the output of the AES-CTR instance.
	//csprng := cipher.StreamReader{
	//	R: zeroReader,
	//	S: cipher.NewCTR(block, []byte(aesIV)),
	//}
	//
	//// See [NSA] 3.4.1
	//c := priv.PublicKey.Curve
	//return sign(priv, &csprng, c, hash)
}



// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature. The security of the private key
// depends on the entropy of rand.
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {

	sm2Priv := &priv.PrivateKey
	return sm2Priv.Sign(rand, hash, nil)
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {

	return sm2.Sm2Verify(&pub.PublicKey, hash, nil, r, s)

	//// See [NSA] 3.4.2
	//c := pub.Curve
	//N := c.Params().N
	//
	//if r.Sign() <= 0 || s.Sign() <= 0 {
	//	return false
	//}
	//if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
	//	return false
	//}
	//return verify(pub, c, hash, r, s)
}


// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func VerifyASN1(pub *PublicKey, hash, sig []byte) bool {

	return pub.Verify(hash, sig)

	//var (
	//	r, s  = &big.Int{}, &big.Int{}
	//	inner cryptobyte.String
	//)
	//input := cryptobyte.String(sig)
	//if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
	//	!input.Empty() ||
	//	!inner.ReadASN1Integer(r) ||
	//	!inner.ReadASN1Integer(s) ||
	//	!inner.Empty() {
	//	return false
	//}
	//return Verify(pub, hash, r, s)
}

//type zr struct {
//	io.Reader
//}
//
//// Read replaces the contents of dst with zeros.
//func (z *zr) Read(dst []byte) (n int, err error) {
//	for i := range dst {
//		dst[i] = 0
//	}
//	return len(dst), nil
//}
//
//var zeroReader = &zr{}
