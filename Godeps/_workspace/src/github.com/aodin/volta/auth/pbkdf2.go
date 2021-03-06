package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

/*
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

func key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

func Pbkdf2(cleartext, salt []byte, rounds int, h func() hash.Hash) []byte {
	// Use the hash Size as the keyLen
	return key(cleartext, salt, rounds, h().Size(), h)
}

// TODO declare private?
type PBKDF2_Base struct {
	BaseHasher
	rounds int
	digest func() hash.Hash // TODO move to base hasher?
}

func (h *PBKDF2_Base) Encode(cleartext, salt string) string {
	// TODO these []byte conversions are a bit silly
	hashed := EncodeBase64String(
		Pbkdf2(
			[]byte(cleartext),
			[]byte(salt),
			h.rounds,
			h.digest,
		),
	)
	return strings.Join(
		[]string{
			h.Algorithm(),
			fmt.Sprintf("%d", h.rounds),
			salt,
			hashed,
		},
		"$")
}

func (h *PBKDF2_Base) Verify(cleartext, encoded string) bool {
	// Split the saved hash apart
	parts := strings.SplitN(encoded, "$", 4)

	// The algorithm should match this hasher
	algo := parts[0]
	if algo != h.Algorithm() {
		return false
	}
	rounds64, err := strconv.ParseInt(parts[1], 10, 0)
	if err != nil {
		return false
	}
	rounds := int(rounds64)
	salt := parts[2]

	// Generate a new hash using the given cleartext
	hashed := Pbkdf2([]byte(cleartext), []byte(salt), rounds, h.digest)
	return ConstantTimeStringCompare(EncodeBase64String(hashed), parts[3])
}

func NewPBKDF2Hasher(alg string, n int, digest func() hash.Hash) *PBKDF2_Base {
	return &PBKDF2_Base{NewBaseHasher(alg), n, digest}
}

func init() {
	pbkdf2_sha256 := NewPBKDF2Hasher("pbkdf2_sha256", 10000, sha256.New)
	RegisterHasher(pbkdf2_sha256.algorithm, pbkdf2_sha256)

	pbkdf2_sha1 := NewPBKDF2Hasher("pbkdf2_sha1", 10000, sha1.New)
	RegisterHasher(pbkdf2_sha1.algorithm, pbkdf2_sha1)
}
