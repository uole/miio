package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"errors"
)

var (
	ErrUnPadding = errors.New("UnPadding error")
)

type (
	TokenCipher struct {
		Token []byte
		key   []byte
		iv    []byte
	}
)

func (c *TokenCipher) md5Sum(bs ...[]byte) []byte {
	hash := md5.New()
	for _, b := range bs {
		hash.Write(b)
	}
	return hash.Sum(nil)
}

func (c *TokenCipher) PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	buf := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, buf...)
}

func (c *TokenCipher) PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return src, ErrUnPadding
	}
	buf := int(src[length-1])
	if length < buf {
		return src, ErrUnPadding
	}
	return src[:(length - buf)], nil
}

func (c *TokenCipher) Encrypt(in []byte) (out []byte, err error) {
	var (
		mode  cipher.BlockMode
		block cipher.Block
	)
	if block, err = aes.NewCipher(c.key); err != nil {
		return
	}
	mode = cipher.NewCBCEncrypter(block, c.iv)
	in = c.PKCS7Padding(in, mode.BlockSize())
	out = make([]byte, len(in))
	mode.CryptBlocks(out, in)
	return
}

func (c *TokenCipher) Decrypt(in []byte) (out []byte, err error) {
	var (
		mode  cipher.BlockMode
		block cipher.Block
	)
	if block, err = aes.NewCipher(c.key); err != nil {
		return
	}
	out = make([]byte, len(in))
	mode = cipher.NewCBCDecrypter(block, c.iv)
	mode.CryptBlocks(out, in)
	return c.PKCS7UnPadding(out)
}

func NewTokenCipher(token []byte) *TokenCipher {
	c := &TokenCipher{
		Token: make([]byte, len(token)),
	}
	copy(c.Token[:], token[:])
	c.key = c.md5Sum(c.Token)
	c.iv = c.md5Sum(c.key, c.Token)
	return c
}
