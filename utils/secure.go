package utils

import (
	"crypto/md5"
	"encoding/hex"
)

// SecureKey returns MD5 hash for the given key
func SecureKey(key string) string {
	hash := md5.Sum([]byte(key))
	return hex.EncodeToString(hash[:])
}
