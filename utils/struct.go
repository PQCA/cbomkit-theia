package utils

import (
	"encoding/binary"
	"github.com/mitchellh/hashstructure/v2"
)

func Struct8Byte(a any) [8]byte {
	hash, err := hashstructure.Hash(a, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		panic(err)
	}
	var b8 [8]byte
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, hash)
	copy(b8[:], b)
	return b8
}
