package main

import (
	"fmt"
	"crypto/sha1"
	"bytes"
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"strconv"
	"time"
	"os"
)

type Hash func() hash.Hash

func GetInterval(period int64) (int64, int64) {
	t := time.Now().Unix()
	iv := t / period
	remain := period - (t - (iv * period))
	return iv, remain
}

func GetCode(secret32 string, iv int64, h Hash, digits int) (string, error) {
	key, err := base32.StdEncoding.DecodeString(secret32)
	if err != nil {
		return "", err
	}

	msg := bytes.Buffer{}
	binary.Write(&msg, binary.BigEndian, iv)

	mac := hmac.New(h, key)
	mac.Write(msg.Bytes())
	digest := mac.Sum(nil)

	offset := digest[len(digest)-1] & 0xF
	trunc := digest[offset : offset+4]

	var code int32
	truncBytes := bytes.NewBuffer(trunc)
	_ = binary.Read(truncBytes, binary.BigEndian, &code)

	code = (code & 0x7FFFFFFF) % 1000000

	stringCode := strconv.Itoa(int(code))
	for len(stringCode) < digits {
		stringCode = "0" + stringCode
	}
	return stringCode, nil
}

func main() {
	if len(os.Args)<2{
		fmt.Println("Hash needed")
		os.Exit(1)
	}
	t, o := GetInterval(30)
	code, _ := GetCode(os.Args[1], t, sha1.New, 6)
	fmt.Println(code, o)
}