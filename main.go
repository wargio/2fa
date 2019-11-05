// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa is a two-factor authentication agent.
//
// Usage:
//
//	2fa -add [-7] [-8] [-hotp] name
//	2fa -list
//	2fa [-clip] name
//
// “2fa -add name” adds a new key to the 2fa keychain with the given name.
// It prints a prompt to standard error and reads a two-factor key from standard input.
// Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.
//
// By default the new key generates time-based (TOTP) authentication codes;
// the -hotp flag makes the new key generate counter-based (HOTP) codes instead.
//
// By default the new key generates 6-digit codes; the -7 and -8 flags select
// 7- and 8-digit codes instead.
//
// “2fa -list” lists the names of all the keys in the keychain.
//
// “2fa name” prints a two-factor authentication code from the key with the
// given name. If “-clip” is specified, 2fa also copies the code to the system
// clipboard.
//
// With no arguments, 2fa prints two-factor authentication codes from all
// known time-based keys.
//
// The default time-based authentication codes are derived from a hash of
// the key and the current time, so it is important that the system clock have
// at least one-minute accuracy.
//
// The keychain is stored unencrypted in the text file $HOME/.2fa.
//
// Example
//
// During GitHub 2FA setup, at the “Scan this barcode with your app” step,
// click the “enter this text code instead” link. A window pops up showing
// “your two-factor secret,” a short string of letters and digits.
//
// Add it to 2fa under the name github, typing the secret at the prompt:
//
//	$ 2fa -add github
//	2fa key for github: nzxxiidbebvwk6jb
//	$
//
// Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:
//
//	$ 2fa github
//	268346
//	$
//
// Or to type less:
//
//	$ 2fa
//	268346	github
//	$
//
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
)

const (
	TypeTOTP        = "TOTP"
	TypeHOTP        = "HOTP"
	AlgorithmSHA1   = "SHA1"
	AlgorithmSHA256 = "SHA256"
	AlgorithmSHA512 = "SHA512"
	AlgorithmMD5    = "MD5"

	counterLen = 20
)

type Key struct {
	Secret    string `json:"secret"`
	Digits    int    `json:"digits"`
	Label     string `json:"label"`
	Algorithm string `json:"algorithm"`
	Type      string `json:"type"`
	Counter   uint64 `json:"counter,omitempty"`
	Period    int    `json:"period,omitempty"`
}

type Keychain struct {
	File string
	Keys []Key
}

var (
	flagAdd    = flag.Bool("add", false, "add a key")
	flagList   = flag.Bool("list", false, "list keys")
	flagHotp   = flag.Bool("hotp", false, "add key as HOTP (counter-based) key")
	flag7      = flag.Bool("7", false, "generate 7-digit code")
	flag8      = flag.Bool("8", false, "generate 8-digit code")
	flagClip   = flag.Bool("clip", false, "copy code to the clipboard")
	flagRemove = flag.Bool("remove", false, "remove a key")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "\t2fa -add [-7] [-8] [-hotp] keyname\n")
	fmt.Fprintf(os.Stderr, "\t2fa -remove keyname\n")
	fmt.Fprintf(os.Stderr, "\t2fa -list\n")
	fmt.Fprintf(os.Stderr, "\t2fa [-clip] keyname\n")
    fmt.Fprintf(os.Stderr, "\n\tconfig at ~/.2fa or via environment variable KEYCHAIN_2FA\n")
	os.Exit(2)
}

func main() {
	log.SetPrefix("2fa: ")
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	keychainPath := filepath.Join(os.Getenv("HOME"), ".2fa")
	if len(os.Getenv("KEYCHAIN_2FA")) > 0 {
		keychainPath = os.Getenv("KEYCHAIN_2FA")
	}

	k := readKeychain(keychainPath)
	if *flagList {
		if flag.NArg() != 0 {
			usage()
		}
		k.list()
		return
	}
	if flag.NArg() == 0 && !*flagAdd && !*flagRemove {
		if *flagClip {
			usage()
		}
		k.showAll()
		return
	}
	if flag.NArg() != 1 {
		usage()
	}
	name := flag.Arg(0)
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		log.Fatal("name must not contain spaces")
	}
	if *flagAdd {
		if *flagClip {
			usage()
		}
		k.add(name)
		return
	}
	if *flagRemove {
		if *flagClip {
			usage()
		}
		k.remove(name)
		return
	}
	k.show(name)
}

func readKeychain(file string) *Keychain {
	c := &Keychain{
		File: file,
		Keys: make([]Key, 0),
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return c
		}
		log.Fatal(err)
	}
	err = json.Unmarshal(data, &c.Keys)
	if err != nil {
		if os.IsNotExist(err) {
			return c
		}
		log.Fatal(err)
	}
	return c
}

func (c *Keychain) list() {
	for _, key := range c.Keys {
		fmt.Printf("%s %s\n", key.Type, key.Label)
	}
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func (c *Keychain) save() {
	data, err := json.MarshalIndent(c.Keys, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.OpenFile(c.File, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("keychain file open: %v", err)
	}
	f.Chmod(0600)

	if _, err := f.Write(data); err != nil {
		log.Fatalf("keychain file write: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("keychain file close: %v", err)
	}
}

func (c *Keychain) add(kName string) {
	_, idx := c.find(kName)
	if idx >= 0 {
		log.Fatalf("label %q exists.", kName)
	}
	kDigits := 6
	if *flag7 {
		kDigits = 7
		if *flag8 {
			log.Fatalf("cannot use -7 and -8 together")
		}
	} else if *flag8 {
		kDigits = 8
	}

	fmt.Fprintf(os.Stderr, "2fa key for %s: ", kName)
	kSecret, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	kSecret = strings.Map(noSpace, kSecret)
	kSecret += strings.Repeat("=", -len(kSecret)&7) // pad to 8 bytes
	if _, err := decodeKey(kSecret); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	kType := TypeTOTP
	kPeriod := 30
	if *flagHotp {
		kType = TypeHOTP
		kPeriod = 0
	}

	c.Keys = append(c.Keys, Key{
		Secret:    kSecret,
		Digits:    kDigits,
		Label:     kName,
		Algorithm: AlgorithmSHA1,
		Type:      kType,
		Counter:   0,
		Period:    kPeriod,
	})
	c.save()
}

func (c *Keychain) remove(kName string) {
	_, idx := c.find(kName)
	if idx < 0 {
		log.Fatalf("no such label %q", kName)
	}
	c.Keys = append(c.Keys[:idx], c.Keys[idx+1:]...)
	c.save()
}

func (c *Keychain) find(name string) (Key, int) {
	for idx, key := range c.Keys {
		if key.Label == name {
			return key, idx
		}
	}
	return Key{}, -1
}

func (k Key) algorithm() func() hash.Hash {
	switch k.Algorithm {
	case AlgorithmSHA1:
		return sha1.New
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	case AlgorithmMD5:
		return md5.New
	}
	panic("unreached")
}

func (k Key) code() (codeStr string, secondLeft int) {
	secondLeft = -1
	var code int
	rawsec, err := decodeKey(k.Secret)
	if err != nil {
		log.Fatalf("invalid key: %v", err)
	}
	if k.Type == TypeHOTP {
		k.Counter++
		code = hotp(rawsec, k.Counter, k.Digits, k.algorithm())
	} else {
		now := time.Now()
		code = totp(rawsec, now, k.Digits, uint64(k.Period), k.algorithm())
		secondLeft = 30 - (now.Second() % 30)
	}
	codeStr = fmt.Sprintf("%0*d", k.Digits, code)
	return
}

func (c *Keychain) code(name string) (codeStr string, secondLeft int) {
	k, idx := c.find(name)
	if idx < 0 {
		log.Fatalf("no such label %q", name)
	}
	codeStr, secondLeft = k.code()
	if k.Type == TypeHOTP {
		c.Keys[idx] = k
		c.save()
	}
	return
}

func (c *Keychain) show(name string) {
	code, secondLeft := c.code(name)
	if *flagClip {
		clipboard.WriteAll(code)
	}
	fmt.Printf("%10s - %02d second(s) left\n", code, secondLeft)
}

func (c *Keychain) showAll() {
	for _, k := range c.Keys {
		code := strings.Repeat("-", k.Digits)
		secondLeft := -1
		if k.Type != TypeHOTP {
			code, secondLeft = k.code()
		}
		fmt.Printf(" %s | %8s", k.Type, code)
		if secondLeft != -1 {
			fmt.Printf(" | %2d second(s) left", secondLeft)

		} else {
			fmt.Print(" |                  ")
		}
		fmt.Printf(" | %s\n", k.Label)
	}
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int, algo func() hash.Hash) int {
	h := hmac.New(algo, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int, period uint64, algo func() hash.Hash) int {
	period = period * 1e9
	return hotp(key, uint64(t.UnixNano())/period, digits, algo)
}
