package utils

import "strings"

type WalletAddressType int

const (
	EVM WalletAddressType = iota
	P2WPKH
	P2SH
	P2TR
	P2PKH
)

type NetworkType int

const (
	MainNet NetworkType = iota
	TestNet
	LiveNet
)

func VerifyAddress(address string) (bool, WalletAddressType, NetworkType) {
	address = strings.Trim(address, " \t\n")
	if (strings.HasPrefix(address, "0x") && len(address) == 42) ||
		strings.HasPrefix(address, "0X") && len(address) == 42 {
		return true, EVM, MainNet
	} else if (strings.HasPrefix(address, "m") || strings.HasPrefix(address, "n")) && len(address) == 34 {
		return true, P2PKH, TestNet
	} else if strings.HasPrefix(address, "2") && len(address) == 35 {
		return true, P2SH, TestNet
	} else if strings.HasPrefix(address, "tb1") && len(address) == 42 {
		return true, P2WPKH, TestNet
	} else if strings.HasPrefix(address, "tb1") && len(address) == 62 {
		return true, P2TR, TestNet
	} else if strings.HasPrefix(address, "1") && len(address) == 34 {
		return true, P2PKH, LiveNet
	} else if strings.HasPrefix(address, "3") && len(address) == 34 {
		return true, P2SH, LiveNet
	} else if strings.HasPrefix(address, "bc1") && len(address) == 42 {
		return true, P2WPKH, LiveNet
	} else if strings.HasPrefix(address, "bc1") && len(address) == 62 {
		return true, P2TR, LiveNet
	} else {
		return false, EVM, MainNet
	}
}
