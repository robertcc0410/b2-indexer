//go:build darwin
// +build darwin

package vsm

func TassSymmKeyOperation(_ OP, _ SymmAlg, inputData []byte, iv []byte, _ uint) ([]byte, []byte, error) {
	return inputData, iv, nil
}
