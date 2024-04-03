//go:build darwin
// +build darwin

package vsm

func TassSymmKeyOperation(_ OP, _ SymmAlg, inputData []byte, _ uint) ([]byte, error) {
	return inputData, nil
}
