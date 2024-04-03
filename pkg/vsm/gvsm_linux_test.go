//go:build linux
// +build linux

package vsm_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/b2network/b2-indexer/pkg/vsm"
	"github.com/stretchr/testify/require"
)

func TestLocalTass_SymmKeyOperation(t *testing.T) {
	srcData := []byte("11da7010d8c1a8cb2a7febdc54f54698f1bc148aa016051d56e0a8c89607c4f00c29a142e567671ec0a7")
	encdata, err := vsm.TassSymmKeyOperation(vsm.TaEnc, vsm.AlgAes256, srcData, 3)
	require.NoError(t, err)
	decdata, err := vsm.TassSymmKeyOperation(vsm.TaDec, vsm.AlgAes256, encdata, 3)
	require.NoError(t, err)
	fmt.Printf("%v\n", encdata)
	fmt.Printf("%v\n", decdata)
	if !bytes.Equal(srcData, bytes.TrimRight(decdata, "\x00")) {
		t.Fatalf("encrypt and decrypt data is not equal")
	}
}
