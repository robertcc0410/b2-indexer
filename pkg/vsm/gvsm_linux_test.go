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
	srcData := []byte("45e12f36f1cf10416eaf29e698efd27fd1c8237136a43f77361d4cdc267067745be0524a4a574a483c17f0dc700739db6485d3eccac55b38474e018b939efc2334572f61a9ddff682d32f25aad0fa87856c7593e94ec045bd3bd4b4be123cca123435af247193aad086444ad12dbb3fc152a7213e99ecb178ead8b39d0273c284d746416fb23f68e78f1a4eed86998154fd4243bcdd259817f4740866bdc06d593cd05e8c0199f2a3f77b5569387d6b54f37c10fa75e092586f9ad23cefc881e14e1db704ea373cc58b4e646872a267c651b05ed465c54a9b7982788920886b93455a19acf333f886730b6440bf4a102d45131392b169554dcf96064c3468f8f4ed95de675332f636bcb730b5f90805f813fa57100dedb611a6875d90813da78")
	srcivData := []byte("123341")
	encdata, ivData, err := vsm.TassSymmKeyOperation(vsm.TaEnc, vsm.AlgAes256, srcData, srcivData, 3)
	require.NoError(t, err)
	decdata, _, err := vsm.TassSymmKeyOperation(vsm.TaDec, vsm.AlgAes256, encdata, srcivData, 3)
	require.NoError(t, err)
	fmt.Printf("%v\n", encdata)
	fmt.Printf("%v\n", decdata)
	fmt.Printf("%v\n", srcivData)
	fmt.Printf("%v\n", ivData)
	if !bytes.Equal(srcData, bytes.TrimRight(decdata, "\x00")) {
		t.Fatalf("encrypt and decrypt data is not equal")
	}
}
