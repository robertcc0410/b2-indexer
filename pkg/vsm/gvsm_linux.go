//go:build linux
// +build linux

package vsm

// #cgo CFLAGS: -I${SRCDIR}/libgvsm/include
// #cgo LDFLAGS: -L${SRCDIR}/libgvsm/linux64 -lTassSDF4GHVSM
//
// #include "SDF.h"
// #include "TassAPI4GHVSM.h"
import "C"

import (
	"fmt"
	"unsafe"
)

var (
	opENC     C.TA_SYMM_OP   = C.TA_ENC
	opDEC     C.TA_SYMM_OP   = C.TA_DEC
	modeECB   C.TA_SYMM_MODE = C.TA_ECB
	algAES256 C.TA_SYMM_ALG  = C.TA_AES256
)

func Open() (unsafe.Pointer, unsafe.Pointer, error) {
	gHsess := new(unsafe.Pointer)
	gHDev := new(unsafe.Pointer)
	rt := C.SDF_OpenDevice(gHDev)
	if rt != 0 {
		return nil, nil, fmt.Errorf("SDF_OpenDevice failed %#08x", rt)
	}
	rt = C.SDF_OpenSession(*gHDev, gHsess)
	if rt != 0 {
		C.SDF_CloseDevice(*gHDev)
		return nil, nil, fmt.Errorf("SDF_OpenSession failed %#08x", rt)
	}
	return *gHDev, *gHsess, nil
}

func TassSymmKeyOperation(op OP, _ SymmAlg, inputData []byte, internalKeyIndex uint) ([]byte, error) {
	if internalKeyIndex == 0 {
		return nil, fmt.Errorf("InternalKeyIndex must be greater than 0")
	}
	gHDev, gHsess, err := Open()
	if err != nil {
		closehDev(gHDev)
		return nil, err
	}
	_op := opENC
	if op == TaDec {
		_op = opDEC
	}
	_alg := algAES256
	ginIv := make([]byte, 8)
	gkey := make([]byte, 1)
	goutData := make([]byte, 512)
	var (
		inIv    = (*C.uchar)(unsafe.Pointer(&ginIv[0]))
		key     = (*C.uchar)(unsafe.Pointer(&gkey[0]))
		inData  = (*C.uchar)(unsafe.Pointer(&inputData[0]))
		outData = (*C.uchar)(unsafe.Pointer(&goutData[0]))
	)
	var index C.uint = C.uint(internalKeyIndex)
	var keyLen C.uint
	var dataLen C.uint = C.uint(len(goutData))
	result := C.Tass_SymmKeyOperation(
		gHsess,
		_op,
		modeECB,
		inIv,
		index,
		key,
		keyLen,
		_alg,
		inData,
		dataLen,
		outData,
		nil)
	if result != 0 {
		closehDev(gHDev)
		return nil, fmt.Errorf("fail TassSymmKeyOperation :%d |  0x%08x", result, result)
	}
	closehDev(gHDev)
	return goutData, nil
}

func closehDev(gHDev unsafe.Pointer) {
	C.SDF_CloseDevice(gHDev)
}
