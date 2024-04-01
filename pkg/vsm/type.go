package vsm

type OP int

const (
	TaEnc OP = iota
	TaDec OP = iota
)

type SymmAlg int

const (
	AlgAes256 SymmAlg = iota
)
