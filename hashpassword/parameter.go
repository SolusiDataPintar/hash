package hashpassword

type Parameter struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func Defaultarameter() Parameter {
	return Parameter{
		Memory:      65536,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   64,
	}
}
