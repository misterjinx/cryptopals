package set3

import (
	"cryptopals/utils"
	"time"
)

func getMT19937RandomNumber(seed uint32) uint32 {
	wait1 := utils.GenerateRandomNumber(40, 100) // reduce the waiting time
	time.Sleep(time.Duration(wait1) * time.Millisecond)

	mt := NewMT19937(seed)
	number := mt.ExtractNumber()

	wait2 := utils.GenerateRandomNumber(40, 100)
	time.Sleep(time.Duration(wait2) * time.Millisecond)

	return number
}

func crackMT19937Seed(random uint32) uint32 {
	seed := uint32(time.Now().UnixNano() / int64(time.Millisecond))

	for seed > 0 {
		mt := NewMT19937(seed)
		if mt.ExtractNumber() == random {
			break
		}

		seed -= 1
	}

	return seed
}
