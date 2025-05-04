package internal

import (
	"fmt"
	"math/rand"
)

// SampleUniqueInts samples `n` unique integers from the range [min, max).
func SampleUniqueUint32s(n, min, max int) ([]uint32, error) {
	if n > max-min {
		return nil, fmt.Errorf("cannot sample %d unique integers from range [%d, %d)", n, min, max)
	}

	result := make(map[int]bool)
	for len(result) < n {
		num := rand.Intn(max-min) + min
		result[num] = true
	}

	uniqueInts := make([]uint32, 0, n)
	for num := range result {
		uniqueInts = append(uniqueInts, uint32(num))
	}
	return uniqueInts, nil
}
