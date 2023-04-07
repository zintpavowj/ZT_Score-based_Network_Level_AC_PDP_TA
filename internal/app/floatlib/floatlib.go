package floatlib

import (
	"errors"
)

// The finction searches for min and max values in the given array.
func MinMax(data []float32) (float32, float32, error) {
	if data == nil {
		return 0.0, 0.0, errors.New("null pointer operation")
	}

	mn := data[0]
	mx := mn

	for i := 1; i < len(data); i++ {
		if mn > data[i] {
			mn = data[i]
		} else if mx < data[i] {
			mx = data[i]
		}
	}

	return mn, mx, nil
}
