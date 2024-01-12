package utils

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

func PrintMatrix(m [][]frontend.Variable) {
	for _, row := range m {
		PrintBits(row)
	}
}

func PrintBits(bs []frontend.Variable) {
	for i, b := range bs {
		if i%8 == 0 && i != 0 {
			fmt.Print(" ")
		}
		fmt.Printf("%d", b)
	}
	fmt.Println()
}
