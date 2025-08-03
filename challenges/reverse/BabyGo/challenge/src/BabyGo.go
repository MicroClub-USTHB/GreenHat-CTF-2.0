// go build -gcflags="all=-N -l" -o challenge/src/BabyGo challenge/src/BabyGo.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the password: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	result := checkInput(input) 

	if result {
		fmt.Println("Correct!")
	} else {
		fmt.Println("Incorrect.")
	}
}

func checkInput(input string) bool {
	expected := []int{
		0xAD, 0xA2, 0xA9, 0xBE, 0xAC, 0xB1, 0x93, 0xF9,
		0xFF, 0x95, 0x9F, 0xB8, 0x95, 0x98, 0xF9, 0xFE,
		0xAE, 0xB3, 0x95, 0x9E, 0xFA, 0x95, 0x8D, 0xFA,
		0x95, 0xAC, 0xA9, 0xAF, 0xFE, 0xFF, 0xAE, 0xB7,
	}

	if len(input) != len(expected) {
		return false
	}

	for i, c := range input {
		if int(c) ^ 0xCA != expected[i] {
			return false
		}
	}
	return true
}
