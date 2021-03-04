package main

import (
	"fmt"
	"github.com/msarvar/godns/pkg"
)

func main() {
	_ = pkg.NewBytePacketBuffer()
	fmt.Println("This is where DNS Server goes.")
}
