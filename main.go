package main

import (
	"context"

	"github.com/msarvar/godns/pkg/server"
)

func main() {
	ctx := context.Background()
	server.Start(ctx)
}
