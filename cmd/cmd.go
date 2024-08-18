package main

import (
	"context"
	"log"
	"time"

	"github.com/raphadam/goblock/node"
)

func main() {
	log.Println("try to do something good!")

	ctx := context.TODO()
	go node.Listen(ctx, ":55000", ":50000", []string{})

	time.Sleep(1 * time.Second)
	go node.Listen(ctx, ":55001", ":50001", []string{":55000"})

	time.Sleep(1 * time.Second)
	go node.Listen(ctx, ":55002", ":50002", []string{":55001"})

	time.Sleep(1 * time.Second)
	go node.Listen(ctx, ":55003", ":50003", []string{":55002"})

	// go client.New(ctx, ":55002")
	// go client.New(ctx, ":55002")
	// go client.New(ctx, ":55002")

	select {}
}
