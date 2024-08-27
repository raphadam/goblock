package client

import (
	"context"
	"crypto/ed25519"
	"log"
	"time"

	"github.com/raphadam/goblock/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

func New(ctx context.Context, addr string) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("unable to connect to node %v", err)
	}
	defer conn.Close()

	c := pb.NewNodeClient(conn)

	// ctx, cancel := context.WithTimeout(ctx, time.Second)
	// defer cancel()

	// generate keys
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	ticker := time.NewTicker(time.Second * 1)

	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			th := &pb.TransactionHeader{
				Version:   1,
				Sender:    pub,
				Receiver:  []byte("someone else"),
				Amount:    10,
				Timestamp: time.Now().UnixNano(),
			}

			data, err := proto.Marshal(th)
			if err != nil {
				log.Fatalf("uable to marshal proto")
			}

			sign, err := priv.Sign(nil, data, &ed25519.Options{})
			if err != nil {
				log.Fatal(err)
			}

			// send transaction
			_, err = c.SubmitTransaction(ctx, &pb.Transaction{
				Header:    th,
				Signature: sign,
			})
			if err != nil {
				log.Fatalf("unable to send transaction %v", err)
			}
		}
	}
}
