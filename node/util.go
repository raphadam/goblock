package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"time"

	"github.com/raphadam/goblock/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

func makeClient(addr string) (pb.NodeClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return pb.NewNodeClient(conn), nil
}

func ComputeMerkleRoot(transactions []*pb.Transaction) []byte {
	len := len(transactions)
	arr := make([][]byte, len)

	for i := range len {
		arr[i] = HashTransaction(transactions[i])
	}

	var a []byte
	var b []byte
	var count int

	for len > 1 {
		count = 0

		for i := 0; i < len; i += 2 {
			a = arr[i]
			if i+1 == len {
				b = a
			} else {
				b = arr[i+1]
			}

			combine := bytes.Join([][]byte{a, b}, []byte{})
			hash := sha256.Sum256(combine)
			arr[count] = hash[:]
			count++
		}

		len = count
	}

	return arr[0]
}

func HashTransaction(t *pb.Transaction) []byte {
	b, err := proto.Marshal(t.Header)
	if err != nil {
		log.Fatal(err)
	}

	hash := sha256.Sum256(b)
	return hash[:]
}

func HashBlockHeader(header *pb.BlockHeader) []byte {
	b, err := proto.Marshal(header)
	if err != nil {
		log.Fatal(err)
	}
	hash := sha256.Sum256(b)
	return hash[:]
}

func isValidHash(hash []byte, difficulty uint32) bool {
	for i := range difficulty {
		if hash[i] != 0 {
			return false
		}
	}

	return true
}

func ComputeNonce(header *pb.BlockHeader) uint32 {
	var nonce uint32 = 0

	for {
		header.Nonce = nonce
		hash := HashBlockHeader(header)

		if isValidHash(hash, header.Difficulty) {
			return nonce
		}

		nonce++
	}
}

func SignBlockHeader(pk ed25519.PrivateKey, header *pb.BlockHeader) []byte {
	sign, err := pk.Sign(nil, HashBlockHeader(header), &ed25519.Options{})
	if err != nil {
		log.Fatal(err)
	}

	return sign
}

func MineBlock(ts []*pb.Transaction, previous *pb.Block, pub ed25519.PublicKey, priv ed25519.PrivateKey) (*pb.Block, error) {
	// TODO: verify the hashes

	// TODO: should create an empty block and give to the miner
	if len(ts) == 0 {
		ts = append(ts, &pb.Transaction{
			Header:    &pb.TransactionHeader{},
			Signature: []byte("miner addr"),
		})
		// return nil, fmt.Errorf("empty block")
	}

	merkle := ComputeMerkleRoot(ts)

	header := &pb.BlockHeader{
		Version:    VERSION,
		Height:     previous.Header.Height + 1,
		PrevHash:   HashBlockHeader(previous.Header),
		Timestamp:  time.Now().UnixNano(),
		Difficulty: DIFFICULTY,
		Nonce:      0,
		MerkleRoot: merkle,
	}
	header.Nonce = ComputeNonce(header)

	sign := SignBlockHeader(priv, header)

	newBlock := &pb.Block{
		Header:       header,
		Transactions: ts,
		MinerKey:     pub,
		Signature:    sign,
	}

	return newBlock, nil
}

func LogBlock(b *pb.Block) {
	log.Printf("Block")
	log.Printf("Height:\t%d", b.Header.Height)
	log.Printf("Nonce:\t%d", b.Header.Nonce)
	log.Printf("MerkleRoot:\t%s", hex.EncodeToString(b.Header.MerkleRoot))
	log.Printf("PrevHash:\t%s", hex.EncodeToString(b.Header.PrevHash))
	log.Printf("CurrHash:\t%s", hex.EncodeToString(HashBlockHeader(b.Header)))
	log.Println("-------------------------------")
}
