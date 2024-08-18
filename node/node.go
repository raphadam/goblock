package node

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/raphadam/goblock/pb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	DELAY_BETWEEN_BLOCK = 5
	DIFFICULTY          = 2
	VERSION             = 1
)

type chain struct {
	chain []*pb.Block
	mux   sync.RWMutex
}

func newchain() *chain {
	bc := &chain{}

	h := sha256.Sum256([]byte("genesis"))
	genesis := &pb.Block{
		Header: &pb.BlockHeader{
			Version:  VERSION,
			Height:   0,
			PrevHash: h[:],
		},
		Transactions: []*pb.Transaction{},
	}

	bc.chain = append(bc.chain, genesis)

	return bc
}

func (bc *chain) add(block *pb.Block) error {
	// verify the version
	if block.Header.Version != VERSION {
		return fmt.Errorf("incorrect block version")
	}

	// verify the transactions

	// verify the merkleroot
	merkle := ComputeMerkleRoot(block.Transactions)
	if slices.Compare(block.Header.MerkleRoot, merkle) != 0 {
		return fmt.Errorf("merkle does not match")
	}

	// verify the nonce
	hash := HashBlockHeader(block.Header)
	if !isValidHash(hash, block.Header.Difficulty) {
		return fmt.Errorf("nonce is not correct")
	}

	if !ed25519.Verify(block.MinerKey, hash, block.Signature) {
		return fmt.Errorf("signature is not valid")
	}

	// verify the timestamp

	bc.mux.Lock()
	defer bc.mux.Unlock()

	previous := bc.chain[len(bc.chain)-1]

	// verify the height
	if previous.Header.Height >= block.Header.Height {
		return fmt.Errorf("height is not bigger")
	}

	prevHash := HashBlockHeader(previous.Header)
	if slices.Compare(block.Header.PrevHash, prevHash) != 0 {
		return fmt.Errorf("prev hash does not match")
	}

	bc.chain = append(bc.chain, block)
	log.Println("chain height", len(bc.chain), hex.EncodeToString(block.MinerKey))

	return nil
}

func (bc *chain) getHeight() uint32 {
	bc.mux.RLock()
	defer bc.mux.RUnlock()

	b := bc.chain[len(bc.chain)-1]
	return b.Header.Height
}

func (bc *chain) getLastBlock() *pb.Block {
	bc.mux.RLock()
	defer bc.mux.RUnlock()
	return bc.chain[len(bc.chain)-1]
}

type pool struct {
	mux sync.Mutex
	m   map[string]*pb.Transaction
}

func newPool() *pool {
	return &pool{
		m: make(map[string]*pb.Transaction),
	}
}

func (p *pool) add(t *pb.Transaction) error {
	// TODO: verify credits

	h, err := proto.Marshal(t.Header)
	if err != nil {
		return err
	}

	if !ed25519.Verify(t.Header.Sender, h, t.Signature) {
		return fmt.Errorf("unable to verify the signature")
	}

	hash := sha256.Sum256(h)
	str := hex.EncodeToString(hash[:])

	p.mux.Lock()
	defer p.mux.Unlock()

	_, ok := p.m[str]
	if ok {
		return fmt.Errorf("transaction already present")
	}

	p.m[str] = t
	return nil
}

func (p *pool) get() []*pb.Transaction {
	p.mux.Lock()
	defer p.mux.Unlock()

	ts := make([]*pb.Transaction, 0, len(p.m))
	for _, t := range p.m {
		ts = append(ts, t)
	}

	clear(p.m)
	return ts
}

type peerList struct {
	peerList    map[string]pb.NodeClient
	muxPeerList sync.RWMutex
	listenAddr  string
}

func newPeerList(addr string) *peerList {
	return &peerList{
		peerList:   make(map[string]pb.NodeClient),
		listenAddr: addr,
	}
}

func (p *peerList) add(addr string, c pb.NodeClient) {
	p.muxPeerList.Lock()
	_, ok := p.peerList[addr]
	if !ok {
		p.peerList[addr] = c
		log.Printf("[%s] -> [%s]", p.listenAddr, addr)

	}
	p.muxPeerList.Unlock()
}

// func (p *peerList) remove(addr string) {
// 	p.muxPeerList.Lock()
// 	delete(p.peerList, addr)
// 	p.muxPeerList.Unlock()
// }

func (p *peerList) getPeers() []string {
	p.muxPeerList.RLock()
	arr := make([]string, 0, len(p.peerList))
	for k := range p.peerList {
		arr = append(arr, k)
	}
	p.muxPeerList.RUnlock()
	return arr
}

func (p *peerList) filter(addrs []string) []string {
	arr := []string{}

	p.muxPeerList.RLock()
	for _, addr := range addrs {
		if addr == p.listenAddr {
			continue
		}

		_, ok := p.peerList[addr]
		if !ok {
			arr = append(arr, addr)
		}
	}
	p.muxPeerList.RUnlock()

	return arr
}

func (p *peerList) broadcastTransaction(t *pb.Transaction) {
	p.muxPeerList.RLock()
	defer p.muxPeerList.RUnlock()

	for _, c := range p.peerList {
		go func() {
			// TODO: might close the client if not able to send something
			c.SubmitTransaction(context.TODO(), t)
			// if err != nil {
			// log.Println("error sending the transaction", err)
			// p.remove(addr)
			// }
		}()
	}
}

func (p *peerList) broadcastBlock(b *pb.Block) {
	p.muxPeerList.RLock()
	defer p.muxPeerList.RUnlock()

	for _, c := range p.peerList {
		go func() {
			// TODO: might close the client if not able to send something
			c.SubmitBlock(context.TODO(), b)
		}()
	}
}

type Node struct {
	chain      *chain
	pool       *pool
	peerList   *peerList
	listenAddr string

	pb.UnimplementedNodeServer
}

func Listen(ctx context.Context, addr string, rest string, bootsrap []string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	p := newPool()
	bc := newchain()
	pl := newPeerList(addr)

	n := &Node{
		chain:      bc,
		pool:       p,
		listenAddr: addr,
		peerList:   pl,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /transaction", n.OnTransactionRequest)
	go func() {
		log.Println("start to listen", rest)
		err := http.ListenAndServe(rest, mux)
		if err != nil {
			log.Fatal("unable to start rest server", err)
		}
		log.Println("end to listen")
	}()

	s := grpc.NewServer()
	pb.RegisterNodeServer(s, n)

	go func() {
		time.Sleep(time.Millisecond * 50)
		n.dialRemoteNodes(bootsrap)
		n.Start(ctx)
	}()

	log.Printf("listening on port :%s...\n", addr)
	return s.Serve(l)
}

func (n *Node) OnTransactionRequest(w http.ResponseWriter, r *http.Request) {
	log.Println("transaction request")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("succeed"))
}

func (n *Node) dialRemoteNodes(addrs []string) {
	addrs = n.peerList.filter(addrs)

	for _, addr := range addrs {
		c, err := makeClient(addr)
		if err != nil {
			log.Println("unable to make client", err)
			return
		}

		info, err := c.Handshake(context.Background(), n.getInfo())
		if err != nil {
			log.Println("unable to make handshake", err)
			return
		}

		n.peerList.add(info.ListenAddr, c)
		n.dialRemoteNodes(info.Peers)
	}
}

func (n *Node) Handshake(ctx context.Context, i *pb.Info) (*pb.Info, error) {
	// TODO: check if the incomming node is valid
	c, err := makeClient(i.ListenAddr)
	if err != nil {
		log.Println("unable to make client", err)
		return nil, err
	}

	n.peerList.add(i.ListenAddr, c)

	go n.dialRemoteNodes(i.Peers)

	return n.getInfo(), nil
}

func (n *Node) getInfo() *pb.Info {
	return &pb.Info{
		Version:    1,
		ListenAddr: n.listenAddr,
		Height:     n.chain.getHeight(),
		Peers:      n.peerList.getPeers(),
	}
}

func (n *Node) SubmitTransaction(ctx context.Context, t *pb.Transaction) (*pb.Ok, error) {
	err := n.pool.add(t)
	if err != nil {
		return nil, err
	}

	n.peerList.broadcastTransaction(t)

	return &pb.Ok{}, nil
}

func (n *Node) SubmitBlock(ctx context.Context, b *pb.Block) (*pb.Ok, error) {
	err := n.chain.add(b)
	if err != nil {
		log.Println(n.listenAddr, "error adding to chain", err)
		return nil, err
	}

	n.peerList.broadcastBlock(b)

	return &pb.Ok{}, nil
}

func (n *Node) Start(ctx context.Context) {
	ticker := time.NewTicker(DELAY_BETWEEN_BLOCK * time.Second)
	defer ticker.Stop()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal("unable to create keys", err)
	}

	for {
		select {
		case <-ctx.Done():
			log.Fatal("the node was closed")

		case <-ticker.C:
			ts := n.pool.get()
			previous := n.chain.getLastBlock()

			b, err := mineBlock(ts, previous, pub, priv)
			if err != nil {
				log.Println("failed creating block")
				break
			}

			// TODO: check if valid at this time
			err = n.chain.add(b)
			if err != nil {
				log.Println("error trying to add itself", err)
				break
			}

			log.Println(n.listenAddr, "successfull add itself", err)
			n.peerList.broadcastBlock(b)
		}
	}
}

func mineBlock(ts []*pb.Transaction, previous *pb.Block, pub ed25519.PublicKey, priv ed25519.PrivateKey) (*pb.Block, error) {
	// TODO: verify the hashes

	// TODO: should create an empty block and give to the miner
	if len(ts) == 0 {
		return nil, fmt.Errorf("empty block")
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
