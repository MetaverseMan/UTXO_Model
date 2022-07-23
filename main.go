package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"github.com/boltdb/bolt"
	"log"
	"math"
	"math/big"
	"os"
	"strconv"
	"time"
)

const dbFile = "blockchain.db"

//定义矿工地址
const miner = "hanpeng"

//创世块留言
const genesisCoinbaseData = "the times 13/Mar/2022 Chancellor on brink of secend bailout for banks"

//bucket名称
const blockBucket = "blocks"
const targetBits = 24

const subsidy = 10

var (
	//Nonce循环上限
	maxNonce int64 = math.MaxInt64
)

//交易输入结构
type TXinput struct {
	TXid     []byte //引用交易ID
	VoutIdx  int    //引用的交易的输出编号 (index)
	FromAddr string //输入方验签
}

//交易输出结构
type TXoutput struct {
	Value  int    //输出金额
	ToAddr string //收方验签
}

type Transaction struct {
	ID   []byte
	Vin  []TXinput
	Vout []TXoutput
}
type ProofOfWork struct {
	block  *Block
	target *big.Int
}
type BlockChain struct {
	//blocks []*Block
	tip []byte
	Db  *bolt.DB
}
type BlockChainIterator struct {
	currentHash []byte   //当前区块数据
	db          *bolt.DB // 已经打开的数据库
}

type Block struct {
	Timestamp    int64
	Transactions []*Transaction
	PreBlockHash []byte
	Hash         []byte
	Nonce        int64
}

func (b *Block) HashTransactions() []byte {
	var txHashes [][]byte
	var txHash [32]byte
	for _, tx := range b.Transactions {
		txHashes = append(txHashes, tx.ID)
	}
	txHash = sha256.Sum256(bytes.Join(txHashes, []byte{}))
	return txHash[:]
}

func (b *Block) SetHash() {
	timestamp := []byte(strconv.FormatInt(b.Timestamp, 10))
	t := b.HashTransactions()
	toByte := bytes.Join([][]byte{b.PreBlockHash, t, timestamp}, []byte{})
	hash := sha256.Sum256(toByte)
	b.Hash = hash[:]
}
func NewBlock(tx []*Transaction, preBlockHash []byte) *Block {
	block := &Block{time.Now().Unix(), tx, preBlockHash, []byte{}, 0}
	//需要先挖矿
	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()
	block.Hash = hash
	block.Nonce = nonce
	return block
}

func NewProofOfWork(b *Block) *ProofOfWork {
	//target为最终难度值
	target := big.NewInt(1)
	//target为向1左位移256-24(挖矿难度)
	target.Lsh(target, uint(256-targetBits))
	pow := &ProofOfWork{b, target}
	return pow
}
func (pow *ProofOfWork) prepareData(nonce int64) []byte {
	data := bytes.Join([][]byte{
		pow.block.PreBlockHash,
		pow.block.HashTransactions(),
		Int2Hex(pow.block.Timestamp),
		Int2Hex(int64(targetBits)),
		Int2Hex(nonce),
	}, []byte{})
	return data
}
func NewGenesisBlock(coinbase *Transaction) *Block {
	return NewBlock([]*Transaction{coinbase}, []byte{})
}
func (bc *BlockChain) Iterator() *BlockChainIterator {
	bci := &BlockChainIterator{bc.tip, bc.Db}
	return bci
}
func (i *BlockChainIterator) PreBlock() (*Block, bool) {
	var block *Block
	i.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blockBucket))
		encodedBlock := b.Get(i.currentHash)
		block = DeserilizeBlock(encodedBlock)
		return nil
	})
	i.currentHash = block.PreBlockHash
	return block, len(i.currentHash) > 0
}
func dbExists() bool {
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		return false
	}
	return true
}

//创建区块链结构 初始化只有创世块
func CreateBlockChain() *BlockChain {
	//只能第一次创建
	//if dbExists() {
	//	fmt.Println("BlockChain already Exists.")
	//	os.Exit(1)
	//}
	var tip []byte
	//没有则创建文件
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		fmt.Println("there is a error on opening DB :%s\n", err)
	}

	db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(blockBucket))
		if bucket == nil {
			//第一次使用 创建创世块
			fmt.Println("No existing blockchain found. Creating a new one...")
			cbtx := NewCoinbaseTX(miner, genesisCoinbaseData)
			genesisBlock := NewGenesisBlock(cbtx)
			//区块数据编码
			block_data := genesisBlock.Serialize()
			oneBucket, _ := tx.CreateBucket([]byte(blockBucket))
			oneBucket.Put(genesisBlock.Hash, block_data)
			oneBucket.Put([]byte("last"), genesisBlock.Hash)
			tip = genesisBlock.Hash
		} else {
			//不是第一次使用 之前有块
			tip = bucket.Get([]byte("last"))
		}
		return nil
	})
	return &BlockChain{tip, db}
}

//序列化区块
func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	//编码器
	encoder := gob.NewEncoder(&result)
	err := encoder.Encode(b)
	if err != nil {
		log.Panicf("serialize the block to byte failed %v \n", err)
	}
	return result.Bytes()
}

//反序列化 （解码器）
func DeserilizeBlock(blockBytes []byte) *Block {
	var block Block
	decoder := gob.NewDecoder(bytes.NewReader(blockBytes))
	err := decoder.Decode(&block)
	if err != nil {
		log.Panicf("deserialize the block to byte failed %v \n", err)
	}
	return &block
}
func Int2Hex(num int64) []byte {
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, num)
	return buff.Bytes()
}

func (pow *ProofOfWork) Run() (int64, []byte) {
	var hashInt big.Int
	var hash [32]byte
	var nonce int64 = 0

	fmt.Printf("Mining the block containing %s,maxNonce=%d\n", pow.block.Transactions, maxNonce)
	fmt.Printf("%s\n", pow.block.Transactions[0].Vin[0].FromAddr)
	startTime := time.Now()
	fmt.Printf("startTime:%s\n", startTime.Format("2006-01-02 15:04:05"))
	for nonce < maxNonce {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)
		//fmt.Printf("hash:%x\n", hash)
		hashInt.SetBytes(hash[:])
		//按字节比较 hashInt.Cmp 小于0代表找到目标Nouce
		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}
	endTime := time.Now()
	fmt.Printf("endTime:%s\t Duration:%s\n", endTime.Format("2006-01-02 15:04:05"), endTime.Sub(startTime))
	fmt.Printf("碰撞次数：%d\n", nonce)
	return nonce, hash[:]
}
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int
	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])
	return hashInt.Cmp(pow.target) == -1
}
func (tx *Transaction) setId() {
	var encoded bytes.Buffer
	var hash [32]byte

	enc := gob.NewEncoder(&encoded)
	enc.Encode(tx)
	hash = sha256.Sum256(encoded.Bytes())
	tx.ID = hash[:]
}
func (tx Transaction) isCoinbase() bool {
	return len(tx.Vin) == 1 && len(tx.Vin[0].TXid) == 0 && tx.Vin[0].VoutIdx == -1
}
func NewCoinbaseTX(to, data string) *Transaction {
	if data == "" {
		data = fmt.Sprintf("reward to '%s'", to)
	}
	txin := TXinput{[]byte{}, -1, data}
	txout := TXoutput{subsidy, to}
	tx := Transaction{nil, []TXinput{txin}, []TXoutput{txout}}
	tx.setId()
	return &tx
}
func (in *TXinput) CanUnlockOutputWith(unlockingData string) bool {
	return in.FromAddr == unlockingData
}
func (out *TXoutput) CanBeUnlockedWith(unlockingData string) bool {
	return out.ToAddr == unlockingData
}
func (bc *BlockChain) FindUnspentTransactions(address string) []Transaction {
	var unspentTxs []Transaction
	//已经花出去的UTXO构建tx->VoutIdx 的map
	spentTXOs := make(map[string][]int)
	bci := bc.Iterator()
	for true {
		block, next := bci.PreBlock()
		for _, tx := range block.Transactions {
			txID := hex.EncodeToString(tx.ID)
		outputs:
			for outIDX, out := range tx.Vout {
				if spentTXOs[txID] != nil {
					for _, spentOut := range spentTXOs[txID] {
						if spentOut == outIDX { //index相同 顺序相同 已经被标记为消费过了 跳过 继续下一个Vout
							continue outputs
						}
					}
				}
				//直到某个Vout未被消费 那么检查地址
				//可以被address解锁 就代表属于address的utxo在此交易中
				if out.CanBeUnlockedWith(address) {
					unspentTxs = append(unspentTxs, *tx)
				}
			}
			//用来维护spentTXOs,已经被引用过了,代表被使用
			if tx.isCoinbase() == false {
				for _, in := range tx.Vin { //同一tx的不同TXinput的TXid是相同的
					if in.CanUnlockOutputWith(address) {
						inTxID := hex.EncodeToString(in.TXid)
						spentTXOs[inTxID] = append(spentTXOs[inTxID], in.VoutIdx)
					}

				}
			}
		}
		if !next {
			break
		}
	}
	return unspentTxs
}
func (bc *BlockChain) FindUTXO(address string) []TXoutput {
	var UTXOs []TXoutput
	//先找所有交易
	unspentTransactions := bc.FindUnspentTransactions(address)
	for _, tx := range unspentTransactions {
		for _, out := range tx.Vout {
			if out.CanBeUnlockedWith(address) {
				UTXOs = append(UTXOs, out)
			}
		}
	}
	return UTXOs
}
func (bc *BlockChain) GetBalance(address string) {
	balance := 0
	utxos := bc.FindUTXO(address)
	for _, out := range utxos {
		balance += out.Value
	}
	fmt.Printf("Balance of '%s':%d\n", address, balance)
}
func (bc *BlockChain) FindSpendableOutputs(address string, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	unspentTransactions := bc.FindUnspentTransactions(address)
	accumulated := 0
work:
	for _, tx := range unspentTransactions {
		txID := hex.EncodeToString(tx.ID)
		for outIdx, out := range tx.Vout {
			if out.CanBeUnlockedWith(address) {
				accumulated += out.Value
				unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)
				//UTXO足够多了就跳出循环 break可以跳出所重循环
				if accumulated >= amount {
					break work
				}
			}

		}
	}
	return accumulated, unspentOutputs
}
func NewUTXOTransaction(from, to string, amount int, bc *BlockChain) *Transaction {
	//1 需要组合输入项和输出项
	var inputs []TXinput
	var outputs []TXoutput
	acc, validOutputs := bc.FindSpendableOutputs(from, amount)
	if acc < amount {
		log.Panic("ERROR: not enough funds")
	}
	//2 构建输入项
	for txid, outs := range validOutputs {
		txID, _ := hex.DecodeString(txid)
		for _, out := range outs {
			input := TXinput{txID, out, from}
			inputs = append(inputs, input)
		}
	}
	//构建输出项
	outputs= append(outputs,TXoutput{amount,to})
	//需要找零
	if acc>amount {
		outputs = append(outputs,TXoutput{acc-amount,from})
	}
	//交易生成
	tx:=Transaction{nil,inputs,outputs}
	tx.setId()
	return &tx

}
func (bc *BlockChain) MinedBlock(transactions []*Transaction, data string) {
	var tip []byte
	//1.获取tip值(preBlockHash []byte) 此时不能再打开数据库文件 要用区块结构
	bc.Db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(blockBucket))
		tip = buck.Get([]byte("last"))
		return nil
	})
	//2.更新数据库
	bc.Db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(blockBucket))
		//创建coinBase交易对象
		cbtx := NewCoinbaseTX(miner, data)
		transactions = append(transactions, cbtx)
		block := NewBlock(transactions, tip)
		//将新区块放入DB
		buck.Put(block.Hash, block.Serialize())
		buck.Put([]byte("last"), block.Hash)
		//覆盖tip值
		bc.tip = block.Hash
		return nil
	})
}
func (bc *BlockChain)send(from,to string,amount int,data string){
	//创建普通交易
	tx:=NewUTXOTransaction(from,to,amount,bc)
	bc.MinedBlock([]*Transaction{tx},data)
	fmt.Println("Send Success!")
}
func main() {
	bc := CreateBlockChain()
	defer bc.Db.Close()
	bci := bc.Iterator()
	for {
		ablock, next := bci.PreBlock()
		fmt.Printf("Prev.hash:%x\n", ablock.PreBlockHash)
		fmt.Printf("Data:%s\n", ablock.Transactions[0].Vin[0].FromAddr)
		fmt.Printf("Hash:%x\n", ablock.Hash)
		fmt.Printf("Nonce:%d\n", ablock.Nonce)
		pow := NewProofOfWork(ablock)
		fmt.Printf("Pow:%t\n", pow.Validate())
		fmt.Println()
		if !next {
			break //next 若为假 代表当前区块链为创世块
		}
	}
	bc.GetBalance("hanpeng")
	bc.GetBalance("jingjing")
	bc.GetBalance("jing")
	bc.send("jing","hanpeng",5,"拿去生活吧")
	bc.GetBalance("hanpeng")
	bc.GetBalance("jingjing")
	bc.GetBalance("jing")
	bci1:= bc.Iterator()
	for {
		ablock, next := bci1.PreBlock()
		fmt.Printf("Prev.hash:%x\n", ablock.PreBlockHash)
		fmt.Printf("Data:%s\n", ablock.Transactions[0].Vin[0].FromAddr)
		fmt.Printf("Hash:%x\n", ablock.Hash)
		fmt.Printf("Nonce:%d\n", ablock.Nonce)
		pow := NewProofOfWork(ablock)
		fmt.Printf("Pow:%t\n", pow.Validate())
		fmt.Println()
		if !next {
			break //next 若为假 代表当前区块链为创世块
		}
	}

}
