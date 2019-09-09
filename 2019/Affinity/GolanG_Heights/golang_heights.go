package main
import "os"
import "fmt"
import "strconv"
import "math/big"
import "math/rand"

type privateKeys struct {
	p *big.Int
	q *big.Int
}

func isPrime(num *big.Int) bool {
	start := big.NewInt(2)
	end := new(big.Int).Div(num, big.NewInt(2))
	for i := new(big.Int).Set(start); i.Cmp(end) < 0; i.Add(i, big.NewInt(1)) {
		if big.NewInt(0).Cmp(new(big.Int).Rem(num, i)) == 0 {
			return false
		}
	}
	return true
}

func getKeys() (privateKeys, *big.Int, error) {
	for true {
		factorHex := make([]byte, 32)
		_, err := rand.Read(factorHex)
		if err != nil {
			return privateKeys{}, big.NewInt(0), err
		}
		factorBigInt := new(big.Int)
		factorBigInt.SetBytes(factorHex)

		p := new(big.Int).Add(new(big.Int).Add(new(big.Int).Mul(new(big.Int).Exp(factorBigInt, big.NewInt(2), nil), big.NewInt(4)), new(big.Int).Mul(factorBigInt, big.NewInt(3))), big.NewInt(7351))
		q := new(big.Int).Add(new(big.Int).Add(new(big.Int).Mul(new(big.Int).Exp(factorBigInt, big.NewInt(2), nil), big.NewInt(19)), new(big.Int).Mul(factorBigInt, big.NewInt(18))), big.NewInt(1379))

		if isPrime(p) && isPrime(q) {
			n := new(big.Int).Mul(p, q)
			return privateKeys{p, q}, n, nil
		}	}

	return privateKeys{}, big.NewInt(0), nil
}

func encrypt(message *big.Int, publicKey *big.Int) *big.Int {
	encryptedMessage := new(big.Int).Rem(new(big.Int).Exp(message, big.NewInt(2), nil) , publicKey)
	return encryptedMessage
}


func main() {
	messageInt, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil {
		return
	}
	messageBigInt := big.NewInt(messageInt)
	_, publicKey, err := getKeys()
	if err != nil {
		return
	}
	encryptedMessage := encrypt(messageBigInt, publicKey)
	fmt.Println("Encrypted message: ", encryptedMessage)
}
