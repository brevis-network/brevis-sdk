package mpt

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"testing"
)

func TestHeaderByNumber(t *testing.T) {
	client, err := ethclient.Dial("https://ethereum.blockpi.network/v1/rpc/public")
	if err != nil {
		fmt.Println("Failed to connect to the Ethereum client:", err)
		return
	}

	// get the header for block number 17037800
	header, err := client.HeaderByNumber(context.Background(), big.NewInt(17037800))
	if err != nil {
		fmt.Println("Failed to retrieve block header:", err)
		return
	}
	headerJson, _ := json.Marshal(header)

	headerRlp, _ := rlp.EncodeToBytes(header)

	fmt.Printf("%s\n", headerJson)

	//f9022fa0b0ff4a0678831b194b50d4147cef9cd4e360e8ac4569a8ccdcfee81f40d82acda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794690b9a9e9aa1c9db991c7721a92d351db4fac990a054820fb8648ea7eacfcdd0668e1a8afbe933341e787d0a09636ac19e11d8ec18a0bffc95ed579c768622108e9d04f8b8f7ee2629d19b016c865848da6639be70dca094c810c747828c9bebcb56c31ec854d1753d37c07bc87081be01a0699117b444b9010075a7e50fff80a746fae996a9c340da630b29104bd3062a11063915f5d645451a1ec743408605052001193b9dd342bdd893890863ab6bbcec0a9c3b03796c6cf19c967f21e53aadaa7ba37b4c12d943648a100191da67594ad270642ccc3c6e23db801f2052478b232d193818e4cdac45a69868f6099c9e8d4276465981ec1c65d1ab2fd24566fa4634cd6c0987be138e7910f5ef0943caf8792d27e80e31b3049abd64ef1192e1c3245349e895b5ade8a77404c0e79bfa0a206eeb6e9a8a5a42f18e4242ba4524450c60b46aa5df3f34d1494b87aebf28944c7f3d069828fbe3b77cbf68488c908624499fefa4e02813a53c0a584dbf6e566fc999c3c1f1d68180840103f9e88401c9c38083f70ce7846437ce7f8c406275696c64657230783639a04f5e3a77c67e55193fc97590474c6a09fe530f231d02ba6ba6c79e00fdc23a568800000000000000008508b5987915a0c3c77de387b43bdb4e36871270f1255e0f1d6255b00b87476e8a1bcb15d53788
	fmt.Printf("%x\n", headerRlp)
}
