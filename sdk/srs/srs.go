package srs

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/constraint"
	"github.com/ethereum/go-ethereum/common/hexutil"

	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

const curveID = ecc.BN254
const key = "kzg_srs_100800000_bn254_MAIN_IGNITION"

var (
	fsLock sync.RWMutex
)

func NewSRS(ccs constraint.ConstraintSystem, fsCacheDir string) (canonical, lagrange kzg.SRS, err error) {
	nbConstraints := ccs.GetNbConstraints()
	sizeSystem := nbConstraints + ccs.GetNbPublicVariables()
	fmt.Println("size system", sizeSystem)
	sizeLagrange := ecc.NextPowerOfTwo(uint64(sizeSystem))
	fmt.Println("size lagrange", sizeLagrange)

	initDir(fsCacheDir)

	fmt.Println("fetching srs ignition from file")
	filePath := filepath.Join(fsCacheDir, key)
	fsLock.RLock()
	srsIgnition, err := ReadFile(filePath)
	fsLock.RUnlock()
	if err == nil {
		return generateLagrange(srsIgnition, sizeLagrange)
	}

	fmt.Println("srs ignition not found in file")
	srsIgnition, err = downloadSRSIgnition(filePath)
	if err == nil {
		return generateLagrange(srsIgnition, sizeLagrange)
	}
	return nil, nil, err
}

func generateLagrange(srsIgnition kzg.SRS, sizeLagrange uint64) (kzg.SRS, kzg.SRS, error) {
	fmt.Println("srs ignition ready")
	var err error
	bn254Srs := srsIgnition.(*kzg_bn254.SRS)
	lagrangeSRS := &kzg_bn254.SRS{Vk: bn254Srs.Vk}
	lagrangeSRS.Pk.G1, err = kzg_bn254.ToLagrangeG1(bn254Srs.Pk.G1[:sizeLagrange])
	if err != nil {
		fmt.Println("cannot generate lagrange srs:", err)
		return nil, nil, err
	}
	return bn254Srs, lagrangeSRS, nil
}

func downloadSRSIgnition(filePath string) (kzg.SRS, error) {
	url := fmt.Sprintf("https://kzg-srs.s3.us-west-2.amazonaws.com/%s", key)
	fmt.Println("downloading file", url)

	// Saving downloading time with curl command
	cmd := exec.Command("curl", "-O", filePath, url)
	err := cmd.Run()
	if err == nil {
		return ReadFile(filePath)
	}

	res, err := http.Get(url)
	if err != nil {
		return kzg.NewSRS(curveID), err
	}
	defer res.Body.Close()

	f, err := os.Create(filePath)
	if err != nil {
		panic("cannot create file")
	}
	fmt.Println("writing srs ignition file")
	fsLock.RLock()
	_, err = io.Copy(f, res.Body)
	fsLock.RUnlock()

	if err != nil {
		panic("cannot save srs ignition file")
	}

	return ReadFile(filePath)
}

func validateFile(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file %s does not exist", filePath)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := bytes.NewBuffer([]byte{})
	buf.ReadFrom(f)

	md5Original := md5.Sum(buf.Bytes())
	if hexutil.Encode(md5Original[:]) != "0x2abd249241a7fe883379db93530365f8" {
		return fmt.Errorf("invalid checksum of local file")
	}
	return nil
}

func ReadFile(filePath string) (kzg.SRS, error) {
	err := validateFile(filePath)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)

	kzgSrs := kzg.NewSRS(curveID)
	kzgSrs.UnsafeReadFrom(r)

	return kzgSrs, nil
}

func initDir(cacheDir string) {
	// populate cache from disk
	fmt.Println("init SRS disk cache dir", cacheDir)

	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		err := os.MkdirAll(cacheDir, 0700)
		if err != nil {
			panic(err)
		}
	}
}
