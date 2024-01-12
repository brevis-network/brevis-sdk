package srs

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fft_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/fft"
	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/constraint"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const curveID = ecc.BLS12_377

var (
	cache           = make(map[string]CacheEntry)
	memLock, fsLock sync.RWMutex
)

func NewSRS(ccs constraint.ConstraintSystem, downloadUrl, fsCacheDir string) (canonical, lagrange kzg.SRS, err error) {
	nbConstraints := ccs.GetNbConstraints()
	sizeSystem := nbConstraints + ccs.GetNbPublicVariables()
	fmt.Println("size system", sizeSystem)
	sizeLagrange := ecc.NextPowerOfTwo(uint64(sizeSystem))
	fmt.Println("size lagrange", sizeLagrange)

	k := log2(sizeLagrange)
	key := CacheKey(k)
	fmt.Println("fetching SRS from cache")
	memLock.RLock()
	entry, ok := cache[key]
	memLock.RUnlock()
	if ok {
		fmt.Println("SRS found in mem cache")
		return entry.Canonical, entry.Lagrange, nil
	}
	fmt.Println("SRS not found in mem cache")

	filePath := filepath.Join(fsCacheDir, key)
	fmt.Println("fetching SRS from fs cache", filePath)
	fsLock.RLock()
	entry, err = ReadFile(filePath)
	fsLock.RUnlock()
	if err == nil {
		fmt.Println("SRS found in fs cache")
		memLock.Lock()
		cache[key] = entry
		memLock.Unlock()
		return entry.Canonical, entry.Lagrange, nil
	} else {
		fmt.Println("SRS not found in fs cache")
	}

	fmt.Println("Downloading SRS from url")

	// not in cache, download
	entry, err = download(downloadUrl, key)
	if err != nil {
		return nil, nil, err
	}

	// cache it
	memLock.Lock()
	cache[key] = entry
	memLock.Unlock()

	fmt.Println("writing SRS to fs cache")
	fsLock.Lock()
	defer fsLock.Unlock()
	err = WriteFile(filePath, entry)
	if err != nil {
		return nil, nil, err
	}

	return entry.Canonical, entry.Lagrange, nil
}

func log2(num uint64) uint64 {
	var res uint64 = 0
	for num > 1 {
		num >>= 1
		res++
	}
	return res
}

func Generate(canonicalSize uint64) (kzg.SRS, kzg.SRS, error) {
	tau, err := rand.Int(rand.Reader, ecc.BLS12_377.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	srs, err := kzg_bls12377.NewSRS(canonicalSize, tau)
	if err != nil {
		return nil, nil, err
	}
	return srs, toLagrange(srs, tau), nil
}

func toLagrange(canonical kzg.SRS, tau *big.Int) kzg.SRS {
	srs := canonical.(*kzg_bls12377.SRS)
	s := &kzg_bls12377.SRS{Vk: srs.Vk}
	size := uint64(len(srs.Pk.G1)) - 3

	pAlpha := make([]fr_bls12377.Element, size)
	pAlpha[0].SetUint64(1)
	pAlpha[1].SetBigInt(tau)
	for i := 2; i < len(pAlpha); i++ {
		pAlpha[i].Mul(&pAlpha[i-1], &pAlpha[1])
	}

	d := fft_bls12377.NewDomain(size)
	d.FFTInverse(pAlpha, fft_bls12377.DIF)
	fmt.Println("pAlpha len", len(pAlpha))
	fft_bls12377.BitReverse(pAlpha)

	_, _, g1gen, _ := bls12377.Generators()
	s.Pk.G1 = bls12377.BatchScalarMultiplicationG1(&g1gen, pAlpha)
	var lagrange kzg.SRS
	lagrange = s
	return lagrange
}

func download(url string, key string) (CacheEntry, error) {
	base := strings.Trim(url, "/")
	fullUrl := fmt.Sprintf("%s/%s", base, key)
	fmt.Println("downloading file", fullUrl)
	res, err := http.Get(fullUrl)
	if err != nil {
		return CacheEntry{}, err
	}
	defer res.Body.Close()
	entry := CacheEntry{
		Canonical: kzg.NewSRS(curveID),
		Lagrange:  kzg.NewSRS(curveID),
	}
	r := bufio.NewReaderSize(res.Body, 1<<20)
	_, err = entry.Canonical.UnsafeReadFrom(r)
	if err != nil {
		return entry, err
	}
	_, err = entry.Lagrange.UnsafeReadFrom(r)
	if err != nil {
		return entry, err
	}
	return entry, nil
}

type CacheEntry struct {
	Canonical kzg.SRS
	Lagrange  kzg.SRS
}

func CacheKey(k uint64) string {
	return fmt.Sprintf("kzgsrs-%s-%d", curveID.String(), k)
}

func ReadFile(filePath string) (CacheEntry, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return CacheEntry{}, fmt.Errorf("file %s does not exist", filePath)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return CacheEntry{}, err
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 1<<20)

	entry := CacheEntry{
		Canonical: kzg.NewSRS(curveID),
		Lagrange:  kzg.NewSRS(curveID),
	}
	_, err = entry.Canonical.UnsafeReadFrom(r)
	if err != nil {
		return entry, err
	}
	_, err = entry.Lagrange.UnsafeReadFrom(r)
	if err != nil {
		return entry, err
	}

	return entry, nil
}

func WriteFile(filePath string, entry CacheEntry) error {
	dir, _ := filepath.Split(filePath)
	initDir(dir)
	// if file exist, return.
	if _, err := os.Stat(filePath); err == nil {
		return err
	}
	// else open file and write the srs.
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 1<<20)
	if _, err = entry.Canonical.WriteRawTo(w); err != nil {
		return err
	}
	if _, err = entry.Lagrange.WriteRawTo(w); err != nil {
		return err
	}
	err = w.Flush()
	return err
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
