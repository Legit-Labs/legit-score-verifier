package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/legit-labs/legit-score-verifier/pkg/legit_score_verifier"
)

var (
	keyPath          string
	attestationPath  string
	attestationStdin bool
	repo             string
	digest           string
	minScore         float64
)

func main() {
	flag.StringVar(&keyPath, "key", "", "The path of the public key")
	flag.StringVar(&attestationPath, "attestation", "", "The path of the attestation document")
	flag.StringVar(&digest, "digest", "", "The expected subject digest")
	flag.Float64Var(&minScore, "min-score", 0, "The minimal Legit score")
	flag.StringVar(&repo, "repository", "", "The repository in question")

	flag.Parse()

	if keyPath == "" {
		log.Panicf("please provide a public key path")
	} else if !attestationStdin && attestationPath == "" {
		log.Panicf("please provide an attestation path (or set -attestation-stdin to read it from stdin)")
	} else if repo == "" {
		log.Panicf("please provide a repository")
	}

	var attestation []byte
	var err error
	if attestationStdin {
		if attestation, err = ioutil.ReadAll(os.Stdin); err != nil {
			log.Panicf("failed to read payload from stdin: %v", err)
		}
	} else {
		attestation, err = os.ReadFile(attestationPath)
		if err != nil {
			log.Panicf("failed to open payload at %v: %v", attestationPath, err)
		}
	}

	err := legit_score_verifier.Verify(attestation, keyPath, digest, minScore, repo)
	if err != nil {
		log.Panicf("Legit score verification failed: %v", err)
	}

	log.Printf("repository and score were verified successfully.")
}
