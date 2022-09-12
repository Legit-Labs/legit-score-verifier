package main

import (
	"flag"
	"log"

	legit_score_verifier "github.com/legit-labs/legit-score-verifier/legit-score-verifier"
)

var (
	keyPath         string
	attestationPath string
	repo            string
	digest          string
	minScore        float64
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
	} else if attestationPath == "" {
		log.Panicf("please provide an attestation path")
	} else if repo == "" {
		log.Panicf("please provide a repository")
	}

	err := legit_score_verifier.Verify(attestationPath, keyPath, digest, minScore, repo)
	if err != nil {
		log.Panicf("Legit score verification failed: %v", err)
	}

	log.Printf("repository and score were verified successfully.")
}
