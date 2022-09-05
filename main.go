package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"

	legitscore "github.com/legit-labs/legit-score"
	verifyattestation "github.com/legit-labs/legit-verify-attestation/verify-attestation"
)

var (
	keyPath         string
	attestationPath string
	repo            string
	minScore        float64
)

func main() {
	flag.StringVar(&keyPath, "key", "", "The path of the public key")
	flag.StringVar(&attestationPath, "attestation", "", "The path of the attestation document")
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

	attestation, err := os.ReadFile(attestationPath)
	if err != nil {
		log.Panicf("failed to open attestation at %v: %v", attestationPath, err)
	}

	payload, err := verifyattestation.VerifiedPayload(context.Background(), keyPath, attestation)
	if err != nil {
		log.Panicf("attestation verification failed: %v", err)
	}

	var statement legitscore.LegitScoreStatement
	err = json.Unmarshal(payload, &statement)
	if err != nil {
		log.Panicf("failed to unmarshal predicate: %v", err)
	}

	if err = statement.Predicate.Verify(repo, minScore); err != nil {
		log.Panicf("score verification failed: %v", err)
	}

	log.Printf("repository and score were verified successfully.")
}
