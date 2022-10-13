package legit_score_verifier

import (
	"context"
	"encoding/json"
	"fmt"

	legitscore "github.com/legit-labs/legit-score"
	verifyattestation "github.com/legit-labs/legit-verify-attestation/verify-attestation"
)

func Verify(attestation []byte, keyPath string, digest string, minScore float64, repo string) error {
	payload, err := verifyattestation.VerifiedPayload(context.Background(), keyPath, attestation)
	if err != nil {
		return fmt.Errorf("attestation verification failed: %v", err)
	}

	var statement legitscore.LegitScoreStatement
	err = json.Unmarshal(payload, &statement)
	if err != nil {
		return fmt.Errorf("failed to unmarshal predicate: %v", err)
	}

	statementDigest := statement.Subject[0].Digest["sha256"]
	if statementDigest != digest {
		return fmt.Errorf("expected digest %v does not match actual: %v", digest, statementDigest)
	}

	if err = statement.Predicate.Verify(repo, minScore); err != nil {
		return fmt.Errorf("score verification failed: %v", err)
	}

	return nil
}
