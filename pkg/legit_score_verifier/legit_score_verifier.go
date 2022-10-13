package legit_score_verifier

import (
	"context"
	"fmt"

	"github.com/legit-labs/legit-attestation/pkg/legit_verify_attestation"
	"github.com/legit-labs/legit-score/pkg/legit_score"
)

var verifyPayload = legit_verify_attestation.VerifiedTypedPayload[legit_score.LegitScoreStatement]

func Verify(ctx context.Context, attestation []byte, keyPath string, digest string, minScore float64, repo string) error {
	statement, err := verifyPayload(ctx, keyPath, attestation, digest)
	if err != nil {
		return fmt.Errorf("Legit score payload verification failed: %v", err)
	}

	if err = statement.Predicate.Verify(repo, minScore); err != nil {
		return fmt.Errorf("score verification failed: %v", err)
	}

	return nil
}
