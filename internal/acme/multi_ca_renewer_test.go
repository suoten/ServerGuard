package acme

import (
	"context"
	"errors"
	"testing"
)

func TestMultiCARenewer_AllSuccess(t *testing.T) {
	renewFunc := func(ctx context.Context, ca CAServer, domain string) (string, error) {
		return "/path/to/cert", nil
	}
	renewer := NewMultiCARenewer(renewFunc)

	result := renewer.RenewWithFallback(context.Background(), "example.com")
	if !result.Success {
		t.Error("should succeed")
	}
	if result.UsedCA != CA_LetsEncrypt {
		t.Errorf("should use letsencrypt first, got %s", result.UsedCA)
	}
}

func TestMultiCARenewer_FallbackToSecond(t *testing.T) {
	callCount := 0
	renewFunc := func(ctx context.Context, ca CAServer, domain string) (string, error) {
		callCount++
		if ca == CA_LetsEncrypt {
			return "", errors.New("rate limited")
		}
		return "/path/to/cert", nil
	}
	renewer := NewMultiCARenewer(renewFunc)

	result := renewer.RenewWithFallback(context.Background(), "example.com")
	if !result.Success {
		t.Error("should succeed with second CA")
	}
	if result.UsedCA != CA_ZeroSSL {
		t.Errorf("should use zerossl, got %s", result.UsedCA)
	}
	if len(result.FailureChain) != 1 {
		t.Errorf("should have 1 failure, got %d", len(result.FailureChain))
	}
}

func TestMultiCARenewer_AllFail(t *testing.T) {
	renewFunc := func(ctx context.Context, ca CAServer, domain string) (string, error) {
		return "", errors.New("failed")
	}
	renewer := NewMultiCARenewer(renewFunc)

	result := renewer.RenewWithFallback(context.Background(), "example.com")
	if result.Success {
		t.Error("should fail")
	}
	if len(result.FailureChain) != 3 {
		t.Errorf("should have 3 failures, got %d", len(result.FailureChain))
	}
}

func TestMultiCARenewer_SetCAOrder(t *testing.T) {
	renewer := NewMultiCARenewer(nil)
	newOrder := []CAServer{CA_TrustAsia, CA_LetsEncrypt}
	renewer.SetCAOrder(newOrder)

	order := renewer.GetCAOrder()
	if order[0] != CA_TrustAsia {
		t.Error("first CA should be trustasia")
	}
}

func TestGetCAConfig(t *testing.T) {
	config, ok := GetCAConfig(CA_LetsEncrypt)
	if !ok {
		t.Error("letsencrypt config should exist")
	}
	if !config.Enabled {
		t.Error("letsencrypt should be enabled")
	}
}

func TestGetAllCAConfigs(t *testing.T) {
	configs := GetAllCAConfigs()
	if len(configs) < 3 {
		t.Errorf("should have at least 3 CA configs, got %d", len(configs))
	}
}
