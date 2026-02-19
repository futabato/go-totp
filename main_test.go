package main

import (
	"testing"
	"time"
)

func TestGenerateTOTPRFC6238VectorsSHA1(t *testing.T) {
	secret := []byte("12345678901234567890")
	tests := []struct {
		unixTime int64
		want     string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tc := range tests {
		counter := tc.unixTime / stepSeconds
		got := generateTOTP(secret, counter, 8)
		if got != tc.want {
			t.Fatalf("time=%d: got %s, want %s", tc.unixTime, got, tc.want)
		}
	}
}

func TestVerifyTOTPAcceptsAdjacentWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0).UTC()

	prevCode := generateTOTP(secret, now.Unix()/stepSeconds-1, 6)
	if !verifyTOTP(secret, prevCode, now, stepSeconds, 6, 1) {
		t.Fatal("expected previous-step code to be accepted with window=1")
	}
}
