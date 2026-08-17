package traffic

import (
	"testing"
)

func TestSlowAttackDetector_Existing(t *testing.T) {
	d := NewSlowAttackDetector()
	if d == nil {
		t.Fatal("should create SlowAttackDetector")
	}
	d.OnConnect("conn-1")
	d.OnActivity("conn-1", 100)
	d.OnDisconnect("conn-1")
}
