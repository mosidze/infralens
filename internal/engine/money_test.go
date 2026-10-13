package engine

import "testing"

func TestMoney(t *testing.T) {
	for in, want := range map[float64]string{
		0: "$0.00", 8: "$8.00", 29.2: "$29.20", 999.99: "$999.99", 1000: "$1,000.00",
		11200.53: "$11,200.53", 1234567.891: "$1,234,567.89", -1234.5: "-$1,234.50",
	} {
		if got := Money(in); got != want {
			t.Errorf("Money(%v) = %q, want %q", in, got, want)
		}
	}
}
