package collector

import (
	"reflect"
	"testing"
)

func TestSSHPortFilter_Default(t *testing.T) {
	// nil/empty defaults to single port 22
	got := SSHPortFilter(nil)
	want := []string{":22"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SSHPortFilter(nil) = %v, want %v", got, want)
	}

	got = SSHPortFilter([]int{})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SSHPortFilter([]) = %v, want %v", got, want)
	}
}

func TestSSHPortFilter_SinglePort(t *testing.T) {
	got := SSHPortFilter([]int{22})
	want := []string{":22"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SSHPortFilter([22]) = %v, want %v", got, want)
	}

	got = SSHPortFilter([]int{2222})
	want = []string{":2222"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SSHPortFilter([2222]) = %v, want %v", got, want)
	}
}

func TestSSHPortFilter_MultiplePorts(t *testing.T) {
	got := SSHPortFilter([]int{22, 2222})
	want := []string{"(", "sport", "=", ":22", "or", "sport", "=", ":2222", ")"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SSHPortFilter([22, 2222]) = %v, want %v", got, want)
	}
}

func TestSSHPortFilter_ThreePorts(t *testing.T) {
	got := SSHPortFilter([]int{22, 2222, 22022})
	want := []string{"(", "sport", "=", ":22", "or", "sport", "=", ":2222", "or", "sport", "=", ":22022", ")"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SSHPortFilter([22, 2222, 22022]) = %v, want %v", got, want)
	}
}
