package collector

import "testing"

func TestIsFailedLogin(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "failed password for root",
			line: "Mar  3 10:15:01 host sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2",
			want: true,
		},
		{
			name: "failed password for invalid user",
			line: "Mar  3 10:15:01 host sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2",
			want: true,
		},
		{
			name: "invalid user",
			line: "Mar  3 10:15:01 host sshd[1234]: Invalid user admin from 10.0.0.1 port 54321",
			want: true,
		},
		{
			name: "connection closed by authenticating user",
			line: "Mar  3 10:15:01 host sshd[1234]: Connection closed by authenticating user admin 10.0.0.1 port 22 [preauth]",
			want: true,
		},
		{
			name: "received disconnect preauth",
			line: "Mar  3 10:15:01 host sshd[1234]: Received disconnect from 10.0.0.1 port 54321:11: Bye Bye [preauth]",
			want: true,
		},
		{
			name: "received disconnect without preauth - not a failed login",
			line: "Mar  3 10:15:01 host sshd[1234]: Received disconnect from 10.0.0.1 port 54321:11: Bye Bye",
			want: false,
		},
		{
			name: "successful login - not a failed login",
			line: "Mar  3 10:15:01 host sshd[1234]: Accepted publickey for user1 from 10.0.0.1 port 22 ssh2",
			want: false,
		},
		{
			name: "empty line",
			line: "",
			want: false,
		},
		{
			name: "unrelated log line",
			line: "Mar  3 10:15:01 host sshd[1234]: pam_unix(sshd:session): session opened for user user1",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFailedLogin(tt.line)
			if got != tt.want {
				t.Errorf("isFailedLogin(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}
