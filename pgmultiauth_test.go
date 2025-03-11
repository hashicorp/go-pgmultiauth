package pgmultiauth

import (
	"testing"
)

func Test_replaceDBPassword(t *testing.T) {
	tests := []struct {
		name        string
		inputURL    string
		newPassword string
		expectedURL string
		expectError bool
	}{
		{
			name:        "Basic URL with password",
			inputURL:    "postgres://user:oldpass@localhost:5432/mydb",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "Basic postgresql URL with password",
			inputURL:    "postgresql://user:oldpass@localhost:5432/mydb",
			newPassword: "newpass",
			expectedURL: "postgresql://user:newpass@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "URL without password",
			inputURL:    "postgres://user@localhost:5432/mydb",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "URL without password with :",
			inputURL:    "postgres://user:@localhost:5432/mydb",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "URL with search_path",
			inputURL:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20search_path=rails",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb?options=-c%20search_path=rails",
			expectError: false,
		},
		{
			name:        "URL with multiple query parameters",
			inputURL:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20search_path%3Drails&sslmode=disable",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb?options=-c%20search_path%3Drails&sslmode=disable",
			expectError: false,
		},
		{
			name:        "URL with special characters in password",
			inputURL:    "postgres://user:old%40pass@localhost:5432/mydb",
			newPassword: "new@pass&special!",
			expectedURL: "postgres://user:new%40pass%26special%21@localhost:5432/mydb",
			expectError: false,
		},
		{
			name:        "URL with options parameter",
			inputURL:    "postgres://user:oldpass@localhost:5432/mydb?options=-c%20statement_timeout%3D5000",
			newPassword: "newpass",
			expectedURL: "postgres://user:newpass@localhost:5432/mydb?options=-c%20statement_timeout%3D5000",
			expectError: false,
		},
		{
			name:        "Invalid URL",
			inputURL:    "postgres://user:oldp/mydb",
			newPassword: "newpass",
			expectedURL: "",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := replaceDBPassword(tc.inputURL, tc.newPassword)

			if tc.expectError && err == nil {
				t.Errorf("Expected error but got none")
				return
			}

			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
				return
			}

			if !tc.expectError {
				if result != tc.expectedURL {
					t.Errorf("Expected URL: %s, but got: %s", tc.expectedURL, result)
				}
			}
		})
	}
}
