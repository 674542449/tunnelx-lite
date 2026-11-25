//go:build !windows

package app

// On Android and Unix platforms the server list lives inside an app-private
// 0600 file in a 0700 directory (hardware-encrypted by Android FBE on mobile).
func protect(plain []byte) ([]byte, error) {
	return append([]byte(nil), plain...), nil
}
func unprotect(blob []byte) ([]byte, error) {
	return append([]byte(nil), blob...), nil
}
