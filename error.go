package rbe

type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "rbe: <nil>"
	}
	return "rbe: " + e.err
}

var (
	ErrDecrypt error = &Error{err: "Decryption cannot be done, you need to get update first"}
)
