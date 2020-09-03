package pkgerrors

import "fmt"

// MongoError struct
type MongoError struct {
	Err    string
	Caller string
	Msg    string
}

func (e *MongoError) Error() string {
	return fmt.Sprintf("Msg: %s, Caller: %s, Err: %s", e.Msg, e.Caller, e.Err)
}

// StdError struct
type StdError struct {
	Err    string
	Caller string
	Msg    string
}

func (e *StdError) Error() string {
	return fmt.Sprintf("Msg: %s, Caller: %s, Err: %s", e.Msg, e.Caller, e.Err)
}
