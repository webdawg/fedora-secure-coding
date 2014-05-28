package main

import "io"

//+ Go Error_Handling-Regular
type Processor interface {
	Process(buf []byte) (message string, err error)
}

type ErrorHandler interface {
	Handle(err error)
}

func RegularError(buf []byte, processor Processor,
	handler ErrorHandler) (message string, err error) {
	message, err = processor.Process(buf)
	if err != nil {
		handler.Handle(err)
		return "", err
	}
	return
}
//-

//+ Go Error_Handling-IO
func IOError(r io.Reader, buf []byte, processor Processor,
	handler ErrorHandler) (message string, err error) {
	n, err := r.Read(buf)
	// First check for available data.
	if n > 0 {
		message, err = processor.Process(buf[0:n])
		// Regular error handling.
		if err != nil {
			handler.Handle(err)
			return "", err
		}
	}
	// Then handle any error.
	if err != nil {
		handler.Handle(err)
		return "", err
	}
	return
}
//-

func main() {
}
