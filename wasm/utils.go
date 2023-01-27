package main

import (
	"fmt"
)

func jsErr(err error, message string) string {
	if message == "" {
		return fmt.Sprintf("{'error': '%s','message': '%s'}", err.Error(), message)
	}
	if err == nil {
		return fmt.Sprintf("{'error': '%s'}", message)
	}
	return fmt.Sprintf("{'error': '%s'}", err.Error())
}
