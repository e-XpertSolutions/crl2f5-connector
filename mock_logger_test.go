package main

// This file defines mock structures for testing. It does not contain test.

// discardLogger does not write any log.
type discardLogger struct{}

func (dl discardLogger) Error(...interface{})           {}
func (dl discardLogger) Errorf(string, ...interface{})  {}
func (dl discardLogger) Notice(...interface{})          {}
func (dl discardLogger) Noticef(string, ...interface{}) {}
