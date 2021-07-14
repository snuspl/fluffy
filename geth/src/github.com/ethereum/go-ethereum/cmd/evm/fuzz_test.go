package main

import (
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/tests"
	"google.golang.org/protobuf/proto"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

var inputPipe string
var outputPipe string

func init() {
	flag.StringVar(&inputPipe, "in", "", "")
	flag.StringVar(&outputPipe, "out", "", "")
}

func TestFuzz(t *testing.T) {
	dirname := "/home/johnyangk/parity-fuzzer/corpus/proto"
	files, err := ioutil.ReadDir(dirname)
	if err != nil {
		panic(err)
	}

	for _, file := range files {
		println("PROCESSING: " + dirname + "/" + file.Name())
		fuzzedInput, err := ioutil.ReadFile(dirname + "/" + file.Name())
		if err != nil {
			panic(err)
		}

		fuzzedInputProto := tests.Fuzzed{}
		err = proto.Unmarshal(fuzzedInput, &fuzzedInputProto)
		if err != nil {
			panic(err)
		}

		tests.RunFuzz(fuzzedInputProto)
	}
}

func TestFuzzOld(t *testing.T) {
	c1 := make(chan string, 1)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				fmt.Println(err)
			}
		}()
		os.Args[1] = inputPipe
		os.Args[2] = outputPipe

		main()

		c1 <- "DONE"
	}()

	select {
	case res := <-c1:
		fmt.Println(res)
	case <-time.After(5 * time.Second): // 1 minute
		fmt.Println("timeout 1 minute")
	}


}

