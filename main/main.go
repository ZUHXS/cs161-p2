package main

import (
	"cs161-p2"
	"fmt"
)

func main() {

	aaa, err := proj2.InitUser("aaa", "bbb")
	//proj2.InitUser("bbb", "bbb")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("aaa", aaa)
	aaa, err = proj2.GetUser("aaa", "bbb")
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Print("aaa");
}