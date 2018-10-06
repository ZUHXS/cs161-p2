package main

import (
	"cs161-p2"
	"fmt"
)

func main() {
	proj2.InitUser("aaa", "bbb")
	proj2.InitUser("bbb", "bbb")
	proj2.GetUser("aaa", "ccc")
	aaa := "jdklfjakldsjflk"
	bbb := []byte(aaa)
	fmt.Println(aaa, bbb)
	//fmt.Print("aaa");
}