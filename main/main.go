package main

import (
	"cs161-p2"
	"fmt"
)

func main() {
	user, err := proj2.InitUser("aaa", "bbb")
	user, err = proj2.GetUser("aaa", "bbb")
	user.StoreFile("file1", []byte("File1content"))
	user.StoreFile("file2", []byte("File2content"))
	user.StoreFile("file3", []byte("File3content"))
	user.StoreFile("file4", []byte("File4content"))
	user.StoreFile("file5", []byte("File5content"))
	user.StoreFile("file6", []byte("File6content"))
	user.StoreFile("file7", []byte("File7content"))
	if err != nil {
		fmt.Println(err)
	}
	data, err := user.LoadFile("file2")
	fmt.Println(string(data))

	data, err = user.LoadFile("file5")
	fmt.Println(string(data))
}