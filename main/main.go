package main

import (
	"cs161-p2"
	"fmt"
)

func main() {
	user, err := proj2.InitUser("aaa", "bbb")
	user2, err := proj2.InitUser("bob", "ccc")
	if err != nil {
		fmt.Println(user2)
	}
	user, err = proj2.GetUser("aaa", "bbb")
	user.StoreFile("file1", []byte("File1content"))
	user.StoreFile("file2", []byte("File2content"))
	data, err := user.LoadFile("file2")
	fmt.Println(string(data))
	user.StoreFile("file3", []byte("File3content"))
	user.StoreFile("file4", []byte("File4content"))
	user.AppendFile("file4", []byte("aaa"))
	data, err = user.LoadFile("file4")
	fmt.Println(string(data))
	user.AppendFile("file4", []byte("bbb"))
	data, err = user.LoadFile("file4")
	fmt.Println(string(data))
	user.AppendFile("file4", []byte("bbdfksdajkfdjkdkjdsjfklasjdfkljdasklfjb"))
	data, err = user.LoadFile("file4")
	fmt.Println(string(data))
	user.StoreFile("file4", []byte("File5content"))
	data, err = user.LoadFile("file4")
	fmt.Println(string(data))
	user.StoreFile("file6", []byte("File6content"))
	user.StoreFile("file7", []byte("File7content"))
	if err != nil {
		fmt.Println(err)
	}
	data, err = user.LoadFile("file2")
	fmt.Println(string(data))

	data, err = user.LoadFile("file4")
	fmt.Println(string(data))

	result, err := user.ShareFile("file4", "bob")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("ttt")
	fmt.Println(result)

}