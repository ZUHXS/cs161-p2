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


	user.StoreFile("file4", []byte("File4content"))
	data, err := user.LoadFile("file4")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))




	user.AppendFile("file4", []byte("aaa"))
	data, err = user.LoadFile("file4")
	if err != nil {
		fmt.Println(err)
	}



	fmt.Println(string(data))
	user.AppendFile("file4", []byte("bbb"))
	data, err = user.LoadFile("file4")
	fmt.Println(string(data))
	user.AppendFile("file4", []byte("ccc"))
	data, err = user.LoadFile("file4")
	fmt.Println(string(data))

	if err != nil {
		fmt.Println(err)
	}


	result, err := user.ShareFile("file4", "bob")
	if err != nil {
		fmt.Println(err)
	}

	err = user2.ReceiveFile("bobfile3", "aaa", result)
	if err != nil {
		fmt.Println(err)
	}

	data, err = user2.LoadFile("bobfile3")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))

	user2.AppendFile("bobfile3", []byte("DDD"))

	data, err = user.LoadFile("file4")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))

	user2.StoreFile("bobfile3", []byte("new file 4"))

	data, err = user.LoadFile("file4")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))


	user.AppendFile("file4", []byte("AAAA"))

	data, err = user.LoadFile("file4")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))



	data, err = user2.LoadFile("bobfile3")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))

	err = user.RevokeFile("file4")
	if err != nil {
		fmt.Println(err)
	}
	user.AppendFile("file4", []byte("bbb"))

	fmt.Println("aaa")

	data, err = user2.LoadFile("bobfile3")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))

	fmt.Println("bbb")
	data, err = user.LoadFile("file4")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))


}