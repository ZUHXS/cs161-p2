package proj2

import (
	"github.com/nweaver/cs161-p2/userlib"
)
import "testing"
import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	//someUsefulThings()

	userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}


func TestAppend(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v1 := []byte("file1Content")
	u.StoreFile("file1", v1)
	v2 := []byte(" file1Append1")
	err = u.AppendFile("file1", v2)
	if err != nil {
		t.Error("Failed to append", err)
	}
	v3 := []byte(" file1Append2")
	err = u.AppendFile("file1", v3)
	if err != nil {
		t.Error("Failed to append", err)
	}
	v_1, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to append", err)
	}
	if !reflect.DeepEqual(v_1, []byte(string(v1)+string(v2)+string(v3))) {
		t.Error("Appending not equal", v_1, []byte(string(v1)+string(v2)+string(v3)))
	}

	// restore and overwrite
	u.StoreFile("file1", v2)
	v_1, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to append", err)
	}
	if !reflect.DeepEqual(v_1, v2) {
		t.Error("Appending not equal", v_1, []byte(string(v1)+string(v2)+string(v3)))
	}

	err = u.AppendFile("file1", v1)
	if err != nil {
		t.Error("Failed to append", err)
	}

	v_1, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to append", err)
	}
	if !reflect.DeepEqual(v_1, []byte(string(v2)+string(v1))) {
		t.Error("Appending not equal", v_1, []byte(string(v2)+string(v1)))
	}

}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}



	u3, err := InitUser("zuhxs", "zuhxs")
	if err != nil {
		t.Error("Failed to initialize zuhxs", err2)
	}
	msgid, err = u2.ShareFile("file2", "zuhxs")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u3.ReceiveFile("file3", "bob", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}



	u3.AppendFile("file3", []byte("AppendbyZUHXS"))
	v_append, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	if !reflect.DeepEqual(v_append, []byte(string(v)+"AppendbyZUHXS")) {
		t.Error("Shared file is not the same", v, v2)
	}

}


func TestRevoke(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}

	u2, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user", err)
	}


	v1, err3 := u.LoadFile("file1")
	if err3 != nil {
		t.Error("Failed to download the file from alice", err)
	}

	v2, err4 := u2.LoadFile("file2")
	if err4 != nil {
		t.Error("Failed to download the file from bob", err)
	}

	if !userlib.Equal(v1, v2) {
		t.Error("File doesn't match")
	}

	err5 := u.RevokeFile("file1")
	if err5 != nil {
		t.Error("Failed to revoke the file",err)
	}

	u2.AppendFile("file2", []byte("b"))

	_, err6 := u2.LoadFile("file2")
	if err6 == nil {
		t.Error("Failed to revoke the file", err6)
	}


	v4, err7 := u.LoadFile("file1")
	if err7 != nil {
		t.Error("Failed to revoke the file", err7)
	}

	if !userlib.Equal(v4, v2) {
		t.Error("File doesn't match")
	}


}