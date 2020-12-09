package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"
)

// SSO 标准格式
type SSO struct {
	URL      string
	Appkey   string //Appkey
	UserName string //用户名
	Date     int64  //过期时间
	UserID   string //用户ID
}

func main() {
	if len(os.Args) != 5 {
		log.Println("您输入的参数有误,请在程序后传入 url token username userid")
	}

	sso := SSO{
		Appkey:   GetRandomString(10),
		UserName: os.Args[3],
		Date:     time.Now().Add(30 * time.Second).Unix(),
		UserID:   os.Args[4],
		URL:      os.Args[1],
	}
	//得到签名
	makesigkey := sso.GetSignature(os.Args[2])
	//生成登录的地址
	url := fmt.Sprintf("%v?app_key=%v&user_name=%v&date=%v&user_id=%v&sign=%v", sso.URL, sso.Appkey, sso.UserName, sso.Date, sso.UserID, makesigkey)
	fmt.Println(url)

}

// GetSignature 签名生成
func (c *SSO) GetSignature(key string) string {
	toSing := fmt.Sprintf("%v%v%v%v", c.Appkey, c.UserName, c.UserID, c.Date)
	byteSing := []byte(toSing)
	bas := base64.StdEncoding.EncodeToString(byteSing)
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(bas))
	ssoEncode := fmt.Sprintf("%x", mac.Sum(nil))
	return string(ssoEncode)
}

// GetRandomString 水机字符串生成
func GetRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
