package main

import (
	"log"
	"time"
	"crypto/sha512"
	"crypto/hmac"
	"encoding/base64"
	"bytes"
	"encoding/json"
	"strings"
	"golang.org/x/crypto/bcrypt"
	"crypto/rand"
	"net/http"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/bson"
	"context"
)

type JWTheader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}
type JWTpayload struct {
	Sub string `json:"sub"`
	Iat string `json:"iat"`
}

type RefreshToken struct {
	Value string
	User string
	Expire time.Time
	Fingerprint string
}

type Application struct {
	secret_access string
	secret_refresh string
	db *mongo.Client
}

func (app *Application) GenerateAccessToken(user string) (string,string,error) {
	jwt_header := JWTheader{"HS512","JWT",}
	jwt_payload := JWTpayload{user,time.Now().UTC().Add(time.Minute*5).Format("20060102150405"),}

	var buffer bytes.Buffer
	b64_encoder := base64.NewEncoder(base64.URLEncoding,&buffer)
	json_encoder := json.NewEncoder(b64_encoder)
	err := json_encoder.Encode(jwt_header)
	if err != nil {
		return "","", err
	}
	j_head := buffer.String()
	buffer.Reset()
	err = json_encoder.Encode(jwt_payload)
	if err != nil {
		return "","", err
	}
	j_pay := buffer.String()
	b64_encoder.Close()

	mac := hmac.New(sha512.New,[]byte(app.secret_access))
	mac.Write([]byte(j_head+"."+j_pay))
	signature := base64.URLEncoding.WithPadding(-1).EncodeToString(mac.Sum(nil))
	jwt := j_head+"."+j_pay+"."+signature
	return jwt,j_pay, nil
}
func (app *Application) GenerateRefreshToken(payload string) (string,error) {
	str := payload[:10]+app.secret_refresh
	hash,err := bcrypt.GenerateFromPassword([]byte(str),10)
	return base64.URLEncoding.WithPadding(-1).EncodeToString(hash),err
}

//Генерация токенов и передача куки
func (app *Application) NewTokens(user string, w http.ResponseWriter, r *http.Request) error {
	s_token,payload,err := app.GenerateAccessToken(user)
	if err != nil {
		return err
	}
	r_token,err := app.GenerateRefreshToken(payload)
	if err != nil {
		return err
	}
	expire := time.Now().UTC().Add(time.Hour)
	err = app.StoreRefreshToken(r_token, user, expire, r.Header.Get("User-Agent"))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: "session_token",
		Value: s_token,
		Expires: expire,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token",
		Value: r_token,
		Expires: expire,
	})
	return nil
}

func (app *Application) VerifyAccessToken(token string) (time.Time,string,bool) {
	sub := strings.Split(token,".")
	json_str,err := base64.URLEncoding.DecodeString(sub[1])
	if err != nil {
		return time.Now(),"",false
	}
	
	var data JWTpayload
	err = json.Unmarshal(json_str,&data)
	if err != nil {
		return time.Now(),"",false
	}
	expire,err := time.Parse("20060102150405", data.Iat)
	if err != nil {
		return time.Now(),"",false
	}

	sign := sub[2]
	mac := hmac.New(sha512.New,[]byte(app.secret_access))
	mac.Write([]byte(sub[0]+"."+sub[1]))
	signature := base64.URLEncoding.WithPadding(-1).EncodeToString(mac.Sum(nil))
	correct := hmac.Equal([]byte(signature),[]byte(sign))
	return expire,data.Sub,correct
}
func (app *Application) VerifyRefreshToken(token,payload,fingerprint string) (string,bool) {
	user,err := app.GetToken(token)
	if err != nil {
		return "",false
	}
	str,err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "",false
	}
	err = bcrypt.CompareHashAndPassword([]byte(str),[]byte(payload[:10]+app.secret_refresh))
	if err != nil {
		return "",false
	}
	if time.Now().UTC().After(user.Expire) { 
		return "",false
	}
	return user.User,true
}

//Маршрут авторизации
func (app *Application) Login(w http.ResponseWriter, r *http.Request) {
	login := r.FormValue("login")
	err := app.NewTokens(login,w,r)
	if err != nil {
		fmt.Fprintf(w, err.Error())
	} else {
		fmt.Fprintf(w, "Login success")
	}
}

//Маршрут обновления токенов
func (app *Application) Refresh(w http.ResponseWriter, r *http.Request) {
	tokenCache, err := r.Cookie("session_token")
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}
	token := tokenCache.Value
	payload := strings.Split(token,".")[1]

	user, found := "", false
	tokenCache, err = r.Cookie("refresh_token")
	if err == nil {
		token := tokenCache.Value
		user, found = app.VerifyRefreshToken(token,payload,r.Header.Get("User-Agent"))
		app.DeleteToken(token)
	}
	if err != nil || !found {
		fmt.Fprintf(w, "Refresh token invalid")
		return
	}

	err = app.NewTokens(user,w,r)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}
}

//Тест токенов
func (app *Application) Test(w http.ResponseWriter, r *http.Request) {
	var expire time.Time
	found := false
	tokenCache, err := r.Cookie("session_token")
	if err == nil {
		token := tokenCache.Value
		expire, _, found = app.VerifyAccessToken(token)
	}
	if err != nil || !found {
		fmt.Fprintf(w, "Auth failed")
		return
	}
	log.Print(time.Now().UTC())
	log.Print(expire)
	if time.Now().After(expire){
		w.Header().Set("Location", "/refresh")
		w.WriteHeader(303)
		return
	}
	fmt.Fprintf(w, "Auth success")
}

func SecretGenerator() (string,error) {
	str := make([]byte, 10)
	_, err := rand.Read(str)
	return base64.StdEncoding.EncodeToString(str),err
}

func main() {
	db, err := OpenDB("localhost",27017,"admin","pass")
	if err != nil {
		log.Fatal(err)
	}
	secret_access, err := SecretGenerator()
	if err != nil {
		log.Fatal(err)
	}
	secret_refresh, err := SecretGenerator()
	if err != nil {
		log.Fatal(err)
	}
	app := Application{secret_access,secret_refresh,db}
	router := http.NewServeMux()
	router.HandleFunc("/login",app.Login)
	router.HandleFunc("/refresh",app.Refresh)
	router.HandleFunc("/",app.Test)
	log.Print("Server started")
	if err = http.ListenAndServe(":8080",router); err != nil{
		log.Fatal(err)
	}
}

//MONGODB

func OpenDB(ip string,port int,user,pass string) (*mongo.Client, error) {
	cred := options.Credential{
		Username: user,
		Password: pass,
	}
	opt := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%d",ip,port)).SetAuth(cred)
	context, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	client,err := mongo.Connect(context, opt)
	if err != nil {
		return client, err
	}
	log.Print("DataBase connected succesfully")
	err = client.Ping(context, readpref.Primary())
	return client, err
}

func (app *Application) GetToken(token string) (RefreshToken,error) {
	var res RefreshToken
	collection := app.db.Database("auth").Collection("sessions")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.D{bson.E{"value",token}}
	err := collection.FindOne(ctx,filter).Decode(&res)
	return res,err
}
func (app *Application) StoreRefreshToken(token,user string,expire time.Time, fingerprint string) error {
	obj := RefreshToken{Value:token,User:user,Expire:expire,Fingerprint:fingerprint}
	collection := app.db.Database("auth").Collection("sessions")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_,err := collection.InsertOne(ctx,obj)
	return err
}
func (app *Application) DeleteToken(token string) error {
	collection := app.db.Database("auth").Collection("sessions")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.D{bson.E{"value",token}}
	_,err := collection.DeleteOne(ctx,filter)
	if err != nil {
		return err
	}
	return nil
}