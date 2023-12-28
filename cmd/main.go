package main

import (
	"github.com/purpleToti/echoJwtAuth/auth"
	"github.com/purpleToti/echoJwtAuth/controllers"

	"github.com/golang-jwt/jwt/v4"
	echojwt "github.com/labstack/echo-jwt"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	adminGroup := e.Group("/admin")

	// Read more about JWT Middleware here: https://echo.labstack.com/middleware/jwt
	adminGroup.Use(echojwt.WithConfig(echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return &auth.Claims{ // this needs to be pointer to json unmarshalling to work
			}
		},
		SigningKey:   []byte(auth.GetJWTSecret()),
		TokenLookup:  "cookie:access-token", // "<source>:<name>"
		ErrorHandler: auth.JWTErrorChecker,
	}))

	adminGroup.Use(auth.TokenRefresherMiddleware)

	adminGroup.GET("", controllers.Admin())

	e.GET("/user/signin", controllers.SignInForm()).Name = "userSignInForm"
	e.POST("/user/signin", controllers.SignIn())

	e.Logger.Fatal(e.Start(":8777"))
}
