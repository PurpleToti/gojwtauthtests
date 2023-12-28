package controllers

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

func Admin() echo.HandlerFunc {
	return func(c echo.Context) error {
		// Gets user cookie.
		userCookie, _ := c.Cookie("user")
		return c.String(http.StatusOK, fmt.Sprintf("Hi, %s! You have been authenticated!", userCookie.Value))
	}
}
