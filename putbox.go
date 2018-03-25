// main.go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/xyproto/permissionbolt"
	"github.com/xyproto/pinterface"
)

type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

func boot(userstate pinterface.IUserState) {
	if !userstate.HasUser("admin") {
		userstate.AddUser("admin", "admin", "")
		userstate.Confirm("admin")
		log.Println("Added Admin User")
	} else {
		log.Println("have Admin User")
	}
}

func main() {
	r := gin.New()

	perm, err := permissionbolt.New()
	if err != nil {
		log.Fatalln(err)
	}

	// Set up a middleware handler for Gin, with a custom "permission denied" message.
	permissionHandler := func(c *gin.Context) {
		// Check if the user has the right admin/user rights
		if perm.Rejected(c.Writer, c.Request) {
			// Deny the request, don't call other middleware handlers
			c.AbortWithStatus(http.StatusForbidden)
			fmt.Fprint(c.Writer, "Permission denied!")
			return
		}
		// Call the next middleware handler
		c.Next()
	}

	r.Use(gin.Logger())
	r.Use(permissionHandler)
	r.Use(gin.Recovery())

	userstate := perm.UserState()
	perm.Clear()
	boot(userstate)

	r.POST("/api/auth/login", func(c *gin.Context) {
		var json Login
		if err := c.ShouldBindJSON(&json); err == nil {
			log.Println(json.Username)
			log.Println(json.Password)
			if userstate.CorrectPassword(json.Username, json.Password) {
				log.Println("You are logged in")
				if err := userstate.Login(c.Writer, json.Username); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				} else {
					c.JSON(http.StatusOK, gin.H{"status": "you are logged in"})
				}
			} else {
				log.Println("Incorrect username/password")
				c.JSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
			}
		} else {
			log.Println(err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
	})

	r.POST("/api/auth/logout", func(c *gin.Context) {
		username, err := userstate.UsernameCookie(c.Request)
		if err == nil {
			userstate.Logout(username)
		}
		c.String(http.StatusOK, "")
	})

	//r.LoadHTMLGlob("html/*")
	r.LoadHTMLFiles("html/index.html")
	r.GET("/", func(c *gin.Context) {
		access := "public"
		username, err := userstate.UsernameCookie(c.Request)
		if err == nil && userstate.IsLoggedIn(username) {
			access = "Logged In"
		}
		c.HTML(http.StatusOK, "index.html", gin.H{
			"access": access,
		})
	})
	r.NoRoute(func(c *gin.Context) {
		access := "public"
		username, err := userstate.UsernameCookie(c.Request)
		if err == nil && userstate.IsLoggedIn(username) {
			access = "Logged In"
		}
		c.HTML(http.StatusOK, "index.html", gin.H{
			"access": access,
		})
	})
	r.Static("/tags", "./html/tags")
	r.Static("/js", "./html/js")
	r.Run() // listen and serve on 0.0.0.0:8080
}
