package main

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"wallet/database"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/mailjet/mailjet-apiv3-go"
	"golang.org/x/crypto/bcrypt"

	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, using system environment variables")
	}

	router := gin.Default()
	database.ConnectDatabase()
	router.POST("/Loginuser", LoginUser)
	router.POST("/Createuser", CreateUser)
	router.POST("/RequestReset", RequestPasswordReset)
	router.POST("/ResetCode", VerifyResetCode)   // for verifying code
	router.POST("/ResetPassword", ResetPassword) // for updating new password in db

	// Routes for adding income, expenses, get balance and stats
	router.POST("/income", AddIncome)
	router.GET("/income/:income_id/remaining", GetRemaining)
	router.POST("/expense", AddExpense)
	router.GET("/income/:income_id/stats", GetExpenseStats)
	

	db := &database.Database{DB: database.DB} // db points to database.Database  which will store database.DB into its variable DB .... /:transactionid
	db.InitDatabase()

	router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{
			"message": "Your server is running well !!",
		})
	})
	err := router.Run(":1010")
	if err != nil {
		panic(err)
	}
	
}

type TheUser struct {
	Userid			 int 		`json:"userid"`
	Email            string     `json:"email"`
	Phonenumber      string     `json:"phonenumber"`
	Password         string     `json:"password"`
	Created          string     `json:"created"`
	ResetToken       *string    `json:"resetToken"` // Pointer to string to handle NULL
	ResetTokenExpiry *time.Time `json:"resetTokenExpiry"`
	// New fields for login attempt tracking and lockout
	FailedAttempts   int        `json:"failedAttempts"`   // Track failed login attempts
	LockoutUntil     *time.Time `json:"lockoutUntil"`     // Handle lockout expiration, use pointer for nullable
}

// Function to validate phone number
func isValidPhoneNumber(phonenumber string) bool {
	// Check if the phone number has exactly 10 digits and starts with "07"
	if len(phonenumber) != 10 || !strings.HasPrefix(phonenumber, "07") {
		return false
	}
	return true
}

// Function to validate email format using regex
func isValidEmail(email string) bool {
	const emailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(emailRegexPattern)
	return regex.MatchString(email)
}

func CreateUser(ctx *gin.Context) {
	var req TheUser

	// Attempt to bind the JSON request body to req struct
	if err := ctx.ShouldBindJSON(&req); err != nil {
		// Log the exact error
		// fmt.Println("Error binding JSON: ", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input. Please ensure all fields are provided correctly."})
		return
	}

	// Normalize the email to lowercase
	req.Email = strings.ToLower(req.Email)

// Validate phone number: should be exactly 10 digits and start with "07"
if !isValidPhoneNumber(req.Phonenumber) {
	ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone number, use 10 digits (e.g., 07XXXXXXXX)."})
	return
}
	// Validate email format
	if !isValidEmail(req.Email) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format. Please provide a valid email like 'example@domain.com'."})
		return
	}

	// Check if the email already exists
	var existingEmail string
	err := database.DB.QueryRow("SELECT email FROM theuser WHERE email = $1", req.Email).Scan(&existingEmail)
	if err != nil && err != sql.ErrNoRows {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	if existingEmail != "" {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Email is already in use"})
		return
	}

	// Check if the phone number already exists
	var existingPhoneNumber string
	err = database.DB.QueryRow("SELECT phonenumber FROM theuser WHERE phonenumber = $1", req.Phonenumber).Scan(&existingPhoneNumber)
	if err != nil && err != sql.ErrNoRows {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	if existingPhoneNumber != "" {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Phone number already in used. Please provide your own phone number"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	req.Password = string(hashedPassword)
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	req.Created = currentTime

	// Insert the new employee into the database
	_, err = database.DB.Exec("INSERT INTO theuser (email, phonenumber, password, created) VALUES ($1, $2, $3, $4)",
		req.Email, req.Phonenumber, req.Password, req.Created,)
	if err != nil {
		fmt.Println("Database error during insert: ", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create a new user"})
		return
	}

	// Send welcome email to user
	// err = sendWelcomEmail(req.Email)
	// if err != nil {
	// 	ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error sending welcome email"})
	// 	return
	// }

	// Successfully created user
	ctx.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
}

func LoginUser(c *gin.Context) {
	var userRequest TheUser
	if err := c.ShouldBindJSON(&userRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Normalize the email to lowercase
	userRequest.Email = strings.ToLower(userRequest.Email)

	var storedUser TheUser
	err := database.DB.QueryRow(
		"SELECT userid, email, phonenumber, password, failed_attempts, lockout_until FROM theuser WHERE email = $1", 
		userRequest.Email).
		Scan(&storedUser.Userid, &storedUser.Email, &storedUser.Phonenumber, &storedUser.Password, &storedUser.FailedAttempts, &storedUser.LockoutUntil,
		)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			fmt.Println("database error", err)
		}
		return
	}

	// Log the current values of failed_attempts and lockout_until
	fmt.Printf("Before update: failed_attempts=%d, lockout_until=%v\n", storedUser.FailedAttempts, storedUser.LockoutUntil)

	// Check if the user is locked out
	if storedUser.LockoutUntil != nil && storedUser.LockoutUntil.After(time.Now()) {
		// User is locked out, return an error
		fmt.Println("User is still locked out.")
		c.JSON(http.StatusForbidden, gin.H{"error": "Account is temporarily locked due to multiple failed login attempts. Please try again later."})
		return
	}
	fmt.Println("Reach here 1: user locked out check passed")

	// Compare passwords
	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(userRequest.Password))
	if err != nil {
		// Password mismatch, increment failed_attempts
		storedUser.FailedAttempts++
		if storedUser.FailedAttempts >= 5 {
			// Lock the account for 2 minutes (for testing purposes)
			lockoutUntil := time.Now().Add(10 * time.Minute)
			_, err := database.DB.Exec(
				"UPDATE theuser SET failed_attempts = $1, lockout_until = $2 WHERE email = $3",
				storedUser.FailedAttempts, lockoutUntil, userRequest.Email,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
				return
			}
			fmt.Printf("User locked out until: %v\n", lockoutUntil)
			//fmt.Println("Reach here 2: Yes, user is locked out")

			// Send account locked email
			err = sendAccountLocked(storedUser.Email)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to send account lockout email"})
				return
			}

			c.JSON(http.StatusForbidden, gin.H{"error": "Too many failed attempts. Account locked for 10 minutes."})
		} else {
			// Update the failed attempts count
			_, err := database.DB.Exec(
				"UPDATE theuser SET failed_attempts = $1 WHERE email = $2",
				storedUser.FailedAttempts, userRequest.Email,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
				return
			}
			fmt.Printf("Failed attempts updated to: %d\n", storedUser.FailedAttempts)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		}
		return
	}
//	fmt.Println("Reach here 3: Password correct")

	// Successful login, reset failed attempts and lockout_until before sending the response
	_, err = database.DB.Exec(
		"UPDATE theuser SET failed_attempts = 0, lockout_until = NULL WHERE email = $1",
		userRequest.Email,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	//fmt.Println("Reach here 4: Reset failed attempts and lockout_until")

	// Log the updated values of failed_attempts and lockout_until
	fmt.Printf("After update: failed_attempts=%d, lockout_until=%v\n", storedUser.FailedAttempts, storedUser.LockoutUntil)

	// Send successful login response
	c.JSON(http.StatusOK, gin.H{
		"message":      "Login successful",
		"email":        storedUser.Email,
		"phone_number": storedUser.Phonenumber,
		"user_id": storedUser.Userid,
	})
}

func sendAccountLocked(userEmail string) error {
	// NEW: Mailjet implementation
	apiKey := os.Getenv("MAILJET_API_KEY")
	apiSecret := os.Getenv("MAILJET_API_SECRET")
	senderEmail := os.Getenv("MAILJET_SENDER_EMAIL")
	senderName := os.Getenv("MAILJET_SENDER_NAME")

	if apiKey == "" || apiSecret == "" || senderEmail == "" {
		return fmt.Errorf("Mailjet credentials not configured")
	}

	mailjetClient := mailjet.NewMailjetClient(apiKey, apiSecret)

	// Prepare email message content
	subject := "Account Locked - Too Many Failed Login Attempts"
	body := fmt.Sprintf("Dear user,\n\nYour account has been temporarily locked due to multiple failed login attempts. " +
		"For security purposes, your account will remain locked for a set duration. Please try again later.\n\n" +
		"If you need immediate assistance or did not attempt to log in, please contact our support team by replying to this email.\n\n" +
		"Thank you,\nThe SWIFTPAY Team")

	messagesInfo := []mailjet.InfoMessagesV31{
		{
			From: &mailjet.RecipientV31{
				Email: senderEmail,
				Name:  senderName,
			},
			To: &mailjet.RecipientsV31{
				{
					Email: userEmail,
				},
			},
			Subject:  subject,
			TextPart: body,
		},
	}

	messages := mailjet.MessagesV31{Info: messagesInfo}
	_, err := mailjetClient.SendMailV31(&messages)
	if err != nil {
		return fmt.Errorf("Unable to send email via Mailjet: %v", err)
	}

	fmt.Println("Account lockout email sent successfully via Mailjet!")
	return nil
}

func sendResetEmail(userEmail string, code string) error {
	// NEW: Mailjet implementation
	apiKey := os.Getenv("MAILJET_API_KEY")
	apiSecret := os.Getenv("MAILJET_API_SECRET")
	senderEmail := os.Getenv("MAILJET_SENDER_EMAIL")
	senderName := os.Getenv("MAILJET_SENDER_NAME")

	if apiKey == "" || apiSecret == "" || senderEmail == "" {
		return fmt.Errorf("Mailjet credentials not configured")
	}

	mailjetClient := mailjet.NewMailjetClient(apiKey, apiSecret)

	subject := "Password Reset Request"
	body := fmt.Sprintf("You requested a password reset. Use the code below to reset your password:\n\n%s", code)

	messagesInfo := []mailjet.InfoMessagesV31{
		{
			From: &mailjet.RecipientV31{
				Email: senderEmail,
				Name:  senderName,
			},
			To: &mailjet.RecipientsV31{
				{
					Email: userEmail,
				},
			},
			Subject:  subject,
			TextPart: body,
		},
	}

	messages := mailjet.MessagesV31{Info: messagesInfo}
	_, err := mailjetClient.SendMailV31(&messages)
	if err != nil {
		return fmt.Errorf("Unable to send email via Mailjet: %v", err)
	}

	fmt.Println("Email sent successfully via Mailjet!")
	return nil
}

// generate random 6 digits code
func generateResetCode() (string, error) {
	// Generate a random 6-digit code
	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	return code, nil
} 

// function for requesting the password reset code via email
func RequestPasswordReset(ctx *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	// Normalize the email to lowercase
	req.Email = strings.ToLower(req.Email)

	var userRequest TheUser
	err := database.DB.QueryRow("SELECT email FROM theuser WHERE email = $1", req.Email).Scan(&userRequest.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Email not found"})
		return
	}

	// Generate the reset code
	code, err := generateResetCode()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset code"})
		return
	}

	// Store the token in the database with an expiry time
	expiry := time.Now().Add(1 * time.Hour).UTC()

	_, err = database.DB.Exec("UPDATE theuser SET resettoken = $1, resettokenexpiry = $2 WHERE email = $3", code, expiry, req.Email)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store reset token"})
		return
	}
	// Send the password reset email
	err = sendResetEmail(userRequest.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send password reset email"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
}

// function used to verify the reset code then allow the user to change their password
func VerifyResetCode(ctx *gin.Context) {
	var req struct {
		Code string `json:"code"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var storedCode string
	var expiry time.Time
	var email string

	// Find the user by the reset code

	err := database.DB.QueryRow("SELECT email, resettoken, resettokenexpiry FROM theuser WHERE resettoken = $1", req.Code).Scan(&email, &storedCode, &expiry)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired code"})
		return
	}

	expiry = expiry.UTC()
	if time.Now().UTC().After(expiry) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Code has expired"})
		return
	}

	if req.Code != storedCode {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}

	// If the code is valid, respond with success
	ctx.JSON(http.StatusOK, gin.H{"message": "Code verified", "email": email})
}

// function for updating the new password in the database
func ResetPassword(ctx *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Hash the new password before storing it in the database

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update the user's password and invalidate the reset token
	_, err = database.DB.Exec("UPDATE theuser SET password = $1, resettoken = NULL, resettokenexpiry = NULL WHERE email = $2", hashedPassword, req.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully"})
}



// Types for the  Expenses and Incomes

type Income struct {
    Incomeid  	int        `json:"incomeid"`
    Userid    	int        `json:"user_id"`
    Amount    	float64    `json:"amount"`
    Description string	   `json:"description"`
    CreatedAt 	time.Time  `json:"createdAr"`
}

type Expense struct {
    Expenseid    int      	`json:"expenseid"`
    Userid	     int      	`json:"user_id"`
    Incomeid    *int     	`json:"income_id"`
    Category    string		`json:"category"`
    Description string		`json:"description"`
    Amount      float64  	`json:"amount"`  
    CreatedAt   time.Time	`json:"createdAt"`
}

// Add income
func AddIncome(ctx *gin.Context) {
    var req Income

    if err := ctx.ShouldBindJSON(&req); err != nil {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    _, err := database.DB.Exec("INSERT INTO incomes (user_id, description, amount) VALUES ($1, $2, $3)", req.Userid, req.Description, req.Amount)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add income"})
		fmt.Println("Adding the income failed", err)
        return
    }

    ctx.JSON(http.StatusOK, gin.H{"message": "Income added successfully"})
}


// Add expense
func AddExpense(ctx *gin.Context) {
    var req Expense

    if err := ctx.ShouldBindJSON(&req); err != nil {
        ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		fmt.Println("the input is invalid because:", err)
        return
    }

    _, err := database.DB.Exec("INSERT INTO expenses (user_id, income_id, category, description, amount) VALUES ($1, $2, $3, $4, $5)", req.Userid, req.Incomeid , req.Category, req.Description, req.Amount)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add expense"})
		fmt.Println("Adding the expenses has failed: ", err)
        return
    }

    ctx.JSON(http.StatusOK, gin.H{"message": "Expense added successfully"})
}


// Get balance
func GetRemaining(ctx *gin.Context) {
    incomeID := ctx.Param("income_id")

    var incomeAmount float64
    err := database.DB.QueryRow("SELECT amount FROM income WHERE id = $1", incomeID).Scan(&incomeAmount)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch income"})
        return
    }

    var totalExpenses float64
    err = database.DB.QueryRow("SELECT COALESCE(SUM(cost),0) FROM expense WHERE incomeid = $1", incomeID).Scan(&totalExpenses)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch expenses"})
        return
    }

    remaining := incomeAmount - totalExpenses
    ctx.JSON(http.StatusOK, gin.H{
        "income":    incomeAmount,
        "spent":     totalExpenses,
        "remaining": remaining,
    })
}

// Get stats by category
func GetExpenseStats(ctx *gin.Context) {
    incomeIDStr  := ctx.Param("income_id")
	incomeID, err := strconv.Atoi(incomeIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid income_id"})
		return
	}
    rows, err := database.DB.Query("SELECT category, amount FROM expenses WHERE income_id = $1", incomeID)
    if err != nil {
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch expenses"})
		fmt.Println("did not fetch expenses because:", err)
        return
    }
    defer rows.Close()

    stats := []map[string]interface{}{}
    for rows.Next() {
        var category string
        var amount float64
        rows.Scan(&category, &amount)
        stats = append(stats, gin.H{
            "item": category,
            "cost": amount,
        })
    }

    ctx.JSON(http.StatusOK, gin.H{"expenses": stats})
}
