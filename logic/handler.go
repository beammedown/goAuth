package logic

import (
	utils "beammedown/goAuth/models"
	"database/sql"
	"errors"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

type App struct {
	DB *sql.DB
}

func (a *App) InitDB() error {
	var err error
	if _, err := os.Stat("db.sqlite3"); errors.Is(err, os.ErrNotExist) {
		os.Remove("db.sqlite3")
	}
	a.DB, err = sql.Open("sqlite", "db.sqlite3")
	if err != nil {
		return err
	}

	if _, err = a.DB.Exec(`
		DROP TABLE IF EXISTS Users;
		CREATE TABLE Users(
		id INTEGER PRIMARY KEY NOT NULL,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		role TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		`); err != nil {
		return err
	}
	insert_statement := fmt.Sprintf("INSERT INTO Users (username, password, role) VALUES ('%v', '%v', '%v');", os.Getenv("DEFAULT_USER"), os.Getenv("DEFAULT_PASSWORD"), os.Getenv("DEFAULT_ROLE"))
	if _, err = a.DB.Exec(insert_statement); err != nil {
		return err
	}

	insert_statement = fmt.Sprintf("INSERT INTO Users (username, password, role) VALUES ('%v', '%v', '%v');", os.Getenv("DEFAULT_ADMIN_USER"), os.Getenv("DEFAULT_ADMIN_PASSWORD"), os.Getenv("DEFAULT_ADMIN_ROLE"))
	if _, err = a.DB.Exec(insert_statement); err != nil {
		return err
	}

	//	rows, err := a.DB.Query("SELECT * FROM Users;")
	//	if err != nil {
	//		return err
	//	}
	//	for rows.Next() {
	//		var id int
	//		var username string
	//		var password string
	//		var role string
	//		var created_at string
	//		if err = rows.Scan(&id, &username, &password, &role, &created_at); err != nil {
	//			return err
	//		}
	//		fmt.Println(id)
	//		fmt.Println(username)
	//		fmt.Println(password)
	//		fmt.Println(role)
	//		fmt.Println(created_at)
	//	}

	return nil
}

func (a *App) GetAllResults(statement string) ([]utils.DbSchema, error) {
	var results []utils.DbSchema

	rows, err := a.DB.Query("SELECT * FROM Users;")
	if err != nil {
		return results, err
	}
	for rows.Next() {
		var id int
		var username string
		var password string
		var role string
		var created_at string
		if err = rows.Scan(&id, &username, &password, &role, &created_at); err != nil {
			return results, err
		}

		results = append(results, utils.DbSchema{
			Id:         id,
			Username:   username,
			Password:   password,
			Role:       role,
			Created_at: created_at,
		})
	}

	return results, nil
}

func (a *App) GetFirstResult(statement string) (utils.DbSchema, error) {
	var results utils.DbSchema

	rows, err := a.DB.Query(statement)
	if err != nil {
		return results, err
	}
	if rows.Next() {
		var id int
		var username string
		var password string
		var role string
		var created_at string
		if err = rows.Scan(&id, &username, &password, &role, &created_at); err != nil {
			return results, err
		}

		results = utils.DbSchema{
			Id:         id,
			Username:   username,
			Password:   password,
			Role:       role,
			Created_at: created_at,
		}

	} else {
		return results, errors.New("No Item Found")
	}
	return results, nil

}

func (a *App) AddUser(username string, password string, role string) error {
	if username == "" {
		return errors.New("No username provided")
	} else if password == "" {
		return errors.New("No password provided")
	}
	if role == "" {
		role = "user"
	}

	utils.Logger.Info().Msg("Preparing Insertion Execution")
	insert_statement := fmt.Sprintf("INSERT INTO Users (username, password, role) VALUES ('%v', '%v', '%v');", username, password, role)

	_, err := a.DB.Exec(insert_statement)
	if err != nil {
		utils.Logger.Err(err).Msg("")
		return err
	}

	utils.Logger.Info().Msg("Inserted successfully")
	return nil
}
