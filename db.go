package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// DBVersion shows the database version this code uses. This is used for update checks.
var DBVersion = 1

var acmeTable = `
	CREATE TABLE IF NOT EXISTS acmedns(
		Name TEXT,
		Value TEXT
	);`

var userTable = `
	CREATE TABLE IF NOT EXISTS records(
        Username TEXT UNIQUE NOT NULL PRIMARY KEY,
        Password TEXT UNIQUE NOT NULL,
        Subdomain TEXT UNIQUE NOT NULL,
		AllowFrom TEXT
    );`

var txtTable = `
    CREATE TABLE IF NOT EXISTS txt(
		Subdomain TEXT NOT NULL,
		Value   TEXT NOT NULL DEFAULT '',
		LastUpdate INT
	);`

var txtTablePG = `
    CREATE TABLE IF NOT EXISTS txt(
		rowid SERIAL,
		Subdomain TEXT NOT NULL,
		Value   TEXT NOT NULL DEFAULT '',
		LastUpdate INT
	);`

// getSQLiteStmt replaces all PostgreSQL prepared statement placeholders (eg. $1, $2) with SQLite variant "?"
func getSQLiteStmt(s string) string {
	re, _ := regexp.Compile("\\$[0-9]")
	return re.ReplaceAllString(s, "?")
}

func (d *acmedb) Init(engine string, connection string) error {
	d.Lock()
	defer d.Unlock()
	db, err := sql.Open(engine, connection)
	if err != nil {
		return err
	}
	d.DB = db
	// Check version first to try to catch old versions without version string
	var versionString string
	_ = d.DB.QueryRow("SELECT Value FROM acmedns WHERE Name='db_version'").Scan(&versionString)
	if versionString == "" {
		versionString = "0"
	}
	_, err = d.DB.Exec(acmeTable)
	_, err = d.DB.Exec(userTable)
	if Config.Database.Engine == "sqlite3" {
		_, err = d.DB.Exec(txtTable)
	} else {
		_, err = d.DB.Exec(txtTablePG)
	}
	// If everything is fine, handle db upgrade tasks
	if err == nil {
		err = d.checkDBUpgrades(versionString)
	}
	if err == nil {
		if versionString == "0" {
			// No errors so we should now be in version 1
			insversion := fmt.Sprintf("INSERT INTO acmedns (Name, Value) values('db_version', '%d')", DBVersion)
			_, err = db.Exec(insversion)
		}
	}
	return err
}

func (d *acmedb) checkDBUpgrades(versionString string) error {
	var err error
	version, err := strconv.Atoi(versionString)
	if err != nil {
		return err
	}
	if version != DBVersion {
		return d.handleDBUpgrades(version)
	}
	return nil

}

func (d *acmedb) handleDBUpgrades(version int) error {
	if version == 0 {
		return d.handleDBUpgradeTo1()
	}
	return nil
}

func (d *acmedb) handleDBUpgradeTo1() error {
	var err error
	var subdomains []string
	rows, err := d.DB.Query("SELECT Subdomain FROM records")
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade")
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var subdomain string
		err = rows.Scan(&subdomain)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while reading values")
			return err
		}
		subdomains = append(subdomains, subdomain)
	}
	err = rows.Err()
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while inserting values")
		return err
	}
	tx, err := d.DB.Begin()
	// Rollback if errored, commit if not
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()
	_, _ = tx.Exec("DELETE FROM txt")
	for _, subdomain := range subdomains {
		if subdomain != "" {
			// Insert two rows for each subdomain to txt table
			err = d.NewTXTValuesInTransaction(tx, subdomain)
			if err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while inserting values")
				return err
			}
		}
	}
	// SQLite doesn't support dropping columns
	if Config.Database.Engine != "sqlite3" {
		_, _ = tx.Exec("ALTER TABLE records DROP COLUMN IF EXISTS Value")
		_, _ = tx.Exec("ALTER TABLE records DROP COLUMN IF EXISTS LastActive")
	}
	_, err = tx.Exec("UPDATE acmedns SET Value='1' WHERE Name='db_version'")
	return err
}

// Create two rows for subdomain to the txt table
func (d *acmedb) NewTXTValuesInTransaction(tx *sql.Tx, subdomain string) error {
	var err error
	instr := fmt.Sprintf("INSERT INTO txt (Subdomain, LastUpdate) values('%s', 0)", subdomain)
	_, err = tx.Exec(instr)
	_, err = tx.Exec(instr)
	return err
}

func (d *acmedb) Register(afrom cidrslice) (ACMETxt, error) {
	d.Lock()
	defer d.Unlock()
	var err error
	tx, err := d.DB.Begin()
	// Rollback if errored, commit if not
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		tx.Commit()
	}()
	a := newACMETxt()
	a.AllowFrom = cidrslice(afrom.ValidEntries())
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(a.Password), 10)
	regSQL := `
    INSERT INTO records(
        Username,
        Password,
        Subdomain,
		AllowFrom) 
        values($1, $2, $3, $4)`
	if Config.Database.Engine == "sqlite3" {
		regSQL = getSQLiteStmt(regSQL)
	}
	sm, err := tx.Prepare(regSQL)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Database error in prepare")
		return a, errors.New("SQL error")
	}
	defer sm.Close()
	_, err = sm.Exec(a.Username.String(), passwordHash, a.Subdomain, a.AllowFrom.JSON())
	if err == nil {
		err = d.NewTXTValuesInTransaction(tx, a.Subdomain)
	}
	return a, err
}

func (d *acmedb) Unregister(username uuid.UUID) error {
	// fmt.Println("Unregister --- Test 1")
	var err error

	// Check if user exists
	user, err := DB.GetByUsername(username)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("User doesn't exist")
		return errors.New("User doesn't exist")
	}
	// fmt.Println("Unregister --- Test 2")

	d.Lock()
	defer d.Unlock()
	tx, err := d.DB.Begin()
	// fmt.Println("Unregister --- Test 3")

	// Delete user's TXT records
	err = d.DeleteTXTForDomain(tx, user.Subdomain)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Could not delete TXT records")
		return err
	}
	// fmt.Println("Unregister --- Test 4")

	// Rollback if errored, commit if not
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		// fmt.Println("Unregister --- Commit")
		err = tx.Commit()
		if err != nil {
			fmt.Println(err)
		}
	}()

	// Delete user record
	// d.Lock()
	// fmt.Println("Unregister --- Test 5")
	// defer d.Unlock()
	unregSQL := `
	DELETE FROM records
        WHERE Username = $1`
	if Config.Database.Engine == "sqlite3" {
		unregSQL = getSQLiteStmt(unregSQL)
	}
	sm, err := tx.Prepare(unregSQL)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Database error in prepare")
		return errors.New("SQL error")
	}
	defer sm.Close()
	_, err = sm.Exec(username.String())
	// fmt.Println("Unregister --- Test 6")
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Database error in execute")
		return errors.New("SQL error")
	}

	return nil
}

func (d *acmedb) GetByUsername(u uuid.UUID) (ACMETxt, error) {
	d.Lock()
	defer d.Unlock()
	var results []ACMETxt
	getSQL := `
	SELECT Username, Password, Subdomain, AllowFrom
	FROM records
	WHERE Username=$1 LIMIT 1
	`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return ACMETxt{}, err
	}
	defer sm.Close()
	rows, err := sm.Query(u.String())
	if err != nil {
		return ACMETxt{}, err
	}
	defer rows.Close()

	// It will only be one row though
	for rows.Next() {
		txt, err := getModelFromRow(rows)
		if err != nil {
			return ACMETxt{}, err
		}
		results = append(results, txt)
	}
	if len(results) > 0 {
		return results[0], nil
	}
	return ACMETxt{}, errors.New("no user")
}

func (d *acmedb) GetTXTForDomain(domain string) ([]string, error) {
	d.Lock()
	defer d.Unlock()
	domain = sanitizeString(domain)
	var txts []string
	getSQL := `
	SELECT Value FROM txt WHERE Subdomain=$1 LIMIT 2
	`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return txts, err
	}
	defer sm.Close()
	rows, err := sm.Query(domain)
	if err != nil {
		return txts, err
	}
	defer rows.Close()

	for rows.Next() {
		var rtxt string
		err = rows.Scan(&rtxt)
		if err != nil {
			return txts, err
		}
		txts = append(txts, rtxt)
	}
	return txts, nil
}

func (d *acmedb) Update(a ACMETxtPost) error {
	d.Lock()
	defer d.Unlock()
	var err error
	// Data in a is already sanitized
	timenow := time.Now().Unix()

	updSQL := `
	UPDATE txt SET Value=$1, LastUpdate=$2
	WHERE rowid=(
		SELECT rowid FROM txt WHERE Subdomain=$3 ORDER BY LastUpdate LIMIT 1)
	`
	if Config.Database.Engine == "sqlite3" {
		updSQL = getSQLiteStmt(updSQL)
	}

	sm, err := d.DB.Prepare(updSQL)
	if err != nil {
		return err
	}
	defer sm.Close()
	_, err = sm.Exec(a.Value, timenow, a.Subdomain)
	if err != nil {
		return err
	}
	return nil
}

func (d *acmedb) DeleteTXTForDomain(tx *sql.Tx, domain string) error {
	domain = sanitizeString(domain)
	getSQL := `DELETE FROM txt WHERE Subdomain=$1`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := tx.Prepare(getSQL)
	if err != nil {
		return err
	}
	defer sm.Close()
	_, err = sm.Exec(domain)
	if err != nil {
		return err
	}
	return nil
}

func (d *acmedb) PurgeUnusedUsers(days int) (int, error) {
	timeNow := time.Now()
	tsMin := timeNow.AddDate(0, 0, days*-1).Unix()

	getSQL := `
	SELECT r.Username, MAX(t.LastUpdate) LatestUpdate
	   FROM records r
	   INNER JOIN txt t
	   ON r.Subdomain = t.Subdomain
	   GROUP BY r.Username
	   HAVING LatestUpdate < $1`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return 0, err
	}
	rows, err := sm.Query(tsMin)
	if err != nil {
		return 0, err
	}
	sm.Close()
	defer rows.Close()

	type userToDelete struct {
		user         uuid.UUID
		LatestUpdate int
	}
	var usersToDelete = []userToDelete{}
	for rows.Next() {
		var userToDelete userToDelete
		err = rows.Scan(&userToDelete.user, &userToDelete.LatestUpdate)
		usersToDelete = append(usersToDelete, userToDelete)
	}
	rows.Close()

	// Delete users
	var deletedUsers int = 0
	for _, userToDelete := range usersToDelete {
		log.WithFields(log.Fields{"user": userToDelete.user.String(), "LatestUpdate": time.Unix(int64(userToDelete.LatestUpdate), 0)}).Info("Delete user")
		err = DB.Unregister(userToDelete.user)
		if err != nil {
			log.Error(fmt.Sprintf("Could not delete user %s [%s]", userToDelete.user, err))
			break
		} else {
			deletedUsers++
		}
	}
	return deletedUsers, err
}

func getModelFromRow(r *sql.Rows) (ACMETxt, error) {
	txt := ACMETxt{}
	afrom := ""
	err := r.Scan(
		&txt.Username,
		&txt.Password,
		&txt.Subdomain,
		&afrom)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Row scan error")
	}

	cslice := cidrslice{}
	err = json.Unmarshal([]byte(afrom), &cslice)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("JSON unmarshall error")
	}
	txt.AllowFrom = cslice
	return txt, err
}

func (d *acmedb) Close() {
	d.DB.Close()
}

func (d *acmedb) GetBackend() *sql.DB {
	return d.DB
}

func (d *acmedb) SetBackend(backend *sql.DB) {
	d.DB = backend
}
