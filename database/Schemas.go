package database

func GetTableQueries() []string {
	return []string{`CREATE TABLE IF NOT EXISTS theuser (
			userid			   SERIAL PRIMARY KEY,
			email              TEXT NOT NULL,
			phonenumber        TEXT NOT NULL,
			password           TEXT NOT NULL,
			created			   TEXT NOT NULL,
			resettoken         TEXT,
	        resettokenexpiry   TIMESTAMP WITH TIME ZONE,
			failed_attempts  INT DEFAULT 0,
    		lockout_until    TIMESTAMP WITH TIME ZONE  
		)`,
		` CREATE TABLE IF NOT EXISTS incomes (
   			 incomeid SERIAL PRIMARY KEY,
   			 user_id INT REFERENCES theuser(userid) ON DELETE CASCADE,
   			 amount NUMERIC(12,2) NOT NULL,
   			 description TEXT,
   			 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`,

		`CREATE TABLE IF NOT EXISTS expenses (
   			 expenseid SERIAL PRIMARY KEY,
   			 user_id INT REFERENCES theuser(userid) ON DELETE CASCADE,
   			 income_id INT REFERENCES incomes(incomeid) ON DELETE CASCADE, -- optional link to an income source
   			 category VARCHAR(100),   -- e.g. Rent, Food, Transport
   			 description TEXT,
   			 amount NUMERIC(12,2) NOT NULL,
   			 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`,
	}

}
