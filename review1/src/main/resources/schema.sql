CREATE TABLE Review (
    Review_ID INT PRIMARY KEY AUTO_INCREMENT,
    
    User_ID INT NOT NULL,            -- reference to User in external service
    Hotel_ID INT,                    -- optional: only for hotel reviews
    Flight_ID INT,                   -- optional: only for flight reviews
 
    Rating INT CHECK (Rating BETWEEN 1 AND 5) NOT NULL,
    Comment TEXT,
 
    Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    Created_Date DATETIME DEFAULT CURRENT_TIMESTAMP,
    Created_By VARCHAR(100),
    Updated_Date DATETIME DEFAULT CURRENT_TIMESTAMP,
    Updated_By VARCHAR(100),
 
    -- Ensure exactly one of HotelID or FlightID is present
    CONSTRAINT chk_review_target CHECK (
        (Hotel_ID IS NOT NULL AND Flight_ID IS NULL)
        OR (Hotel_ID IS NULL AND Flight_ID IS NOT NULL)
    )
);