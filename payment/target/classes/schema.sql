CREATE TABLE Payment (
    payment_Id INT PRIMARY KEY AUTO_INCREMENT,
    user_Id INT NOT NULL,
    booking_Id INT NOT NULL UNIQUE,
    amount DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) CHECK (Status IN ('Pending', 'Completed', 'Failed')) NOT NULL,
    payment_Method VARCHAR(255) NOT NULL,
    payment_Date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_Date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_By VARCHAR(100),
    updated_Date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_By VARCHAR(100)
);
 