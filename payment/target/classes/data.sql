INSERT INTO Payment (user_Id, booking_Id, amount, status, payment_Method, payment_Date, created_Date, created_By, updated_Date, updated_By)
VALUES (1, 101, 2500.00, 'Completed', 'Credit Card', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'System', CURRENT_TIMESTAMP, 'System'),
	 (2, 102, 1500.50, 'Pending', 'PayPal', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'System', CURRENT_TIMESTAMP, 'System'),
 	(3, 103, 3200.75, 'Failed', 'Debit Card', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'System', CURRENT_TIMESTAMP, 'System');
 