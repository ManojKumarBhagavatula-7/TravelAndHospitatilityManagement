
-- Insert sample travel packages with audit fields
INSERT INTO package (packageId, packageName, price, created_by, created_date, last_modified_by, last_modified_date)
VALUES (1, 'Beach Paradise', 15000.00, 'admin', CURRENT_TIMESTAMP, 'admin', CURRENT_TIMESTAMP),
       (2, 'Mountain Adventure', 20000.00, 'admin', CURRENT_TIMESTAMP, 'admin', CURRENT_TIMESTAMP);

-- Insert included hotel IDs
INSERT INTO travel_package_included_hotel_ids (travel_package_package_id, included_hotel_ids)
VALUES (1, 101), (1, 102), (2, 201);

-- Insert included flight IDs
INSERT INTO travel_package_included_flight_ids (travel_package_package_id, included_flight_ids)
VALUES (1, 301), (2, 401), (2, 402);

-- Insert activities
INSERT INTO travel_package_activities (travel_package_package_id, activities)
VALUES (1, 'Snorkeling'), (1, 'Beach Volleyball'), (2, 'Hiking'), (2, 'Rock Climbing');

-- Insert itineraries with audit fields
INSERT INTO itinerary (itineraryId, userId, customizationDetails, price, packageId, created_by, created_date, last_modified_by, last_modified_date)
VALUES (1, 1001, 'Custom details 1', 5000.00, 1, 'admin', CURRENT_TIMESTAMP, 'admin', CURRENT_TIMESTAMP),
       (2, 1002, 'Custom details 2', 6000.00, 1, 'admin', CURRENT_TIMESTAMP, 'admin', CURRENT_TIMESTAMP),
       (3, 1003, 'Custom details 3', 7000.00, 2, 'admin', CURRENT_TIMESTAMP, 'admin', CURRENT_TIMESTAMP),
       (4, 1004, 'Custom details 4', 8000.00, 2, 'admin', CURRENT_TIMESTAMP, 'admin', CURRENT_TIMESTAMP);
