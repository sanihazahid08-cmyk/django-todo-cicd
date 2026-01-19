-- Database schema for Aura Home Real Estate Platform (MySQL/MariaDB version)
-- Converted from PostgreSQL/Supabase schema

-- 1. Users Table (for regular users)
CREATE TABLE users (
  id CHAR(36) PRIMARY KEY,
  name TEXT NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  phone VARCHAR(20),
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 2. Profiles Table (for user profiles)
CREATE TABLE profiles (
  id CHAR(36) PRIMARY KEY,
  name TEXT,
  phone TEXT,
  role VARCHAR(50) DEFAULT 'user',
  is_admin BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Note: RLS and Policies are PostgreSQL/Supabase features
-- Implement row-level security at the application level in MySQL

-- 2. Agent Applications Table
CREATE TABLE agent_applications (
  id CHAR(36) PRIMARY KEY DEFAULT UUID(),
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT NOT NULL,
  agency TEXT NOT NULL,
  experience INTEGER NOT NULL,
  cnic TEXT NOT NULL,
  address TEXT NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  attachments JSON DEFAULT '[]',
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Note: Implement security policies at the application level

-- 3. Agents Table (for approved agents)
CREATE TABLE agents (
  id CHAR(36) PRIMARY KEY DEFAULT UUID(),
  user_id CHAR(36),
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT NOT NULL,
  agency TEXT NOT NULL,
  experience INTEGER NOT NULL,
  cnic TEXT NOT NULL,
  address TEXT NOT NULL,
  attachments JSON DEFAULT '[]',
  approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Note: Implement security policies at the application level

-- 4. Properties Table
CREATE TABLE properties (
  id CHAR(36) PRIMARY KEY DEFAULT UUID(),
  title TEXT NOT NULL,
  description TEXT,
  price DECIMAL(12,2) NOT NULL,
  property_type VARCHAR(50) NOT NULL,
  bedrooms INTEGER,
  bathrooms INTEGER,
  area_sqft INTEGER,
  address TEXT NOT NULL,
  city TEXT NOT NULL,
  state TEXT,
  zip_code TEXT,
  latitude DECIMAL(10,8),
  longitude DECIMAL(11,8),
  images JSON DEFAULT '[]',
  amenities JSON DEFAULT '[]',
  agent_id CHAR(36),
  status VARCHAR(50) DEFAULT 'available',
  featured BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Note: Implement security policies at the application level

-- 5. Storage Setup
-- Note: File storage should be handled at the application level
-- Consider using AWS S3, Azure Blob Storage, or similar services

-- 6. Stored Procedure to handle agent approval (MySQL version)
DELIMITER //
CREATE PROCEDURE approve_agent(IN application_id CHAR(36))
BEGIN
  DECLARE app_password_hash VARCHAR(255);
  
  SELECT status, email, name, phone, agency, experience, cnic, address, attachments, password_hash
  INTO app_status, app_email, app_name, app_phone, app_agency, app_experience, app_cnic, app_address, app_attachments, app_password_hash
  FROM agent_applications WHERE id = application_id;
  
  IF app_status != 'pending' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Application is not pending';
  END IF;
  
  INSERT INTO agents (user_id, name, email, phone, agency, experience, cnic, address, attachments, password_hash)
  VALUES (NULL, app_name, app_email, app_phone, app_agency, app_experience, app_cnic, app_address, app_attachments, app_password_hash);
  
  UPDATE agent_applications SET status = 'approved' WHERE id = application_id;
END//
DELIMITER ;

-- 7. Stored Procedure to handle agent rejection (MySQL version)
DELIMITER //
CREATE PROCEDURE reject_agent(IN application_id CHAR(36))
BEGIN
  UPDATE agent_applications SET status = 'rejected' WHERE id = application_id;
END//
DELIMITER ;

-- 8. Note: User profile creation trigger
-- This should be handled at the application level when users sign up
-- Create profiles through your authentication provider's webhooks or application code

-- 9. Admin Setup Instructions
-- To make a user an admin, run this query after they sign up:
-- UPDATE profiles SET is_admin = true WHERE id = 'USER_UUID_HERE';