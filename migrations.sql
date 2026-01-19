-- Migration: Add users table for regular users
CREATE TABLE users (
  id CHAR(36) PRIMARY KEY,
  name TEXT NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  phone VARCHAR(20),
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Migration: Add password_hash column to agents table
ALTER TABLE agents ADD COLUMN password_hash VARCHAR(255) NOT NULL DEFAULT '';

-- Add unique constraint to email
ALTER TABLE agents ADD UNIQUE KEY unique_agent_email (email);

-- Optional: Add password_hash to profiles table as well if needed
ALTER TABLE profiles ADD COLUMN password_hash VARCHAR(255);

-- Migration: Add amenities column to properties table
ALTER TABLE properties ADD COLUMN amenities JSON DEFAULT '[]';
-- Migration: Add housing society fields to properties table
-- These fields store the society hierarchy: society -> phase/sector -> block
ALTER TABLE properties ADD COLUMN society_id VARCHAR(100) DEFAULT NULL;
ALTER TABLE properties ADD COLUMN society_phase VARCHAR(100) DEFAULT NULL;
ALTER TABLE properties ADD COLUMN society_block VARCHAR(100) DEFAULT NULL;

-- Add index for faster society-based searches
CREATE INDEX idx_properties_society ON properties(society_id);
CREATE INDEX idx_properties_society_phase ON properties(society_id, society_phase);
CREATE INDEX idx_properties_society_full ON properties(society_id, society_phase, society_block);

-- Migration: Add society fields to agents table for their area of expertise
ALTER TABLE agents ADD COLUMN society_id VARCHAR(100) DEFAULT NULL;
ALTER TABLE agents ADD COLUMN society_phase VARCHAR(100) DEFAULT NULL;
ALTER TABLE agents ADD COLUMN society_block VARCHAR(100) DEFAULT NULL;

-- Add index for faster agent lookup by society
CREATE INDEX idx_agents_society ON agents(society_id);