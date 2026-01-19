import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const PORT = 3001;
const JWT_SECRET = 'aura_home_secret_key_2024';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// MySQL connection pool
const pool = mysql.createPool({
  host: '216.106.180.123',
  user: 'webdevco_realuser',
  password: 'adeel@490A',
  database: 'webdevco_real',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
pool.getConnection()
  .then(conn => {
    console.log('✓ MySQL database connected successfully');
    conn.release();
  })
  .catch(err => {
    console.error('✗ Database connection failed:', err.message);
  });

// ============== AUTHENTICATION MIDDLEWARE ==============

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
};

// ============== AUTHENTICATION ENDPOINTS ==============

// Register Agent or User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, phone, agency, experience, cnic, address, userType, attachments } = req.body;

    if (!email || !password || !name || !phone) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    const connection = await pool.getConnection();

    // Check if email already exists in users table
    const [existingUsers] = await connection.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      connection.release();
      return res.status(400).json({ success: false, error: 'Email already registered' });
    }

    // Check if email already exists in agents table
    const [existingAgents] = await connection.query('SELECT * FROM agents WHERE email = ?', [email]);
    if (existingAgents.length > 0) {
      connection.release();
      return res.status(400).json({ success: false, error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    if (userType === 'agent') {
      // Agent registration - all fields required
      if (!agency || !experience || !cnic || !address) {
        connection.release();
        return res.status(400).json({ success: false, error: 'All agent fields are required' });
      }

      // Store attachments as JSON array
      const attachmentArray = Array.isArray(attachments) ? attachments : [];

      await connection.query(
        'INSERT INTO agent_applications (id, name, email, phone, agency, experience, cnic, address, password_hash, attachments) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [userId, name, email, phone, agency, experience, cnic, address, hashedPassword, JSON.stringify(attachmentArray)]
      );

      connection.release();
      res.status(201).json({ 
        success: true, 
        message: 'Agent application submitted successfully. Please wait for admin approval.' 
      });
    } else {
      // Regular user registration
      await connection.query(
        'INSERT INTO users (id, name, email, phone, password_hash) VALUES (?, ?, ?, ?, ?)',
        [userId, name, email, phone, hashedPassword]
      );

      connection.release();
      res.status(201).json({ 
        success: true, 
        message: 'User registered successfully. You can now login.' 
      });
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Login Agent or User
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password required' });
    }

    // Check for admin login
    if (email === 'dummy@gmail.com' && password === 'asd123') {
      const token = jwt.sign(
        { id: 'admin-uuid', email: 'dummy@gmail.com', name: 'Admin', type: 'admin' },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        success: true,
        message: 'Admin login successful',
        token,
        user: {
          id: 'admin-uuid',
          name: 'Admin',
          email: 'dummy@gmail.com',
          type: 'admin'
        }
      });
    }

    const connection = await pool.getConnection();

    // Try to find in users table first
    const [users] = await connection.query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length > 0) {
      const user = users[0];
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      
      if (!isPasswordValid) {
        connection.release();
        return res.status(401).json({ success: false, error: 'Invalid credentials' });
      }

      connection.release();

      const token = jwt.sign(
        { id: user.id, email: user.email, name: user.name, type: 'user' },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        success: true,
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          type: 'user'
        }
      });
    }

    // Try to find in agents table
    const [agents] = await connection.query('SELECT * FROM agents WHERE email = ?', [email]);
    
    if (agents.length > 0) {
      const agent = agents[0];
      const isPasswordValid = await bcrypt.compare(password, agent.password_hash);
      
      if (!isPasswordValid) {
        connection.release();
        return res.status(401).json({ success: false, error: 'Invalid credentials' });
      }

      connection.release();

      const token = jwt.sign(
        { id: agent.id, email: agent.email, name: agent.name, type: 'agent', status: 'approved' },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        success: true,
        message: 'Login successful',
        token,
        agent: {
          id: agent.id,
          name: agent.name,
          email: agent.email,
          phone: agent.phone,
          agency: agent.agency,
          experience: agent.experience,
          type: 'agent',
          status: 'approved'
        }
      });
    }

    // Try to find in agent_applications table
    const [applications] = await connection.query('SELECT * FROM agent_applications WHERE email = ?', [email]);
    
    if (applications.length > 0) {
      const application = applications[0];
      const isPasswordValid = await bcrypt.compare(password, application.password_hash);
      
      if (!isPasswordValid) {
        connection.release();
        return res.status(401).json({ success: false, error: 'Invalid credentials' });
      }

      connection.release();

      const token = jwt.sign(
        { id: application.id, email: application.email, name: application.name, type: 'agent', status: application.status },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        success: true,
        message: 'Login successful',
        token,
        agent: {
          id: application.id,
          name: application.name,
          email: application.email,
          phone: application.phone,
          agency: application.agency,
          experience: application.experience,
          type: 'agent',
          status: application.status
        }
      });
    }

    connection.release();
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get current user profile
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [agents] = await connection.query('SELECT * FROM agents WHERE id = ?', [req.userId]);
    connection.release();

    if (agents.length === 0) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    const agent = agents[0];
    res.json({
      success: true,
      agent: {
        id: agent.id,
        name: agent.name,
        email: agent.email,
        phone: agent.phone,
        agency: agent.agency,
        experience: agent.experience,
        cnic: agent.cnic,
        address: agent.address
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Logout (frontend removes token)
app.post('/api/auth/logout', (req, res) => {
  res.json({ success: true, message: 'Logout successful' });
});


// ============== PROFILES ENDPOINTS ==============

// Get all profiles
app.get('/api/profiles', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM profiles');
    connection.release();
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get profile by ID
app.get('/api/profiles/:id', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM profiles WHERE id = ?', [req.params.id]);
    connection.release();
    res.json({ success: true, data: rows[0] || null });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create profile
app.post('/api/profiles', async (req, res) => {
  try {
    const { id, name, phone, role, is_admin } = req.body;
    const connection = await pool.getConnection();
    await connection.query(
      'INSERT INTO profiles (id, name, phone, role, is_admin) VALUES (?, ?, ?, ?, ?)',
      [id, name, phone, role || 'user', is_admin || false]
    );
    connection.release();
    res.status(201).json({ success: true, message: 'Profile created' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update profile
app.put('/api/profiles/:id', async (req, res) => {
  try {
    const { name, phone, role, is_admin } = req.body;
    const connection = await pool.getConnection();
    await connection.query(
      'UPDATE profiles SET name = ?, phone = ?, role = ?, is_admin = ?, updated_at = NOW() WHERE id = ?',
      [name, phone, role, is_admin, req.params.id]
    );
    connection.release();
    res.json({ success: true, message: 'Profile updated' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============== AGENT APPLICATIONS ENDPOINTS ==============

// Get all agent applications
app.get('/api/agent-applications', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM agent_applications ORDER BY created_at DESC');
    connection.release();
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get agent application by ID
app.get('/api/agent-applications/:id', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM agent_applications WHERE id = ?', [req.params.id]);
    connection.release();
    res.json({ success: true, data: rows[0] || null });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create agent application
app.post('/api/agent-applications', async (req, res) => {
  try {
    const { id, name, email, phone, agency, experience, cnic, address, attachments } = req.body;
    const connection = await pool.getConnection();
    await connection.query(
      'INSERT INTO agent_applications (id, name, email, phone, agency, experience, cnic, address, attachments) VALUES (UUID(), ?, ?, ?, ?, ?, ?, ?, ?)',
      [name, email, phone, agency, experience, cnic, address, JSON.stringify(attachments || [])]
    );
    connection.release();
    res.status(201).json({ success: true, message: 'Application submitted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update agent application status
app.put('/api/agent-applications/:id', async (req, res) => {
  try {
    const { status } = req.body;
    const connection = await pool.getConnection();
    await connection.query(
      'UPDATE agent_applications SET status = ?, updated_at = NOW() WHERE id = ?',
      [status, req.params.id]
    );
    connection.release();
    res.json({ success: true, message: 'Application updated' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Approve agent application
app.post('/api/agent-applications/:id/approve', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.query('CALL approve_agent(?)', [req.params.id]);
    connection.release();
    res.json({ success: true, message: 'Agent approved successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Reject agent application
app.post('/api/agent-applications/:id/reject', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.query('CALL reject_agent(?)', [req.params.id]);
    connection.release();
    res.json({ success: true, message: 'Agent application rejected' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============== AGENTS ENDPOINTS ==============

// Search agents by housing society - MUST be before /:id route
// Searches in properties table for society_id, society_phase, society_block fields
app.get('/api/agents/by-society', async (req, res) => {
  try {
    const { society_id, society_phase, society_block } = req.query;
    const connection = await pool.getConnection();
    
    console.log('Society search params:', { society_id, society_phase, society_block });
    
    // Map society_id to search keywords
    const societyKeywords = {
      '1': ['DHA', 'Defence', 'Defense', 'DHA Lahore'],
      'dha-karachi': ['DHA', 'Defence', 'Defense', 'DHA Karachi'],
      'dha-islamabad': ['DHA', 'Defence', 'Defense', 'DHA Islamabad'],
      'bahria-town-lahore': ['Bahria Town', 'Bahria'],
      'bahria-town-karachi': ['Bahria Town', 'Bahria'],
      'bahria-town-islamabad': ['Bahria Town', 'Bahria'],
      'lake-city-lahore': ['Lake City'],
      'lda-city-lahore': ['LDA City', 'LDA'],
      'gulberg-lahore': ['Gulberg'],
      'model-town-lahore': ['Model Town'],
      'johar-town-lahore': ['Johar Town'],
      'al-kabir-town-lahore': ['Al Kabir', 'Al-Kabir', 'Alkabir'],
    };
    
    let sql;
    let params = [];
    
    // If phase or block is specified, do strict filtering
    if (society_phase || society_block) {
      let whereConditions = [];
      
      if (society_id) {
        whereConditions.push(`LOWER(p.society_id) = LOWER(?)`);
        params.push(society_id);
      }
      if (society_phase) {
        whereConditions.push(`LOWER(p.society_phase) = LOWER(?)`);
        params.push(society_phase);
      }
      if (society_block) {
        whereConditions.push(`LOWER(p.society_block) = LOWER(?)`);
        params.push(society_block);
      }
      
      sql = `
        SELECT DISTINCT a.*, 
          COUNT(DISTINCT p.id) as property_count,
          GROUP_CONCAT(DISTINCT p.society_phase) as available_phases,
          GROUP_CONCAT(DISTINCT p.society_block) as available_blocks
        FROM agents a 
        INNER JOIN properties p ON a.id = p.agent_id 
        WHERE ${whereConditions.join(' AND ')}
        GROUP BY a.id 
        ORDER BY property_count DESC, a.created_at DESC
        LIMIT 50
      `;
    } else if (society_id) {
      // Only society is specified - search broadly in society_id, title, and address
      const keywords = societyKeywords[society_id] || [society_id.replace(/-/g, ' ')];
      
      let searchConditions = [];
      
      // Match exact society_id
      searchConditions.push(`LOWER(p.society_id) = LOWER(?)`);
      params.push(society_id);
      
      // Also match keywords in title and address
      keywords.forEach(keyword => {
        searchConditions.push(`LOWER(p.title) LIKE LOWER(?)`);
        params.push(`%${keyword}%`);
        searchConditions.push(`LOWER(p.address) LIKE LOWER(?)`);
        params.push(`%${keyword}%`);
      });
      
      sql = `
        SELECT DISTINCT a.*, 
          COUNT(DISTINCT p.id) as property_count,
          GROUP_CONCAT(DISTINCT p.society_phase) as available_phases,
          GROUP_CONCAT(DISTINCT p.society_block) as available_blocks
        FROM agents a 
        INNER JOIN properties p ON a.id = p.agent_id 
        WHERE (${searchConditions.join(' OR ')})
        GROUP BY a.id 
        ORDER BY property_count DESC, a.created_at DESC
        LIMIT 50
      `;
    } else {
      // No filters - return top agents with properties
      sql = `
        SELECT DISTINCT a.*, COUNT(DISTINCT p.id) as property_count
        FROM agents a 
        INNER JOIN properties p ON a.id = p.agent_id
        GROUP BY a.id
        ORDER BY property_count DESC, a.created_at DESC
        LIMIT 20
      `;
    }
    
    console.log('Executing SQL:', sql);
    console.log('With params:', params);
    
    const [rows] = await connection.query(sql, params);
    console.log('Search found:', rows.length, 'agents');
    
    connection.release();
    res.json({ success: true, data: rows || [] });
  } catch (error) {
    console.error('Society search error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get agent by ID
app.get('/api/agents/:id', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM agents WHERE id = ?', [req.params.id]);
    connection.release();
    res.json({ success: true, data: rows[0] || null });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get agents by city
app.get('/api/agents/city/:city', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const city = req.params.city;
    const searchTerm = `%${city}%`;
    
    // First try: agents with properties in that city
    const [rows] = await connection.query(
      `SELECT DISTINCT a.* FROM agents a 
       LEFT JOIN properties p ON a.id = p.agent_id 
       WHERE p.city LIKE ? OR a.address LIKE ? 
       ORDER BY a.created_at DESC`,
      [searchTerm, searchTerm]
    );
    
    connection.release();
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Search agents by area with STRICT matching - show only agents from the EXACT area entered
app.get('/api/agents/search/:query', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const query = req.params.query.toLowerCase().trim();
    const searchTerm = `%${query}%`;
    
    // ALWAYS use STRICT matching: Agent's address must contain the FULL search text
    // This ensures whatever user types, only agents from that SPECIFIC area are shown
    // e.g., "DHA Lahore Phase 1" only returns Phase 1 agents, not all DHA Lahore agents
    // e.g., "Bahria Town" only returns Bahria Town agents, not mixing with other areas
    
    const sql = `
      SELECT DISTINCT a.* FROM agents a 
      LEFT JOIN properties p ON a.id = p.agent_id 
      WHERE LOWER(a.address) LIKE ?
         OR LOWER(p.city) LIKE ?
         OR LOWER(p.title) LIKE ?
      ORDER BY 
        CASE 
          WHEN LOWER(a.address) LIKE ? THEN 1
          WHEN LOWER(p.city) LIKE ? THEN 2
          ELSE 3
        END,
        a.created_at DESC
    `;
    const params = [searchTerm, searchTerm, searchTerm, searchTerm, searchTerm];
    
    const [rows] = await connection.query(sql, params);
    
    connection.release();
    res.json({ success: true, data: rows || [] });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Advanced property search to find agents by property criteria
app.get('/api/agents/by-property/:query', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const query = req.params.query.toLowerCase();
    
    // Extract potential city name (last word or after "in")
    let cityKeyword = '';
    const inIndex = query.indexOf(' in ');
    if (inIndex !== -1) {
      cityKeyword = `%${query.substring(inIndex + 4).trim()}%`;
    } else {
      const words = query.split(' ');
      cityKeyword = `%${words[words.length - 1]}%`;
    }
    
    // Extract property type keywords
    const propertyTypes = ['marla', 'kanal', 'apartment', 'flat', 'house', 'villa', 'commercial', 'office', 'shop', 'plot'];
    const matchedTypes = propertyTypes.filter(type => query.includes(type));
    
    let sql = `
      SELECT DISTINCT a.* FROM agents a 
      LEFT JOIN properties p ON a.id = p.agent_id 
      WHERE p.city LIKE ?
    `;
    
    let params = [cityKeyword];
    
    // Add property type matching if found
    if (matchedTypes.length > 0) {
      const typeConditions = matchedTypes.map(() => 'p.property_type LIKE ?').join(' OR ');
      sql += ` AND (${typeConditions})`;
      matchedTypes.forEach(type => {
        params.push(`%${type}%`);
      });
    }
    
    // Add title/description search for specifics like "5 marla"
    const numbers = query.match(/\d+/g);
    if (numbers && numbers.length > 0) {
      sql += ` AND (p.title LIKE ? OR p.description LIKE ?)`;
      params.push(`%${numbers[0]}%`, `%${numbers[0]}%`);
    }
    
    sql += ` ORDER BY a.created_at DESC LIMIT 50`;
    
    const [rows] = await connection.query(sql, params);
    
    connection.release();
    res.json({ success: true, data: rows || [] });
  } catch (error) {
    console.error('Property search error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Debug endpoint to check properties with society data
app.get('/api/debug/properties-with-society', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query(`
      SELECT id, title, society_id, society_phase, society_block, agent_id 
      FROM properties 
      WHERE society_id IS NOT NULL OR society_phase IS NOT NULL OR society_block IS NOT NULL
    `);
    connection.release();
    res.json({ success: true, data: rows || [] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Search properties by housing society
app.get('/api/properties/by-society', async (req, res) => {
  try {
    const { society_id, society_phase, society_block, type, minPrice, maxPrice } = req.query;
    const connection = await pool.getConnection();
    
    let sql = 'SELECT * FROM properties WHERE society_id IS NOT NULL';
    let params = [];
    
    if (society_id) {
      sql += ' AND society_id = ?';
      params.push(society_id);
    }
    if (society_phase) {
      sql += ' AND society_phase = ?';
      params.push(society_phase);
    }
    if (society_block) {
      sql += ' AND society_block = ?';
      params.push(society_block);
    }
    if (type) {
      sql += ' AND property_type = ?';
      params.push(type);
    }
    if (minPrice) {
      sql += ' AND price >= ?';
      params.push(minPrice);
    }
    if (maxPrice) {
      sql += ' AND price <= ?';
      params.push(maxPrice);
    }
    
    sql += ' ORDER BY created_at DESC';
    
    const [rows] = await connection.query(sql, params);
    
    connection.release();
    res.json({ success: true, data: rows || [] });
  } catch (error) {
    console.error('Society property search error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============== PROPERTIES ENDPOINTS ==============

// Get all properties
app.get('/api/properties', async (req, res) => {
  try {
    const { city, type, status, minPrice, maxPrice, society_id, society_phase, society_block } = req.query;
    let query = 'SELECT * FROM properties WHERE 1=1';
    const params = [];

    if (city) {
      query += ' AND city = ?';
      params.push(city);
    }
    if (type) {
      query += ' AND property_type = ?';
      params.push(type);
    }
    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }
    if (minPrice) {
      query += ' AND price >= ?';
      params.push(minPrice);
    }
    if (maxPrice) {
      query += ' AND price <= ?';
      params.push(maxPrice);
    }
    // Housing society filters
    if (society_id) {
      query += ' AND society_id = ?';
      params.push(society_id);
    }
    if (society_phase) {
      query += ' AND society_phase = ?';
      params.push(society_phase);
    }
    if (society_block) {
      query += ' AND society_block = ?';
      params.push(society_block);
    }

    query += ' ORDER BY created_at DESC';

    const connection = await pool.getConnection();
    const [rows] = await connection.query(query, params);
    connection.release();
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get property by ID
app.get('/api/properties/:id', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM properties WHERE id = ?', [req.params.id]);
    connection.release();
    res.json({ success: true, data: rows[0] || null });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get featured properties (mix of featured + recent user properties)
app.get('/api/properties/featured/true', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    // Get featured properties first
    const [featuredRows] = await connection.query(
      'SELECT * FROM properties WHERE featured = 1 ORDER BY created_at DESC LIMIT 10'
    );
    
    let allProperties = featuredRows;
    
    // If we have fewer than 10 featured properties, add recent properties
    if (allProperties.length < 10) {
      const needed = 10 - allProperties.length;
      const [recentRows] = await connection.query(
        'SELECT * FROM properties WHERE featured = 0 ORDER BY created_at DESC LIMIT ?',
        [needed]
      );
      allProperties = allProperties.concat(recentRows);
    }
    
    connection.release();
    res.json({ success: true, data: allProperties });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create property
app.post('/api/properties', verifyToken, async (req, res) => {
  try {
    const { title, description, price, property_type, type, bedrooms, bathrooms, area_sqft, address, location, city, state, zip_code, latitude, longitude, images, agent_id, status, featured, amenities, user_id, society_id, society_phase, society_block } = req.body;
    const propertyType = property_type || type || 'Apartment';
    const connection = await pool.getConnection();
    const propertyId = uuidv4();
    
    // Build the INSERT query with available columns including society fields
    const insertQuery = `
      INSERT INTO properties 
      (id, title, description, price, property_type, bedrooms, bathrooms, area_sqft, address, city, state, zip_code, latitude, longitude, images, agent_id, status, featured, created_at, updated_at, amenities, society_id, society_phase, society_block) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    await connection.query(insertQuery, [
      propertyId, 
      title, 
      description, 
      price, 
      propertyType, 
      bedrooms, 
      bathrooms, 
      area_sqft, 
      location || address, 
      city, 
      state, 
      zip_code, 
      latitude || null, 
      longitude || null, 
      images ? JSON.stringify(images) : null, 
      agent_id || user_id || req.userId, 
      status || 'available', 
      featured || false,
      null, // created_at
      null, // updated_at
      amenities ? JSON.stringify(amenities) : null,
      society_id || null,
      society_phase || null,
      society_block || null
    ]);
    connection.release();
    res.status(201).json({ success: true, message: 'Property created', id: propertyId });
  } catch (error) {
    console.error('Error creating property:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update property
app.put('/api/properties/:id', verifyToken, async (req, res) => {
  try {
    const { title, description, price, property_type, type, bedrooms, bathrooms, area_sqft, address, location, city, state, zip_code, latitude, longitude, images, status, featured, amenities, society_id, society_phase, society_block } = req.body;
    const propertyType = property_type || type || 'Apartment';
    const connection = await pool.getConnection();
    
    const updateQuery = `
      UPDATE properties 
      SET title = ?, description = ?, price = ?, property_type = ?, bedrooms = ?, bathrooms = ?, area_sqft = ?, address = ?, city = ?, state = ?, zip_code = ?, latitude = ?, longitude = ?, images = ?, amenities = ?, status = ?, featured = ?, society_id = ?, society_phase = ?, society_block = ?, updated_at = NOW() 
      WHERE id = ?
    `;
    
    await connection.query(updateQuery, [
      title, 
      description, 
      price, 
      propertyType, 
      bedrooms, 
      bathrooms, 
      area_sqft, 
      location || address, 
      city, 
      state, 
      zip_code, 
      latitude || null, 
      longitude || null, 
      images ? JSON.stringify(images) : null,
      amenities ? JSON.stringify(amenities) : null,
      status, 
      featured,
      society_id || null,
      society_phase || null,
      society_block || null,
      req.params.id
    ]);
    connection.release();
    res.json({ success: true, message: 'Property updated' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete property
app.delete('/api/properties/:id', verifyToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.query('DELETE FROM properties WHERE id = ?', [req.params.id]);
    connection.release();
    res.json({ success: true, message: 'Property deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all users (for agents to start chat)
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT id, name, email, phone, created_at FROM users ORDER BY created_at DESC');
    connection.release();
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all agents
app.get('/api/agents', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT id, name, email, phone, agency, experience, cnic, address, attachments, created_at FROM agents ORDER BY created_at DESC');
    connection.release();
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get agent by ID
app.get('/api/agents/:agentId', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT id, name, email, phone, agency, experience, cnic, address, attachments, created_at FROM agents WHERE id = ?', [req.params.agentId]);
    connection.release();
    
    if (rows.length > 0) {
      res.json({ success: true, data: rows[0] });
    } else {
      res.status(404).json({ success: false, error: 'Agent not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get properties by agent ID with optional society filter
app.get('/api/agents/:agentId/properties', async (req, res) => {
  try {
    const { society_id, society_phase, society_block } = req.query;
    const connection = await pool.getConnection();
    
    console.log('=== Agent Properties Request ===');
    console.log('Agent ID:', req.params.agentId);
    console.log('Filters:', { society_id, society_phase, society_block });
    
    let sql = 'SELECT * FROM properties WHERE agent_id = ?';
    let params = [req.params.agentId];
    
    // Add society filters if provided - strict matching
    if (society_id) {
      sql += ' AND LOWER(society_id) = LOWER(?)';
      params.push(society_id);
    }
    if (society_phase) {
      sql += ' AND LOWER(society_phase) = LOWER(?)';
      params.push(society_phase);
    }
    if (society_block) {
      sql += ' AND LOWER(society_block) = LOWER(?)';
      params.push(society_block);
    }
    
    sql += ' ORDER BY created_at DESC';
    
    console.log('SQL:', sql);
    console.log('Params:', params);
    
    const [rows] = await connection.query(sql, params);
    
    console.log('Found properties:', rows.length);
    rows.forEach(r => console.log(`  - ${r.title} | society_id: ${r.society_id} | phase: ${r.society_phase} | block: ${r.society_block}`));
    
    connection.release();
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching agent properties:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get single property by ID
app.get('/api/properties/:propertyId', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT * FROM properties WHERE id = ?', [req.params.propertyId]);
    connection.release();
    
    if (rows.length > 0) {
      res.json({ success: true, data: rows[0] });
    } else {
      res.status(404).json({ success: false, error: 'Property not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Search amenities by area (simulates Google search results)
app.get('/api/search/amenities', async (req, res) => {
  try {
    const { q, area, amenity } = req.query;
    
    // Comprehensive amenity data based on area and type
    const amenityDatabase = {
      "karachi": {
        "Top Schools": [
          { name: "Aitchison College", description: "Premier educational institution in Karachi with excellent academics" },
          { name: "Lycee Francais de Karachi", description: "International school offering French curriculum" },
          { name: "Karachi Grammar School", description: "Leading independent school with strong reputation" },
          { name: "Beaconhouse School System", description: "Modern educational system with multiple branches" },
          { name: "Nixor College", description: "Top-tier college in Defence, Karachi" }
        ],
        "Healthcare": [
          { name: "Aga Khan Hospital", description: "State-of-the-art healthcare facility with specialist doctors" },
          { name: "Liaquat National Hospital", description: "Major hospital providing comprehensive medical services" },
          { name: "Ziauddin Medical Center", description: "Multi-specialty hospital with modern equipment" },
          { name: "Pacific Medical Complex", description: "Advanced healthcare center for emergency and routine care" },
          { name: "Sindh Institute of Urology", description: "Specialized urology hospital" }
        ],
        "Shopping": [
          { name: "Dolmen Mall Karachi", description: "Premium shopping destination with international brands" },
          { name: "Serena Hotel", description: "Luxury shopping and dining complex in Clifton" },
          { name: "Atrium Mall", description: "Modern retail center with cafes and restaurants" },
          { name: "Lucky One Mall", description: "Large shopping mall with entertainment options" },
          { name: "Hyperstar", description: "Popular supermarket chain with multiple locations" }
        ],
        "Transport Links": [
          { name: "Jinnah International Airport", description: "Main airport connecting Pakistan to international destinations" },
          { name: "Karachi Port Trust", description: "Major seaport for international trade" },
          { name: "Orange Line Metro", description: "Modern public transportation system" },
          { name: "Karachiway Motorway", description: "Highway connecting major areas of the city" },
          { name: "City Bus Service", description: "Comprehensive public transport network" }
        ],
        "Parks": [
          { name: "Port Grand Park", description: "Waterfront park with recreational facilities and food stalls" },
          { name: "Jilani Park", description: "Large public park with walking trails and green spaces" },
          { name: "Hill Park", description: "Scenic hilltop park with panoramic views of the city" },
          { name: "Sea View Park", description: "Coastal park with beach access and sunset views" },
          { name: "Clifton Beach", description: "Popular beach destination in Karachi" }
        ],
        "Safe Area": [
          { name: "Defence Housing Authority (DHA)", description: "Gated community with 24/7 security" },
          { name: "Clifton", description: "Upscale residential area with high security" },
          { name: "Bath Island", description: "Secure residential community" },
          { name: "Gulberg", description: "Established neighborhood with good security" }
        ]
      },
      "lahore": {
        "Top Schools": [
          { name: "Aitchison College Lahore", description: "Elite boarding school with international standards" },
          { name: "Lahore Grammar School", description: "Leading educational institution in Punjab" },
          { name: "Beaconhouse School", description: "Modern school with advanced learning facilities" },
          { name: "PAF College Lahore", description: "Military school with strict discipline and excellence" },
          { name: "Fazaia Schools", description: "Air Force schools with quality education" }
        ],
        "Healthcare": [
          { name: "Shaukat Khanum Hospital", description: "Top cancer hospital with specialist oncologists" },
          { name: "Fatima Memorial Hospital", description: "Leading healthcare provider in Lahore" },
          { name: "Combined Military Hospital", description: "Major military hospital with advanced equipment" },
          { name: "Services Hospital", description: "Government hospital providing quality healthcare" },
          { name: "Ittefaq Hospital", description: "Multi-specialty hospital in Lahore" }
        ],
        "Shopping": [
          { name: "Packages Mall", description: "Premium shopping center with luxury brands" },
          { name: "Emporium Mall", description: "High-end retail destination in Gulberg" },
          { name: "Liberty Market", description: "Historic shopping area with traditional and modern shops" },
          { name: "Mall Road", description: "Famous street with international retail brands" },
          { name: "Galleria", description: "Modern shopping complex with restaurants" }
        ],
        "Transport Links": [
          { name: "Allama Iqbal International Airport", description: "Main airport serving Lahore and region" },
          { name: "Lahore Railway Station", description: "Historic station connecting major cities" },
          { name: "Orange Line Metro", description: "Modern rapid transit system across the city" },
          { name: "Grand Trunk Road", description: "Historic highway connecting northern cities" },
          { name: "Lahore Circular Railway", description: "Commuter rail service connecting neighborhoods" }
        ],
        "Parks": [
          { name: "Jilani Park Lahore", description: "Large public park in city center with jogging track" },
          { name: "Racecourse Park", description: "Historic park with sports facilities and events" },
          { name: "Lawrence Garden", description: "Beautiful botanical garden with rare plants" },
          { name: "Mall Road Park", description: "Urban park with recreational activities" },
          { name: "Thokar Niaz Baig Park", description: "Modern park with playgrounds" }
        ],
        "Safe Area": [
          { name: "DHA Lahore", description: "Premium gated community with top security" },
          { name: "Defence Colony", description: "Established safe residential area" },
          { name: "Cantt Area", description: "Military cantonment with excellent security" },
          { name: "Gulberg", description: "Upscale neighborhood with gated communities" }
        ]
      },
      "islamabad": {
        "Top Schools": [
          { name: "Islamabad Model College", description: "Premier educational institution in the capital" },
          { name: "FAST School Islamabad", description: "Modern school with technology focus" },
          { name: "Roots School", description: "Leading private school in Islamabad" },
          { name: "Army Public School Islamabad", description: "Military-managed school with excellent standards" },
          { name: "Cadet College Islamabad", description: "Premier boarding school for boys" }
        ],
        "Healthcare": [
          { name: "Pakistan Institute of Medical Sciences (PIMS)", description: "Major government hospital in Islamabad" },
          { name: "Shifa International Hospital", description: "Top private hospital with all specialties" },
          { name: "Poly Clinic Hospital", description: "Multi-specialty hospital in city center" },
          { name: "Federal Government Hospital", description: "Government healthcare facility" },
          { name: "HNP Civil Hospital", description: "Public hospital in Islamabad" }
        ],
        "Shopping": [
          { name: "Centaurus Mall", description: "Premium shopping mall in Blue Area" },
          { name: "F-7 Shopping Center", description: "Elite shopping destination in Islamabad" },
          { name: "Rawal Trade Centre", description: "Commercial hub with shops and offices" },
          { name: "Blue Area Market", description: "High-end shopping and dining district" },
          { name: "Jinnah Supermarket", description: "Popular shopping destination" }
        ],
        "Transport Links": [
          { name: "New Islamabad International Airport", description: "Modern international airport" },
          { name: "Grand Trunk Road", description: "Major highway connecting cities" },
          { name: "Motorway Network", description: "Expressway system for quick connectivity" },
          { name: "Blue Bus Service", description: "Public transportation system" },
          { name: "Margalla Road", description: "Main arterial road in Islamabad" }
        ],
        "Parks": [
          { name: "Margalla Hills National Park", description: "Beautiful hills with trekking trails and hiking" },
          { name: "Rawal Lake", description: "Scenic lake with recreational facilities" },
          { name: "F-9 Park", description: "Large central park in Islamabad" },
          { name: "Shakarparian", description: "Historic park with viewpoint overlooking city" },
          { name: "Zero Point Park", description: "Popular recreational area" }
        ],
        "Safe Area": [
          { name: "DHA Islamabad", description: "Premium gated community with high security" },
          { name: "F-7 Sector", description: "Diplomatic area with excellent security" },
          { name: "G-6 Sector", description: "Secure residential sector" },
          { name: "Bahria Town Islamabad", description: "Master-planned community with security" }
        ]
      },
      "rawalpindi": {
        "Top Schools": [
          { name: "Beaconhouse School Rawalpindi", description: "Modern educational institution" },
          { name: "Military College Rawalpindi", description: "Premier military educational institution" },
          { name: "Rangers School", description: "Rangers-managed educational institution" }
        ],
        "Healthcare": [
          { name: "Holy Family Hospital", description: "Major hospital in Rawalpindi" },
          { name: "Combined Military Hospital Rawalpindi", description: "Military hospital with advanced facilities" },
          { name: "Bahria Hospital", description: "Hospital in Bahria Town Rawalpindi" }
        ],
        "Shopping": [
          { name: "Bahria Town Rawalpindi", description: "Master-planned community with shopping facilities" },
          { name: "Pindi Point", description: "Shopping and entertainment complex" },
          { name: "Rawalpindi Mall", description: "Modern shopping destination" }
        ],
        "Transport Links": [
          { name: "Benazir Bhutto International Airport", description: "Serves Rawalpindi and Islamabad" },
          { name: "Grand Trunk Road", description: "Major highway" },
          { name: "Motorway Junction", description: "Highway connectivity" }
        ],
        "Parks": [
          { name: "Ayub Park", description: "Large recreational park in Rawalpindi" },
          { name: "Mall Road", description: "Historical road with parks" },
          { name: "Race Course Park", description: "Sports and recreation area" }
        ],
        "Safe Area": [
          { name: "Bahria Town", description: "Master-planned gated community" },
          { name: "Pindi Point", description: "Secure residential development" },
          { name: "Adiala Road", description: "Established safe neighborhood" }
        ]
      },
      "dha": {
        "Top Schools": [
          { name: "DHA School System", description: "Excellent schools within DHA communities" },
          { name: "DHA Grammar School", description: "Leading school in DHA" }
        ],
        "Healthcare": [
          { name: "DHA Medical Center", description: "Healthcare facility within DHA" },
          { name: "DHA Clinic", description: "Medical facilities for residents" }
        ],
        "Shopping": [
          { name: "DHA Shopping Mall", description: "Shopping facilities within DHA" },
          { name: "DHA Market", description: "Retail shops in DHA" }
        ],
        "Transport Links": [
          { name: "DHA Roads", description: "Well-maintained internal road network" },
          { name: "Main Gate Access", description: "Easy access to main highways" }
        ],
        "Parks": [
          { name: "DHA Parks", description: "Multiple parks within DHA community" },
          { name: "DHA Sports Complex", description: "Sports and recreation facilities" }
        ],
        "Safe Area": [
          { name: "DHA Gated Security", description: "24/7 armed security and CCTV" },
          { name: "DHA Police Station", description: "Dedicated police force" },
          { name: "Security Gates", description: "Multiple controlled entry points" }
        ]
      },
      "bahria town": {
        "Top Schools": [
          { name: "Bahria School System", description: "Quality schools in Bahria Town" },
          { name: "Bahria Academy", description: "Educational institution" }
        ],
        "Healthcare": [
          { name: "Bahria Hospital", description: "Multi-specialty hospital in Bahria Town" },
          { name: "Bahria Medical Center", description: "Healthcare services for residents" }
        ],
        "Shopping": [
          { name: "Bahria Mall", description: "Shopping center in Bahria Town" },
          { name: "Bahria Plaza", description: "Retail and dining complex" }
        ],
        "Transport Links": [
          { name: "Bahria Roads", description: "Modern road infrastructure" },
          { name: "Main Highway Access", description: "Easy connectivity to main roads" }
        ],
        "Parks": [
          { name: "Bahria Parks", description: "Multiple green spaces" },
          { name: "Community Center", description: "Recreation facilities" }
        ],
        "Safe Area": [
          { name: "24/7 Security", description: "Armed security patrol" },
          { name: "Gated Community", description: "Controlled entry and exit" },
          { name: "CCTV Coverage", description: "Comprehensive surveillance system" }
        ]
      },
      "gulberg": {
        "Top Schools": [
          { name: "Gulberg Schools", description: "Quality educational institutions in Gulberg" }
        ],
        "Healthcare": [
          { name: "Gulberg Medical Center", description: "Healthcare facilities in Gulberg" }
        ],
        "Shopping": [
          { name: "Gulberg Market", description: "Shopping and dining area" }
        ],
        "Transport Links": [
          { name: "Gulberg Roads", description: "Well-connected road network" }
        ],
        "Parks": [
          { name: "Gulberg Parks", description: "Green spaces in neighborhood" }
        ],
        "Safe Area": [
          { name: "Secure Neighborhood", description: "Well-established safe area" }
        ]
      }
    };

    // Normalize inputs
    const normalizedArea = area.toLowerCase().trim();
    const normalizedAmenity = amenity.toLowerCase().trim().replace(/\s+/g, ' ');

    // Get amenities for the specific area and type
    const areaData = amenityDatabase[normalizedArea];
    
    let results = [];
    if (areaData) {
      // Find matching amenity (case-insensitive)
      for (const [amenityKey, amenityList] of Object.entries(areaData)) {
        if (amenityKey.toLowerCase() === normalizedAmenity) {
          results = amenityList;
          break;
        }
      }
    }

    // If no results found, provide helpful message
    if (results.length === 0) {
      results = [
        { name: "Not Found", description: `No specific data found for ${amenity} in ${area}. Please try searching for another amenity type.` }
      ];
    }

    res.json({ 
      success: true, 
      data: results,
      query: q,
      area: area,
      amenity: amenity
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get user properties (properties where agent_id matches user/agent)
app.get('/api/properties/user/:userId', verifyToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query(
      'SELECT * FROM properties WHERE agent_id = ? ORDER BY created_at DESC',
      [req.params.userId]
    );
    connection.release();
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============== LIVE CHAT ENDPOINTS ==============

// Create chat_conversations table if not exists
const initChatTables = async () => {
  try {
    const connection = await pool.getConnection();
    
    // Create conversations table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS chat_conversations (
        id CHAR(36) PRIMARY KEY,
        user_id CHAR(36) NOT NULL,
        user_name VARCHAR(255) NOT NULL,
        user_email VARCHAR(255),
        agent_id CHAR(36) NOT NULL,
        agent_name VARCHAR(255) NOT NULL,
        agent_email VARCHAR(255),
        agent_phone VARCHAR(50),
        agent_agency VARCHAR(255),
        last_message TEXT,
        last_message_time TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);
    
    // Create messages table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id CHAR(36) PRIMARY KEY,
        conversation_id CHAR(36) NOT NULL,
        sender_id CHAR(36) NOT NULL,
        sender_type ENUM('user', 'agent') NOT NULL,
        sender_name VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        read_status BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE
      )
    `);
    
    connection.release();
    console.log('✓ Chat tables initialized successfully');
  } catch (error) {
    console.error('Error initializing chat tables:', error.message);
  }
};

// Initialize chat tables on server start
initChatTables();

// Get conversations for a user or agent
app.get('/api/chat/conversations', verifyToken, async (req, res) => {
  try {
    const { userId, userType } = req.query;
    
    if (!userId || !userType) {
      return res.status(400).json({ success: false, error: 'userId and userType are required' });
    }
    
    const connection = await pool.getConnection();
    
    let query;
    if (userType === 'user') {
      query = `
        SELECT c.*, 
          (SELECT COUNT(*) FROM chat_messages m WHERE m.conversation_id = c.id AND m.read_status = false AND m.sender_type = 'agent') as unread_count
        FROM chat_conversations c 
        WHERE c.user_id = ? 
        ORDER BY c.last_message_time DESC, c.created_at DESC
      `;
    } else {
      query = `
        SELECT c.*, 
          (SELECT COUNT(*) FROM chat_messages m WHERE m.conversation_id = c.id AND m.read_status = false AND m.sender_type = 'user') as unread_count
        FROM chat_conversations c 
        WHERE c.agent_id = ? 
        ORDER BY c.last_message_time DESC, c.created_at DESC
      `;
    }
    
    const [rows] = await connection.query(query, [userId]);
    connection.release();
    
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create a new conversation
app.post('/api/chat/conversations', verifyToken, async (req, res) => {
  try {
    const { userId, userName, userEmail, agentId, agentName, agentEmail, agentPhone, agentAgency } = req.body;
    
    if (!userId || !agentId) {
      return res.status(400).json({ success: false, error: 'userId and agentId are required' });
    }
    
    const connection = await pool.getConnection();
    
    // Check if conversation already exists
    const [existing] = await connection.query(
      'SELECT * FROM chat_conversations WHERE user_id = ? AND agent_id = ?',
      [userId, agentId]
    );
    
    if (existing.length > 0) {
      connection.release();
      return res.json({ success: true, data: existing[0], existing: true });
    }
    
    // Create new conversation
    const conversationId = uuidv4();
    await connection.query(
      `INSERT INTO chat_conversations 
        (id, user_id, user_name, user_email, agent_id, agent_name, agent_email, agent_phone, agent_agency) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [conversationId, userId, userName, userEmail, agentId, agentName, agentEmail, agentPhone, agentAgency]
    );
    
    const [newConversation] = await connection.query(
      'SELECT * FROM chat_conversations WHERE id = ?',
      [conversationId]
    );
    
    connection.release();
    res.json({ success: true, data: newConversation[0] });
  } catch (error) {
    console.error('Error creating conversation:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get messages for a conversation
app.get('/api/chat/messages/:conversationId', verifyToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    
    const connection = await pool.getConnection();
    const [rows] = await connection.query(
      'SELECT * FROM chat_messages WHERE conversation_id = ? ORDER BY created_at ASC',
      [conversationId]
    );
    connection.release();
    
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Send a new message
app.post('/api/chat/messages', verifyToken, async (req, res) => {
  try {
    const { conversationId, senderId, senderType, senderName, message } = req.body;
    
    if (!conversationId || !senderId || !senderType || !message) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }
    
    const connection = await pool.getConnection();
    
    const messageId = uuidv4();
    await connection.query(
      `INSERT INTO chat_messages (id, conversation_id, sender_id, sender_type, sender_name, message) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [messageId, conversationId, senderId, senderType, senderName, message]
    );
    
    // Update conversation's last message
    await connection.query(
      `UPDATE chat_conversations 
       SET last_message = ?, last_message_time = CURRENT_TIMESTAMP 
       WHERE id = ?`,
      [message.substring(0, 100), conversationId]
    );
    
    const [newMessage] = await connection.query(
      'SELECT * FROM chat_messages WHERE id = ?',
      [messageId]
    );
    
    connection.release();
    res.json({ success: true, data: newMessage[0] });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Mark messages as read
app.put('/api/chat/messages/:conversationId/read', verifyToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { readerId, readerType } = req.body;
    
    const connection = await pool.getConnection();
    
    // Mark messages from the other party as read
    const senderType = readerType === 'user' ? 'agent' : 'user';
    await connection.query(
      `UPDATE chat_messages 
       SET read_status = true 
       WHERE conversation_id = ? AND sender_type = ? AND read_status = false`,
      [conversationId, senderType]
    );
    
    connection.release();
    res.json({ success: true, message: 'Messages marked as read' });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get unread message count for a user
app.get('/api/chat/unread-count', verifyToken, async (req, res) => {
  try {
    const { userId, userType } = req.query;
    
    if (!userId || !userType) {
      return res.status(400).json({ success: false, error: 'userId and userType are required' });
    }
    
    const connection = await pool.getConnection();
    
    let query;
    if (userType === 'user') {
      query = `
        SELECT COUNT(*) as count 
        FROM chat_messages m 
        JOIN chat_conversations c ON m.conversation_id = c.id 
        WHERE c.user_id = ? AND m.sender_type = 'agent' AND m.read_status = false
      `;
    } else {
      query = `
        SELECT COUNT(*) as count 
        FROM chat_messages m 
        JOIN chat_conversations c ON m.conversation_id = c.id 
        WHERE c.agent_id = ? AND m.sender_type = 'user' AND m.read_status = false
      `;
    }
    
    const [rows] = await connection.query(query, [userId]);
    connection.release();
    
    res.json({ success: true, count: rows[0].count });
  } catch (error) {
    console.error('Error fetching unread count:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'Server is running' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
