# Use official Node.js image as the base
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy the rest of the application code
COPY . .

# Build the app (if using a build step)
RUN npm run build

# Expose port (change if your app uses a different port)
EXPOSE 3000

# Start the application
CMD ["npm", "run", "preview"]
