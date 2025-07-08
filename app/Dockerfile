# Use official Node.js image
FROM node:18

# Set working directory
WORKDIR /app

# Copy all project files into the container
COPY . .

# Install dependencies
RUN npm install

# Expose the port your server is listening on
EXPOSE 10000

# Run the server
CMD ["node", "backend/server.js"]
