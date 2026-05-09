# Dockerfile for Admin Dashboard

FROM node:18-alpine as build

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
# Note: In a production monorepo, we'd use 'npm run build' 
# and serve static files. For development/demo, we use the dev server.
EXPOSE 3001

CMD ["npm", "run", "web", "--", "--port", "3001"]
