# Dockerfile for Flask app with Nginx
FROM python:3.9-alpine

# Install Nginx and other dependencies
RUN apk update && apk add --no-cache nginx

# Set up Flask app
WORKDIR /app

# Install Flask and other Python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Flask app code into the container
COPY . .

# Nginx configuration
COPY configs/nginx.conf /etc/nginx/nginx.conf

COPY start.sh /start.sh
RUN chmod +x /start.sh

# Expose ports
EXPOSE 80 
EXPOSE 443
# Start Supervisor to manage processes
CMD ["/start.sh"]  