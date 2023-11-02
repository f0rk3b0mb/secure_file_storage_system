This is for a school project on secure file storage system


This webapp uses flask as the web server. There is also a sqlite database that stores details about users and files its model can be found in database.py. 
The is an nginx server listening on port 80 that handles https connection provideas a way of catching access and error logs. 
The files are encrypted using AES( Advanced encryption algorithm). 
The app also gnerates reports this functionality can be found in report_generator. 