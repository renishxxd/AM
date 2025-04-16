# AM Apparel Customization System

This system allows users to submit customization requests for clothing items, which are stored directly in MongoDB.

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (running on localhost:27017)

## Setup Instructions

1. **Install MongoDB**
   - Download and install MongoDB from [mongodb.com](https://www.mongodb.com/try/download/community)
   - Start MongoDB server:
     ```
     mongod --dbpath /path/to/your/data/directory
     ```

2. **Install Dependencies**
   - Run the following command in the project directory:
     ```
     npm install
     ```

3. **Start the Server**
   - Run the following command:
     ```
     npm start
     ```
   - The server will start on http://localhost:5000

## How It Works

1. The customize2.html page contains a form for users to submit customization requests
2. When a user submits the form, the data is sent to the Node.js server
3. The server connects directly to MongoDB and stores the data in the ecommerceDB database
4. The customization requests are stored in the 'customizations' collection
5. User activities are logged in the 'activities' collection

## MongoDB Collections

- **customizations**: Stores all customization requests
- **activities**: Logs user activities

## Troubleshooting

If you encounter connection issues:
1. Make sure MongoDB is running on localhost:27017
2. Check that the Node.js server is running on localhost:5000
3. Verify that the user is logged in (localStorage contains 'token' and 'userId')