# Socket

> A Real-Time Anonymous Chat Application

Socket is a real-time anonymous chat application where users can log in or register with a unique username and email. This username serves as the pass to engage in anonymous chats with other users who have accepted their request. Users can send friend requests to others using their usernames and start chatting once the requests are accepted.

## Getting Started

1. **Fork the Repository**: Start by forking the repository to your GitHub account.

2. **Clone the Repository**: Clone the forked repository to your local machine using the following command:

   ```bash
   git clone https://github.com/your-github-username/socket-server
   ```

3. **Install Required Packages**: Navigate to the cloned directory and install the required packages:

   ```bash
   npm install
   ```

4. **Create the .env file and populate it with required Environment Variables**: Create a .env file in the root directory and add the necessary environment variables, such as: 
```javascript
MONGODB_URI=your_mongodb_connection_uri
JWT_SECRET=your_jwt_secret
```

5. **Run the Development Server**: Start the development server for the front-end:

   ```bash
   npm run dev
   ```

   You can also use `yarn dev`, `pnpm dev`, or `bun dev` depending on your package manager.

6. **View the Application**:View the Application: Open your browser and go to http://localhost:8000 to see the Socket Server application in action.


## Project Overview

Socket is built using TypeScript, Node.js, Express.js and Socket.io.

It incorporates the following technologies and features:

- **TypeScript**: Ensures static typing for a more robust codebase.
- **Socket.io**: Used for real time communication.
- **Express**: Utilized for creating REST APIs.
- **Mongoose**: Used for operating on MongoDB database

## Additional Notes
Make sure to have MongoDB installed and running on your system or use a cloud-based MongoDB service.