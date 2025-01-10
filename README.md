# Chronicle: Your Ultimate Travel Companion 

Welcome to Chronicle – your go-to platform for documenting and sharing travel experiences!

The Chronicle app is a mobile web application designed to streamline the documentation and sharing of travel experiences. It offers users a platform to record their journeys, capturing memories through text, photos, and videos. With features like user authentication, multimedia file storage, and interactive maps, Chronicle facilitates seamless travel documentation and sharing. Whether users are solo adventurers, globetrotting families, or travel enthusiasts, Chronicle provides a centralized hub for organizing and reliving their travel adventures.

[Live Demo](https://chronicle-web-app-eight.vercel.app/) - unavailable

Feel free to create an account to try out the application!

## Development Team 
- #### Riccardo Moncada (e-mail: rmoncada@myseneca.ca)
- #### Vaibhav Parmar   (e-mail: vgparmar@myseneca.ca)
- #### Artem Pankov     (e-mail: apankov@myseneca.ca)
- #### Juan David Rodriguez Castelblanco (e-mail: jdrodriguez-castelbl@myseneca.ca)

# Installation Instructions

## Prerequisites
Before you begin, ensure you have the following installed on your machine:

```
Node.js
npm
Git
```
## Cloning the Repository

Clone the repository and its submodules to your local machine using the following commands:

```
git clone https://github.com/Vaibhav-G-Parmar/PRJ566-Team_4.git
cd PRJ566-Team_
git submodule init
git submodule update
```
# Chronicle Frontend

## Core Technologies

- **React**: Built with React for a dynamic and responsive user interface.
- **Next.js**: Utilizing Next.js for server-side rendering and optimized routing.
- **TypeScript**: Enhancing code readability and maintainability with TypeScript.
- **Redux**: Managing state across components with Redux for a seamless user experience.
- **HTML5**: Semantic markup for enhanced accessibility and SEO.
- **Tailwind CSS**: Styling components with Tailwind CSS for a sleek and modern look.
- **Google Places Autocomplete**: Integrating location search and autocomplete functionality for seamless user experience.
- **Leaflet Maps**: Providing interactive and visually appealing maps for exploring destinations.
- **Heroicons**: Utilizing Heroicons for high-quality SVG icons to enhance user interface elements.

## Features and Functionalities

- **Document Travel Experiences**: Seamlessly document your travel adventures with our intuitive interface.
- **Connect with Like-Minded Travelers**: Connect and engage with fellow travelers to share insights and tips.
- **Explore New Destinations**: Explore new destinations with interactive maps and discover hidden gems.
- **Personalized Recommendations**: Rate and review destinations to receive personalized recommendations tailored to your preferences.
- **Real-Time Feedback and Insights**: Share real-time feedback and insights with the travel community to enhance experiences for all.
- **User-Friendly Interface**: Enjoy a user-friendly interface designed to provide a seamless browsing experience.
- **Multimedia Content Support**: Upload and share multimedia content including photos and videos to enrich your travel stories.
- **Responsive Design**: Access Travel Chronicle from any device with our responsive design that adapts to various screen sizes.

## Installation

## Front-end (Next.js App)
```
1. Navigate to the front-end directory:
```
```
cd Chronicle_Web_App_Repo_SubModule
```
```
2. Install the required packages:
```
```
npm install
```
```
3. Configure environment variables:
```
```
Create a .env file in the front-end directory.
Add the necessary environment variables:
```
```
NEXT_PUBLIC_API_URL="http://localhost:8080/api"
NEXT_PUBLIC_GOOGLE_MAPS_API_KEY=<your_google_maps_api_key>
```
```
To obtain a Google Maps API key, follow the steps outlined here.
```

# Chronicle Backend

## Core Technologies

- **Node.js**: Built with Node.js for server-side logic and API development.
- **Express.js**: Utilizing Express.js for building robust and scalable APIs with ease.
- **MongoDB**: Storing and managing data using MongoDB, a flexible and scalable NoSQL database.
- **Mongoose**: Interfacing with MongoDB using Mongoose for simplified data modeling and validation.
- **Passport.js**: Implementing authentication middleware with Passport.js for secure user authentication.
- **Bcrypt**: Encrypting passwords using Bcrypt for enhanced security.
- **Dropbox API**: Integrating Dropbox API for storing and managing multimedia content such as photos and videos.
- **Cyclic.sh**: Deploying backend servers on Cyclic.sh for automated testing and scaling.

## Features and Functionalities

- **User Authentication**: Implement secure user authentication with Passport.js and Bcrypt.
- **Data Management**: Store and manage travel data efficiently using MongoDB and Mongoose.
- **File Storage**: Integrate with Dropbox API for storing multimedia content associated with travel entries.
- **API Endpoints**: Define and implement API endpoints to handle CRUD operations for travel entries, user authentication, and more.
- **Scalable Architecture**: Deploy backend servers on Cyclic.sh for automated scaling and testing.
- **Security**: Ensure data security and integrity with robust authentication and encryption mechanisms.

## Back-end (Express.js API)

```
1. Navigate to the back-end directory:
```
```
cd ../Chronicle_Users_API_Repo_SubModule
```
```
2. Install the required packages:
```
```
npm install
```
```
3. Configure environment variables:
```
```
Create a .env file in the back-end directory.
Add the necessary environment variables:
```
```
MONGO_URL=<your_database_connection_string>
REFRESH_TOKEN=<your_dropbox_refresh_token>
APP_KEY=<your_dropbox_app_key>
APP_SECRET=<your_dropbox_app_secret>
```
```
Obtain REFRESH_TOKEN, APP_KEY, and APP_SECRET by setting up your application storage at Dropbox for Developers.
Get MONGO_URL by creating a cluster at Mongo Atlas
```
## Running the Application

## Running the API


```
1. In the backend directory, start the API server:
```
```
node server.js
```
## Running the Front-end
```
1. Open a new terminal and navigate to the frontend directory.
2. Start the Next.js development server:
```
```
npm run dev
```
## Accessing the Application
```
The front-end application will be available at http://localhost:3000.
The API will be accessible at http://localhost:8080.
```
# Deployment Instructions

## Frontend Deployment on Vercel
```
1. Sign up or log in to your Vercel account.
2. Click on the "New Project" button.
3. Import your project from your GitHub repository.
4. Before deploying, set up your environment variables by going to the "Settings" tab of your project:
Click on the "Environment Variables" section.
Add all the necessary variables such as NEXT_PUBLIC_API_URL and NEXT_PUBLIC_GOOGLE_MAPS_API_KEY.
5. After setting your environment variables, deploy your application by clicking the "Deploy" button.
```
## Backend Deployment on Cyclic

```
1. Sign up or log in to your Cyclic account.
2. Click on "New App" and choose to import from GitHub.
3. Select your repository containing the Express.js backend.
4. Configure your environment variables in the Cyclic dashboard:
Navigate to the "Environment" tab of your app settings.
Add the environment variables such as MONGO_URL, REFRESH_TOKEN, APP_KEY, and APP_SECRET.
5. Once you've set up the environment variables, deploy your application.
```
## Database Setup with MongoDB Atlas

```
1. Sign up or log in to MongoDB Atlas.
2. Create a new cluster if you haven't already.
3. Create a new database user with read and write privileges.
4. Go to the "Network Access" section and add an IP address to allowlist from which your backend will connect.
5. Navigate to the "Clusters" section, click on "Connect" and then choose "Connect your application".
6. Copy the connection string provided.
7. Replace the <password> with the database user's password you created and add this to your environment variables on Cyclic as MONGO_URL.
```

