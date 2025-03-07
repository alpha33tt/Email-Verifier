const express = require('express');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Serve static files (like CSS, JS, images) from the "public" folder
app.use(express.static(path.join(__dirname, '../public')));

// Serve index.html on root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));  // Adjust path to index.html
});

// Your email validation logic or other server-side code goes here

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

