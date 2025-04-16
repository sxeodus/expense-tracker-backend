const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

(async () => {
  try {
    // Connect to the database
    const connection = await mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: 'Allsouth22$$', // Replace with your MySQL password
      database: 'ExpenseTrackerDB', // Replace with your database name
    });

    // User details
    const username = 'whiteman001';
    const email = 'segunodumeso@hotmail.com';
    const plainPassword = '777Good@';

    // Hash the password
    const hashedPassword = await bcrypt.hash(plainPassword, 10);

    // Insert the user into the database
    await connection.execute(
      'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
      [username, hashedPassword, email]
    );

    console.log('User added successfully!');
    await connection.end();
  } catch (error) {
    console.error('Error adding user:', error);
  }
})();