<?php

	if (isset($_POST['submit'])) {

		$servername = "localhost";
		$username 	= "chris";
		$password 	= "chris";
		$dbname 	= 'users';
		// Create connection
		$conn = new mysqli($servername, $username, $password, $dbname);

		// Check connection
		if ($conn->connect_error) {
		    die("Connection failed: " . $conn->connect_error);
		}
		else {
			echo "Connected successfully";
		}

		$var = $_POST['firstname'];
		$sql = "SELECT * FROM users WHERE firstname = '$var';";
		// ' or '1'='1
		$result = $conn->query($sql);

		if ($result->num_rows > 0) {
		    // output data of each row
		    while($row = $result->fetch_assoc()) {
		        echo "id: " . $row["id"]. " - Name: " . $row["firstname"]. " " . $row["lastname"]. " " . $row["email"] . "<br>";
		    }
		}
		else {
   			echo "0 results";
		}
	}
?>

<?php require "templates/header.php"; ?>

<h2>Retrieve a user</h2>

<form method="post">
	<label for="firstname">First Name</label>
	<input type="text" name="firstname" id="firstname">
	<input type="submit" name="submit" value="Submit">
</form>

<a href="index.php">Back to home</a>

<?php require "templates/footer.php"; ?>