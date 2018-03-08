<?php

if (isset($_POST['submit'])) {

$servername = "localhost";
$username 	= "chris";
$password 	= "chris";
$dbname 	= 'users';
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
else {
	echo "Connected successfully";
}

$var = $_POST['firstname'];
$stmt = $conn->prepare('SELECT * FROM users WHERE firstname = ?');
$stmt->bind_param('s', $var);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
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