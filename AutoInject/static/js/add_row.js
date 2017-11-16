$(document).ready(function() {
   
    var table = $('#packages').DataTable();
    var JSON_data = {{ package_JSON_data }};
    console.log(JSON_data);

        table.row.add( [
            "Hello",
            "Hola",
            "Senor"
        ] ).draw();

} );